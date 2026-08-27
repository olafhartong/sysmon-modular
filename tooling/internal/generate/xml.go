package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
	"github.com/olafhartong/sysmon-modular/tooling/internal/validate"
)

type Condition struct {
	Field     string
	Operator  string
	Value     string
	Technique string
	Comment   string
}

type RuleSpec struct {
	Name          string
	GroupRelation string
	Conditions    []Condition
}

func Module(event, onmatch string, conditions []Condition, schema string) *sysmonxml.Document {
	rule := RuleSpec{GroupRelation: "and", Conditions: conditions}
	return ModuleFromRules(event, onmatch, []RuleSpec{rule}, schema)
}

func ModuleFromRules(event, onmatch string, rules []RuleSpec, schema string) *sysmonxml.Document {
	if schema == "" {
		schema = "4.90"
	}
	eventNode := sysmonxml.Element(event, map[string]string{"onmatch": onmatch})
	for _, rule := range normalizeUniqueRules(rules) {
		if rule.GroupRelation == "" {
			rule.GroupRelation = "and"
		}
		if len(rule.Conditions) == 1 {
			eventNode.Children = append(eventNode.Children, conditionNode(rule.Conditions[0], rule.Name))
			continue
		}
		attrs := map[string]string{"groupRelation": rule.GroupRelation}
		if rule.Name != "" {
			attrs["name"] = rule.Name
		}
		ruleNode := sysmonxml.Element("Rule", attrs)
		for _, cond := range rule.Conditions {
			ruleNode.Children = append(ruleNode.Children, conditionNode(cond, ""))
		}
		eventNode.Children = append(eventNode.Children, ruleNode)
	}
	root := sysmonxml.Element("Sysmon", map[string]string{"schemaversion": schema},
		sysmonxml.Element("EventFiltering", nil,
			sysmonxml.Element("RuleGroup", map[string]string{"groupRelation": "or", "name": "MDE generated " + event + " " + onmatch}, eventNode),
		),
	)
	return &sysmonxml.Document{Root: root}
}

func WriteModule(path, event, onmatch string, conditions []Condition) error {
	doc := Module(event, onmatch, conditions, "4.90")
	if err := validateGeneratedModule(doc, path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, doc.Bytes(), 0o644)
}

func WriteModuleFromRules(path, event, onmatch string, rules []RuleSpec) error {
	doc := ModuleFromRules(event, onmatch, rules, "4.90")
	if err := validateGeneratedModule(doc, path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, doc.Bytes(), 0o644)
}

func validateGeneratedModule(doc *sysmonxml.Document, path string) error {
	for _, finding := range validate.Schema(doc, path) {
		if finding.Severity == validate.Error {
			return fmt.Errorf("generated module failed schema validation: %s: %s", finding.Message, finding.Detail)
		}
	}
	return nil
}

func conditionNode(cond Condition, fallbackName string) *sysmonxml.Node {
	attrs := map[string]string{"condition": cond.Operator}
	if cond.Technique != "" {
		attrs["name"] = cond.Technique
	} else if fallbackName != "" {
		attrs["name"] = fallbackName
	}
	node := sysmonxml.TextElement(cond.Field, cond.Value, attrs)
	node.TrailingComment = cond.Comment
	return node
}

func normalizeUniqueConditions(conditions []Condition) []Condition {
	seen := map[string]bool{}
	var out []Condition
	for _, c := range conditions {
		c.Field = strings.TrimSpace(c.Field)
		c.Operator = strings.TrimSpace(c.Operator)
		if c.Field == "" || c.Operator == "" || strings.TrimSpace(c.Value) == "" {
			continue
		}
		key := c.Field + "\x00" + c.Operator + "\x00" + strings.ToLower(c.Value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Field == out[j].Field {
			return out[i].Value < out[j].Value
		}
		return out[i].Field < out[j].Field
	})
	return out
}

func normalizeUniqueRules(rules []RuleSpec) []RuleSpec {
	seen := map[string]bool{}
	var out []RuleSpec
	for _, rule := range rules {
		rule.Name = strings.TrimSpace(rule.Name)
		rule.GroupRelation = strings.TrimSpace(strings.ToLower(rule.GroupRelation))
		rule.Conditions = normalizeUniqueConditions(rule.Conditions)
		if len(rule.Conditions) == 0 {
			continue
		}
		parts := []string{rule.Name, rule.GroupRelation}
		for _, c := range rule.Conditions {
			parts = append(parts, c.Field, c.Operator, strings.ToLower(c.Value))
		}
		key := strings.Join(parts, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, rule)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			if len(out[i].Conditions) == 0 || len(out[j].Conditions) == 0 {
				return len(out[i].Conditions) < len(out[j].Conditions)
			}
			return out[i].Conditions[0].Value < out[j].Conditions[0].Value
		}
		return out[i].Name < out[j].Name
	})
	return out
}
