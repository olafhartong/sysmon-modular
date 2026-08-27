package expression

import (
	"sort"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/mitre"
	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

type Operator string

const (
	ConditionNode Operator = "condition"
	AndNode       Operator = "and"
	OrNode        Operator = "or"
)

type Condition struct {
	Field      string   `json:"field"`
	Operator   string   `json:"operator"`
	Value      string   `json:"value"`
	Name       string   `json:"name,omitempty"`
	Technique  string   `json:"technique,omitempty"`
	Techniques []string `json:"techniques,omitempty"`
	Comment    string   `json:"comment,omitempty"`
	Line       int      `json:"line,omitempty"`
}

func (c Condition) canonical() string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(c.Field)),
		strings.ToLower(strings.TrimSpace(c.Operator)),
		strings.ToLower(strings.TrimSpace(c.Value)),
	}, "=")
}

type Node struct {
	Operator   Operator   `json:"operator"`
	Name       string     `json:"name,omitempty"`
	Techniques []string   `json:"techniques,omitempty"`
	Condition  *Condition `json:"condition,omitempty"`
	Children   []Node     `json:"children,omitempty"`
	Line       int        `json:"line,omitempty"`
}

func Leaf(condition Condition) Node {
	copy := condition
	return Node{Operator: ConditionNode, Condition: &copy, Line: condition.Line}
}

func Combine(operator Operator, children ...Node) Node {
	if operator != AndNode && operator != OrNode {
		operator = AndNode
	}
	flattened := make([]Node, 0, len(children))
	for _, child := range children {
		if child.Empty() {
			continue
		}
		if child.Operator == operator && child.Name == "" {
			flattened = append(flattened, child.Children...)
			continue
		}
		flattened = append(flattened, child)
	}
	if len(flattened) == 1 {
		return flattened[0]
	}
	return Node{Operator: operator, Children: flattened}
}

func (n Node) Empty() bool {
	return n.Condition == nil && len(n.Children) == 0
}

func (n Node) Canonical() string {
	if n.Operator == ConditionNode && n.Condition != nil {
		return n.Condition.canonical()
	}
	parts := make([]string, 0, len(n.Children))
	for _, child := range n.Children {
		if canonical := child.Canonical(); canonical != "" {
			parts = append(parts, canonical)
		}
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return ""
	}
	return string(n.Operator) + "(" + strings.Join(parts, ",") + ")"
}

func (n Node) Conditions() []Condition {
	if n.Operator == ConditionNode && n.Condition != nil {
		return []Condition{*n.Condition}
	}
	var out []Condition
	for _, child := range n.Children {
		out = append(out, child.Conditions()...)
	}
	return out
}

func (n Node) DNF(limit int) ([][]Condition, bool) {
	if limit < 1 {
		limit = 1
	}
	switch n.Operator {
	case ConditionNode:
		if n.Condition == nil {
			return nil, false
		}
		return [][]Condition{{*n.Condition}}, false
	case OrNode:
		var out [][]Condition
		for _, child := range n.Children {
			branches, tooLarge := child.DNF(limit)
			if tooLarge || len(out)+len(branches) > limit {
				return nil, true
			}
			out = append(out, branches...)
		}
		return out, false
	case AndNode:
		out := [][]Condition{{}}
		for _, child := range n.Children {
			branches, tooLarge := child.DNF(limit)
			if tooLarge || len(branches) > 0 && len(out) > limit/len(branches) {
				return nil, true
			}
			var next [][]Condition
			for _, left := range out {
				for _, right := range branches {
					combined := append([]Condition(nil), left...)
					combined = append(combined, right...)
					next = append(next, combined)
				}
			}
			out = next
		}
		return out, false
	default:
		return nil, false
	}
}

type Rule struct {
	Name          string      `json:"name,omitempty"`
	GroupRelation string      `json:"group_relation"`
	Conditions    []Condition `json:"conditions"`
}

func (r Rule) Expression() Node {
	children := make([]Node, 0, len(r.Conditions))
	for _, condition := range r.Conditions {
		children = append(children, Leaf(condition))
	}
	return Combine(relationOperator(r.GroupRelation, AndNode), children...)
}

type Event struct {
	Name          string   `json:"name"`
	Onmatch       string   `json:"onmatch"`
	GroupName     string   `json:"group_name,omitempty"`
	GroupRelation string   `json:"group_relation"`
	Techniques    []string `json:"techniques,omitempty"`
	Expression    Node     `json:"expression"`
	Line          int      `json:"line,omitempty"`
}

func (e Event) Key() string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(e.Name)),
		strings.ToLower(strings.TrimSpace(e.Onmatch)),
		e.Expression.Canonical(),
	}, "\x00")
}

type Config struct {
	Events     []Event  `json:"events"`
	Techniques []string `json:"techniques"`
}

func FromXML(doc *sysmonxml.Document) Config {
	var config Config
	if doc == nil || doc.Root == nil {
		return config
	}
	techniques := map[string]bool{}
	doc.Root.Walk(func(node *sysmonxml.Node) {
		for _, id := range mitre.IDsFromValue(node.AttrValue("name")) {
			techniques[id] = true
		}
	})
	eventFiltering := doc.Root.FirstChild("EventFiltering")
	if eventFiltering == nil {
		eventFiltering = doc.Root
	}
	for _, child := range eventFiltering.ElementChildren() {
		if child.Name == "RuleGroup" {
			groupRelation := normalizedRelation(child.AttrValue("groupRelation"), "or")
			for _, event := range child.ElementChildren() {
				config.Events = append(config.Events, eventFromXML(event, child.AttrValue("name"), groupRelation))
			}
			continue
		}
		config.Events = append(config.Events, eventFromXML(child, "", "or"))
	}
	for id := range techniques {
		config.Techniques = append(config.Techniques, id)
	}
	sort.Strings(config.Techniques)
	sort.SliceStable(config.Events, func(i, j int) bool {
		if config.Events[i].Key() == config.Events[j].Key() {
			return config.Events[i].GroupName < config.Events[j].GroupName
		}
		return config.Events[i].Key() < config.Events[j].Key()
	})
	return config
}

func eventFromXML(event *sysmonxml.Node, groupName, groupRelation string) Event {
	onmatch := strings.ToLower(strings.TrimSpace(event.AttrValue("onmatch")))
	if onmatch == "" {
		onmatch = "include"
	}
	children := make([]Node, 0, len(event.ElementChildren()))
	for _, child := range event.ElementChildren() {
		children = append(children, nodeFromXML(child))
	}
	expression := Combine(relationOperator(groupRelation, OrNode), children...)
	techniques := append(mitre.IDsFromValue(groupName), mitre.IDsFromValue(event.AttrValue("name"))...)
	techniques = append(techniques, expression.TechniqueIDs()...)
	return Event{
		Name: event.Name, Onmatch: onmatch, GroupName: strings.TrimSpace(groupName),
		GroupRelation: normalizedRelation(groupRelation, "or"),
		Techniques:    uniqueSorted(techniques), Expression: expression,
		Line: event.Line,
	}
}

func nodeFromXML(node *sysmonxml.Node) Node {
	if node.Name != "Rule" {
		name := strings.TrimSpace(node.AttrValue("name"))
		return Leaf(Condition{
			Field: node.Name, Operator: strings.ToLower(strings.TrimSpace(node.AttrValue("condition"))),
			Value: strings.TrimSpace(node.Text), Name: name, Techniques: mitre.IDsFromValue(name),
			Line: node.Line,
		})
	}
	children := make([]Node, 0, len(node.ElementChildren()))
	for _, child := range node.ElementChildren() {
		children = append(children, nodeFromXML(child))
	}
	name := strings.TrimSpace(node.AttrValue("name"))
	return Node{
		Operator: relationOperator(node.AttrValue("groupRelation"), AndNode),
		Name:     name, Techniques: mitre.IDsFromValue(name), Children: children, Line: node.Line,
	}
}

func (n Node) TechniqueIDs() []string {
	techniques := append([]string(nil), n.Techniques...)
	if n.Condition != nil {
		techniques = append(techniques, n.Condition.Techniques...)
	}
	for _, child := range n.Children {
		techniques = append(techniques, child.TechniqueIDs()...)
	}
	return uniqueSorted(techniques)
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizedRelation(relation, fallback string) string {
	relation = strings.ToLower(strings.TrimSpace(relation))
	if relation != "and" && relation != "or" {
		return fallback
	}
	return relation
}

func relationOperator(relation string, fallback Operator) Operator {
	if normalizedRelation(relation, string(fallback)) == "or" {
		return OrNode
	}
	return AndNode
}
