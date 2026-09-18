package generate

import (
	"fmt"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/expression"
)

const strictMDERuleLimit = 256

type mdeFilterExpression struct {
	Kind     string
	Operator string
	Source   string
	Filter   string
	Values   []string
	Children []mdeFilterExpression
}

func decodeMDEFilterExpression(raw any) (mdeFilterExpression, error) {
	object, ok := raw.(map[string]any)
	if !ok {
		return mdeFilterExpression{}, fmt.Errorf("filter expression is not an object")
	}
	kind := strings.ToLower(strings.TrimSpace(stringValue(object["expressionType"])))
	switch kind {
	case "predicate":
		source := strings.TrimSpace(stringValue(object["source"]))
		filter := strings.TrimSpace(stringValue(object["filter"]))
		values, err := decodeMDEFilterValues(object["values"])
		if source == "" || filter == "" || err != nil {
			if err != nil {
				return mdeFilterExpression{}, err
			}
			return mdeFilterExpression{}, fmt.Errorf("predicate requires source, filter, and literal values")
		}
		return mdeFilterExpression{Kind: kind, Source: source, Filter: filter, Values: values}, nil
	case "operator":
		operator := strings.ToLower(strings.TrimSpace(stringValue(object["operator"])))
		if operator != "and" && operator != "or" && operator != "not" {
			return mdeFilterExpression{}, fmt.Errorf("unsupported Boolean operator %q", operator)
		}
		rawChildren, ok := object["expressions"].([]any)
		if !ok || len(rawChildren) == 0 {
			return mdeFilterExpression{}, fmt.Errorf("operator %s requires child expressions", operator)
		}
		children := make([]mdeFilterExpression, 0, len(rawChildren))
		for index, rawChild := range rawChildren {
			child, err := decodeMDEFilterExpression(rawChild)
			if err != nil {
				return mdeFilterExpression{}, fmt.Errorf("%s child %d: %w", operator, index+1, err)
			}
			children = append(children, child)
		}
		return mdeFilterExpression{Kind: kind, Operator: operator, Children: children}, nil
	default:
		return mdeFilterExpression{}, fmt.Errorf("unsupported expression type %q", kind)
	}
}

func decodeMDEFilterValues(raw any) ([]string, error) {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("predicate values must be a non-empty literal array")
	}
	values := make([]string, 0, len(items))
	for index, item := range items {
		value := scalarString(item)
		if value == "" {
			return nil, fmt.Errorf("predicate value %d is not a supported string or number", index+1)
		}
		if strings.Contains(value, ";") {
			return nil, fmt.Errorf("predicate value %d contains a semicolon and cannot be represented safely", index+1)
		}
		values = append(values, value)
	}
	return values, nil
}

func (m mdeFilterExpression) exactNode(event string) (expression.Node, bool, error) {
	switch m.Kind {
	case "predicate":
		condition, ok := exactMDEPredicateCondition(event, m.Source, m.Filter, m.Values)
		if !ok {
			return expression.Node{}, false, fmt.Errorf("predicate %s %s has no exact Sysmon mapping on %s", m.Source, m.Filter, event)
		}
		return expression.Leaf(condition), false, nil
	case "operator":
		if m.Operator == "not" {
			if len(m.Children) != 1 || m.Children[0].Kind != "predicate" {
				return expression.Node{}, true, fmt.Errorf("NOT is exact only when applied to one predicate")
			}
			node, _, err := m.Children[0].exactNode(event)
			return node, true, err
		}
		children := make([]expression.Node, 0, len(m.Children))
		for _, child := range m.Children {
			node, negative, err := child.exactNode(event)
			if err != nil {
				return expression.Node{}, negative, err
			}
			if negative {
				return expression.Node{}, true, fmt.Errorf("%s expression contains a negated branch", strings.ToUpper(m.Operator))
			}
			children = append(children, node)
		}
		operator := expression.AndNode
		if m.Operator == "or" {
			operator = expression.OrNode
		}
		return expression.Combine(operator, children...), false, nil
	default:
		return expression.Node{}, false, fmt.Errorf("unsupported expression type %q", m.Kind)
	}
}

func exactMDEPredicateCondition(event, source, filter string, values []string) (Condition, bool) {
	switch strings.ToLower(strings.TrimSpace(filter)) {
	case "eq", "==", "contains", "endswith", "startswith", "gt", "lt":
		if len(values) != 1 {
			return Condition{}, false
		}
	case "in", "containsany", "containsall":
		if len(values) == 0 {
			return Condition{}, false
		}
	default:
		return Condition{}, false
	}
	return conditionFromMDEPredicate(event, source, filter, append([]string(nil), values...))
}

func exactMDERules(event string, raw any) ([]RuleSpec, []RuleSpec, string, bool) {
	filter, err := decodeMDEFilterExpression(raw)
	if err != nil {
		return nil, nil, err.Error(), false
	}
	node, negative, err := filter.exactNode(event)
	if err != nil {
		return nil, nil, err.Error(), false
	}
	branches, tooLarge := node.DNF(strictMDERuleLimit)
	if tooLarge {
		return nil, nil, fmt.Sprintf("Boolean expansion exceeds %d Sysmon rules", strictMDERuleLimit), false
	}
	rules := make([]RuleSpec, 0, len(branches))
	for _, branch := range branches {
		rules = append(rules, RuleSpec{GroupRelation: "and", Conditions: branch})
	}
	rules = normalizeUniqueRules(rules)
	if negative {
		return nil, rules, "", true
	}
	return rules, nil, "", true
}
