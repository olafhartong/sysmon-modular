package generate

import (
	"fmt"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/expression"
)

const strictKQLRuleLimit = 256

type kqlTokenKind int

const (
	kqlIdentifier kqlTokenKind = iota
	kqlString
	kqlNumber
	kqlSymbol
	kqlLeftParen
	kqlRightParen
	kqlComma
)

type kqlToken struct {
	kind kqlTokenKind
	text string
}

type strictKQLParser struct {
	tokens []kqlToken
	query  string
	event  string
	pos    int
}

func strictKQLRules(query, event string) ([]RuleSpec, []string, bool) {
	reasons := unsupportedKQLPipelineReasons(query)
	whereExpressions := kqlWhereExpressions(query)
	var nodes []expression.Node
	for index, where := range whereExpressions {
		tokens, err := tokenizeKQLExpression(where)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("where stage %d: %v", index+1, err))
			continue
		}
		parser := strictKQLParser{tokens: tokens, query: query, event: event}
		node, err := parser.parseExpression()
		if err == nil && parser.pos != len(parser.tokens) {
			err = fmt.Errorf("unsupported token %q", parser.tokens[parser.pos].text)
		}
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("where stage %d: %v", index+1, err))
			continue
		}
		nodes = append(nodes, node)
	}
	if len(reasons) > 0 {
		return nil, dedupeStrings(reasons), false
	}
	if len(nodes) == 0 {
		return nil, nil, false
	}
	branches, tooLarge := expression.Combine(expression.AndNode, nodes...).DNF(strictKQLRuleLimit)
	if tooLarge {
		return nil, []string{fmt.Sprintf("Boolean expansion exceeds %d Sysmon rules", strictKQLRuleLimit)}, true
	}
	rules := make([]RuleSpec, 0, len(branches))
	for _, branch := range branches {
		rules = append(rules, RuleSpec{GroupRelation: "and", Conditions: branch})
	}
	return normalizeUniqueRules(rules), nil, false
}

func (p *strictKQLParser) parseExpression() (expression.Node, error) {
	return p.parseOr()
}

func (p *strictKQLParser) parseOr() (expression.Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return expression.Node{}, err
	}
	children := []expression.Node{left}
	for p.matchWord("or") {
		right, err := p.parseAnd()
		if err != nil {
			return expression.Node{}, err
		}
		children = append(children, right)
	}
	return expression.Combine(expression.OrNode, children...), nil
}

func (p *strictKQLParser) parseAnd() (expression.Node, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return expression.Node{}, err
	}
	children := []expression.Node{left}
	for p.matchWord("and") {
		right, err := p.parsePrimary()
		if err != nil {
			return expression.Node{}, err
		}
		children = append(children, right)
	}
	return expression.Combine(expression.AndNode, children...), nil
}

func (p *strictKQLParser) parsePrimary() (expression.Node, error) {
	if p.matchKind(kqlLeftParen) {
		node, err := p.parseExpression()
		if err != nil {
			return expression.Node{}, err
		}
		if !p.matchKind(kqlRightParen) {
			return expression.Node{}, fmt.Errorf("missing closing parenthesis")
		}
		return node, nil
	}
	if p.peekWord("not") {
		return expression.Node{}, fmt.Errorf("negation is not supported")
	}
	return p.parsePredicate()
}

func (p *strictKQLParser) parsePredicate() (expression.Node, error) {
	field, ok := p.takeKind(kqlIdentifier)
	if !ok {
		return expression.Node{}, fmt.Errorf("expected a predicate field")
	}
	operator, ok := p.takeOperator()
	if !ok {
		return expression.Node{}, fmt.Errorf("unsupported predicate after %s", field.text)
	}
	operatorLower := strings.ToLower(operator.text)
	var values []string
	if kqlListOperator(operatorLower) {
		if !p.matchKind(kqlLeftParen) {
			return expression.Node{}, fmt.Errorf("%s requires a parenthesized list", operator.text)
		}
		if identifier, ok := p.takeKind(kqlIdentifier); ok {
			if !p.matchKind(kqlRightParen) {
				return expression.Node{}, fmt.Errorf("list variable %s must be the only list argument", identifier.text)
			}
			values = kqlExpressionValues(p.query, identifier.text)
			if len(values) == 0 {
				return expression.Node{}, fmt.Errorf("list variable %s does not resolve to literal values", identifier.text)
			}
		} else {
			for {
				value, ok := p.takeLiteral()
				if !ok {
					return expression.Node{}, fmt.Errorf("%s list requires literal values", operator.text)
				}
				values = append(values, value.text)
				if p.matchKind(kqlRightParen) {
					break
				}
				if !p.matchKind(kqlComma) {
					return expression.Node{}, fmt.Errorf("expected a comma between list values")
				}
			}
		}
	} else {
		value, ok := p.takeLiteral()
		if !ok {
			return expression.Node{}, fmt.Errorf("%s requires a literal value", operator.text)
		}
		values = []string{value.text}
	}
	return strictKQLPredicate(p.event, field.text, operatorLower, values)
}

func strictKQLPredicate(event, sourceField, operator string, values []string) (expression.Node, error) {
	operator = strings.ToLower(operator)
	if operator != "=~" {
		operator = strings.TrimSuffix(operator, "~")
	}
	if strings.HasPrefix(operator, "has") {
		return expression.Node{}, fmt.Errorf("%s uses token matching, which Sysmon cannot represent exactly", operator)
	}
	for _, value := range values {
		if strings.Contains(value, ";") {
			return expression.Node{}, fmt.Errorf("literal value contains a semicolon")
		}
	}
	fieldLower := strings.ToLower(sourceField)
	field := ""
	switch fieldLower {
	case "filename", "initiatingprocessfilename", "imagefilename", "processname":
		field = kqlMultiValueFilenameField(event, sourceField)
	case "processcommandline", "initiatingprocesscommandline", "commandline":
		field = kqlCommandLineTarget(event, sourceField)
	case "remoteport", "destinationport":
		if event == "NetworkConnect" {
			field = "DestinationPort"
		}
	case "localport":
		if event == "NetworkConnect" {
			field = "SourcePort"
		}
	case "remoteurl", "destinationurl":
		if event == "NetworkConnect" {
			field = "DestinationHostname"
		}
	case "remoteip", "destinationipaddress":
		if event == "NetworkConnect" {
			field = "DestinationIp"
		}
	case "folderpath":
		field = kqlPathField(event)
	case "registrykey", "registryvaluename", "registryvaluedata":
		if event == "RegistryEvent" {
			field = kqlRegistryField(sourceField)
		}
	default:
		return expression.Node{}, fmt.Errorf("field %s is not supported", sourceField)
	}
	if field == "" {
		return expression.Node{}, fmt.Errorf("field %s has no Sysmon equivalent on %s", sourceField, event)
	}
	conditionForValue := func(value string) expression.Condition {
		sysmonOperator := sysmonOperatorForKQL(operator)
		if operator == "in" {
			sysmonOperator = "is"
		}
		if (field == "Image" || field == "ParentImage") && (operator == "==" || operator == "=~" || operator == "in") {
			sysmonOperator = "image"
		}
		return expression.Condition{Field: field, Operator: sysmonOperator, Value: value}
	}
	switch operator {
	case "==", "=~", "contains", "startswith", "endswith":
		if len(values) != 1 {
			return expression.Node{}, fmt.Errorf("operator %s requires one value", operator)
		}
		return expression.Leaf(conditionForValue(values[0])), nil
	case "in":
		children := make([]expression.Node, 0, len(values))
		for _, value := range values {
			children = append(children, expression.Leaf(conditionForValue(value)))
		}
		return expression.Combine(expression.OrNode, children...), nil
	case "contains_any", "contains_all":
		condition, ok := kqlMultiValueCondition(field, operator, values)
		if !ok {
			return expression.Node{}, fmt.Errorf("operator %s has no representable literal values", operator)
		}
		return expression.Leaf(condition), nil
	default:
		return expression.Node{}, fmt.Errorf("operator %s is not supported", operator)
	}
}

func (p *strictKQLParser) matchWord(word string) bool {
	if !p.peekWord(word) {
		return false
	}
	p.pos++
	return true
}

func (p *strictKQLParser) peekWord(word string) bool {
	return p.pos < len(p.tokens) && p.tokens[p.pos].kind == kqlIdentifier && strings.EqualFold(p.tokens[p.pos].text, word)
}

func (p *strictKQLParser) matchKind(kind kqlTokenKind) bool {
	if p.pos >= len(p.tokens) || p.tokens[p.pos].kind != kind {
		return false
	}
	p.pos++
	return true
}

func (p *strictKQLParser) takeKind(kind kqlTokenKind) (kqlToken, bool) {
	if p.pos >= len(p.tokens) || p.tokens[p.pos].kind != kind {
		return kqlToken{}, false
	}
	token := p.tokens[p.pos]
	p.pos++
	return token, true
}

func (p *strictKQLParser) takeLiteral() (kqlToken, bool) {
	if token, ok := p.takeKind(kqlString); ok {
		return token, true
	}
	return p.takeKind(kqlNumber)
}

func (p *strictKQLParser) takeOperator() (kqlToken, bool) {
	if p.pos >= len(p.tokens) {
		return kqlToken{}, false
	}
	token := p.tokens[p.pos]
	if token.kind == kqlSymbol && (token.text == "==" || token.text == "=~") {
		p.pos++
		return token, true
	}
	if token.kind != kqlIdentifier {
		return kqlToken{}, false
	}
	switch strings.ToLower(token.text) {
	case "contains", "contains~", "startswith", "startswith~", "endswith", "endswith~", "in", "in~", "contains_any", "contains_all", "has", "has~", "has_any", "has_all":
		p.pos++
		return token, true
	default:
		return kqlToken{}, false
	}
}

func kqlListOperator(operator string) bool {
	operator = strings.TrimSuffix(strings.ToLower(operator), "~")
	return operator == "in" || strings.HasSuffix(operator, "_any") || strings.HasSuffix(operator, "_all")
}

func tokenizeKQLExpression(input string) ([]kqlToken, error) {
	var tokens []kqlToken
	for index := 0; index < len(input); {
		char := input[index]
		if char == ' ' || char == '\t' || char == '\r' || char == '\n' {
			index++
			continue
		}
		switch char {
		case '(':
			tokens = append(tokens, kqlToken{kind: kqlLeftParen, text: "("})
			index++
			continue
		case ')':
			tokens = append(tokens, kqlToken{kind: kqlRightParen, text: ")"})
			index++
			continue
		case ',':
			tokens = append(tokens, kqlToken{kind: kqlComma, text: ","})
			index++
			continue
		}
		if (char == '@' && index+1 < len(input) && (input[index+1] == '\'' || input[index+1] == '"')) || char == '\'' || char == '"' {
			if char == '@' {
				index++
				char = input[index]
			}
			quote := char
			index++
			var value strings.Builder
			closed := false
			for index < len(input) {
				if input[index] == quote {
					if index+1 < len(input) && input[index+1] == quote {
						value.WriteByte(quote)
						index += 2
						continue
					}
					index++
					closed = true
					break
				}
				value.WriteByte(input[index])
				index++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string literal")
			}
			tokens = append(tokens, kqlToken{kind: kqlString, text: value.String()})
			continue
		}
		if index+1 < len(input) {
			pair := input[index : index+2]
			switch pair {
			case "==", "=~", "!=", "!~", ">=", "<=":
				tokens = append(tokens, kqlToken{kind: kqlSymbol, text: pair})
				index += 2
				continue
			}
		}
		if char >= '0' && char <= '9' {
			start := index
			for index < len(input) && input[index] >= '0' && input[index] <= '9' {
				index++
			}
			tokens = append(tokens, kqlToken{kind: kqlNumber, text: input[start:index]})
			continue
		}
		if isKQLIdentifierByte(char) && (char < '0' || char > '9') {
			start := index
			for index < len(input) && isKQLIdentifierByte(input[index]) {
				index++
			}
			if index < len(input) && input[index] == '~' {
				index++
			}
			tokens = append(tokens, kqlToken{kind: kqlIdentifier, text: input[start:index]})
			continue
		}
		return nil, fmt.Errorf("unsupported character %q", char)
	}
	return tokens, nil
}

func kqlWhereExpressions(query string) []string {
	var expressions []string
	for _, stage := range splitKQLPipeline(query) {
		stage = strings.TrimSpace(stage)
		fields := strings.Fields(stage)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "where") {
			continue
		}
		expressionText := strings.TrimSpace(stage[len(fields[0]):])
		if expressionText != "" {
			expressions = append(expressions, expressionText)
		}
	}
	return expressions
}

func splitKQLPipeline(query string) []string {
	parts := []string{}
	start := 0
	quote := byte(0)
	for index := 0; index < len(query); index++ {
		if quote != 0 {
			if query[index] == quote {
				if index+1 < len(query) && query[index+1] == quote {
					index++
					continue
				}
				quote = 0
			}
			continue
		}
		if query[index] == '\'' || query[index] == '"' {
			quote = query[index]
			continue
		}
		if query[index] == '|' {
			parts = append(parts, query[start:index])
			start = index + 1
		}
	}
	parts = append(parts, query[start:])
	return parts
}

func unsupportedKQLPipelineReasons(query string) []string {
	var reasons []string
	for _, stage := range splitKQLPipeline(query)[1:] {
		fields := strings.Fields(strings.TrimSpace(stage))
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "summarize", "join", "union", "lookup", "invoke", "evaluate", "mv-expand", "make-series", "top", "take", "limit", "sample", "distinct", "count":
			reasons = append(reasons, "pipeline operator "+fields[0]+" changes query semantics and has no Sysmon equivalent")
		}
	}
	return reasons
}
