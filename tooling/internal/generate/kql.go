package generate

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

type KQLResult struct {
	Table        string
	Event        string
	Onmatch      string
	Conditions   []Condition
	Rules        []RuleSpec
	Warnings     []string
	LossyReasons []string
}

func FromKQLFile(path string) (*KQLResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromKQL(string(data)), nil
}

func FromKQL(query string) *KQLResult {
	executableQuery := stripKQLComments(query)
	table := firstMatch(`(?im)^\s*(Device[A-Za-z]+Events)\b`, executableQuery)
	event := eventForTable(table)
	var warnings []string
	if event == "ProcessCreate" && table == "" {
		warnings = append(warnings, "could not identify MDE table; defaulted to ProcessCreate")
	}
	rules, lossyReasons, expansionTooLarge := strictKQLRules(executableQuery, event)
	if len(lossyReasons) > 0 {
		// Preserve the best-effort preview for callers that explicitly opt in to a
		// lossy conversion. The default module-writing path rejects these results.
		groups := extractKQLConditionGroups(executableQuery, event)
		rules, expansionTooLarge = rulesFromKQLConditionGroups(groups)
	}
	var conditions []Condition
	for _, rule := range rules {
		conditions = append(conditions, rule.Conditions...)
	}
	conditions = normalizeUniqueConditions(conditions)
	if len(conditions) == 0 && !expansionTooLarge {
		warnings = append(warnings, "no supported literal conditions were translated")
	}
	if expansionTooLarge {
		warnings = append(warnings, "boolean expansion exceeds 256 Sysmon rules; query was not translated")
	}
	return &KQLResult{Table: table, Event: event, Onmatch: "include", Conditions: conditions, Rules: rules, Warnings: warnings, LossyReasons: dedupeStrings(lossyReasons)}
}

func stripKQLComments(query string) string {
	var out strings.Builder
	inBlockComment := false
	for i := 0; i < len(query); {
		if inBlockComment {
			if i+1 < len(query) && query[i] == '*' && query[i+1] == '/' {
				inBlockComment = false
				i += 2
				continue
			}
			if query[i] == '\n' {
				out.WriteByte('\n')
			}
			i++
			continue
		}
		if i+1 < len(query) && query[i] == '/' && query[i+1] == '*' {
			inBlockComment = true
			i += 2
			continue
		}
		if i+1 < len(query) && query[i] == '/' && query[i+1] == '/' {
			for i < len(query) && query[i] != '\n' {
				i++
			}
			continue
		}
		if query[i] == '\'' || query[i] == '"' {
			quote := query[i]
			out.WriteByte(query[i])
			i++
			for i < len(query) {
				out.WriteByte(query[i])
				if query[i] == quote {
					if i+1 < len(query) && query[i+1] == quote {
						out.WriteByte(query[i+1])
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			continue
		}
		out.WriteByte(query[i])
		i++
	}
	return out.String()
}

func eventForTable(table string) string {
	switch strings.ToLower(table) {
	case "devicenetworkevents":
		return "NetworkConnect"
	case "devicefileevents":
		return "FileCreate"
	case "deviceregistryevents":
		return "RegistryEvent"
	case "deviceimageloadevents":
		return "ImageLoad"
	default:
		return "ProcessCreate"
	}
}

type kqlConditionGroup struct {
	Alternatives []Condition
}

func extractKQLConditionGroups(query, event string) []kqlConditionGroup {
	return extractKQLPredicateGroups(kqlWherePredicateText(query), query, event)
}

func extractKQLPredicateGroups(query, sourceQuery, event string) []kqlConditionGroup {
	orGroups, query := extractSimpleKQLOrGroups(query, sourceQuery, event)
	groups := append([]kqlConditionGroup(nil), orGroups...)
	addOne := func(condition Condition) {
		groups = append(groups, kqlConditionGroup{Alternatives: []Condition{condition}})
	}
	addAny := func(conditions []Condition) {
		conditions = normalizeUniqueConditions(conditions)
		if len(conditions) > 0 {
			groups = append(groups, kqlConditionGroup{Alternatives: conditions})
		}
	}
	for _, m := range regexp.MustCompile(`(?i)\b(FileName|InitiatingProcessFileName|ImageFileName|ProcessName)\s*(?:==|=~)\s*@?["']([^"']+)["']`).FindAllStringSubmatch(query, -1) {
		if field, operator := kqlFilenameTarget(event, m[1], m[2]); field != "" {
			addOne(Condition{Field: field, Operator: operator, Value: m[2]})
		}
	}
	for _, m := range regexp.MustCompile(`(?is)\b(FileName|InitiatingProcessFileName|ImageFileName|ProcessName)\s+in~?\s*\(([^)]*)\)`).FindAllStringSubmatch(query, -1) {
		var alternatives []Condition
		for _, value := range kqlExpressionValues(sourceQuery, m[2]) {
			if field, operator := kqlFilenameTarget(event, m[1], value); field != "" {
				alternatives = append(alternatives, Condition{Field: field, Operator: operator, Value: value})
			}
		}
		addAny(alternatives)
	}
	for _, m := range regexp.MustCompile(`(?is)\b(FileName|InitiatingProcessFileName|ImageFileName|ProcessName)\s+(has_any|contains_any|has_all|contains_all)\s*\(([^)]*)\)`).FindAllStringSubmatch(query, -1) {
		if field := kqlMultiValueFilenameField(event, m[1]); field != "" {
			if condition, ok := kqlMultiValueCondition(field, m[2], kqlExpressionValues(sourceQuery, m[3])); ok {
				addOne(condition)
			}
		}
	}
	for _, m := range regexp.MustCompile(`(?i)\b(ProcessCommandLine|InitiatingProcessCommandLine|CommandLine)\s+(contains|has|startswith|endswith)~?\s*@?["']([^"']+)["']`).FindAllStringSubmatch(query, -1) {
		if field := kqlCommandLineTarget(event, m[1]); field != "" {
			addOne(Condition{Field: field, Operator: sysmonOperatorForKQL(m[2]), Value: m[3]})
		}
	}
	for _, m := range regexp.MustCompile(`(?is)\b(ProcessCommandLine|InitiatingProcessCommandLine|CommandLine)\s+(has_any|contains_any|has_all|contains_all)\s*\(([^)]*)\)`).FindAllStringSubmatch(query, -1) {
		if field := kqlCommandLineTarget(event, m[1]); field != "" {
			if condition, ok := kqlMultiValueCondition(field, m[2], kqlExpressionValues(sourceQuery, m[3])); ok {
				addOne(condition)
			}
		}
	}
	for _, m := range regexp.MustCompile(`(?i)\b(RemotePort|LocalPort|DestinationPort)\s*(?:==|=~)\s*([0-9]+)`).FindAllStringSubmatch(query, -1) {
		field := "DestinationPort"
		if strings.EqualFold(m[1], "LocalPort") {
			field = "SourcePort"
		}
		addOne(Condition{Field: field, Operator: "is", Value: m[2]})
	}
	for _, m := range regexp.MustCompile(`(?i)\b(RemoteUrl|RemoteIP|DestinationUrl|DestinationIpAddress)\s+(contains|has|startswith|endswith|==|=~)~?\s*@?["']([^"']+)["']`).FindAllStringSubmatch(query, -1) {
		field := "DestinationHostname"
		if strings.Contains(strings.ToLower(m[1]), "ip") {
			field = "DestinationIp"
		}
		addOne(Condition{Field: field, Operator: sysmonOperatorForKQL(m[2]), Value: m[3]})
	}
	for _, m := range regexp.MustCompile(`(?is)\b(RemoteUrl|RemoteIP|DestinationUrl|DestinationIpAddress)\s+(has_any|contains_any|has_all|contains_all)\s*\(([^)]*)\)`).FindAllStringSubmatch(query, -1) {
		field := "DestinationHostname"
		if strings.Contains(strings.ToLower(m[1]), "ip") {
			field = "DestinationIp"
		}
		if condition, ok := kqlMultiValueCondition(field, m[2], kqlExpressionValues(sourceQuery, m[3])); ok {
			addOne(condition)
		}
	}
	for _, m := range regexp.MustCompile(`(?i)\b(FolderPath|FileName)\s+(contains|has|startswith|endswith|==|=~)~?\s*@?["']([^"']+)["']`).FindAllStringSubmatch(query, -1) {
		if field := kqlPathField(event); field != "" {
			addOne(Condition{Field: field, Operator: sysmonOperatorForKQL(m[2]), Value: m[3]})
		}
	}
	for _, m := range regexp.MustCompile(`(?is)\b(FolderPath|FileName)\s+in~?\s*\(([^)]*)\)`).FindAllStringSubmatch(query, -1) {
		if field := kqlPathField(event); field != "" {
			var alternatives []Condition
			for _, value := range kqlExpressionValues(sourceQuery, m[2]) {
				alternatives = append(alternatives, Condition{Field: field, Operator: "is", Value: value})
			}
			addAny(alternatives)
		}
	}
	for _, m := range regexp.MustCompile(`(?is)\b(FolderPath|FileName)\s+(has_any|contains_any|has_all|contains_all)\s*\(([^)]*)\)`).FindAllStringSubmatch(query, -1) {
		if field := kqlPathField(event); field != "" {
			if condition, ok := kqlMultiValueCondition(field, m[2], kqlExpressionValues(sourceQuery, m[3])); ok {
				addOne(condition)
			}
		}
	}
	for _, m := range regexp.MustCompile(`(?i)\b(RegistryKey|RegistryValueName|RegistryValueData)\s+(contains|has|startswith|endswith|==|=~)~?\s*@?["']([^"']+)["']`).FindAllStringSubmatch(query, -1) {
		if event == "RegistryEvent" {
			addOne(Condition{Field: kqlRegistryField(m[1]), Operator: sysmonOperatorForKQL(m[2]), Value: m[3]})
		}
	}
	for _, m := range regexp.MustCompile(`(?is)\b(RegistryKey|RegistryValueName|RegistryValueData)\s+in~?\s*\(([^)]*)\)`).FindAllStringSubmatch(query, -1) {
		if event == "RegistryEvent" {
			var alternatives []Condition
			for _, value := range kqlExpressionValues(sourceQuery, m[2]) {
				alternatives = append(alternatives, Condition{Field: kqlRegistryField(m[1]), Operator: "is", Value: value})
			}
			addAny(alternatives)
		}
	}
	for _, m := range regexp.MustCompile(`(?is)\b(RegistryKey|RegistryValueName|RegistryValueData)\s+(has_any|contains_any|has_all|contains_all)\s*\(([^)]*)\)`).FindAllStringSubmatch(query, -1) {
		if event == "RegistryEvent" {
			if condition, ok := kqlMultiValueCondition(kqlRegistryField(m[1]), m[2], kqlExpressionValues(sourceQuery, m[3])); ok {
				addOne(condition)
			}
		}
	}
	return groups
}

func extractSimpleKQLOrGroups(query, sourceQuery, event string) ([]kqlConditionGroup, string) {
	lines := strings.Split(query, "\n")
	var groups []kqlConditionGroup
	for i, line := range lines {
		branches := splitKQLOrExpression(line)
		if len(branches) < 2 {
			continue
		}
		var alternatives []Condition
		valid := true
		for _, branch := range branches {
			branchGroups := extractKQLPredicateGroups(branch, sourceQuery, event)
			if len(branchGroups) != 1 || len(branchGroups[0].Alternatives) != 1 {
				valid = false
				break
			}
			alternatives = append(alternatives, branchGroups[0].Alternatives[0])
		}
		if !valid {
			continue
		}
		groups = append(groups, kqlConditionGroup{Alternatives: normalizeUniqueConditions(alternatives)})
		lines[i] = ""
	}
	return groups, strings.Join(lines, "\n")
}

func kqlWherePredicateText(query string) string {
	lines := strings.Split(query, "\n")
	wherePattern := regexp.MustCompile(`(?i)\|\s*where\b`)
	var out strings.Builder
	inWhere := false
	for _, line := range lines {
		remaining := line
		foundWhere := false
		for {
			location := wherePattern.FindStringIndex(remaining)
			if location == nil {
				break
			}
			foundWhere = true
			expression, nextPipeline := splitAtKQLPipeline(remaining[location[1]:])
			out.WriteString(expression)
			out.WriteByte('\n')
			if nextPipeline < 0 {
				inWhere = true
				break
			}
			inWhere = false
			remaining = remaining[location[1]+nextPipeline:]
		}
		if foundWhere {
			continue
		}
		if !inWhere {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "|") {
			inWhere = false
			continue
		}
		expression, nextPipeline := splitAtKQLPipeline(line)
		out.WriteString(expression)
		out.WriteByte('\n')
		if nextPipeline >= 0 {
			inWhere = false
		}
	}
	return out.String()
}

func splitAtKQLPipeline(expression string) (string, int) {
	quote := byte(0)
	for i := 0; i < len(expression); i++ {
		if quote != 0 {
			if expression[i] == quote {
				if i+1 < len(expression) && expression[i+1] == quote {
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		if expression[i] == '\'' || expression[i] == '"' {
			quote = expression[i]
			continue
		}
		if expression[i] == '|' {
			return strings.TrimSpace(expression[:i]), i
		}
	}
	return strings.TrimSpace(expression), -1
}

func splitKQLOrExpression(expression string) []string {
	var parts []string
	start := 0
	quote := byte(0)
	for i := 0; i < len(expression); i++ {
		if quote != 0 {
			if expression[i] == quote {
				if i+1 < len(expression) && expression[i+1] == quote {
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		if expression[i] == '\'' || expression[i] == '"' {
			quote = expression[i]
			continue
		}
		if i+2 <= len(expression) && strings.EqualFold(expression[i:i+2], "or") &&
			(i == 0 || !isKQLIdentifierByte(expression[i-1])) &&
			(i+2 == len(expression) || !isKQLIdentifierByte(expression[i+2])) {
			parts = append(parts, strings.TrimSpace(expression[start:i]))
			start = i + 2
			i++
		}
	}
	if len(parts) == 0 {
		return nil
	}
	parts = append(parts, strings.TrimSpace(expression[start:]))
	return parts
}

func isKQLIdentifierByte(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func rulesFromKQLConditionGroups(groups []kqlConditionGroup) ([]RuleSpec, bool) {
	if len(groups) == 0 {
		return nil, false
	}
	combinations := [][]Condition{{}}
	for _, group := range groups {
		if len(group.Alternatives) == 0 {
			continue
		}
		if len(combinations) > 256/len(group.Alternatives) {
			return nil, true
		}
		next := make([][]Condition, 0, len(combinations)*len(group.Alternatives))
		for _, combination := range combinations {
			for _, alternative := range group.Alternatives {
				conditions := append([]Condition(nil), combination...)
				conditions = append(conditions, alternative)
				next = append(next, conditions)
			}
		}
		combinations = next
	}
	rules := make([]RuleSpec, 0, len(combinations))
	for _, conditions := range combinations {
		if conditions = normalizeUniqueConditions(conditions); len(conditions) > 0 {
			rules = append(rules, RuleSpec{GroupRelation: "and", Conditions: conditions})
		}
	}
	return normalizeUniqueRules(rules), false
}

func kqlFilenameTarget(event, sourceField, value string) (string, string) {
	if strings.HasPrefix(strings.ToLower(sourceField), "initiatingprocess") {
		if strings.HasSuffix(strings.ToLower(value), ".exe") {
			if event == "ProcessCreate" {
				return "ParentImage", "image"
			}
			return "Image", "image"
		}
		return "", ""
	}
	switch event {
	case "FileCreate":
		return "TargetFilename", "is"
	case "ImageLoad":
		return "ImageLoaded", "is"
	default:
		if strings.HasSuffix(strings.ToLower(value), ".exe") {
			return "Image", "image"
		}
		return "", ""
	}
}

func kqlMultiValueFilenameField(event, sourceField string) string {
	if strings.HasPrefix(strings.ToLower(sourceField), "initiatingprocess") {
		if event == "ProcessCreate" {
			return "ParentImage"
		}
		return "Image"
	}
	switch event {
	case "FileCreate":
		return "TargetFilename"
	case "ImageLoad":
		return "ImageLoaded"
	default:
		return "Image"
	}
}

func kqlCommandLineTarget(event, sourceField string) string {
	if event != "ProcessCreate" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(sourceField), "initiatingprocess") {
		return "ParentCommandLine"
	}
	return "CommandLine"
}

func kqlMultiValueCondition(field, kqlOperator string, values []string) (Condition, bool) {
	seen := map[string]bool{}
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if strings.Contains(value, ";") {
			return Condition{}, false
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		cleaned = append(cleaned, value)
	}
	if len(cleaned) == 0 {
		return Condition{}, false
	}
	operator := "contains any"
	if strings.HasSuffix(strings.ToLower(kqlOperator), "_all") {
		operator = "contains all"
	}
	if len(cleaned) == 1 {
		operator = "contains"
	}
	return Condition{Field: field, Operator: operator, Value: strings.Join(cleaned, ";")}, true
}

func kqlPathField(event string) string {
	switch event {
	case "FileCreate":
		return "TargetFilename"
	case "ImageLoad":
		return "ImageLoaded"
	default:
		return ""
	}
}

func kqlRegistryField(field string) string {
	if strings.EqualFold(field, "RegistryValueData") {
		return "Details"
	}
	return "TargetObject"
}

func sysmonOperatorForKQL(operator string) string {
	operator = strings.ToLower(strings.TrimSpace(operator))
	switch {
	case strings.HasPrefix(operator, "startswith"):
		return "begin with"
	case strings.HasPrefix(operator, "endswith"):
		return "end with"
	case operator == "==" || operator == "=~":
		return "is"
	default:
		return "contains"
	}
}

func kqlExpressionValues(query, expression string) []string {
	if values := quotedValues(expression); len(values) > 0 {
		return values
	}
	identifier := strings.TrimSpace(expression)
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(identifier) {
		return nil
	}
	quotedIdentifier := regexp.QuoteMeta(identifier)
	pattern := `(?is)\blet\s+` + quotedIdentifier + `\s*=\s*(?:dynamic\s*\(\s*)?\[([^]]*)\]`
	if values := quotedValues(firstMatch(pattern, query)); len(values) > 0 {
		return values
	}
	pattern = `(?im)\blet\s+` + quotedIdentifier + `\s*=\s*@?["']([^"']+)["']\s*;`
	if value := firstMatch(pattern, query); value != "" {
		return []string{value}
	}
	return nil
}

func quotedValues(s string) []string {
	re := regexp.MustCompile(`["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(s, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		out = append(out, match[1])
	}
	return out
}

func firstMatch(pattern, s string) string {
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func KQLModule(query string) (*sysmonxml.Document, []string, error) {
	return KQLModuleNamed(query, "")
}

func KQLModuleNamed(query, name string) (*sysmonxml.Document, []string, error) {
	doc, warnings, _, err := KQLModuleNamedWithExisting(query, name, nil)
	return doc, warnings, err
}

func KQLModuleNamedWithExisting(query, name string, existingModules []string) (*sysmonxml.Document, []string, int, error) {
	return KQLModuleNamedWithExistingOptions(query, name, existingModules, false)
}

func KQLModuleNamedWithExistingOptions(query, name string, existingModules []string, allowLossy bool) (*sysmonxml.Document, []string, int, error) {
	result := FromKQL(query)
	if len(result.LossyReasons) > 0 && !allowLossy {
		warnings := append([]string(nil), result.Warnings...)
		warnings = append(warnings, "skipped lossy KQL conversion: "+strings.Join(result.LossyReasons, "; ")+"; use --allow-lossy to opt in")
		return nil, warnings, 0, fmt.Errorf("KQL query cannot be represented without changing its meaning")
	}
	if len(result.LossyReasons) > 0 {
		result.Warnings = append(result.Warnings, "converted lossy KQL because --allow-lossy was supplied: "+strings.Join(result.LossyReasons, "; "))
	}
	if len(result.Rules) == 0 {
		return nil, result.Warnings, 0, fmt.Errorf("no translatable KQL conditions")
	}
	sources, err := loadExistingConditionSources(existingModules)
	if err != nil {
		return nil, result.Warnings, 0, err
	}
	rules := append([]RuleSpec(nil), result.Rules...)
	annotated := 0
	for i := range rules {
		rules[i].Name = name
		rules[i].Conditions, annotated = annotateExistingConditions(rules[i].Conditions, result.Event, result.Onmatch, sources, annotated)
	}
	doc := ModuleFromRules(result.Event, result.Onmatch, rules, "4.90")
	if err := validateGeneratedModule(doc, "generated KQL module"); err != nil {
		return nil, result.Warnings, annotated, err
	}
	return doc, result.Warnings, annotated, nil
}
