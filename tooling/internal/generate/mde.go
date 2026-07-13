package generate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type MDEMode string

const (
	MDEModeFiltered   MDEMode = "filtered"
	MDEModeUnfiltered MDEMode = "unfiltered"
	MDEModeInverse    MDEMode = "inverse"
)

type MDEResult struct {
	Files    []string
	Warnings []string
	Stats    MDEStats
}

type MDEStats struct {
	RulesSeen             int
	RulesMapped           int
	UnsupportedRules      int
	UnsupportedPredicates int
}

type eventRules struct {
	Include []RuleSpec
	Exclude []RuleSpec
}

type mdeRule struct {
	Name     string
	TaskName string
	EventID  string
	Filters  any
	Raw      map[string]any
}

func FromMDEConfigFile(configPath, outputDir string) (*MDEResult, error) {
	return FromMDEConfigFileMode(configPath, outputDir, MDEModeFiltered)
}

func FromMDEConfigFileMode(configPath, outputDir string, mode MDEMode) (*MDEResult, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	g := &mdeGenerator{
		mode:     mode,
		byEvent:  map[string]*eventRules{},
		warnings: []string{},
	}
	g.analyze(root)
	return g.write(outputDir)
}

type mdeGenerator struct {
	mode     MDEMode
	byEvent  map[string]*eventRules
	warnings []string
	stats    MDEStats
}

func (g *mdeGenerator) analyze(root any) {
	g.walkConfigTypes(root)
	for _, rule := range collectMDERules(root) {
		g.stats.RulesSeen++
		event := inferSysmonEvent(rule)
		if event == "" {
			g.stats.UnsupportedRules++
			continue
		}
		g.stats.RulesMapped++
		switch g.mode {
		case MDEModeUnfiltered:
			g.addInclude(event, []RuleSpec{broadRule(event, "MDE unfiltered "+ruleLabel(rule))})
		case MDEModeInverse:
			_, neg := g.rulesFromFilter(event, rule)
			if len(neg) > 0 {
				g.addInclude(event, prefixRuleNames(neg, "MDE inverse "+ruleLabel(rule)))
			}
		default:
			pos, neg := g.rulesFromFilter(event, rule)
			if len(pos) == 0 && len(neg) == 0 {
				pos = []RuleSpec{broadRule(event, "MDE "+ruleLabel(rule))}
			}
			g.addInclude(event, prefixRuleNames(pos, "MDE "+ruleLabel(rule)))
			g.addExclude(event, prefixRuleNames(neg, "MDE filtered "+ruleLabel(rule)))
		}
	}
}

func (g *mdeGenerator) walkConfigTypes(root any) {
	top, ok := root.(map[string]any)
	if !ok {
		return
	}
	configTypes, _ := top["configTypes"].([]any)
	for _, item := range configTypes {
		cfg, _ := item.(map[string]any)
		if cfg == nil {
			continue
		}
		g.addExclusionConfiguration(cfg)
		g.addRegistryMonitoring(cfg)
		g.addFileMonitoring(cfg)
	}
}

func (g *mdeGenerator) addExclusionConfiguration(cfg map[string]any) {
	ex, _ := cfg["ExclusionConfiguration"].(map[string]any)
	if ex == nil || !boolValue(ex["EnableExclusions"]) {
		return
	}
	paths, _ := ex["Paths"].([]any)
	for _, item := range paths {
		entry, _ := item.(map[string]any)
		if entry == nil {
			continue
		}
		process := expandMDEPath(stringValue(entry["Process"]))
		value := expandMDEPath(stringValue(entry["Value"]))
		var rules []RuleSpec
		if process != "" {
			rules = append(rules, RuleSpec{Name: "MDE exclusion process", GroupRelation: "and", Conditions: []Condition{{Field: "Image", Operator: "is", Value: process}}})
		}
		if value != "" && value != `\\` {
			rules = append(rules, RuleSpec{Name: "MDE exclusion file path", GroupRelation: "and", Conditions: []Condition{{Field: "TargetFilename", Operator: pathOperator(value), Value: normalizePathPattern(value)}}})
		}
		if value == `\\` && process == "" {
			g.warnings = append(g.warnings, "skipped broad MDE path exclusion value \\\\ without a process constraint")
		}
		if len(rules) == 0 {
			continue
		}
		switch g.mode {
		case MDEModeInverse:
			g.addInclude("ProcessCreate", rulesForEvent("ProcessCreate", rules))
			g.addInclude("FileCreate", rulesForEvent("FileCreate", rules))
		case MDEModeFiltered:
			g.addExclude("ProcessCreate", rulesForEvent("ProcessCreate", rules))
			g.addExclude("FileCreate", rulesForEvent("FileCreate", rules))
		}
	}
}

func (g *mdeGenerator) addRegistryMonitoring(cfg map[string]any) {
	if g.mode == MDEModeInverse {
		return
	}
	reg, _ := cfg["RegistryMonitoringConfiguration"].(map[string]any)
	if reg == nil {
		return
	}
	entries, _ := reg["registryEntries"].([]any)
	var rules []RuleSpec
	for _, item := range entries {
		entry, _ := item.(map[string]any)
		key := normalizeRegistryPath(stringValue(entry["registryKey"]))
		if key == "" {
			continue
		}
		if value := stringValue(entry["registryValue"]); value != "" {
			key = strings.TrimRight(key, `\`) + `\` + value
		}
		rules = append(rules, RuleSpec{
			Name:          "MDE registry monitoring",
			GroupRelation: "and",
			Conditions:    []Condition{{Field: "TargetObject", Operator: pathOperator(key), Value: normalizePathPattern(key)}},
		})
	}
	if len(rules) > 0 {
		g.addInclude("RegistryEvent", rules)
	}
}

func (g *mdeGenerator) addFileMonitoring(cfg map[string]any) {
	fileMon, _ := cfg["FileMonitorConfiguration"].(map[string]any)
	if fileMon == nil {
		return
	}
	if g.mode != MDEModeInverse {
		entries, _ := fileMon["FileMonitorEntries"].([]any)
		rules := fileMonitorRules(entries, "MDE file monitor")
		if len(rules) > 0 {
			g.addInclude("FileCreate", rules)
			g.warnings = append(g.warnings, "MDE FileMonitorConfiguration includes file-open/read visibility that Sysmon cannot fully replicate; generated FileCreate path coverage only")
		}
	}
	if g.mode != MDEModeUnfiltered {
		excluded, _ := fileMon["ExpandedCollectionExcludedFileMonitorEntries"].([]any)
		rules := fileMonitorRules(excluded, "MDE excluded file monitor")
		if len(rules) > 0 {
			if g.mode == MDEModeInverse {
				g.addInclude("FileCreate", rules)
			} else {
				g.addExclude("FileCreate", rules)
			}
		}
	}
}

func fileMonitorRules(entries []any, name string) []RuleSpec {
	var rules []RuleSpec
	for _, item := range entries {
		entry, _ := item.(map[string]any)
		path := expandMDEPath(stringValue(entry["FilePath"]))
		if path == "" {
			continue
		}
		rules = append(rules, RuleSpec{
			Name:          name,
			GroupRelation: "and",
			Conditions:    []Condition{{Field: "TargetFilename", Operator: pathOperator(path), Value: normalizePathPattern(path)}},
		})
	}
	return rules
}

func (g *mdeGenerator) rulesFromFilter(event string, rule mdeRule) ([]RuleSpec, []RuleSpec) {
	filter, ok := rule.Filters.(map[string]any)
	if !ok || len(filter) == 0 {
		return nil, nil
	}
	pos, neg := g.translateExpr(event, filter, false)
	return pos, neg
}

func (g *mdeGenerator) translateExpr(event string, expr map[string]any, negated bool) ([]RuleSpec, []RuleSpec) {
	switch strings.ToLower(stringValue(expr["expressionType"])) {
	case "predicate":
		cond, ok := conditionFromPredicate(event, expr)
		if !ok {
			g.stats.UnsupportedPredicates++
			return nil, nil
		}
		rule := RuleSpec{GroupRelation: "and", Conditions: []Condition{cond}}
		if negated {
			return nil, []RuleSpec{rule}
		}
		return []RuleSpec{rule}, nil
	case "operator":
		op := strings.ToLower(stringValue(expr["operator"]))
		children := expressionChildren(expr)
		switch op {
		case "not":
			var pos, neg []RuleSpec
			for _, child := range children {
				p, n := g.translateExpr(event, child, !negated)
				pos = append(pos, p...)
				neg = append(neg, n...)
			}
			return pos, neg
		case "or":
			var pos, neg []RuleSpec
			for _, child := range children {
				p, n := g.translateExpr(event, child, negated)
				pos = append(pos, p...)
				neg = append(neg, n...)
			}
			return pos, neg
		case "and":
			pos := []RuleSpec{{GroupRelation: "and"}}
			var neg []RuleSpec
			for _, child := range children {
				p, n := g.translateExpr(event, child, negated)
				neg = append(neg, n...)
				if len(p) == 0 {
					continue
				}
				pos = combineAnd(pos, p)
			}
			return pos, neg
		default:
			g.stats.UnsupportedPredicates++
			return nil, nil
		}
	default:
		return nil, nil
	}
}

func combineAnd(left, right []RuleSpec) []RuleSpec {
	if len(left) == 0 {
		return right
	}
	if len(right) == 0 {
		return left
	}
	const maxExpandedRules = 300
	var out []RuleSpec
	for _, l := range left {
		for _, r := range right {
			conds := append([]Condition{}, l.Conditions...)
			conds = append(conds, r.Conditions...)
			out = append(out, RuleSpec{GroupRelation: "and", Conditions: conds})
			if len(out) >= maxExpandedRules {
				return out
			}
		}
	}
	return out
}

func (g *mdeGenerator) addInclude(event string, rules []RuleSpec) {
	if len(rules) == 0 {
		return
	}
	g.ensure(event).Include = append(g.ensure(event).Include, rules...)
}

func (g *mdeGenerator) addExclude(event string, rules []RuleSpec) {
	if len(rules) == 0 {
		return
	}
	g.ensure(event).Exclude = append(g.ensure(event).Exclude, rules...)
}

func (g *mdeGenerator) ensure(event string) *eventRules {
	if g.byEvent[event] == nil {
		g.byEvent[event] = &eventRules{}
	}
	return g.byEvent[event]
}

func (g *mdeGenerator) write(outputDir string) (*MDEResult, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, err
	}
	var files []string
	events := make([]string, 0, len(g.byEvent))
	for event := range g.byEvent {
		events = append(events, event)
	}
	sort.Strings(events)
	for _, event := range events {
		group := g.byEvent[event]
		if len(group.Include) > 0 {
			path := filepath.Join(outputDir, "include_mde_"+strings.ToLower(event)+".xml")
			if err := WriteModuleFromRules(path, event, "include", group.Include); err != nil {
				return nil, err
			}
			files = append(files, path)
		}
		if g.mode == MDEModeFiltered && len(group.Exclude) > 0 {
			path := filepath.Join(outputDir, "exclude_mde_"+strings.ToLower(event)+".xml")
			if err := WriteModuleFromRules(path, event, "exclude", group.Exclude); err != nil {
				return nil, err
			}
			files = append(files, path)
		}
	}
	if len(files) == 0 {
		g.warnings = append(g.warnings, "no Sysmon-supported MDE telemetry could be converted")
	}
	return &MDEResult{Files: files, Warnings: dedupeStrings(g.warnings), Stats: g.stats}, nil
}

func collectMDERules(root any) []mdeRule {
	var out []mdeRule
	walkAny(root, func(obj map[string]any) {
		if _, hasFilters := obj["filters"]; !hasFilters {
			return
		}
		if _, hasName := obj["name"]; !hasName {
			if _, hasTask := obj["taskName"]; !hasTask {
				return
			}
		}
		out = append(out, mdeRule{
			Name:     stringValue(obj["name"]),
			TaskName: stringValue(obj["taskName"]),
			EventID:  scalarString(obj["eventId"]),
			Filters:  obj["filters"],
			Raw:      obj,
		})
	})
	return out
}

func walkAny(v any, fn func(map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		fn(x)
		for _, child := range x {
			walkAny(child, fn)
		}
	case []any:
		for _, child := range x {
			walkAny(child, fn)
		}
	}
}

func inferSysmonEvent(rule mdeRule) string {
	text := strings.ToLower(rule.Name + " " + rule.TaskName)
	switch {
	case containsAny(text, "dns query", "send query to dns", "zeekdns", "signaturedns"):
		return "DnsQuery"
	case containsAny(text, "create process", "process created", "process creation", "legacyprocessnotify", "win32_process:create"):
		return "ProcessCreate"
	case containsAny(text, "process termination", "filter process termination"):
		return "ProcessTerminate"
	case containsAny(text, "network", "connect complete", "connect failure", "connection accepted", "listening socket", "socket created"):
		return "NetworkConnect"
	case containsAny(text, "named pipe"):
		return "PipeEvent"
	case containsAny(text, "remote thread", "setthreadcontextremote"):
		return "CreateRemoteThread"
	case containsAny(text, "open process", "process access"):
		return "ProcessAccess"
	case containsAny(text, "process tampering", "tampering through object", "possible acl tampering"):
		return "ProcessTampering"
	case containsAny(text, "loadimage", "load image", "image load", "module load", "moduledcstart", "dllload"):
		return "ImageLoad"
	case containsAny(text, "driver loaded", "driver load"):
		return "DriverLoad"
	case containsAny(text, "registry", "reg query", "reg save"):
		return "RegistryEvent"
	case containsAny(text, "wmi", "win32_process"):
		return "WmiEvent"
	case containsAny(text, "clipboard"):
		return "ClipboardChange"
	case containsAny(text, "file delete", "delete file"):
		return "FileDeleteDetected"
	case containsAny(text, "file stream"):
		return "FileCreateStreamHash"
	case containsAny(text, "pe create file", "file executable"):
		return "FileExecutableDetected"
	case containsAny(text, "create file", "file create", "shell link create", "non pe create"):
		return "FileCreate"
	default:
		return ""
	}
}

func conditionFromPredicate(event string, pred map[string]any) (Condition, bool) {
	field, ok := sysmonField(event, stringValue(pred["source"]))
	if !ok {
		return Condition{}, false
	}
	values := stringValues(pred["values"])
	if len(values) == 0 {
		return Condition{}, false
	}
	op, value, ok := sysmonOperatorValue(stringValue(pred["filter"]), values)
	if !ok {
		return Condition{}, false
	}
	return Condition{Field: field, Operator: op, Value: value}, true
}

func sysmonField(event, source string) (string, bool) {
	s := strings.ToLower(source)
	switch event {
	case "ProcessCreate":
		switch {
		case strings.Contains(s, "parent") || strings.Contains(s, "initiatingprocess"):
			if strings.Contains(s, "cmd") {
				return "ParentCommandLine", true
			}
			return "ParentImage", true
		case strings.Contains(s, "cmd"):
			return "CommandLine", true
		case strings.Contains(s, "original"):
			return "OriginalFileName", true
		case strings.Contains(s, "file_native_path") || strings.Contains(s, "process_name") || strings.Contains(s, "filename") || strings.Contains(s, "image"):
			return "Image", true
		}
	case "NetworkConnect":
		switch {
		case strings.Contains(s, "remoteport") || strings.Contains(s, "destinationport") || s == "port":
			return "DestinationPort", true
		case strings.Contains(s, "localport") || strings.Contains(s, "sourceport"):
			return "SourcePort", true
		case strings.Contains(s, "remoteip") || strings.Contains(s, "destinationip") || strings.Contains(s, "socketaddress") || strings.Contains(s, "address"):
			return "DestinationIp", true
		case strings.Contains(s, "hostname") || strings.Contains(s, "remoteurl"):
			return "DestinationHostname", true
		case strings.Contains(s, "protocol"):
			return "Protocol", true
		case strings.Contains(s, "process") || strings.Contains(s, "image") || strings.Contains(s, "filename"):
			return "Image", true
		}
	case "ImageLoad":
		if strings.Contains(s, "process") || strings.Contains(s, "initiatingprocess") {
			return "Image", true
		}
		if strings.Contains(s, "image") || strings.Contains(s, "module") || strings.Contains(s, "dll") || strings.Contains(s, "filename") {
			return "ImageLoaded", true
		}
	case "DriverLoad":
		if strings.Contains(s, "signature") {
			return "Signature", true
		}
		if strings.Contains(s, "image") || strings.Contains(s, "driver") || strings.Contains(s, "filename") {
			return "ImageLoaded", true
		}
	case "FileCreate", "FileDelete", "FileDeleteDetected", "FileBlockExecutable", "FileBlockShredding":
		if strings.Contains(s, "process") || strings.Contains(s, "initiatingprocess") {
			return "Image", true
		}
		if strings.Contains(s, "file") || strings.Contains(s, "path") || strings.Contains(s, "name") {
			return "TargetFilename", true
		}
	case "FileExecutableDetected":
		if strings.Contains(s, "process") || strings.Contains(s, "image") || strings.Contains(s, "filename") {
			return "Image", true
		}
	case "RegistryEvent":
		if strings.Contains(s, "process") || strings.Contains(s, "image") {
			return "Image", true
		}
		if strings.Contains(s, "detail") || strings.Contains(s, "data") {
			return "Details", true
		}
		if strings.Contains(s, "registry") || strings.Contains(s, "key") || strings.Contains(s, "value") || strings.Contains(s, "targetobject") {
			return "TargetObject", true
		}
	case "DnsQuery":
		if strings.Contains(s, "process") || strings.Contains(s, "image") {
			return "Image", true
		}
		if strings.Contains(s, "query") || strings.Contains(s, "domain") || strings.Contains(s, "hostname") || strings.Contains(s, "dns") {
			return "QueryName", true
		}
	case "PipeEvent":
		if strings.Contains(s, "process") || strings.Contains(s, "image") {
			return "Image", true
		}
		if strings.Contains(s, "pipe") || strings.Contains(s, "name") {
			return "PipeName", true
		}
	case "CreateRemoteThread":
		if strings.Contains(s, "target") {
			return "TargetImage", true
		}
		if strings.Contains(s, "start") {
			return "StartAddress", true
		}
		if strings.Contains(s, "process") || strings.Contains(s, "source") || strings.Contains(s, "image") {
			return "SourceImage", true
		}
	case "ProcessAccess":
		if strings.Contains(s, "target") {
			return "TargetImage", true
		}
		if strings.Contains(s, "access") {
			return "GrantedAccess", true
		}
		if strings.Contains(s, "process") || strings.Contains(s, "source") || strings.Contains(s, "image") {
			return "SourceImage", true
		}
	case "ProcessTerminate", "ProcessTampering", "ClipboardChange", "RawAccessRead":
		if strings.Contains(s, "process") || strings.Contains(s, "image") || strings.Contains(s, "filename") {
			return "Image", true
		}
	case "WmiEvent":
		if strings.Contains(s, "operation") {
			return "Operation", true
		}
		if strings.Contains(s, "name") || strings.Contains(s, "query") || strings.Contains(s, "consumer") || strings.Contains(s, "filter") {
			return "Name", true
		}
	}
	return "", false
}

func sysmonOperatorValue(filter string, values []string) (string, string, bool) {
	f := strings.ToLower(filter)
	for i := range values {
		values[i] = expandMDEPath(values[i])
	}
	switch f {
	case "eq", "==":
		if len(values) == 1 {
			return "is", values[0], true
		}
		return "is any", strings.Join(values, ";"), true
	case "in":
		return "is any", strings.Join(values, ";"), true
	case "contains":
		if len(values) == 1 {
			return "contains", values[0], true
		}
		return "contains any", strings.Join(values, ";"), true
	case "containsany":
		return "contains any", strings.Join(values, ";"), true
	case "containsall":
		return "contains all", strings.Join(values, ";"), true
	case "endswith":
		if len(values) == 1 {
			return "end with", values[0], true
		}
		return "contains any", strings.Join(values, ";"), true
	case "startswith":
		if len(values) == 1 {
			return "begin with", values[0], true
		}
		return "contains any", strings.Join(values, ";"), true
	case "gt":
		return "more than", values[0], true
	case "lt":
		return "less than", values[0], true
	default:
		return "", "", false
	}
}

func expressionChildren(expr map[string]any) []map[string]any {
	raw, _ := expr["expressions"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if child, ok := item.(map[string]any); ok {
			out = append(out, child)
		}
	}
	return out
}

func broadRule(event, name string) RuleSpec {
	field := map[string]string{
		"ProcessCreate":          "Image",
		"FileCreateTime":         "Image",
		"NetworkConnect":         "Image",
		"ProcessTerminate":       "Image",
		"DriverLoad":             "ImageLoaded",
		"ImageLoad":              "ImageLoaded",
		"CreateRemoteThread":     "SourceImage",
		"RawAccessRead":          "Image",
		"ProcessAccess":          "SourceImage",
		"FileCreate":             "TargetFilename",
		"RegistryEvent":          "TargetObject",
		"FileCreateStreamHash":   "TargetFilename",
		"PipeEvent":              "PipeName",
		"WmiEvent":               "Operation",
		"DnsQuery":               "QueryName",
		"FileDelete":             "TargetFilename",
		"ClipboardChange":        "Image",
		"ProcessTampering":       "Image",
		"FileDeleteDetected":     "TargetFilename",
		"FileBlockExecutable":    "TargetFilename",
		"FileBlockShredding":     "TargetFilename",
		"FileExecutableDetected": "Image",
	}[event]
	value := `\`
	if event == "DnsQuery" {
		value = "."
	}
	if event == "WmiEvent" {
		value = "Created"
	}
	return RuleSpec{Name: name, GroupRelation: "and", Conditions: []Condition{{Field: field, Operator: "contains", Value: value}}}
}

func prefixRuleNames(rules []RuleSpec, fallback string) []RuleSpec {
	out := make([]RuleSpec, len(rules))
	for i, rule := range rules {
		out[i] = rule
		if out[i].Name == "" {
			out[i].Name = fallback
		}
	}
	return out
}

func rulesForEvent(event string, rules []RuleSpec) []RuleSpec {
	var out []RuleSpec
	for _, rule := range rules {
		var conds []Condition
		for _, cond := range rule.Conditions {
			if field, ok := remapGenericConditionField(event, cond.Field); ok {
				cond.Field = field
				conds = append(conds, cond)
			}
		}
		if len(conds) > 0 {
			rule.Conditions = conds
			out = append(out, rule)
		}
	}
	return out
}

func remapGenericConditionField(event, field string) (string, bool) {
	if field == "Image" {
		switch event {
		case "ProcessCreate", "NetworkConnect", "FileCreate", "RegistryEvent", "ProcessTerminate", "ImageLoad", "FileExecutableDetected":
			return "Image", true
		default:
			return "", false
		}
	}
	if field == "TargetFilename" {
		switch event {
		case "FileCreate", "FileDelete", "FileDeleteDetected":
			return "TargetFilename", true
		default:
			return "", false
		}
	}
	return field, true
}

func ruleLabel(rule mdeRule) string {
	label := strings.TrimSpace(rule.Name)
	if label == "" {
		label = strings.TrimSpace(rule.TaskName)
	}
	if label == "" && rule.EventID != "" {
		label = "event " + rule.EventID
	}
	return label
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func boolValue(v any) bool {
	b, _ := v.(bool)
	return b
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func scalarString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return ""
	}
}

func stringValues(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s := scalarString(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func expandMDEPath(value string) string {
	replacements := map[string]string{
		"%ProgramFiles(x86)%": `C:\Program Files (x86)`,
		"%ProgramFiles%":      `C:\Program Files`,
		"%SystemRoot%":        `C:\Windows`,
		"%systemroot%":        `C:\Windows`,
		"%windir%":            `C:\Windows`,
		"%SystemDrive%":       `C:`,
		"%systemdrive%":       `C:`,
	}
	out := value
	for from, to := range replacements {
		out = strings.ReplaceAll(out, from, to)
	}
	return out
}

func normalizeRegistryPath(value string) string {
	v := strings.TrimSpace(value)
	replacements := map[string]string{
		"hkcu\\": "HKCU\\",
		"hklm\\": "HKLM\\",
		"hkcr\\": "HKCR\\",
		"hku\\":  "HKU\\",
	}
	lower := strings.ToLower(v)
	for from, to := range replacements {
		if strings.HasPrefix(lower, from) {
			return to + v[len(from):]
		}
	}
	return v
}

func pathOperator(value string) string {
	if strings.Contains(value, "*") || strings.Contains(value, "(1)") {
		return "contains"
	}
	if strings.HasSuffix(value, `\`) {
		return "begin with"
	}
	return "contains"
}

func normalizePathPattern(value string) string {
	v := strings.TrimSpace(value)
	v = strings.ReplaceAll(v, "(1)", "")
	v = strings.ReplaceAll(v, "\\\\*", "\\")
	v = strings.ReplaceAll(v, "\\*", "\\")
	v = strings.ReplaceAll(v, "*", "")
	v = regexp.MustCompile(`\\{3,}`).ReplaceAllString(v, `\\`)
	return v
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
