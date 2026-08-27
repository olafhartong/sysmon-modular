package validate

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

// BinarySchema describes a known Sysmon executable/schema snapshot.
type BinarySchema struct {
	Version       string
	SchemaVersion string
	major         int
	minor         int
}

// Release boundaries come from the printed manifests supplied with this work:
// Sysmon 13 (schema 4.50), 13.1 (4.60), 14 (4.82), 15 (4.90), and 15.20
// (4.91). Sysmon 12's
// ClipboardChange boundary is schema 4.40. Microsoft's Sysmon 14.1 release
// notes document the later FileBlockShredding addition (schema 4.83).
var eventMinBinary = map[string][2]int{
	"ClipboardChange":        {12, 0},
	"ProcessTampering":       {13, 0},
	"FileDeleteDetected":     {13, 1},
	"FileBlockExecutable":    {14, 0},
	"FileBlockShredding":     {14, 1},
	"FileExecutableDetected": {15, 0},
}

// Fields added to existing filterable events in the Sysmon 14 schema.
var fieldMinBinary = map[string]map[string][2]int{
	"ProcessCreate":        {"ParentUser": {14, 0}},
	"FileCreateTime":       {"User": {14, 0}},
	"ProcessTerminate":     {"User": {14, 0}},
	"ImageLoad":            {"User": {14, 0}},
	"CreateRemoteThread":   {"SourceUser": {14, 0}, "TargetUser": {14, 0}},
	"RawAccessRead":        {"User": {14, 0}},
	"ProcessAccess":        {"SourceUser": {14, 0}, "TargetUser": {14, 0}},
	"FileCreate":           {"User": {14, 0}},
	"RegistryEvent":        {"User": {14, 0}},
	"FileCreateStreamHash": {"User": {14, 0}},
	"PipeEvent":            {"User": {14, 0}},
	"DnsQuery":             {"User": {14, 0}},
	"ClipboardChange":      {"User": {14, 0}},
	"ProcessTampering":     {"User": {14, 0}},
}

// ResolveBinarySchema maps the public Sysmon executable version to the schema
// shipped with that release. Version 12 is the oldest supported target.
func ResolveBinarySchema(version string) (BinarySchema, error) {
	major, minor, err := parseBinaryVersion(version)
	if err != nil {
		return BinarySchema{}, err
	}
	if major < 12 || major > 15 {
		return BinarySchema{}, fmt.Errorf("unsupported Sysmon version %q: supported executable versions are 12 through 15", version)
	}
	schema := map[int]string{12: "4.40", 13: "4.50", 14: "4.82", 15: "4.90"}[major]
	canonical := strconv.Itoa(major)
	if major == 13 && minor >= 1 {
		schema = "4.60"
		canonical = "13.1"
	}
	if major == 14 && minor >= 1 {
		schema = "4.83"
		canonical = "14.1"
	}
	if major == 15 && minor >= 20 {
		schema = "4.91"
		canonical = fmt.Sprintf("15.%d", minor)
	}
	return BinarySchema{Version: canonical, SchemaVersion: schema, major: major, minor: minor}, nil
}

func parseBinaryVersion(version string) (int, int, error) {
	version = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(version), "v"))
	if version == "" {
		return 0, 0, fmt.Errorf("sysmon version cannot be empty")
	}
	parts := strings.Split(version, ".")
	if len(parts) > 3 {
		return 0, 0, fmt.Errorf("invalid Sysmon version %q", version)
	}
	values := make([]int, len(parts))
	for i, part := range parts {
		if part == "" {
			return 0, 0, fmt.Errorf("invalid Sysmon version %q", version)
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return 0, 0, fmt.Errorf("invalid Sysmon version %q", version)
		}
		values[i] = value
	}
	minor := 0
	if len(values) > 1 {
		minor = values[1]
	}
	return values[0], minor, nil
}

// BinaryCompatibility reports filter events and fields unsupported by target.
func BinaryCompatibility(doc *sysmonxml.Document, path, version string) ([]Finding, error) {
	target, err := ResolveBinarySchema(version)
	if err != nil {
		return nil, err
	}
	if doc == nil || doc.Root == nil {
		return nil, fmt.Errorf("empty XML document")
	}
	var findings []Finding
	eventFiltering := doc.Root.FirstChild("EventFiltering")
	if eventFiltering == nil {
		// Legacy modules may place RuleGroup directly below Sysmon.
		eventFiltering = doc.Root
	}
	eventFiltering.Walk(func(node *sysmonxml.Node) {
		if _, known := eventFields[node.Name]; !known {
			return
		}
		if !eventSupported(node.Name, target) {
			findings = append(findings, unsupportedEventFinding(path, node, target, false))
			return
		}
		checkUnsupportedFields(path, node.Name, node, target, false, &findings)
	})
	return findings, nil
}

// ExcludeBinaryUnsupported mutates doc by removing unsupported event filters
// and fields. It also sets the output schema version to the target binary's
// schema so the merged configuration can be consumed by that binary.
func ExcludeBinaryUnsupported(doc *sysmonxml.Document, path, version string) ([]Finding, error) {
	target, err := ResolveBinarySchema(version)
	if err != nil {
		return nil, err
	}
	if doc == nil || doc.Root == nil {
		return nil, fmt.Errorf("empty XML document")
	}
	doc.Root.SetAttr("schemaversion", target.SchemaVersion)
	eventFiltering := doc.Root.FirstChild("EventFiltering")
	if eventFiltering == nil {
		// Legacy modules may place RuleGroup directly below Sysmon.
		eventFiltering = doc.Root
	}
	var findings []Finding
	var groups []*sysmonxml.Node
	for _, child := range eventFiltering.Children {
		if child.Name != "RuleGroup" {
			groups = append(groups, child)
			continue
		}
		var events []*sysmonxml.Node
		for _, event := range child.Children {
			if _, known := eventFields[event.Name]; !known {
				events = append(events, event)
				continue
			}
			if !eventSupported(event.Name, target) {
				findings = append(findings, unsupportedEventFinding(path, event, target, true))
				continue
			}
			hadFilters := len(event.ElementChildren()) > 0
			filterSupportedFields(path, event.Name, event, target, &findings)
			if hadFilters && len(event.ElementChildren()) == 0 {
				findings = append(findings, Finding{Code: "SYS206", Severity: Warning, Path: path, Line: event.Line, Message: "event excluded after all of its filter fields were excluded", Detail: fmt.Sprintf("%s is not safe as an empty filter for Sysmon %s", event.Name, target.Version)})
				continue
			}
			events = append(events, event)
		}
		child.Children = events
		if len(child.ElementChildren()) > 0 {
			groups = append(groups, child)
		}
	}
	eventFiltering.Children = groups
	return findings, nil
}

func eventSupported(event string, target BinarySchema) bool {
	minimum, ok := eventMinBinary[event]
	return !ok || versionAtLeast(target, minimum)
}

func fieldSupported(event, field string, target BinarySchema) bool {
	minimum, ok := fieldMinBinary[event][field]
	return !ok || versionAtLeast(target, minimum)
}

func versionAtLeast(target BinarySchema, minimum [2]int) bool {
	return target.major > minimum[0] || target.major == minimum[0] && target.minor >= minimum[1]
}

func checkUnsupportedFields(path, event string, parent *sysmonxml.Node, target BinarySchema, excluded bool, findings *[]Finding) {
	for _, child := range parent.ElementChildren() {
		if child.Name == "Rule" {
			checkUnsupportedFields(path, event, child, target, excluded, findings)
			continue
		}
		if !fieldSupported(event, child.Name, target) {
			*findings = append(*findings, unsupportedFieldFinding(path, event, child, target, excluded))
		}
	}
}

func filterSupportedFields(path, event string, parent *sysmonxml.Node, target BinarySchema, findings *[]Finding) {
	var children []*sysmonxml.Node
	for _, child := range parent.Children {
		if child.Name == "Rule" {
			filterSupportedFields(path, event, child, target, findings)
			if len(child.ElementChildren()) > 0 {
				children = append(children, child)
			}
			continue
		}
		if child.Name != "" && !fieldSupported(event, child.Name, target) {
			*findings = append(*findings, unsupportedFieldFinding(path, event, child, target, true))
			continue
		}
		children = append(children, child)
	}
	parent.Children = children
}

func unsupportedEventFinding(path string, event *sysmonxml.Node, target BinarySchema, excluded bool) Finding {
	action := "is unsupported"
	if excluded {
		action = "was excluded"
	}
	minimum := eventMinBinary[event.Name]
	return Finding{Code: "SYS204", Severity: Warning, Path: path, Line: event.Line, Message: "event " + action + " by the target Sysmon binary", Detail: fmt.Sprintf("%s requires Sysmon %s; target is %s (schema %s)", event.Name, formatMinimum(minimum), target.Version, target.SchemaVersion)}
}

func unsupportedFieldFinding(path, event string, field *sysmonxml.Node, target BinarySchema, excluded bool) Finding {
	action := "is unsupported"
	if excluded {
		action = "was excluded"
	}
	minimum := fieldMinBinary[event][field.Name]
	return Finding{Code: "SYS205", Severity: Warning, Path: path, Line: field.Line, Message: "field " + action + " by the target Sysmon binary", Detail: fmt.Sprintf("%s.%s requires Sysmon %s; target is %s (schema %s)", event, field.Name, formatMinimum(minimum), target.Version, target.SchemaVersion)}
}

func formatMinimum(version [2]int) string {
	if version[1] == 0 {
		return strconv.Itoa(version[0])
	}
	return fmt.Sprintf("%d.%d", version[0], version[1])
}
