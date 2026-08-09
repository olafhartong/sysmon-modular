package validate

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/merger"
	"github.com/olafhartong/sysmon-modular/tooling/internal/mitre"
	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

type Severity string

const (
	Error          Severity = "error"
	Warning        Severity = "warning"
	Recommendation Severity = "recommendation"
	Performance    Severity = "performance"
)

type Finding struct {
	Code     string
	Severity Severity
	Path     string
	Line     int
	Message  string
	Detail   string
}

func SyntaxFile(path string, preserveComments bool) []Finding {
	_, err := sysmonxml.ParseFile(path, preserveComments)
	if err == nil {
		return nil
	}
	line := 0
	var syntaxError *xml.SyntaxError
	if errors.As(err, &syntaxError) {
		line = syntaxError.Line
	}
	return []Finding{{Code: "XML001", Severity: Error, Path: path, Line: line, Message: "XML syntax validation failed", Detail: err.Error()}}
}

func Schema(doc *sysmonxml.Document, path string) []Finding {
	var findings []Finding
	if doc == nil || doc.Root == nil {
		return []Finding{{Code: "SYS001", Severity: Error, Path: path, Message: "empty XML document"}}
	}
	if doc.Root.Name != "Sysmon" {
		findings = append(findings, Finding{Code: "SYS002", Severity: Error, Path: path, Line: doc.Root.Line, Message: "root element must be Sysmon"})
	}
	if doc.Root.AttrValue("schemaversion") == "" {
		findings = append(findings, Finding{Code: "SYS003", Severity: Warning, Path: path, Line: doc.Root.Line, Message: "Sysmon root is missing schemaversion"})
	}
	eventFiltering := doc.Root.FirstChild("EventFiltering")
	if eventFiltering == nil {
		hasRuleGroup := false
		doc.Root.Walk(func(n *sysmonxml.Node) {
			if n.Name == "RuleGroup" {
				hasRuleGroup = true
			}
		})
		if hasRuleGroup {
			findings = append(findings, Finding{Code: "SYS004", Severity: Warning, Path: path, Line: doc.Root.Line, Message: "missing EventFiltering element", Detail: "legacy module layout still contains RuleGroup elements"})
			return append(findings, validateRuleGroups(path, doc.Root)...)
		}
		findings = append(findings, Finding{Code: "SYS005", Severity: Error, Path: path, Line: doc.Root.Line, Message: "missing EventFiltering element"})
		return findings
	}
	findings = append(findings, validateEventFilteringChildren(path, eventFiltering)...)
	findings = append(findings, validateRuleGroups(path, eventFiltering)...)
	findings = append(findings, validateSchemaFields(path, doc.Root.AttrValue("schemaversion"), eventFiltering)...)
	return findings
}

func MITRE(doc *sysmonxml.Document, path string) []Finding {
	issues := mitre.CheckDocument(doc, path)
	findings := make([]Finding, 0, len(issues))
	for _, issue := range issues {
		findings = append(findings, Finding{
			Code:     "MITRE_" + strings.ToUpper(strings.ReplaceAll(string(issue.Kind), "-", "_")),
			Severity: Error,
			Path:     path,
			Line:     issue.Line,
			Message:  mitre.IssueMessage(issue),
			Detail:   mitre.IssueDetail(issue),
		})
	}
	return findings
}

func validateRuleGroups(path string, root *sysmonxml.Node) []Finding {
	var findings []Finding
	root.Walk(func(child *sysmonxml.Node) {
		if child.Name != "RuleGroup" {
			return
		}
		if rel := strings.ToLower(child.AttrValue("groupRelation")); rel != "" && rel != "or" && rel != "and" {
			findings = append(findings, Finding{Code: "SYS101", Severity: Error, Path: path, Line: child.Line, Message: "RuleGroup has invalid groupRelation", Detail: rel})
		}
		for _, event := range child.ElementChildren() {
			if !merger.EventSet[event.Name] {
				findings = append(findings, Finding{Code: "SYS102", Severity: Error, Path: path, Line: event.Line, Message: "unknown Sysmon event element", Detail: event.Name})
				continue
			}
			onmatch := strings.ToLower(event.AttrValue("onmatch"))
			if onmatch != "" && onmatch != "include" && onmatch != "exclude" {
				findings = append(findings, Finding{Code: "SYS103", Severity: Error, Path: path, Line: event.Line, Message: "event has invalid onmatch", Detail: fmt.Sprintf("%s onmatch=%s", event.Name, onmatch)})
			}
			findings = append(findings, validateRuleChildren(path, event)...)
		}
	})
	return findings
}

func validateEventFilteringChildren(path string, eventFiltering *sysmonxml.Node) []Finding {
	var findings []Finding
	for _, child := range eventFiltering.ElementChildren() {
		if child.Name != "RuleGroup" {
			findings = append(findings, Finding{Code: "SYS104", Severity: Error, Path: path, Line: child.Line, Message: "EventFiltering children must be RuleGroup", Detail: child.Name})
		}
	}
	return findings
}

func validateRuleChildren(path string, parent *sysmonxml.Node) []Finding {
	var findings []Finding
	validConditions := map[string]bool{
		"is": true, "is not": true, "contains": true, "contains any": true, "contains all": true,
		"excludes": true, "begin with": true, "end with": true, "image": true, "not image": true,
		"less than": true, "more than": true,
		"is any": true, "excludes any": true, "excludes all": true, "not begin with": true, "not end with": true,
	}
	multiValueConditions := map[string]bool{
		"is any": true, "contains any": true, "contains all": true,
		"excludes any": true, "excludes all": true,
	}
	for _, child := range parent.ElementChildren() {
		if child.Name == "Rule" {
			rel := strings.ToLower(child.AttrValue("groupRelation"))
			if rel != "" && rel != "or" && rel != "and" {
				findings = append(findings, Finding{Code: "SYS105", Severity: Error, Path: path, Line: child.Line, Message: "Rule has invalid groupRelation", Detail: rel})
			}
			findings = append(findings, validateRuleChildren(path, child)...)
			continue
		}
		cond := strings.ToLower(strings.TrimSpace(child.AttrValue("condition")))
		if cond != "" && !validConditions[cond] {
			findings = append(findings, Finding{Code: "SYS106", Severity: Warning, Path: path, Line: child.Line, Message: "unknown condition operator", Detail: fmt.Sprintf("%s condition=%s", child.Name, cond)})
		}
		if strings.Contains(child.Text, ";") && !multiValueConditions[cond] {
			findings = append(findings, Finding{Code: "SYS107", Severity: Error, Path: path, Line: child.Line, Message: "semicolon-delimited value requires a multi-value condition", Detail: fmt.Sprintf("%s condition=%s", child.Name, cond)})
		}
	}
	return findings
}

func HasErrors(findings []Finding) bool {
	for _, finding := range findings {
		if finding.Severity == Error {
			return true
		}
	}
	return false
}
