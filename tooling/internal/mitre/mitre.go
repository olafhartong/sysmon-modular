package mitre

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

type Technique struct {
	Name        string
	Tactics     []string
	Revoked     bool
	Deprecated  bool
	Replacement string
}

func IDsFromValue(value string) []string {
	matches := techniqueIDPattern.FindAllStringSubmatch(value, -1)
	seen := map[string]bool{}
	var out []string
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		id := strings.ToUpper(match[2])
		if validIDPattern.MatchString(id) && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

type IssueKind string

const (
	IssueMalformed    IssueKind = "malformed"
	IssueUnknownID    IssueKind = "unknown-id"
	IssueRetiredID    IssueKind = "retired-id"
	IssueAttributeKey IssueKind = "attribute-key"
	IssueNameMismatch IssueKind = "name-mismatch"
)

type Issue struct {
	Kind         IssueKind
	Path         string
	Element      string
	Line         int
	Value        string
	ID           string
	UsedName     string
	OfficialName string
	Replacement  string
	Detail       string
}

type FixResult struct {
	Path     string
	Changed  bool
	Changes  int
	Proposed int
	Skipped  int
	Issues   []Issue
	Unfixed  []Issue
	BytesIn  int
	BytesOut int
}

type Change struct {
	Path   string
	Line   int
	Before string
	After  string
}

var (
	techniqueIDPattern   = regexp.MustCompile(`\b(technique_id|technique)\s*=\s*(T(?:\d{4}(?:\.\d{3})?)?)\b`)
	techniqueNamePattern = regexp.MustCompile(`\btechnique_name\s*=\s*([^,]*)`)
	validIDPattern       = regexp.MustCompile(`^T\d{4}(?:\.\d{3})?$`)
	metadataHintPattern  = regexp.MustCompile(`(?i)\btechnique(?:_id|_name)?\s*=`)
)

func CheckDocument(doc *sysmonxml.Document, path string) []Issue {
	if doc == nil || doc.Root == nil {
		return nil
	}
	var issues []Issue
	doc.Root.Walk(func(n *sysmonxml.Node) {
		if n.Name == "" {
			return
		}
		for _, attr := range n.Attr {
			if attr.Name.Local != "name" || !strings.Contains(strings.ToLower(attr.Value), "technique") {
				continue
			}
			for _, issue := range CheckValue(attr.Value, path) {
				issue.Element = n.Name
				issue.Line = n.Line
				issues = append(issues, issue)
			}
		}
	})
	return issues
}

func CheckValue(value, path string) []Issue {
	var issues []Issue
	idMatch := techniqueIDPattern.FindStringSubmatchIndex(value)
	if idMatch == nil {
		if metadataHintPattern.MatchString(value) {
			issues = append(issues, Issue{
				Kind:   IssueMalformed,
				Path:   path,
				Value:  value,
				Detail: "MITRE metadata must include technique_id=T#### or technique_id=T####.###",
			})
		}
		return issues
	}

	key := value[idMatch[2]:idMatch[3]]
	id := strings.ToUpper(value[idMatch[4]:idMatch[5]])
	usedName := techniqueName(value)
	if key != "technique_id" {
		issues = append(issues, Issue{
			Kind:   IssueAttributeKey,
			Path:   path,
			Value:  value,
			ID:     id,
			Detail: `MITRE metadata key must be "technique_id"`,
		})
	}
	if !validIDPattern.MatchString(id) {
		issues = append(issues, Issue{
			Kind:     IssueMalformed,
			Path:     path,
			Value:    value,
			ID:       id,
			UsedName: usedName,
			Detail:   "MITRE technique ID is incomplete or malformed",
		})
		return issues
	}

	tech, ok := techniques[id]
	if !ok {
		issues = append(issues, Issue{
			Kind:     IssueUnknownID,
			Path:     path,
			Value:    value,
			ID:       id,
			UsedName: usedName,
			Detail:   "MITRE technique ID is not present in the embedded Enterprise ATT&CK table",
		})
		return issues
	}
	if tech.Revoked || tech.Deprecated {
		replacement := tech.Replacement
		official := tech.Name
		if replacement != "" {
			if repl, ok := techniques[replacement]; ok {
				official = repl.Name
			}
		}
		issues = append(issues, Issue{
			Kind:         IssueRetiredID,
			Path:         path,
			Value:        value,
			ID:           id,
			UsedName:     usedName,
			OfficialName: official,
			Replacement:  replacement,
			Detail:       retiredDetail(tech),
		})
		return issues
	}

	if usedName == "" {
		issues = append(issues, Issue{
			Kind:         IssueMalformed,
			Path:         path,
			Value:        value,
			ID:           id,
			OfficialName: tech.Name,
			Detail:       "MITRE metadata is missing technique_name",
		})
		return issues
	}
	if !nameMatches(id, usedName) {
		issues = append(issues, Issue{
			Kind:         IssueNameMismatch,
			Path:         path,
			Value:        value,
			ID:           id,
			UsedName:     usedName,
			OfficialName: tech.Name,
			Detail:       "MITRE technique_name differs from Enterprise ATT&CK",
		})
	}
	return issues
}

func FixFile(path string, write bool) (FixResult, error) {
	return ReviewFile(path, write, nil)
}

// ReviewFile discovers fixable metadata values and asks approve before each
// replacement. A nil approve function accepts every proposed change.
func ReviewFile(path string, write bool, approve func(Change) bool) (FixResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FixResult{}, err
	}
	fixed, result := fixBytes(data, path, approve)
	result.Path = path
	result.BytesIn = len(data)
	result.BytesOut = len(fixed)
	if write && result.Changed {
		if err := os.WriteFile(path, fixed, 0o644); err != nil {
			return result, err
		}
	}
	return result, nil
}

func fixBytes(data []byte, path string, approve func(Change) bool) ([]byte, FixResult) {
	input := string(data)
	var out strings.Builder
	out.Grow(len(input))
	var result FixResult
	for i := 0; i < len(input); {
		if strings.HasPrefix(input[i:], "<!--") {
			end := strings.Index(input[i+4:], "-->")
			if end == -1 {
				out.WriteString(input[i:])
				break
			}
			end += i + 7
			out.WriteString(input[i:end])
			i = end
			continue
		}
		if match, ok := parseNameAttribute(input, i); ok {
			issues := CheckValue(match.Value, path)
			result.Issues = append(result.Issues, issues...)
			newValue, changed := FixValue(match.Value)
			if changed {
				result.Proposed++
				change := Change{Path: path, Line: 1 + strings.Count(input[:match.ValueStart], "\n"), Before: match.Value, After: newValue}
				if approve == nil || approve(change) {
					result.Changed = true
					result.Changes++
				} else {
					newValue = match.Value
					result.Skipped++
				}
			}
			for _, issue := range issues {
				if !changed {
					result.Unfixed = append(result.Unfixed, issue)
				}
			}
			out.WriteString(input[i:match.ValueStart])
			out.WriteString(newValue)
			i = match.ValueEnd
			continue
		}
		out.WriteByte(input[i])
		i++
	}
	return []byte(out.String()), result
}

func FixValue(value string) (string, bool) {
	issues := CheckValue(value, "")
	if len(issues) == 0 {
		return value, false
	}
	idMatch := techniqueIDPattern.FindStringSubmatchIndex(value)
	if idMatch == nil {
		return value, false
	}
	id := strings.ToUpper(value[idMatch[4]:idMatch[5]])
	if !validIDPattern.MatchString(id) {
		return value, false
	}
	targetID := id
	if tech, ok := techniques[id]; ok && (tech.Revoked || tech.Deprecated) && tech.Replacement != "" {
		targetID = tech.Replacement
	}
	tech, ok := techniques[targetID]
	if !ok || tech.Revoked || tech.Deprecated {
		return value, false
	}

	out := value
	out = replaceRange(out, idMatch[2], idMatch[3], "technique_id")
	idMatch = techniqueIDPattern.FindStringSubmatchIndex(out)
	if idMatch == nil {
		return value, false
	}
	out = replaceRange(out, idMatch[4], idMatch[5], targetID)
	nameMatch := techniqueNamePattern.FindStringSubmatchIndex(out)
	if nameMatch == nil {
		out += ",technique_name=" + tech.Name
	} else {
		out = replaceRange(out, nameMatch[2], nameMatch[3], tech.Name)
	}
	return out, out != value
}

func Lookup(id string) (Technique, bool) {
	tech, ok := techniques[strings.ToUpper(id)]
	tech.Tactics = append([]string(nil), tech.Tactics...)
	return tech, ok
}

func Tactics(id string) []string {
	tech, ok := techniques[strings.ToUpper(id)]
	if !ok {
		return nil
	}
	return append([]string(nil), tech.Tactics...)
}

func CurrentName(id string) (string, bool) {
	tech, ok := techniques[strings.ToUpper(id)]
	if !ok || tech.Revoked || tech.Deprecated {
		return "", false
	}
	return tech.Name, true
}

func IssueMessage(issue Issue) string {
	switch issue.Kind {
	case IssueMalformed:
		return "malformed MITRE technique metadata"
	case IssueUnknownID:
		return "unknown MITRE technique ID"
	case IssueRetiredID:
		return "retired MITRE technique ID"
	case IssueAttributeKey:
		return "MITRE technique metadata uses technique instead of technique_id"
	case IssueNameMismatch:
		return "MITRE technique name mismatch"
	default:
		return "MITRE technique issue"
	}
}

func IssueDetail(issue Issue) string {
	parts := []string{}
	if issue.ID != "" {
		parts = append(parts, "id="+issue.ID)
	}
	if issue.Replacement != "" {
		parts = append(parts, "replacement="+issue.Replacement)
	}
	if issue.UsedName != "" {
		parts = append(parts, "used="+issue.UsedName)
	}
	if issue.OfficialName != "" {
		parts = append(parts, "official="+issue.OfficialName)
	}
	if issue.Detail != "" {
		parts = append(parts, issue.Detail)
	}
	if issue.Value != "" {
		parts = append(parts, "value="+issue.Value)
	}
	return strings.Join(parts, "; ")
}

func techniqueName(value string) string {
	match := techniqueNamePattern.FindStringSubmatch(value)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func nameMatches(id, name string) bool {
	tech, ok := techniques[id]
	if !ok {
		return false
	}
	if normalizeName(name) == normalizeName(tech.Name) {
		return true
	}
	if dot := strings.IndexByte(id, '.'); dot >= 0 {
		id = id[:dot]
	} else {
		return false
	}
	parent, ok := techniques[id]
	if !ok || parent.Revoked || parent.Deprecated {
		return false
	}
	combinedColon := parent.Name + ": " + tech.Name
	combinedDash := parent.Name + " - " + tech.Name
	return normalizeName(name) == normalizeName(combinedColon) || normalizeName(name) == normalizeName(combinedDash)
}

func normalizeName(name string) string {
	return strings.ToLower(strings.Join(strings.Fields(name), " "))
}

func retiredDetail(tech Technique) string {
	status := "revoked"
	if tech.Deprecated {
		status = "deprecated"
	}
	if tech.Replacement != "" {
		return fmt.Sprintf("MITRE technique is %s; replacement=%s", status, tech.Replacement)
	}
	return fmt.Sprintf("MITRE technique is %s", status)
}

func replaceRange(s string, start, end int, replacement string) string {
	return s[:start] + replacement + s[end:]
}

type nameAttributeMatch struct {
	Value      string
	ValueStart int
	ValueEnd   int
}

func parseNameAttribute(s string, pos int) (nameAttributeMatch, bool) {
	if pos+4 > len(s) || s[pos:pos+4] != "name" {
		return nameAttributeMatch{}, false
	}
	if pos > 0 {
		prev := s[pos-1]
		if prev != ' ' && prev != '\t' && prev != '\n' && prev != '\r' {
			return nameAttributeMatch{}, false
		}
	}
	i := pos + 4
	for i < len(s) && isXMLSpace(s[i]) {
		i++
	}
	if i >= len(s) || s[i] != '=' {
		return nameAttributeMatch{}, false
	}
	i++
	for i < len(s) && isXMLSpace(s[i]) {
		i++
	}
	if i >= len(s) || (s[i] != '"' && s[i] != '\'') {
		return nameAttributeMatch{}, false
	}
	quote := s[i]
	valueStart := i + 1
	valueEnd := valueStart
	for valueEnd < len(s) && s[valueEnd] != quote {
		valueEnd++
	}
	if valueEnd >= len(s) {
		return nameAttributeMatch{}, false
	}
	value := s[valueStart:valueEnd]
	if !strings.Contains(strings.ToLower(value), "technique") {
		return nameAttributeMatch{}, false
	}
	return nameAttributeMatch{Value: value, ValueStart: valueStart, ValueEnd: valueEnd}, true
}

func isXMLSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
