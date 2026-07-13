package analyze

import (
	"encoding/csv"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	_ "embed"

	"github.com/olafhartong/sysmon-modular/internal/sysmonxml"
	"github.com/olafhartong/sysmon-modular/internal/validate"
)

type condition struct {
	Event   string
	Onmatch string
	Field   string
	Op      string
	Value   string
	Line    int
}

//go:embed known_image_paths.csv
var knownImagePathsCSV string

var knownImagePaths = loadKnownImagePaths()

func loadKnownImagePaths() map[string][]string {
	paths := map[string][]string{}
	reader := csv.NewReader(strings.NewReader(knownImagePathsCSV))
	reader.FieldsPerRecord = -1
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(fmt.Sprintf("load known image paths: %v", err))
		}
		if len(record) < 2 || strings.EqualFold(strings.TrimSpace(record[0]), "image") {
			continue
		}
		image := strings.ToLower(strings.TrimSpace(record[0]))
		if image == "" {
			continue
		}
		for _, path := range strings.Split(record[1], "|") {
			path = strings.TrimSpace(path)
			if path != "" {
				paths[image] = append(paths[image], path)
			}
		}
	}
	return paths
}

func Config(doc *sysmonxml.Document, path string) []validate.Finding {
	var findings []validate.Finding
	if doc == nil || doc.Root == nil {
		return findings
	}
	findings = append(findings, bestPractices(doc, path)...)
	conditions := collectConditions(doc)
	findings = append(findings, conflictFindings(path, conditions)...)
	findings = append(findings, imagePathRecommendations(path, conditions)...)
	findings = append(findings, performanceFindings(path, doc, conditions)...)
	return findings
}

func bestPractices(doc *sysmonxml.Document, path string) []validate.Finding {
	var findings []validate.Finding
	hashes := doc.Root.FirstChild("HashAlgorithms")
	if hashes == nil || strings.TrimSpace(hashes.Text) == "" {
		findings = append(findings, validate.Finding{Code: "ANL001", Severity: validate.Recommendation, Path: path, Message: "set HashAlgorithms explicitly", Detail: "Use '*' for maximum hash coverage unless storage constraints require a narrower set."})
	} else if strings.TrimSpace(hashes.Text) != "*" {
		findings = append(findings, validate.Finding{Code: "ANL002", Severity: validate.Recommendation, Path: path, Line: hashes.Line, Message: "HashAlgorithms is not set to '*'", Detail: "Consider SHA256/IMPHASH coverage or '*' for richer triage data."})
	}
	if dns := doc.Root.FirstChild("DnsLookup"); dns != nil && strings.EqualFold(strings.TrimSpace(dns.Text), "true") {
		findings = append(findings, validate.Finding{Code: "ANL003", Severity: validate.Performance, Path: path, Line: dns.Line, Message: "DnsLookup=True can add resolver overhead"})
	}
	if revocation := doc.Root.FirstChild("CheckRevocation"); revocation != nil && strings.EqualFold(strings.TrimSpace(revocation.Text), "true") {
		findings = append(findings, validate.Finding{Code: "ANL004", Severity: validate.Performance, Path: path, Line: revocation.Line, Message: "CheckRevocation=True can add certificate lookup overhead"})
	}
	return findings
}

func collectConditions(doc *sysmonxml.Document) []condition {
	var out []condition
	eventFiltering := doc.Root.FirstChild("EventFiltering")
	if eventFiltering == nil {
		return out
	}
	for _, rg := range eventFiltering.ElementChildren() {
		if rg.Name != "RuleGroup" {
			continue
		}
		for _, event := range rg.ElementChildren() {
			onmatch := strings.ToLower(event.AttrValue("onmatch"))
			if onmatch == "" {
				onmatch = "include"
			}
			collectFromNode(event, event.Name, onmatch, &out)
		}
	}
	return out
}

func collectFromNode(n *sysmonxml.Node, event, onmatch string, out *[]condition) {
	for _, child := range n.ElementChildren() {
		if child.Name == "Rule" {
			collectFromNode(child, event, onmatch, out)
			continue
		}
		*out = append(*out, condition{
			Event: event, Onmatch: onmatch, Field: child.Name,
			Op: strings.ToLower(child.AttrValue("condition")), Value: strings.ToLower(strings.TrimSpace(child.Text)), Line: child.Line,
		})
	}
}

func conflictFindings(path string, conditions []condition) []validate.Finding {
	seenInclude := map[string]condition{}
	seenExclude := map[string]condition{}
	var findings []validate.Finding
	for _, c := range conditions {
		key := c.Event + "\x00" + c.Field + "\x00" + c.Op + "\x00" + c.Value
		if c.Onmatch == "include" {
			seenInclude[key] = c
		} else if c.Onmatch == "exclude" {
			seenExclude[key] = c
		}
	}
	for key, inc := range seenInclude {
		if _, ok := seenExclude[key]; ok && inc.Value != "" {
			findings = append(findings, validate.Finding{Code: "ANL005", Severity: validate.Warning, Path: path, Line: inc.Line, Message: "same condition appears in include and exclude rules", Detail: fmt.Sprintf("%s %s %s %q", inc.Event, inc.Field, inc.Op, inc.Value)})
		}
	}
	return findings
}

func imagePathRecommendations(path string, conditions []condition) []validate.Finding {
	var findings []validate.Finding
	seen := map[string]bool{}
	for _, c := range conditions {
		if !imagePathField(c.Field) || !imageNameOnlyOperator(c.Op) {
			continue
		}
		for _, base := range imageNameCandidates(c.Value) {
			paths, ok := knownImagePaths[base]
			key := c.Event + "|" + c.Onmatch + "|" + c.Field + "|" + base
			if !ok || seen[key] {
				continue
			}
			seen[key] = true
			message := "known binary is matched by image name only"
			detail := fmt.Sprintf("%s %s %s=%s; consider full path variants such as %s", c.Event, c.Onmatch, c.Field, base, strings.Join(paths, " or "))
			if c.Onmatch == "exclude" {
				message = "exclude rule matches a known binary by image name only"
				detail = fmt.Sprintf("%s; for exclusions, prefer full paths where possible to avoid suppressing lookalike binaries outside their expected locations", detail)
			}
			findings = append(findings, validate.Finding{
				Code:     "ANL006",
				Severity: validate.Recommendation,
				Path:     path,
				Line:     c.Line,
				Message:  message,
				Detail:   detail,
			})
		}
	}
	return findings
}

func imagePathField(field string) bool {
	switch field {
	case "Image", "ParentImage", "SourceImage", "TargetImage", "ImageLoaded":
		return true
	default:
		return false
	}
}

func imageNameOnlyOperator(op string) bool {
	switch op {
	case "", "image", "is", "is any", "end with", "excludes any", "excludes all":
		return true
	default:
		return false
	}
}

func imageNameCandidates(value string) []string {
	parts := strings.Split(strings.Trim(value, `"`), ";")
	candidates := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		part = strings.Trim(strings.TrimSpace(part), `"`)
		if part == "" || strings.Contains(part, `\`) || strings.Contains(part, `/`) {
			continue
		}
		base := strings.ToLower(filepath.Base(part))
		if base == "" || !strings.Contains(base, ".") || seen[base] {
			continue
		}
		seen[base] = true
		candidates = append(candidates, base)
	}
	return candidates
}

func performanceFindings(path string, doc *sysmonxml.Document, conditions []condition) []validate.Finding {
	var findings []validate.Finding
	eventFiltering := doc.Root.FirstChild("EventFiltering")
	if eventFiltering != nil {
		for _, rg := range eventFiltering.ElementChildren() {
			for _, event := range rg.ElementChildren() {
				onmatch := event.AttrValue("onmatch")
				if onmatch == "" {
					onmatch = "include"
				}
				if onmatch == "include" && len(event.ElementChildren()) == 0 {
					findings = append(findings, validate.Finding{Code: "ANL007", Severity: validate.Performance, Path: path, Line: event.Line, Message: "include rule has no conditions and logs the full event stream", Detail: event.Name})
				}
			}
		}
	}
	heavyEvents := map[string]string{
		"ImageLoad":       "ImageLoad can produce very high volume without tight includes/excludes.",
		"FileCreate":      "FileCreate can produce high volume on busy endpoints.",
		"FileDelete":      "FileDelete archives deleted content and can consume disk space.",
		"ClipboardChange": "ClipboardChange can create privacy exposure and noisy telemetry.",
		"DnsQuery":        "DnsQuery can be high volume in browser-heavy environments.",
		"NetworkConnect":  "NetworkConnect broad includes can be high volume.",
	}
	counts := map[string]int{}
	for _, c := range conditions {
		if c.Onmatch == "include" {
			counts[c.Event]++
		}
		if c.Op == "contains" && (c.Value == `c:\` || c.Value == `\` || len(c.Value) <= 2) {
			findings = append(findings, validate.Finding{Code: "ANL008", Severity: validate.Performance, Path: path, Line: c.Line, Message: "very broad contains condition may generate high volume", Detail: fmt.Sprintf("%s %s contains %q", c.Event, c.Field, c.Value)})
		}
	}
	for event, detail := range heavyEvents {
		if counts[event] > 50 {
			findings = append(findings, validate.Finding{Code: "ANL009", Severity: validate.Performance, Path: path, Message: "large include set on high-volume event", Detail: fmt.Sprintf("%s has %d include conditions. %s", event, counts[event], detail)})
		}
	}
	return findings
}
