package analyze

import (
	"encoding/csv"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	_ "embed"

	"github.com/olafhartong/sysmon-modular/tooling/internal/expression"
	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
	"github.com/olafhartong/sysmon-modular/tooling/internal/validate"
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
	config := expression.FromXML(doc)
	conditions := collectConditions(config)
	findings = append(findings, conflictFindings(path, config.Events)...)
	findings = append(findings, imagePathRecommendations(path, conditions)...)
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

func collectConditions(config expression.Config) []condition {
	var out []condition
	for _, event := range config.Events {
		for _, leaf := range event.Expression.Conditions() {
			out = append(out, condition{
				Event: event.Name, Onmatch: event.Onmatch, Field: leaf.Field,
				Op: strings.ToLower(leaf.Operator), Value: strings.ToLower(strings.TrimSpace(leaf.Value)), Line: leaf.Line,
			})
		}
	}
	return out
}

func conflictFindings(path string, events []expression.Event) []validate.Finding {
	seenInclude := map[string]expression.Event{}
	seenExclude := map[string]expression.Event{}
	var findings []validate.Finding
	for _, event := range events {
		key := strings.ToLower(event.Name) + "\x00" + event.Expression.Canonical()
		switch event.Onmatch {
		case "include":
			seenInclude[key] = event
		case "exclude":
			seenExclude[key] = event
		}
	}
	for key, inc := range seenInclude {
		if _, ok := seenExclude[key]; ok {
			findings = append(findings, validate.Finding{Code: "ANL005", Severity: validate.Warning, Path: path, Line: inc.Line, Message: "same condition appears in include and exclude rules", Detail: inc.Name + " " + inc.Expression.Canonical()})
		}
	}
	return findings
}

func imagePathRecommendations(path string, conditions []condition) []validate.Finding {
	var findings []validate.Finding
	seen := map[string]bool{}
	for _, c := range conditions {
		if c.Onmatch != "exclude" || !imagePathField(c.Field) || !imageNameOnlyOperator(c.Op) {
			continue
		}
		for _, base := range imageNameCandidates(c.Value) {
			paths, ok := knownImagePaths[base]
			key := c.Event + "|" + c.Onmatch + "|" + c.Field + "|" + base
			if !ok || seen[key] {
				continue
			}
			seen[key] = true
			detail := fmt.Sprintf("%s %s %s=%s; consider full path variants such as %s", c.Event, c.Onmatch, c.Field, base, strings.Join(paths, " or "))
			detail = fmt.Sprintf("%s; for exclusions, prefer full paths where possible to avoid suppressing lookalike binaries outside their expected locations", detail)
			findings = append(findings, validate.Finding{
				Code:     "ANL006",
				Severity: validate.Recommendation,
				Path:     path,
				Line:     c.Line,
				Message:  "exclude rule matches a known binary by image name only",
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
