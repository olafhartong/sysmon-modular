package generate

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

type KQLResult struct {
	Event      string
	Onmatch    string
	Conditions []Condition
	Warnings   []string
}

func FromKQLFile(path string) (*KQLResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromKQL(string(data)), nil
}

func FromKQL(query string) *KQLResult {
	table := firstMatch(`(?im)^\s*(Device[A-Za-z]+Events)\b`, query)
	event := eventForTable(table)
	var warnings []string
	if event == "ProcessCreate" && table == "" {
		warnings = append(warnings, "could not identify MDE table; defaulted to ProcessCreate")
	}
	conditions := extractKQLConditions(query, event)
	if len(conditions) == 0 {
		warnings = append(warnings, "no simple equality/contains conditions were translated")
	}
	return &KQLResult{Event: event, Onmatch: "include", Conditions: normalizeUniqueConditions(conditions), Warnings: warnings}
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

func extractKQLConditions(query, event string) []Condition {
	var conditions []Condition
	for _, m := range regexp.MustCompile(`(?i)\b(FileName|InitiatingProcessFileName|ImageFileName|ProcessName)\s*(?:==|=~)\s*["']([^"']+)["']`).FindAllStringSubmatch(query, -1) {
		if strings.HasSuffix(strings.ToLower(m[2]), ".exe") {
			conditions = append(conditions, Condition{Field: imageFieldForEvent(event), Operator: "image", Value: m[2]})
		}
	}
	for _, m := range regexp.MustCompile(`(?is)\b(FileName|InitiatingProcessFileName|ImageFileName|ProcessName)\s+in~?\s*\(([^)]*)\)`).FindAllStringSubmatch(query, -1) {
		for _, value := range quotedValues(m[2]) {
			if strings.HasSuffix(strings.ToLower(value), ".exe") {
				conditions = append(conditions, Condition{Field: imageFieldForEvent(event), Operator: "image", Value: value})
			}
		}
	}
	for _, m := range regexp.MustCompile(`(?i)\b(ProcessCommandLine|InitiatingProcessCommandLine|CommandLine)\s+(?:contains|has)\s*["']([^"']+)["']`).FindAllStringSubmatch(query, -1) {
		conditions = append(conditions, Condition{Field: "CommandLine", Operator: "contains", Value: m[2]})
	}
	for _, m := range regexp.MustCompile(`(?is)\b(ProcessCommandLine|InitiatingProcessCommandLine|CommandLine)\s+(?:has_any|contains_any)\s*\(([^)]*)\)`).FindAllStringSubmatch(query, -1) {
		for _, value := range quotedValues(m[2]) {
			conditions = append(conditions, Condition{Field: "CommandLine", Operator: "contains", Value: value})
		}
	}
	for _, m := range regexp.MustCompile(`(?i)\b(RemotePort|LocalPort|DestinationPort)\s*(?:==|=~)\s*([0-9]+)`).FindAllStringSubmatch(query, -1) {
		conditions = append(conditions, Condition{Field: "DestinationPort", Operator: "is", Value: m[2]})
	}
	for _, m := range regexp.MustCompile(`(?i)\b(RemoteUrl|RemoteIP|DestinationUrl|DestinationIpAddress)\s+(?:contains|has|==|=~)\s*["']([^"']+)["']`).FindAllStringSubmatch(query, -1) {
		field := "DestinationHostname"
		if strings.Contains(strings.ToLower(m[1]), "ip") {
			field = "DestinationIp"
		}
		conditions = append(conditions, Condition{Field: field, Operator: operatorForKQL(m[0]), Value: m[2]})
	}
	for _, m := range regexp.MustCompile(`(?i)\b(FolderPath|FileName)\s+(?:contains|has|==|=~)\s*["']([^"']+)["']`).FindAllStringSubmatch(query, -1) {
		if event == "FileCreate" {
			conditions = append(conditions, Condition{Field: "TargetFilename", Operator: operatorForKQL(m[0]), Value: m[2]})
		}
	}
	for _, m := range regexp.MustCompile(`(?i)\b(RegistryKey|RegistryValueName|RegistryValueData)\s+(?:contains|has|==|=~)\s*["']([^"']+)["']`).FindAllStringSubmatch(query, -1) {
		if event == "RegistryEvent" {
			conditions = append(conditions, Condition{Field: "TargetObject", Operator: operatorForKQL(m[0]), Value: m[2]})
		}
	}
	return conditions
}

func imageFieldForEvent(event string) string {
	if event == "NetworkConnect" || event == "ProcessCreate" {
		return "Image"
	}
	return "Image"
}

func operatorForKQL(expr string) string {
	if strings.Contains(expr, "==") || strings.Contains(expr, "=~") {
		return "is"
	}
	return "contains"
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
	result := FromKQL(query)
	if len(result.Conditions) == 0 {
		return nil, result.Warnings, fmt.Errorf("no translatable KQL conditions")
	}
	return Module(result.Event, result.Onmatch, result.Conditions, "4.90"), result.Warnings, nil
}
