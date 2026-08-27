package generate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type KQLRule struct {
	Name       string
	Query      string
	SourcePath string
	Platform   string
	Section    string
	Ordinal    int
}

type KQLAnalyzerOptions struct {
	URL                   string
	Environment           string
	ParserProfile         string
	StrictMode            bool
	CheckNRTCompatibility bool
	Timeout               time.Duration
	HTTPClient            *http.Client
}

type KQLDirectoryOptions struct {
	InputDir        string
	OutputDir       string
	Platform        string
	Analyzer        *KQLAnalyzerOptions
	ExistingModules []string
	AllowLossy      bool
}

type KQLBatchStats struct {
	FilesScanned        int
	QueriesFound        int
	QueriesSelected     int
	QueriesGenerated    int
	QueriesSkipped      int
	QueriesLossy        int
	QueriesAnalyzed     int
	AnalyzerFailures    int
	ConditionsAnnotated int
}

type KQLBatchResult struct {
	Files    []string
	Warnings []string
	Stats    KQLBatchStats
}

func GenerateKQLDirectory(options KQLDirectoryOptions) (*KQLBatchResult, error) {
	if strings.TrimSpace(options.InputDir) == "" || strings.TrimSpace(options.OutputDir) == "" {
		return nil, fmt.Errorf("KQL directory conversion requires input and output directories")
	}
	platform, err := normalizeKQLPlatform(options.Platform)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(options.InputDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("KQL input is not a directory: %s", options.InputDir)
	}
	rules, scanned, err := discoverKQLRules(options.InputDir)
	if err != nil {
		return nil, err
	}
	existing, err := loadExistingConditionSources(options.ExistingModules)
	if err != nil {
		return nil, err
	}
	result := &KQLBatchResult{Stats: KQLBatchStats{FilesScanned: scanned, QueriesFound: len(rules)}}
	selected := make([]KQLRule, 0, len(rules))
	for _, rule := range rules {
		if kqlPlatformSelected(rule.Platform, platform) {
			selected = append(selected, rule)
		}
	}
	result.Stats.QueriesSelected = len(selected)

	usedOutputPaths := map[string]int{}
	for _, rule := range selected {
		label := fmt.Sprintf("%s query %d", rule.SourcePath, rule.Ordinal)
		if options.Analyzer != nil {
			result.Stats.QueriesAnalyzed++
			if err := analyzeKQL(rule.Query, *options.Analyzer); err != nil {
				result.Stats.AnalyzerFailures++
				result.Warnings = append(result.Warnings, label+": analyzer: "+err.Error())
			}
		}

		converted := FromKQL(rule.Query)
		if !supportedKQLTable(converted.Table) {
			result.Stats.QueriesSkipped++
			result.Warnings = append(result.Warnings, label+": skipped unsupported table "+emptyLabel(converted.Table, "unknown"))
			continue
		}
		for _, warning := range converted.Warnings {
			result.Warnings = append(result.Warnings, label+": "+warning)
		}
		if len(converted.LossyReasons) > 0 {
			result.Stats.QueriesLossy++
			if !options.AllowLossy {
				result.Stats.QueriesSkipped++
				result.Warnings = append(result.Warnings, label+": skipped lossy conversion: "+strings.Join(converted.LossyReasons, "; ")+"; use --allow-lossy to opt in")
				continue
			}
			result.Warnings = append(result.Warnings, label+": converted lossy query because --allow-lossy was supplied: "+strings.Join(converted.LossyReasons, "; "))
		}
		if len(converted.Rules) == 0 {
			result.Stats.QueriesSkipped++
			continue
		}

		ruleName := strings.TrimSpace(rule.Name)
		if rule.Section != "" && !strings.EqualFold(rule.Section, rule.Name) {
			ruleName += " (" + rule.Section + ")"
		}
		rules := append([]RuleSpec(nil), converted.Rules...)
		for i := range rules {
			rules[i].Name = ruleName
			rules[i].Conditions, result.Stats.ConditionsAnnotated = annotateExistingConditions(
				rules[i].Conditions, converted.Event, converted.Onmatch, existing, result.Stats.ConditionsAnnotated,
			)
		}
		doc := ModuleFromRules(converted.Event, converted.Onmatch, rules, "4.90")
		base := kqlOutputBase(rule)
		rel, relErr := filepath.Rel(options.InputDir, rule.SourcePath)
		if relErr != nil {
			rel = filepath.Base(rule.SourcePath)
		}
		outputBase := filepath.Join(options.OutputDir, filepath.Dir(rel), base)
		outputKey := strings.ToLower(filepath.Clean(outputBase))
		usedOutputPaths[outputKey]++
		if usedOutputPaths[outputKey] > 1 {
			outputBase += fmt.Sprintf("-%d", usedOutputPaths[outputKey])
		}
		outputPath := outputBase + ".xml"
		if err := validateGeneratedModule(doc, outputPath); err != nil {
			result.Stats.QueriesSkipped++
			result.Warnings = append(result.Warnings, label+": "+err.Error())
			continue
		}
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(outputPath, doc.Bytes(), 0o644); err != nil {
			return nil, err
		}
		result.Files = append(result.Files, outputPath)
		result.Stats.QueriesGenerated++
	}
	sort.Strings(result.Files)
	result.Warnings = dedupeStrings(result.Warnings)
	return result, nil
}

func discoverKQLRules(root string) ([]KQLRule, int, error) {
	var rules []KQLRule
	scanned := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
			return nil
		}
		scanned++
		ext := strings.ToLower(filepath.Ext(path))
		var found []KQLRule
		switch ext {
		case ".md", ".markdown":
			found = extractMarkdownKQL(string(data), path)
		default:
			query := strings.TrimSpace(string(data))
			if looksLikeKQL(query) {
				found = []KQLRule{{Name: filenameTitle(path), Query: query, SourcePath: path, Platform: "unknown", Ordinal: 1}}
			}
		}
		rules = append(rules, found...)
		return nil
	})
	if err != nil {
		return nil, scanned, err
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].SourcePath == rules[j].SourcePath {
			return rules[i].Ordinal < rules[j].Ordinal
		}
		return rules[i].SourcePath < rules[j].SourcePath
	})
	return rules, scanned, nil
}

func extractMarkdownKQL(content, path string) []KQLRule {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	title := filenameTitle(path)
	section := ""
	inFence := false
	fenceLanguage := ""
	fenceSection := ""
	var block strings.Builder
	var rules []KQLRule
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inFence {
			if heading := markdownHeading(trimmed); heading != "" {
				if strings.HasPrefix(trimmed, "# ") && title == filenameTitle(path) {
					title = heading
				}
				section = heading
			}
			if language, ok := markdownFenceStart(trimmed); ok {
				inFence = true
				fenceLanguage = language
				fenceSection = section
				block.Reset()
			}
			continue
		}
		if strings.HasPrefix(trimmed, "```") {
			query := strings.TrimSpace(block.String())
			if isKQLFence(fenceLanguage, fenceSection, query) {
				rules = append(rules, KQLRule{
					Name:       title,
					Query:      query,
					SourcePath: path,
					Platform:   kqlPlatformFromHeading(fenceSection),
					Section:    fenceSection,
					Ordinal:    len(rules) + 1,
				})
			}
			inFence = false
			continue
		}
		block.WriteString(line)
		block.WriteByte('\n')
	}
	return rules
}

func markdownHeading(line string) string {
	if !strings.HasPrefix(line, "#") {
		return ""
	}
	return strings.TrimSpace(strings.TrimLeft(line, "#"))
}

func markdownFenceStart(line string) (string, bool) {
	if !strings.HasPrefix(line, "```") {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "```"))), true
}

func isKQLFence(language, section, query string) bool {
	if query == "" {
		return false
	}
	fields := strings.Fields(language)
	language = ""
	if len(fields) > 0 {
		language = fields[0]
	}
	if language == "kql" || language == "kusto" {
		return true
	}
	if language != "" {
		return false
	}
	return kqlPlatformFromHeading(section) != "unknown" && looksLikeKQL(query)
}

func looksLikeKQL(query string) bool {
	if !strings.Contains(query, "|") {
		return false
	}
	return regexp.MustCompile(`(?im)^\s*[A-Za-z][A-Za-z0-9_]*(?:\s*\([^\n]*\))?\s*(?:\||$)`).MatchString(query)
}

func kqlPlatformFromHeading(heading string) string {
	lower := strings.ToLower(heading)
	defender := strings.Contains(lower, "defender") || strings.Contains(lower, "mde") || strings.Contains(lower, "xdr")
	sentinel := strings.Contains(lower, "sentinel")
	if defender && sentinel {
		return "both"
	}
	if defender {
		return "defender"
	}
	if sentinel {
		return "sentinel"
	}
	return "unknown"
}

func normalizeKQLPlatform(platform string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "", "defender", "defender-xdr", "mde", "xdr":
		return "defender", nil
	case "sentinel":
		return "sentinel", nil
	case "all":
		return "all", nil
	default:
		return "", fmt.Errorf("unsupported KQL platform %q: use defender, sentinel, or all", platform)
	}
}

func kqlPlatformSelected(rulePlatform, selected string) bool {
	return selected == "all" || rulePlatform == "unknown" || rulePlatform == "both" || rulePlatform == selected
}

func supportedKQLTable(table string) bool {
	switch strings.ToLower(table) {
	case "deviceprocessevents", "devicenetworkevents", "devicefileevents", "deviceregistryevents", "deviceimageloadevents":
		return true
	default:
		return false
	}
}

func kqlOutputBase(rule KQLRule) string {
	base := strings.TrimSuffix(filepath.Base(rule.SourcePath), filepath.Ext(rule.SourcePath))
	platform := rule.Platform
	if platform == "" || platform == "unknown" {
		platform = "kql"
	}
	return sanitizeKQLFilename(base) + "__" + sanitizeKQLFilename(platform)
}

func sanitizeKQLFilename(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = regexp.MustCompile(`[^a-z0-9._-]+`).ReplaceAllString(value, "-")
	value = strings.Trim(value, "-._")
	if value == "" {
		return "query"
	}
	return value
}

func filenameTitle(path string) string {
	return strings.TrimSpace(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
}

func analyzeKQL(query string, options KQLAnalyzerOptions) error {
	if strings.TrimSpace(options.URL) == "" {
		return fmt.Errorf("analyzer URL is empty")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	payload := map[string]any{
		"environment":             emptyLabel(options.Environment, "m365_with_sentinel"),
		"parser_profile":          emptyLabel(options.ParserProfile, "current"),
		"strict_mode":             options.StrictMode,
		"check_nrt_compatibility": options.CheckNRTCompatibility,
		"query":                   query,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, options.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTP %s: %s", response.Status, truncateKQLMessage(string(responseBody), 500))
	}
	return nil
}

func AnalyzeKQL(query string, options KQLAnalyzerOptions) error {
	return analyzeKQL(query, options)
}

func truncateKQLMessage(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func emptyLabel(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
