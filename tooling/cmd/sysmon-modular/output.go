package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/validate"
)

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiOrange  = "\x1b[38;5;208m"
	ansiBlue    = "\x1b[34m"
	ansiMagenta = "\x1b[35m"
	ansiCyan    = "\x1b[36m"
)

func useColor() bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled {
		return false
	}
	if forced := os.Getenv("FORCE_COLOR"); forced != "" && forced != "0" {
		return true
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := os.Stderr.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func paint(style, value string) string {
	if !useColor() {
		return value
	}
	return style + value + ansiReset
}

func findingStyle(severity validate.Severity) string {
	switch severity {
	case validate.Error:
		return ansiBold + ansiRed
	case validate.Warning:
		return ansiBold + ansiYellow
	case validate.Recommendation:
		return ansiBold + ansiMagenta
	case validate.Performance:
		return ansiBold + ansiCyan
	default:
		return ansiBold
	}
}

type findingOutputOptions struct {
	ShowSource   bool
	ShowLocation bool
	ShowPath     bool
}

func printFindings(findings []validate.Finding, options findingOutputOptions) {
	type displayedFinding struct {
		finding validate.Finding
		count   int
	}
	var displayed []displayedFinding
	indexes := map[string]int{}
	for _, finding := range findings {
		lineKey := ""
		if options.ShowLocation || options.ShowSource {
			lineKey = strconv.Itoa(finding.Line)
		}
		key := strings.Join([]string{finding.Path, finding.Code, string(finding.Severity), finding.Message, finding.Detail, lineKey}, "\x00")
		if index, exists := indexes[key]; exists {
			displayed[index].count++
			continue
		}
		indexes[key] = len(displayed)
		displayed = append(displayed, displayedFinding{finding: finding, count: 1})
	}

	lastPath := ""
	for _, item := range displayed {
		finding := item.finding
		if !options.ShowLocation && finding.Path != lastPath {
			if lastPath != "" {
				fmt.Fprintln(os.Stderr)
			}
			fmt.Fprintln(os.Stderr, paint(ansiBold+ansiBlue, displayPath(finding.Path)))
			lastPath = finding.Path
		}

		label := paint(findingStyle(finding.Severity), "["+finding.Code+"]")
		occurrences := ""
		if item.count > 1 {
			occurrences = paint(ansiBold+ansiYellow, fmt.Sprintf(" ×%d", item.count))
		}
		location := ""
		if options.ShowLocation {
			location = findingLocation(finding, options.ShowPath)
			if location != "" {
				location = paint(ansiBold+ansiCyan, location) + ": "
			}
		}
		fmt.Fprintf(os.Stderr, "  %s %s%s%s\n", label, location, finding.Message, occurrences)
		for _, line := range formatDetail(finding.Detail, outputWidth()-8) {
			fmt.Fprintf(os.Stderr, "  %s %s\n", paint(ansiDim, "↳"), paint(ansiDim, line))
		}
		if options.ShowSource {
			printSourceLine(finding)
		}
	}
}

func findingLocation(finding validate.Finding, showPath bool) string {
	location := ""
	if showPath {
		location = displayPath(finding.Path)
	}
	// Merged nodes retain input line numbers, which do not describe the output.
	if finding.Line > 0 && finding.Path != "merged" {
		if location != "" {
			return fmt.Sprintf("%s:%d", location, finding.Line)
		}
		return fmt.Sprintf("line %d", finding.Line)
	}
	return location
}

func printSourceLine(finding validate.Finding) {
	if finding.Line <= 0 || finding.Path == "" || finding.Path == "merged" {
		return
	}
	data, err := os.ReadFile(finding.Path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	if finding.Line > len(lines) {
		return
	}
	source := strings.TrimSpace(strings.TrimSuffix(sourceLineWithoutComments(lines, finding.Line-1), "\r"))
	if source == "" {
		return
	}
	prefix := fmt.Sprintf("%d │", finding.Line)
	fmt.Fprintf(os.Stderr, "    %s %s\n", paint(ansiBold+ansiCyan, prefix), source)
}

func sourceLineWithoutComments(lines []string, target int) string {
	inComment := false
	for index := 0; index <= target && index < len(lines); index++ {
		line := lines[index]
		var visible strings.Builder
		for len(line) > 0 {
			if inComment {
				end := strings.Index(line, "-->")
				if end < 0 {
					line = ""
					continue
				}
				line = line[end+3:]
				inComment = false
				continue
			}
			start := strings.Index(line, "<!--")
			if start < 0 {
				visible.WriteString(line)
				line = ""
				continue
			}
			visible.WriteString(line[:start])
			line = line[start+4:]
			inComment = true
		}
		if index == target {
			return visible.String()
		}
	}
	return ""
}

func displayPath(path string) string {
	if strings.HasPrefix(path, "../") {
		return strings.TrimPrefix(path, "../")
	}
	return path
}

func printFindingSummary(findings []validate.Finding, files int) {
	if len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "%s %d file(s), no findings\n", paint(ansiBold+ansiGreen, "✓ VALID"), files)
		return
	}
	counts := map[validate.Severity]int{}
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "%s %d file(s) · ", paint(ansiBold, "SUMMARY"), files)
	parts := []string{}
	for _, severity := range []validate.Severity{validate.Error, validate.Warning, validate.Recommendation, validate.Performance} {
		if count := counts[severity]; count > 0 {
			text := fmt.Sprintf("%d %s", count, severity)
			if count != 1 {
				text += "s"
			}
			parts = append(parts, paint(findingStyle(severity), text))
		}
	}
	fmt.Fprintln(os.Stderr, strings.Join(parts, " · "))
}

func formatDetail(detail string, width int) []string {
	if strings.TrimSpace(detail) == "" {
		return nil
	}
	var lines []string
	for _, part := range strings.Split(detail, "; ") {
		lines = append(lines, wrapText(strings.TrimSpace(part), width)...)
	}
	return lines
}

func wrapText(value string, width int) []string {
	if width < 40 {
		width = 40
	}
	words := strings.Fields(value)
	if len(words) == 0 {
		return nil
	}
	lines := []string{words[0]}
	for _, word := range words[1:] {
		last := len(lines) - 1
		if len(lines[last])+1+len(word) <= width {
			lines[last] += " " + word
		} else {
			lines = append(lines, word)
		}
	}
	return lines
}

func outputWidth() int {
	if columns, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && columns >= 60 {
		return columns
	}
	return 120
}
