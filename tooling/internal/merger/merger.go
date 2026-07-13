package merger

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

var EventOrder = []string{
	"ProcessCreate", "FileCreateTime", "NetworkConnect", "ProcessTerminate", "DriverLoad",
	"ImageLoad", "CreateRemoteThread", "RawAccessRead", "ProcessAccess", "FileCreate",
	"RegistryEvent", "FileCreateStreamHash", "PipeEvent", "WmiEvent", "DnsQuery",
	"FileDelete", "ClipboardChange", "ProcessTampering", "FileDeleteDetected",
	"FileBlockExecutable", "FileBlockShredding", "FileExecutableDetected",
}

var EventSet = func() map[string]bool {
	out := map[string]bool{}
	for _, e := range EventOrder {
		out[e] = true
	}
	return out
}()

type Options struct {
	Template             string
	PreserveComments     bool
	ForceGroupRelationOr bool
}

type InputFile struct {
	Path     string `json:"filepath"`
	Priority int    `json:"priority"`
}

type Result struct {
	Document *sysmonxml.Document
	Warnings []string
	Inputs   []string
}

func Merge(paths []string, opts Options) (*Result, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no input XML files")
	}
	var groups []*sysmonxml.Node
	maxSchema := ""
	var warnings []string
	for _, path := range paths {
		doc, err := sysmonxml.ParseFile(path, opts.PreserveComments)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if doc.Root.Name != "Sysmon" {
			return nil, fmt.Errorf("%s: root element must be Sysmon", path)
		}
		if schema := doc.Root.AttrValue("schemaversion"); compareSchema(schema, maxSchema) > 0 {
			maxSchema = schema
		}
		foundRuleGroup := false
		doc.Root.Walk(func(rg *sysmonxml.Node) {
			if rg.Name != "RuleGroup" {
				return
			}
			foundRuleGroup = true
			clone := rg.Clone()
			if opts.ForceGroupRelationOr {
				clone.SetAttr("groupRelation", "or")
			}
			// Preserve each RuleGroup as a semantic unit. Flattening groups by event
			// changes the meaning of groupRelation="and" and loses group names.
			groups = append(groups, clone)
		})
		if !foundRuleGroup {
			warnings = append(warnings, fmt.Sprintf("%s: no RuleGroup elements found", path))
		}
	}
	out, err := baseDocument(opts.Template, opts.PreserveComments)
	if err != nil {
		return nil, err
	}
	if maxSchema != "" {
		out.Root.SetAttr("schemaversion", maxSchema)
	}
	eventFiltering := out.Root.FirstChild("EventFiltering")
	if eventFiltering == nil {
		eventFiltering = sysmonxml.Element("EventFiltering", nil)
		out.Root.Children = append(out.Root.Children, eventFiltering)
	}
	eventFiltering.Children = nil
	eventFiltering.Children = append(eventFiltering.Children, groups...)
	return &Result{Document: out, Warnings: warnings, Inputs: paths}, nil
}

func baseDocument(template string, preserveComments bool) (*sysmonxml.Document, error) {
	if template != "" {
		return sysmonxml.ParseFile(template, preserveComments)
	}
	return sysmonxml.Parse([]byte(defaultTemplate), preserveComments)
}

const defaultTemplate = `<Sysmon schemaversion="4.90">
  <HashAlgorithms>*</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <DnsLookup>False</DnsLookup>
  <ArchiveDirectory>Sysmon</ArchiveDirectory>
  <EventFiltering/>
</Sysmon>`

func FindRuleFiles(basePath string) ([]string, error) {
	var out []string
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) == 0 || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		matches, err := filepath.Glob(filepath.Join(basePath, entry.Name(), "*.xml"))
		if err != nil {
			return nil, err
		}
		out = append(out, matches...)
	}
	sort.Strings(out)
	return out, nil
}

func ResolveLists(basePath string, initial []string, includeList, excludeList string) ([]string, []string, error) {
	paths := append([]string{}, initial...)
	var warnings []string
	if includeList != "" {
		paths = nil
		lines, err := readList(includeList)
		if err != nil {
			return nil, nil, err
		}
		for _, line := range lines {
			resolved, err := resolveEntry(basePath, line)
			if err != nil {
				warnings = append(warnings, err.Error())
				continue
			}
			paths = append(paths, resolved...)
		}
	}
	if excludeList != "" {
		lines, err := readList(excludeList)
		if err != nil {
			return nil, nil, err
		}
		excluded := map[string]bool{}
		for _, line := range lines {
			resolved, err := resolveEntry(basePath, line)
			if err != nil {
				warnings = append(warnings, err.Error())
				continue
			}
			for _, path := range resolved {
				excluded[clean(path)] = true
			}
		}
		var kept []string
		for _, path := range paths {
			if excluded[clean(path)] {
				warnings = append(warnings, fmt.Sprintf("path selected by include/input and exclude list: %s", path))
				continue
			}
			kept = append(kept, path)
		}
		paths = kept
	}
	for i, path := range paths {
		if !filepath.IsAbs(path) {
			paths[i] = filepath.Join(basePath, path)
		}
	}
	sort.Strings(paths)
	return dedupe(paths), warnings, nil
}

func resolveEntry(basePath, entry string) ([]string, error) {
	entry = strings.TrimSpace(strings.TrimLeft(entry, `\/`))
	if entry == "" || strings.HasPrefix(entry, "#") {
		return nil, nil
	}
	full := entry
	if !filepath.IsAbs(full) {
		full = filepath.Join(basePath, filepath.FromSlash(entry))
	}
	info, err := os.Stat(full)
	if err != nil {
		return nil, fmt.Errorf("referenced rule not found: %s", full)
	}
	if info.IsDir() {
		matches, err := filepath.Glob(filepath.Join(full, "*.xml"))
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)
		return matches, nil
	}
	return []string{full}, nil
}

func readList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

func ReadPriorityList(path, format string) ([]string, error) {
	if format == "" {
		format = strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var items []InputFile
	switch format {
	case "json":
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, err
		}
	case "csv", "tsv":
		reader := csv.NewReader(strings.NewReader(string(data)))
		if format == "tsv" {
			reader.Comma = '\t'
		}
		rows, err := reader.ReadAll()
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, nil
		}
		headers := map[string]int{}
		for i, h := range rows[0] {
			headers[strings.ToLower(strings.TrimSpace(h))] = i
		}
		fp, ok1 := headers["filepath"]
		pr, ok2 := headers["priority"]
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("priority list requires filepath and priority columns")
		}
		for _, row := range rows[1:] {
			if len(row) <= fp || len(row) <= pr {
				continue
			}
			priority, _ := strconv.Atoi(strings.TrimSpace(row[pr]))
			items = append(items, InputFile{Path: strings.TrimSpace(row[fp]), Priority: priority})
		}
	default:
		return nil, fmt.Errorf("unsupported priority list format %q", format)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Priority > items[j].Priority })
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Path)
	}
	return out, nil
}

func compareSchema(a, b string) int {
	parse := func(s string) []int {
		parts := strings.Split(s, ".")
		out := make([]int, len(parts))
		for i, part := range parts {
			out[i], _ = strconv.Atoi(part)
		}
		return out
	}
	aa, bb := parse(a), parse(b)
	for len(aa) < len(bb) {
		aa = append(aa, 0)
	}
	for len(bb) < len(aa) {
		bb = append(bb, 0)
	}
	for i := range aa {
		if aa[i] > bb[i] {
			return 1
		}
		if aa[i] < bb[i] {
			return -1
		}
	}
	return 0
}

func clean(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Clean(abs)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range in {
		if item == "" {
			continue
		}
		c := clean(item)
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, item)
	}
	return out
}
