package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/generate"
	"github.com/olafhartong/sysmon-modular/tooling/internal/mitre"
)

func TestRunDispatchesEveryCommandAndClassifiesErrors(t *testing.T) {
	for _, command := range []string{
		"merge", "validate", "verify", "fix-mitre", "analyze", "generate-kql",
		"generate-mde", "generate-mde-unfiltered", "generate-mde-inverse",
		"list-rules", "diff", "coverage",
	} {
		t.Run(command+" help", func(t *testing.T) {
			var code int
			_, stderr := captureCommandOutput(t, func() { code = run([]string{command, "--help"}) })
			if code != exitOK || !strings.Contains(stderr, "Usage of") {
				t.Fatalf("%s --help returned code=%d stderr=%q", command, code, stderr)
			}
		})
	}

	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{name: "missing command", want: exitUsage},
		{name: "top-level help", args: []string{"help"}, want: exitOK},
		{name: "unknown command", args: []string{"unknown"}, want: exitUsage},
		{name: "command usage error", args: []string{"coverage"}, want: exitUsage},
		{name: "invalid input", args: []string{"validate", "--sysmon-version", "nope", "--path", "missing.xml"}, want: exitInvalidInput},
		{name: "internal error", args: []string{"generate-mde", "--mde-config", "missing.json"}, want: exitInternal},
	} {
		t.Run(test.name, func(t *testing.T) {
			var code int
			_, _ = captureCommandOutput(t, func() { code = run(test.args) })
			if code != test.want {
				t.Fatalf("run(%v) returned %d, want %d", test.args, code, test.want)
			}
		})
	}
}

func TestRunCoverageSupportsEveryFormatAndRejectsBadInput(t *testing.T) {
	base := t.TempDir()
	moduleDir := filepath.Join(base, "1_process_creation")
	mustMkdirAll(t, moduleDir)
	module := filepath.Join(moduleDir, "include_test.xml")
	writeCLIFile(t, module, cliConfig("cmd.exe", `name="technique_id=T1059.001,technique_name=PowerShell"`))

	formats := map[string]string{
		"text":      "filters: include=1 exclude=0 modules=1 techniques=1",
		"json":      `"id": "T1059.001"`,
		"csv":       "technique,T1059.001,PowerShell",
		"navigator": `"techniqueID": "T1059.001"`,
	}
	for format, expected := range formats {
		t.Run(format, func(t *testing.T) {
			output := filepath.Join(base, "coverage-"+format+".out")
			if err := runCoverage([]string{"--all", "--base-path", base, "--format", format, "--output", output}); err != nil {
				t.Fatal(err)
			}
			data := readCLIFile(t, output)
			if !strings.Contains(data, expected) {
				t.Fatalf("%s output does not contain %q:\n%s", format, expected, data)
			}
			if format == "json" || format == "navigator" {
				var parsed any
				if err := json.Unmarshal([]byte(data), &parsed); err != nil {
					t.Fatalf("%s output is not JSON: %v", format, err)
				}
			}
		})
	}

	if err := runCoverage(nil); err == nil || !strings.Contains(err.Error(), "requires --path or --all") {
		t.Fatalf("expected missing-input error, got %v", err)
	}
	if err := runCoverage([]string{"--path", module, "--base-path", base, "--format", "yaml"}); err == nil || !strings.Contains(err.Error(), "unsupported coverage format") {
		t.Fatalf("expected unsupported-format error, got %v", err)
	}
	broken := filepath.Join(base, "broken.xml")
	writeCLIFile(t, broken, "<Sysmon>")
	if err := runCoverage([]string{"--path", broken}); err == nil || !strings.Contains(err.Error(), broken) {
		t.Fatalf("expected parse error for %s, got %v", broken, err)
	}
}

func TestRunDiffSupportsTextAndJSONAndReportsInputErrors(t *testing.T) {
	dir := t.TempDir()
	before := filepath.Join(dir, "before.xml")
	after := filepath.Join(dir, "after.xml")
	writeCLIFile(t, before, cliConfig("cmd.exe", `name="technique_id=T1059.001,technique_name=PowerShell"`))
	writeCLIFile(t, after, cliConfig("powershell.exe", `name="technique_id=T1105,technique_name=Ingress Tool Transfer"`))

	textOutput := filepath.Join(dir, "diff.txt")
	if err := runDiff([]string{"--before", before, "--after", after, "--output", textOutput}); err != nil {
		t.Fatal(err)
	}
	textDiff := readCLIFile(t, textOutput)
	for _, expected := range []string{"expression-added", "expression-removed", "technique-added", "technique-removed"} {
		if !strings.Contains(textDiff, expected) {
			t.Fatalf("text diff is missing %q:\n%s", expected, textDiff)
		}
	}

	jsonOutput := filepath.Join(dir, "diff.json")
	if err := runDiff([]string{"--before", before, "--after", after, "--format", "json", "--output", jsonOutput}); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Changes []any `json:"changes"`
	}
	if err := json.Unmarshal([]byte(readCLIFile(t, jsonOutput)), &parsed); err != nil || len(parsed.Changes) != 4 {
		t.Fatalf("unexpected JSON diff: changes=%d err=%v", len(parsed.Changes), err)
	}

	unchanged := filepath.Join(dir, "unchanged.txt")
	if err := runDiff([]string{"--before", before, "--after", before, "--output", unchanged}); err != nil {
		t.Fatal(err)
	}
	if got := readCLIFile(t, unchanged); got != "no semantic changes\n" {
		t.Fatalf("unexpected unchanged diff: %q", got)
	}

	for _, test := range []struct {
		name string
		args []string
		text string
	}{
		{name: "missing paths", text: "requires --before and --after"},
		{name: "bad format", args: []string{"--before", before, "--after", after, "--format", "yaml"}, text: "unsupported diff format"},
		{name: "missing before", args: []string{"--before", filepath.Join(dir, "missing.xml"), "--after", after}, text: "read before config"},
		{name: "missing after", args: []string{"--before", before, "--after", filepath.Join(dir, "missing.xml")}, text: "read after config"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := runDiff(test.args); err == nil || !strings.Contains(err.Error(), test.text) {
				t.Fatalf("expected %q error, got %v", test.text, err)
			}
		})
	}
}

func TestRunAnalyzeCoversCleanWarningAndInvalidConfigurations(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.xml")
	writeCLIFile(t, clean, cliConfig("cmd.exe", ""))
	var cleanErr error
	_, cleanOutput := captureCommandOutput(t, func() { cleanErr = runAnalyze([]string{"--config", clean}) })
	if cleanErr != nil || !strings.Contains(cleanOutput, "no findings") {
		t.Fatalf("clean analysis returned err=%v output=%q", cleanErr, cleanOutput)
	}

	warning := filepath.Join(dir, "warning.xml")
	writeCLIFile(t, warning, `<Sysmon schemaversion="4.90">
  <HashAlgorithms>*</HashAlgorithms>
  <DnsLookup>true</DnsLookup>
  <EventFiltering><RuleGroup groupRelation="or"><ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image></ProcessCreate></RuleGroup></EventFiltering>
</Sysmon>`)
	var warningErr error
	_, warningOutput := captureCommandOutput(t, func() { warningErr = runAnalyze([]string{"--config", warning, "--verbose"}) })
	if warningErr != nil || !strings.Contains(warningOutput, "ANL003") || !strings.Contains(warningOutput, "3 │") {
		t.Fatalf("warning analysis returned err=%v output=%q", warningErr, warningOutput)
	}

	invalid := filepath.Join(dir, "invalid.xml")
	writeCLIFile(t, invalid, `<Sysmon schemaversion="4.90"><HashAlgorithms>*</HashAlgorithms><EventFiltering><UnknownEvent onmatch="include"/></EventFiltering></Sysmon>`)
	var invalidErr error
	_, invalidOutput := captureCommandOutput(t, func() { invalidErr = runAnalyze([]string{"--config", invalid}) })
	if invalidErr == nil || !strings.Contains(invalidErr.Error(), "invalid configuration") || !strings.Contains(invalidOutput, "SYS102") {
		t.Fatalf("invalid analysis returned err=%v output=%q", invalidErr, invalidOutput)
	}

	if err := runAnalyze(nil); err == nil || !strings.Contains(err.Error(), "provide --config") {
		t.Fatalf("expected missing-config error, got %v", err)
	}
	broken := filepath.Join(dir, "broken.xml")
	writeCLIFile(t, broken, "<Sysmon>")
	if err := runAnalyze([]string{"--config", broken}); err == nil {
		t.Fatal("expected malformed XML error")
	}
}

func TestRunFixMITREDryRunApplyAndDiscoveryModes(t *testing.T) {
	base := t.TempDir()
	moduleDir := filepath.Join(base, "1_process_creation")
	mustMkdirAll(t, moduleDir)
	module := filepath.Join(moduleDir, "include_mitre.xml")
	stale := cliConfig("bitsadmin.exe", `name="technique_id=T1105,technique_name=Remote File Copy"`)
	writeCLIFile(t, module, stale)

	if err := runFixMITRE([]string{"--path", module, "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	if got := readCLIFile(t, module); got != stale {
		t.Fatal("dry-run changed the source file")
	}
	if err := runFixMITRE([]string{"--path", module, "--yes"}); err != nil {
		t.Fatal(err)
	}
	if got := readCLIFile(t, module); !strings.Contains(got, "technique_name=Ingress Tool Transfer") {
		t.Fatalf("MITRE fix was not applied:\n%s", got)
	}
	if err := runFixMITRE([]string{"--all", "--base-path", base, "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	if err := runFixMITRE([]string{"--all-xml", "--base-path", base, "--dry-run"}); err != nil {
		t.Fatal(err)
	}

	broken := filepath.Join(base, "broken.xml")
	writeCLIFile(t, broken, `<Sysmon><EventFiltering><RuleGroup><ProcessCreate><Image name="technique_id=T,technique_name=">bad.exe</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`)
	if err := runFixMITRE([]string{"--path", broken, "--dry-run"}); err == nil || !strings.Contains(err.Error(), "manual fixes") {
		t.Fatalf("expected unfixed metadata error, got %v", err)
	}
}

func TestMITREReviewerDecisions(t *testing.T) {
	change := mitre.Change{Path: "module.xml", Line: 12, Before: "old", After: "new"}
	for _, test := range []struct {
		name       string
		input      string
		want       bool
		approveAll bool
		quit       bool
	}{
		{name: "yes", input: "yes\n", want: true},
		{name: "no after invalid answer", input: "maybe\nno\n", want: false},
		{name: "all", input: "all\n", want: true, approveAll: true},
		{name: "quit", input: "quit\n", want: false, quit: true},
		{name: "closed input applies all", want: true, approveAll: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reviewer := &mitreReviewer{reader: bufio.NewReader(strings.NewReader(test.input))}
			var got bool
			_, _ = captureCommandOutput(t, func() { got = reviewer.approve(change) })
			if got != test.want || reviewer.approveAll != test.approveAll || reviewer.quit != test.quit {
				t.Fatalf("approve returned %v, approveAll=%v, quit=%v", got, reviewer.approveAll, reviewer.quit)
			}
			if reviewer.approveAll && !reviewer.approve(change) {
				t.Fatal("approveAll did not approve the next change")
			}
			if reviewer.quit && reviewer.approve(change) {
				t.Fatal("quit reviewer approved another change")
			}
		})
	}
}

func TestRunValidateAndDiscoveryInputModes(t *testing.T) {
	base := t.TempDir()
	moduleDir := filepath.Join(base, "1_process_creation")
	mustMkdirAll(t, moduleDir)
	module := filepath.Join(moduleDir, "include_test.xml")
	writeCLIFile(t, module, cliConfig("cmd.exe", ""))
	templateDir := filepath.Join(base, "templates")
	mustMkdirAll(t, templateDir)
	writeCLIFile(t, filepath.Join(templateDir, "template.XML"), cliConfig("template.exe", ""))

	for _, args := range [][]string{
		{"--all", "--base-path", base, "--mitre=false"},
		{"--all-xml", "--base-path", base, "--mitre=false"},
		{"--path", module, "--mitre=false", "--sysmon-version", "15.21"},
	} {
		if err := runValidate(args); err != nil {
			t.Fatalf("runValidate(%v): %v", args, err)
		}
	}
	if err := runValidate([]string{"--path", moduleDir}); err == nil || !strings.Contains(err.Error(), "expects an XML file") {
		t.Fatalf("expected directory error, got %v", err)
	}
	if err := runValidate([]string{"--all", "--base-path", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "no Sysmon module") {
		t.Fatalf("expected empty-discovery error, got %v", err)
	}
	for _, args := range [][]string{
		{"--path", module, "--unsupported", "drop"},
		{"--path", module, "--unsupported", "exclude"},
		{"--path", module, "--sysmon-version", "99"},
	} {
		if err := runValidate(args); err == nil {
			t.Fatalf("expected invalid compatibility flags for %v", args)
		}
	}
}

func TestRunMergePriorityListAndValidationFailures(t *testing.T) {
	dir := t.TempDir()
	writeCLIFile(t, filepath.Join(dir, "first.xml"), cliConfig("first.exe", ""))
	writeCLIFile(t, filepath.Join(dir, "second.xml"), cliConfig("second.exe", ""))
	priority := filepath.Join(dir, "priority.csv")
	writeCLIFile(t, priority, "filepath,priority\nsecond.xml,20\nfirst.xml,10\n")
	output := filepath.Join(dir, "merged.xml")
	if err := runMerge([]string{
		"--base-path", dir, "--file-list", priority, "--output", output,
		"--sysmon-version=", "--schema-validate=false",
	}); err != nil {
		t.Fatal(err)
	}
	merged := readCLIFile(t, output)
	if first, second := strings.Index(merged, "first.exe"), strings.Index(merged, "second.exe"); first < 0 || second < 0 || second >= first {
		t.Fatalf("priority order was not preserved:\n%s", merged)
	}

	withoutHashes := filepath.Join(dir, "without-hashes.xml")
	writeCLIFile(t, withoutHashes, `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or"><ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`)
	analyzerTemplate := filepath.Join(dir, "analyzer-template.xml")
	writeCLIFile(t, analyzerTemplate, `<Sysmon schemaversion="4.90"><HashAlgorithms>*</HashAlgorithms><DnsLookup>true</DnsLookup><EventFiltering/></Sysmon>`)
	if err := runMerge([]string{
		"--path", withoutHashes, "--output", filepath.Join(dir, "analyzed.xml"),
		"--template", analyzerTemplate, "--sysmon-version=", "--schema-validate=false", "--analyze", "--warnings-as-errors",
	}); err == nil || !strings.Contains(err.Error(), "findings were emitted") {
		t.Fatalf("expected analyzer recommendation to fail strict merge, got %v", err)
	}
	broken := filepath.Join(dir, "broken.xml")
	writeCLIFile(t, broken, "<Sysmon>")
	if err := runMerge([]string{"--path", broken, "--output", filepath.Join(dir, "broken-output.xml")}); err == nil || !strings.Contains(err.Error(), "syntax validation failed") {
		t.Fatalf("expected syntax validation error, got %v", err)
	}
}

func TestRunListRulesFindXMLAndPathHelpers(t *testing.T) {
	base := t.TempDir()
	moduleDir := filepath.Join(base, "1_process_creation")
	mustMkdirAll(t, moduleDir)
	module := filepath.Join(moduleDir, "include_test.xml")
	writeCLIFile(t, module, cliConfig("cmd.exe", ""))
	writeCLIFile(t, filepath.Join(base, "UPPER.XML"), cliConfig("upper.exe", ""))
	mustMkdirAll(t, filepath.Join(base, ".git"))
	writeCLIFile(t, filepath.Join(base, ".git", "ignored.xml"), "<broken>")

	var listErr error
	stdout, _ := captureCommandOutput(t, func() { listErr = runListRules([]string{"--base-path", base}) })
	if listErr != nil || !strings.Contains(stdout, "1_process_creation/include_test.xml") {
		t.Fatalf("list-rules returned err=%v stdout=%q", listErr, stdout)
	}
	paths, err := findXMLFiles(base)
	if err != nil || len(paths) != 2 {
		t.Fatalf("findXMLFiles returned paths=%v err=%v", paths, err)
	}
	if _, err := findXMLFiles(filepath.Join(base, "missing")); err == nil {
		t.Fatal("expected missing-base error")
	}
	if got := dedupeStrings([]string{"b", "a", "b", "a"}); strings.Join(got, ",") != "b,a" {
		t.Fatalf("dedupeStrings changed first-seen order: %v", got)
	}
	if got := resolveTemplate(base, module); got != module {
		t.Fatalf("explicit template resolved to %q", got)
	}
	if got := resolveTemplate(base, ""); got != "" {
		t.Fatalf("unexpected implicit template without conventional path: %q", got)
	}
}

func TestRunGenerateKQLAndMDEHappyPaths(t *testing.T) {
	dir := t.TempDir()
	kql := filepath.Join(dir, "rule.kql")
	writeCLIFile(t, kql, `DeviceProcessEvents | where FileName == "cmd.exe"`)
	kqlOutput := filepath.Join(dir, "kql.xml")
	if err := runGenerateKQL([]string{"--kql", kql, "--output", kqlOutput}); err != nil {
		t.Fatal(err)
	}
	if got := readCLIFile(t, kqlOutput); !strings.Contains(got, "<ProcessCreate") || !strings.Contains(got, "cmd.exe") {
		t.Fatalf("unexpected KQL output:\n%s", got)
	}
	moduleDir := filepath.Join(dir, "1_process_creation")
	mustMkdirAll(t, moduleDir)
	writeCLIFile(t, filepath.Join(moduleDir, "existing.xml"), cliConfig("cmd.exe", ""))
	dedupOutput := filepath.Join(dir, "kql-dedup.xml")
	var dedupErr error
	_, dedupLog := captureCommandOutput(t, func() {
		dedupErr = runGenerateKQL([]string{
			"--kql", kql, "--output", dedupOutput, "--dedup", "--base-path", dir,
			"--analyzer", "--analyzer-url", "://invalid",
		})
	})
	if dedupErr != nil || !strings.Contains(dedupLog, "KQL analyzer") || !strings.Contains(dedupLog, "conditions_annotated=1") {
		t.Fatalf("KQL dedup/analyzer run returned err=%v log=%q", dedupErr, dedupLog)
	}

	kqlDir := filepath.Join(dir, "queries")
	mustMkdirAll(t, kqlDir)
	writeCLIFile(t, filepath.Join(kqlDir, "network.kql"), `DeviceNetworkEvents | where RemotePort == 443`)
	kqlOutputDir := filepath.Join(dir, "kql-output")
	if err := runGenerateKQL([]string{"--directory", kqlDir, "--output-dir", kqlOutputDir}); err != nil {
		t.Fatal(err)
	}
	if files, err := filepath.Glob(filepath.Join(kqlOutputDir, "*.xml")); err != nil || len(files) != 1 {
		t.Fatalf("directory KQL conversion produced files=%v err=%v", files, err)
	}

	mdeConfig := filepath.Join(dir, "mde.json")
	writeCLIFile(t, mdeConfig, `{
  "Provider": {"Rules": [{
    "name": "Create process using G-ETW",
    "filters": {"expressionType": "Predicate", "source": "ProcessEntity:PROCESS_NAME", "values": ["cmd.exe"], "filter": "EQ"}
  }]}
}`)
	mdeOutput := filepath.Join(dir, "mde-output")
	if err := runGenerateMDE([]string{"--mde-config", mdeConfig, "--output-dir", mdeOutput}, generate.MDEModeFiltered); err != nil {
		t.Fatal(err)
	}
	if files, err := filepath.Glob(filepath.Join(mdeOutput, "*.xml")); err != nil || len(files) != 1 {
		t.Fatalf("MDE conversion produced files=%v err=%v", files, err)
	}
	if got := defaultMDEOutputDir(generate.MDEModeUnfiltered); !strings.Contains(got, "unfiltered") {
		t.Fatalf("unexpected unfiltered output directory: %s", got)
	}
}

func captureCommandOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()
	dir := t.TempDir()
	stdoutFile, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	stderrFile, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutFile, stderrFile
	defer func() {
		os.Stdout, os.Stderr = oldStdout, oldStderr
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
	}()

	fn()
	if err := stdoutFile.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := stderrFile.Sync(); err != nil {
		t.Fatal(err)
	}
	stdout := readCLIFile(t, stdoutFile.Name())
	stderr := readCLIFile(t, stderrFile.Name())
	return stdout, stderr
}

func cliConfig(image, nameAttribute string) string {
	if nameAttribute != "" {
		nameAttribute = " " + nameAttribute
	}
	return `<Sysmon schemaversion="4.90"><HashAlgorithms>*</HashAlgorithms><EventFiltering><RuleGroup groupRelation="or"><ProcessCreate onmatch="include"><Image` + nameAttribute + ` condition="image">` + image + `</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeCLIFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readCLIFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
