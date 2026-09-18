package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func TestFromMDEConfigFilteredGeneratesIncludeAndExcludeModules(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	outDir := filepath.Join(dir, "out")
	result, err := FromMDEConfigFileOptions(config, outDir, MDEOptions{Mode: MDEModeFiltered, AllowLossy: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) < 4 {
		t.Fatalf("expected multiple generated files, got %#v", result)
	}
	assertFileContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "<Rule", "cmd.exe", "CommandLine")
	assertFileContains(t, filepath.Join(outDir, "exclude_mde_processcreate.xml"), `C:\Program Files\App\app.exe`)
	assertFileContains(t, filepath.Join(outDir, "include_mde_registryevent.xml"), `<TargetObject condition="begin with"`, "HKCU\\software\\classes")
	assertFileContains(t, filepath.Join(outDir, "include_mde_registryevent.xml"), `HKLM\software\microsoft\office\addins\`)
	assertFileContains(t, filepath.Join(outDir, "include_mde_registryevent.xml"), `HKLM\software\microsoft</TargetObject> <!-- high-level duplicate; remove if too generic -->`)
	assertFileNotContains(t, filepath.Join(outDir, "include_mde_registryevent.xml"), `<TargetObject condition="contains"`)
	assertFileContains(t, filepath.Join(outDir, "include_mde_filecreate.xml"), "TargetFilename", `C:\Users\`)
	assertFileContains(t, filepath.Join(outDir, "exclude_mde_filecreate.xml"), `C:\Temp`)
	assertFileNotContains(t, filepath.Join(outDir, "exclude_mde_filecreate.xml"), `C:\\Temp`)
	assertMDEFileExclusionKeepsProcessAndPathTogether(t, filepath.Join(outDir, "exclude_mde_filecreate.xml"))
	if result.Stats.RulesSeen == 0 || result.Stats.RulesMapped == 0 {
		t.Fatalf("expected stats to count mapped rules, got %#v", result.Stats)
	}
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "skipped broad MDE path exclusion") {
			t.Fatalf("process-scoped broad path exclusion should not warn, got %q", warning)
		}
	}
	assertFileContains(t, filepath.Join(outDir, "exclude_mde_filecreate.xml"), `C:\Program Files (x86)\Office\winword.exe`)
}

func TestFromMDEConfigSkipsLossyFilterUnlessExplicitlyAllowed(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "lossy.json")
	data := `{"rules":[{"name":"process creation unsupported filter","filters":{"expressionType":"predicate","source":"AccountName","filter":"Eq","values":["admin"]}}]}`
	if err := os.WriteFile(config, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := FromMDEConfigFileOptions(config, filepath.Join(dir, "safe"), MDEOptions{Mode: MDEModeFiltered})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.LossyRules != 1 || len(result.Files) != 0 || !containsString(result.Warnings, "--allow-lossy") {
		t.Fatalf("lossy conversion must fail closed by default: %#v", result)
	}
	allowed, err := FromMDEConfigFileOptions(config, filepath.Join(dir, "allowed"), MDEOptions{Mode: MDEModeFiltered, AllowLossy: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed.Files) == 0 || allowed.Stats.LossyRules != 1 {
		t.Fatalf("explicit lossy opt-in should retain legacy fallback behavior: %#v", allowed)
	}
}

func TestMDECompositeNegationIsMarkedLossy(t *testing.T) {
	predicate := func(source, value string) map[string]any {
		return map[string]any{"expressionType": "Predicate", "source": source, "filter": "Eq", "values": []any{value}}
	}
	expr := map[string]any{
		"expressionType": "Operator", "operator": "Not",
		"expressions": []any{map[string]any{
			"expressionType": "Operator", "operator": "And",
			"expressions": []any{predicate("ProcessEntity:PROCESS_NAME", "cmd.exe"), predicate("ProcessEntity:PROCESS_CMD_LINE", "/c")},
		}},
	}
	if _, safe := mdeExpressionSafety("ProcessCreate", expr); safe {
		t.Fatal("NOT over an AND expression cannot be flattened without changing its meaning")
	}
}

func TestMDETypedExpressionPreservesNestedBooleanLogic(t *testing.T) {
	predicate := func(source, filter string, values ...any) map[string]any {
		return map[string]any{"expressionType": "Predicate", "source": source, "filter": filter, "values": values}
	}
	expr := map[string]any{
		"expressionType": "Operator", "operator": "Or",
		"expressions": []any{
			map[string]any{
				"expressionType": "Operator", "operator": "And",
				"expressions": []any{
					predicate("ProcessEntity:PROCESS_NAME", "Eq", "cmd.exe"),
					predicate("ProcessEntity:PROCESS_CMD_LINE", "Contains", "/c"),
				},
			},
			predicate("ProcessEntity:PROCESS_NAME", "Eq", "powershell.exe"),
		},
	}
	positive, negative, reason, exact := exactMDERules("ProcessCreate", expr)
	if !exact || reason != "" || len(negative) != 0 {
		t.Fatalf("expected exact positive expression, got positive=%#v negative=%#v reason=%q", positive, negative, reason)
	}
	if len(positive) != 2 || len(positive[0].Conditions)+len(positive[1].Conditions) != 3 {
		t.Fatalf("expected two exact DNF branches, got %#v", positive)
	}
}

func TestMDETypedExpressionRejectsMalformedChild(t *testing.T) {
	expr := map[string]any{
		"expressionType": "Operator", "operator": "And",
		"expressions": []any{"not an expression"},
	}
	if _, _, reason, exact := exactMDERules("ProcessCreate", expr); exact || !strings.Contains(reason, "child 1") {
		t.Fatalf("malformed child must be reported, exact=%v reason=%q", exact, reason)
	}
}

func TestMDEBooleanExpansionLimitFailsClosed(t *testing.T) {
	predicate := func(value string) map[string]any {
		return map[string]any{"expressionType": "Predicate", "source": "ProcessEntity:PROCESS_NAME", "filter": "Eq", "values": []any{value}}
	}
	andChildren := make([]any, 0, 9)
	for i := 0; i < 9; i++ {
		andChildren = append(andChildren, map[string]any{
			"expressionType": "Operator", "operator": "Or",
			"expressions": []any{predicate(fmt.Sprintf("tool-%d-a.exe", i)), predicate(fmt.Sprintf("tool-%d-b.exe", i))},
		})
	}
	expr := map[string]any{"expressionType": "Operator", "operator": "And", "expressions": andChildren}
	if _, _, reason, exact := exactMDERules("ProcessCreate", expr); exact || !strings.Contains(reason, "exceeds 256") {
		t.Fatalf("oversized expansion must fail closed, exact=%v reason=%q", exact, reason)
	}
}

func assertMDEFileExclusionKeepsProcessAndPathTogether(t *testing.T, path string) {
	t.Helper()
	doc, err := sysmonxml.ParseFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	doc.Root.Walk(func(node *sysmonxml.Node) {
		if node.Name != "Rule" || !strings.EqualFold(node.AttrValue("groupRelation"), "and") {
			return
		}
		fields := map[string]string{}
		for _, child := range node.ElementChildren() {
			fields[child.Name] = child.Text
		}
		if fields["Image"] == `C:\Program Files\App\app.exe` && fields["TargetFilename"] == `C:\Temp` {
			found = true
		}
	})
	if !found {
		t.Fatalf("expected the process and path exclusion to remain one AND rule in %s", path)
	}
}

func TestFromMDEConfigUnfilteredGeneratesOnlyIncludeModules(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	outDir := filepath.Join(dir, "unfiltered")
	result, err := FromMDEConfigFileMode(config, outDir, MDEModeUnfiltered)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range result.Files {
		if strings.Contains(filepath.Base(file), "exclude") {
			t.Fatalf("unfiltered mode generated exclude file: %s", file)
		}
	}
	assertFileContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "MDE unfiltered", "Image")
	assertFileNotContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "cmd.exe")
}

func TestFromMDEConfigInverseGeneratesFilteredBlindSpotsAsIncludes(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	outDir := filepath.Join(dir, "inverse")
	result, err := FromMDEConfigFileOptions(config, outDir, MDEOptions{Mode: MDEModeInverse, AllowLossy: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range result.Files {
		if strings.Contains(filepath.Base(file), "exclude") {
			t.Fatalf("inverse mode generated exclude file: %s", file)
		}
	}
	assertFileContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "MsSense.exe", `C:\Program Files\App\app.exe`)
	assertFileContains(t, filepath.Join(outDir, "include_mde_filecreate.xml"), `C:\Windows\`)
}

func TestFromMDEConfigProcessesOnlySelectedArea(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	outDir := filepath.Join(dir, "process-only")
	result, err := FromMDEConfigFileOptions(config, outDir, MDEOptions{
		Mode:       MDEModeFiltered,
		Areas:      []string{"process-creation"},
		AllowLossy: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.RulesSeen != 1 || result.Stats.RulesMapped != 1 {
		t.Fatalf("expected only the process-creation rule to be processed, got %#v", result.Stats)
	}
	for _, file := range result.Files {
		if !strings.Contains(filepath.Base(file), "processcreate") {
			t.Fatalf("selected process-creation area generated unrelated file %s", file)
		}
	}
	assertFileContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "cmd.exe")
	if _, err := os.Stat(filepath.Join(outDir, "include_mde_registryevent.xml")); !os.IsNotExist(err) {
		t.Fatalf("registry output should not be generated, stat error: %v", err)
	}
}

func TestFromMDEConfigAcceptsMultipleAreas(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	outDir := filepath.Join(dir, "selected")
	result, err := FromMDEConfigFileOptions(config, outDir, MDEOptions{
		Mode:       MDEModeFiltered,
		Areas:      []string{"process-creation", "registry"},
		AllowLossy: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(outDir, "include_mde_processcreate.xml"), "cmd.exe")
	assertFileContains(t, filepath.Join(outDir, "include_mde_registryevent.xml"), "TargetObject")
	for _, file := range result.Files {
		if strings.Contains(filepath.Base(file), "filecreate") {
			t.Fatalf("unselected file-create area generated %s", file)
		}
	}
}

func TestFromMDEConfigRejectsUnknownArea(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	_, err := FromMDEConfigFileOptions(config, filepath.Join(dir, "out"), MDEOptions{
		Mode:  MDEModeFiltered,
		Areas: []string{"not-an-area"},
	})
	if err == nil || !strings.Contains(err.Error(), "supported areas") {
		t.Fatalf("expected supported-area error, got %v", err)
	}
}

func TestFromMDEConfigDeduplicatesAgainstExistingModules(t *testing.T) {
	dir := t.TempDir()
	config := writeMDEFixture(t, dir)
	baselineDir := filepath.Join(dir, "baseline")
	baseline, err := FromMDEConfigFileOptions(config, baselineDir, MDEOptions{
		Mode:       MDEModeFiltered,
		Areas:      []string{"process-creation"},
		AllowLossy: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Files) == 0 {
		t.Fatal("expected baseline modules")
	}

	result, err := FromMDEConfigFileOptions(config, filepath.Join(dir, "deduped"), MDEOptions{
		Mode:            MDEModeFiltered,
		Areas:           []string{"process-creation"},
		ExistingModules: baseline.Files,
		AllowLossy:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 0 {
		t.Fatalf("expected every process rule to be deduplicated, generated %#v", result.Files)
	}
	if result.Stats.DuplicateRules == 0 {
		t.Fatalf("expected duplicate rule count, got %#v", result.Stats)
	}
	if !containsString(result.Warnings, "all generated MDE rules already exist") {
		t.Fatalf("expected all-rules-deduplicated warning, got %#v", result.Warnings)
	}
}

func TestMDEDeduplicationKeepsDifferentOnmatch(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.xml")
	if err := WriteModuleFromRules(existing, "ProcessCreate", "include", []RuleSpec{{
		GroupRelation: "and",
		Conditions:    []Condition{{Field: "Image", Operator: "is", Value: "cmd.exe"}},
	}}); err != nil {
		t.Fatal(err)
	}
	keys, err := loadExistingRuleKeys([]string{existing})
	if err != nil {
		t.Fatal(err)
	}
	g := &mdeGenerator{dedup: true, existing: keys}
	rules := []RuleSpec{{GroupRelation: "and", Conditions: []Condition{{Field: "Image", Operator: "is", Value: "cmd.exe"}}}}
	if kept := g.removeExistingRules("ProcessCreate", "include", rules); len(kept) != 0 {
		t.Fatalf("expected matching include to be removed, got %#v", kept)
	}
	if kept := g.removeExistingRules("ProcessCreate", "exclude", rules); len(kept) != 1 {
		t.Fatalf("expected differently scoped exclude to remain, got %#v", kept)
	}
}

func TestMDEDeduplicationNormalizesConditionOrderCaseAndNames(t *testing.T) {
	left := RuleSpec{
		Name:          "Existing display name",
		GroupRelation: "AND",
		Conditions: []Condition{
			{Field: "CommandLine", Operator: "contains", Value: " /C "},
			{Field: "Image", Operator: "IS", Value: "CMD.EXE"},
		},
	}
	right := RuleSpec{
		Name:          "Different generated name",
		GroupRelation: "and",
		Conditions: []Condition{
			{Field: "image", Operator: "is", Value: "cmd.exe"},
			{Field: "commandline", Operator: "CONTAINS", Value: "/c"},
		},
	}
	if got, want := mdeRuleKey("ProcessCreate", "include", left), mdeRuleKey("processcreate", "INCLUDE", right); got != want {
		t.Fatalf("normalized rule keys differ:\nleft  %q\nright %q", got, want)
	}
}

func TestMDEPathNormalizationCollapsesDoubleBackslashes(t *testing.T) {
	tests := map[string]string{
		`C:\\Windows\\System32\\cmd.exe`:            `C:\Windows\System32\cmd.exe`,
		`%SystemRoot%\\System32\\WindowsPowerShell`: `C:\Windows\System32\WindowsPowerShell`,
		`HKLM\\Software\\Microsoft`:                 `HKLM\Software\Microsoft`,
		`\\server\\share\\folder`:                   `\\server\share\folder`,
	}
	for input, want := range tests {
		if got := expandMDEPath(input); got != want {
			t.Errorf("expandMDEPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizePathPatternCollapsesDoubleBackslashes(t *testing.T) {
	if got, want := normalizePathPattern(`C:\\Users\\*\\.ssh\\*`), `C:\Users\.ssh\`; got != want {
		t.Fatalf("normalizePathPattern() = %q, want %q", got, want)
	}
}

func TestRegistryPathOperatorUsesBeginWithForRootedKeys(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: `HKLM\Software\Microsoft`, want: "begin with"},
		{value: `hkcu\\software\\classes`, want: "begin with"},
		{value: `Software\Microsoft\Windows`, want: "contains"},
		{value: `HKLM\Software\*\Run`, want: "contains"},
	}
	for _, test := range tests {
		if got := registryPathOperator(test.value); got != test.want {
			t.Errorf("registryPathOperator(%q) = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestRegistryPredicatePromotesRootedContainsToBeginWith(t *testing.T) {
	predicate := map[string]any{
		"source": "RegistryKey:REGISTRY_KEY",
		"filter": "Contains",
		"values": []any{`HKLM\\Software\\Microsoft`},
	}
	condition, ok := conditionFromPredicate("RegistryEvent", predicate)
	if !ok {
		t.Fatal("expected registry predicate to be converted")
	}
	if condition.Operator != "begin with" || condition.Value != `HKLM\Software\Microsoft` {
		t.Fatalf("unexpected condition: %#v", condition)
	}
}

func TestMarkHighLevelRegistryRulesCommentsOnlyParentPrefixes(t *testing.T) {
	rules := []RuleSpec{
		{Conditions: []Condition{{Field: "TargetObject", Operator: "begin with", Value: `HKLM\system`}}},
		{Conditions: []Condition{{Field: "TargetObject", Operator: "begin with", Value: `HKLM\system\services`}}},
		{Conditions: []Condition{{Field: "TargetObject", Operator: "begin with", Value: `HKLM\system\services\sharedaccess`}}},
		{Conditions: []Condition{{Field: "TargetObject", Operator: "begin with", Value: `HKLM\systemwide`}}},
		{Conditions: []Condition{{Field: "TargetObject", Operator: "contains", Value: `HKLM\system`}}},
	}
	marked := markHighLevelRegistryRules(rules)
	if marked[0].Conditions[0].Comment != highLevelRegistryComment {
		t.Fatalf("expected root parent comment, got %#v", marked[0])
	}
	if marked[1].Conditions[0].Comment != highLevelRegistryComment {
		t.Fatalf("expected intermediate parent comment, got %#v", marked[1])
	}
	for _, index := range []int{2, 3, 4} {
		if marked[index].Conditions[0].Comment != "" {
			t.Fatalf("rule %d should not be marked: %#v", index, marked[index])
		}
	}

	xmlOutput := string(ModuleFromRules("RegistryEvent", "include", marked, "4.90").Bytes())
	if !strings.Contains(xmlOutput, `HKLM\system</TargetObject> <!-- high-level duplicate; remove if too generic -->`) {
		t.Fatalf("expected inline high-level comment, got:\n%s", xmlOutput)
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func writeMDEFixture(t *testing.T, dir string) string {
	t.Helper()
	config := filepath.Join(dir, "mde-config.json")
	data := `{
  "configTypes": [{
    "configType": "host",
    "ExclusionConfiguration": {
      "EnableExclusions": true,
      "Paths": [
        {"Value": "C:\\\\Temp", "Process": "%ProgramFiles%\\App\\app.exe"},
        {"Value": "\\\\", "Process": "%ProgramFiles(x86)%\\Office\\winword.exe"}
      ]
    },
    "FileMonitorConfiguration": {
      "FileMonitorEntries": [{"FilePath": "%SystemDrive%\\Users\\*\\.ssh\\*", "FileMonitorType": [1]}],
      "ExpandedCollectionExcludedFileMonitorEntries": [{"FilePath": "%SystemDrive%\\Windows\\*", "FileMonitorType": [1]}]
    },
    "RegistryMonitoringConfiguration": {
      "registryEntries": [
        {"registryKey": "hkcu\\software\\classes\\ms-settings\\shell\\open\\command\\", "registryValue": "delegateexecute"},
        {"registryKey": "hklm\\software\\microsoft", "registryValue": ""},
        {"registryKey": "hklm\\software\\microsoft\\office\\addins\\*", "registryValue": ""},
        {"registryKey": "hklm\\software\\microsoft\\msdtc\\mtxoci\\(1)", "registryValue": ""}
      ]
    },
    "Provider": {
      "Rules": [{
        "name": "Create process using G-ETW",
        "taskName": "GenericEtwCreateProcess",
        "filters": {
          "expressionType": "Operator",
          "operator": "And",
          "expressions": [
            {"expressionType": "Predicate", "source": "ProcessEntity:PROCESS_NAME", "values": ["cmd.exe"], "filter": "EQ"},
            {"expressionType": "Predicate", "source": "ProcessEntity:PROCESS_CMD_LINE", "values": ["/c"], "filter": "Contains"},
            {"expressionType": "Operator", "operator": "Not", "expressions": [
              {"expressionType": "Predicate", "source": "InitiatingProcess:PROCESS_NAME", "values": ["MsSense.exe"], "filter": "EQ"}
            ]}
          ]
        }
      }]
    }
  }]
}`
	if err := os.WriteFile(config, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return config
}

func assertFileContains(t *testing.T, path string, needles ...string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range needles {
		if !strings.Contains(string(content), needle) {
			t.Fatalf("expected %s to contain %q, got:\n%s", path, needle, content)
		}
	}
}

func assertFileNotContains(t *testing.T, path string, needles ...string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range needles {
		if strings.Contains(string(content), needle) {
			t.Fatalf("expected %s not to contain %q, got:\n%s", path, needle, content)
		}
	}
}
