package merger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeCombinesEventChildrenAndHighestSchema(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.xml")
	b := filepath.Join(dir, "b.xml")
	if err := os.WriteFile(a, []byte(`<Sysmon schemaversion="4.30"><EventFiltering><RuleGroup groupRelation="or"><ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or"><ProcessCreate onmatch="include"><CommandLine condition="contains">/c</CommandLine></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Merge([]string{a, b}, Options{ForceGroupRelationOr: true})
	if err != nil {
		t.Fatal(err)
	}
	out := result.Document.String()
	if !strings.Contains(out, `schemaversion="4.90"`) {
		t.Fatalf("expected highest schema version, got:\n%s", out)
	}
	if strings.Count(out, "<ProcessCreate") != 2 || strings.Count(out, "<RuleGroup") != 2 {
		t.Fatalf("expected source rule groups to remain separate, got:\n%s", out)
	}
	if !strings.Contains(out, "cmd.exe") || !strings.Contains(out, "/c") {
		t.Fatalf("expected merged children, got:\n%s", out)
	}
}

func TestMergePreservesRuleGroupSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "and.xml")
	input := `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="correlated" groupRelation="and"><ProcessCreate onmatch="include"><Rule groupRelation="and" name="pair"><Image condition="image">cmd.exe</Image><CommandLine condition="contains">/c</CommandLine></Rule></ProcessCreate><NetworkConnect onmatch="include"><DestinationPort condition="is">443</DestinationPort></NetworkConnect></RuleGroup></EventFiltering></Sysmon>`
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Merge([]string{path}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := result.Document.String()
	for _, want := range []string{`name="correlated"`, `groupRelation="and"`, `name="pair"`, "<ProcessCreate", "<NetworkConnect"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in:\n%s", want, out)
		}
	}
}

func TestResolveListsWarnsOnIncludeExcludeConflict(t *testing.T) {
	dir := t.TempDir()
	ruleDir := filepath.Join(dir, "1_process_creation")
	if err := os.MkdirAll(ruleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(ruleDir, "include_test.xml")
	if err := os.WriteFile(rule, []byte(`<Sysmon/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	include := filepath.Join(dir, "include.txt")
	exclude := filepath.Join(dir, "exclude.txt")
	if err := os.WriteFile(include, []byte("1_process_creation/include_test.xml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exclude, []byte("1_process_creation/include_test.xml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths, warnings, err := ResolveLists(dir, nil, include, exclude)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("expected excluded path removed, got %v", paths)
	}
	if len(warnings) == 0 {
		t.Fatal("expected conflict warning")
	}
}

func TestResolveListsPreservesPriorityOrder(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.xml", "z.xml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`<Sysmon/>`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	paths, warnings, err := ResolveLists(dir, []string{"z.xml", "a.xml"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 || len(paths) != 2 || filepath.Base(paths[0]) != "z.xml" || filepath.Base(paths[1]) != "a.xml" {
		t.Fatalf("explicit priority order was not preserved: paths=%v warnings=%v", paths, warnings)
	}
}

func TestReadPriorityListRejectsInvalidPriority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "priority.csv")
	if err := os.WriteFile(path, []byte("filepath,priority\na.xml,urgent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPriorityList(path, "csv"); err == nil || !strings.Contains(err.Error(), "invalid priority") {
		t.Fatalf("expected invalid-priority error, got %v", err)
	}
}

func TestResolveListsExclusionFromDiscoveredInputsIsNotAConflict(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "a.xml")
	if err := os.WriteFile(rule, []byte(`<Sysmon/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	exclude := filepath.Join(dir, "exclude.txt")
	if err := os.WriteFile(exclude, []byte("a.xml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths, warnings, err := ResolveLists(dir, []string{rule}, "", exclude)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 || len(warnings) != 0 {
		t.Fatalf("ordinary exclusion should be silent: paths=%v warnings=%v", paths, warnings)
	}
}
