package merger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
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
	if strings.Count(out, "<ProcessCreate") != 1 || strings.Count(out, "<RuleGroup") != 1 {
		t.Fatalf("expected one filter for the shared event and onmatch value, got:\n%s", out)
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

func writeModules(t *testing.T, modules ...string) []string {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for i, module := range modules {
		path := filepath.Join(dir, fmt.Sprintf("m%d.xml", i))
		if err := os.WriteFile(path, []byte(module), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

func TestMergeKeepsOneFilterPerEventAndOnmatch(t *testing.T) {
	paths := writeModules(t,
		`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="" groupRelation="or"><ProcessCreate onmatch="include"/></RuleGroup><RuleGroup name="" groupRelation="or"><PipeEvent onmatch="exclude"/></RuleGroup></EventFiltering></Sysmon>`,
		`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="technique_id=T1059,technique_name=Command and Scripting Interpreter" groupRelation="or"><ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image><Image name="own" condition="image">pwsh.exe</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`,
		`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="" groupRelation="or"><ProcessCreate onmatch="exclude"><Image condition="is">C:\a.exe</Image></ProcessCreate></RuleGroup><RuleGroup name="" groupRelation="or"><PipeEvent onmatch="exclude"><PipeName condition="is">\x</PipeName></PipeEvent></RuleGroup></EventFiltering></Sysmon>`,
	)
	result, err := Merge(paths, Options{})
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	result.Document.Root.Walk(func(n *sysmonxml.Node) {
		if n.Name == "RuleGroup" {
			if len(n.ElementChildren()) != 1 {
				t.Errorf("each RuleGroup must hold one filter, got %d", len(n.ElementChildren()))
			}
			for _, f := range n.ElementChildren() {
				counts[f.Name+"/"+f.AttrValue("onmatch")]++
			}
		}
	})
	want := map[string]int{"ProcessCreate/include": 1, "ProcessCreate/exclude": 1, "PipeEvent/exclude": 1}
	if fmt.Sprint(counts) != fmt.Sprint(want) {
		t.Fatalf("filters per event and onmatch = %v, want %v", counts, want)
	}
	out := result.Document.String()
	for _, want := range []string{`condition="image" name="technique_id=T1059,technique_name=Command and Scripting Interpreter">cmd.exe`, `name="own"`, `\x</PipeName>`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in:\n%s", want, out)
		}
	}
	if strings.Count(out, "technique_id=T1059") != 1 {
		t.Fatalf("a rule with its own name must keep it, got:\n%s", out)
	}
}

func TestMergeTurnsAndGroupsIntoRules(t *testing.T) {
	paths := writeModules(t,
		`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="pair" groupRelation="and"><ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image><Rule groupRelation="and"><CommandLine condition="contains">/c</CommandLine></Rule></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`,
		`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="" groupRelation="or"><ProcessCreate onmatch="include"><Image condition="image">wscript.exe</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`,
	)
	result, err := Merge(paths, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := result.Document.String()
	for _, want := range []string{`<Rule groupRelation="and" name="pair">`, "cmd.exe", "/c", "wscript.exe"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in:\n%s", want, out)
		}
	}
	if strings.Count(out, "<Rule ") != 1 || strings.Count(out, "<ProcessCreate") != 1 {
		t.Fatalf("expected the and group as one Rule in one filter, got:\n%s", out)
	}
}

func TestMergeRejectsOrRuleInsideAndGroup(t *testing.T) {
	paths := writeModules(t,
		`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="and"><ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image><Rule groupRelation="or"><CommandLine condition="contains">/c</CommandLine></Rule></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`,
	)
	if _, err := Merge(paths, Options{}); err == nil {
		t.Fatal("expected an error for an or Rule inside an and RuleGroup")
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
