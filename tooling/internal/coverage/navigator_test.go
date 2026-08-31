package coverage

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func TestBuildCountsTechniqueMetadataOccurrences(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
		<ProcessCreate onmatch="include">
			<Image name="technique_id=T1059.001,technique_name=PowerShell" condition="end with">powershell.exe</Image>
			<CommandLine name="technique_id=T1059.001,technique_name=PowerShell" condition="contains">-enc</CommandLine>
		</ProcessCreate>
	</EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}

	report := Build(map[string]*sysmonxml.Document{"process.xml": doc})
	if len(report.Techniques) != 1 {
		t.Fatalf("got %d techniques, want 1: %#v", len(report.Techniques), report.Techniques)
	}
	if report.Techniques[0].Count != 2 {
		t.Fatalf("got score count %d, want 2", report.Techniques[0].Count)
	}
}

func TestWriteNavigatorProducesImportableLayer(t *testing.T) {
	report := Report{Techniques: []Technique{
		{ID: "T1059.001", Modules: []string{"1_process_creation/powershell.xml"}, Count: 3},
	}}
	var output bytes.Buffer
	if err := WriteNavigatorWithOptions(&output, report, NavigatorOptions{
		Name: "Test layer", Description: "Generated for a test.",
	}); err != nil {
		t.Fatal(err)
	}

	var layer map[string]any
	if err := json.Unmarshal(output.Bytes(), &layer); err != nil {
		t.Fatalf("decode layer: %v", err)
	}
	if layer["name"] != "Test layer" || layer["domain"] != "enterprise-attack" {
		t.Fatalf("unexpected layer identity: %#v", layer)
	}
	versions := layer["versions"].(map[string]any)
	if versions["attack"] != "18" || versions["navigator"] != "5.3.2" || versions["layer"] != "4.5" {
		t.Fatalf("unexpected Navigator versions: %#v", versions)
	}
	techniques := layer["techniques"].([]any)
	technique := techniques[0].(map[string]any)
	if technique["techniqueID"] != "T1059.001" || technique["score"] != float64(3) {
		t.Fatalf("unexpected technique: %#v", technique)
	}
	if technique["comment"] != "1_process_creation/powershell.xml" {
		t.Fatalf("unexpected technique comment: %#v", technique["comment"])
	}
	gradient := layer["gradient"].(map[string]any)
	if gradient["maxValue"] != float64(3) {
		t.Fatalf("gradient maxValue = %#v, want 3", gradient["maxValue"])
	}
	colors := gradient["colors"].([]any)
	wantColors := []string{"#18e8ff", "#37b6ff", "#1a60ff"}
	for i, want := range wantColors {
		if colors[i] != want {
			t.Fatalf("gradient color %d = %#v, want %q", i, colors[i], want)
		}
	}
}

func TestWriteNavigatorPreservesTemplateSettings(t *testing.T) {
	template := []byte(`{
		"name": "old name",
		"versions": {"attack": "19", "navigator": "4.0.0", "layer": "4.3"},
		"layout": {"showID": true},
		"gradient": {"maxValue": 100},
		"legendItems": [{"label": "High", "color": "#ff0000"}],
		"techniques": [{"techniqueID": "T0000", "score": 99}]
	}`)
	report := Report{Techniques: []Technique{{ID: "T1547.001", Modules: []string{"registry.xml"}, Count: 2}}}
	var output bytes.Buffer
	if err := WriteNavigatorWithOptions(&output, report, NavigatorOptions{
		Name: "new name", Description: "new description", Template: template,
	}); err != nil {
		t.Fatal(err)
	}

	var layer map[string]any
	if err := json.Unmarshal(output.Bytes(), &layer); err != nil {
		t.Fatal(err)
	}
	if layer["name"] != "new name" || layer["description"] != "new description" {
		t.Fatalf("command values did not replace template identity: %#v", layer)
	}
	versions := layer["versions"].(map[string]any)
	if versions["attack"] != "18" || versions["navigator"] != "5.3.2" || versions["layer"] != "4.5" {
		t.Fatalf("generated versions did not replace template versions: %#v", versions)
	}
	if layer["layout"].(map[string]any)["showID"] != true {
		t.Fatalf("template layout was not retained: %#v", layer["layout"])
	}
	if layer["gradient"].(map[string]any)["maxValue"] != float64(100) {
		t.Fatalf("template gradient was not retained: %#v", layer["gradient"])
	}
	techniques := layer["techniques"].([]any)
	if len(techniques) != 1 || techniques[0].(map[string]any)["techniqueID"] != "T1547.001" {
		t.Fatalf("generated techniques did not replace template techniques: %#v", techniques)
	}
}

func TestWriteNavigatorRemapsATTACK19TechniquesForVersion18(t *testing.T) {
	report := Report{Techniques: []Technique{
		{ID: "T1562.001", Modules: []string{"legacy.xml"}, Count: 2},
		{ID: "T1685", Modules: []string{"current.xml"}, Count: 3},
		{ID: "T1685.001", Modules: []string{"eventlog.xml"}, Count: 4},
		{ID: "T1685.005", Modules: []string{"clear.xml"}, Count: 5},
	}}
	var output bytes.Buffer
	if err := WriteNavigatorWithOptions(&output, report, NavigatorOptions{AttackVersion: "18"}); err != nil {
		t.Fatal(err)
	}

	var layer map[string]any
	if err := json.Unmarshal(output.Bytes(), &layer); err != nil {
		t.Fatal(err)
	}
	techniques := layer["techniques"].([]any)
	if len(techniques) != 3 {
		t.Fatalf("got %d techniques, want 3: %#v", len(techniques), techniques)
	}
	byID := map[string]map[string]any{}
	for _, item := range techniques {
		technique := item.(map[string]any)
		byID[technique["techniqueID"].(string)] = technique
	}
	if byID["T1562.001"]["score"] != float64(5) || byID["T1562.001"]["comment"] != "current.xml, legacy.xml" {
		t.Fatalf("combined T1562.001 = %#v", byID["T1562.001"])
	}
	if byID["T1562.002"]["score"] != float64(4) || byID["T1070.001"]["score"] != float64(5) {
		t.Fatalf("unexpected remapped techniques: %#v", byID)
	}
	remappings := NavigatorRemappings(report, "18")
	if len(remappings) != 3 || remappings[0].From != "T1685" || remappings[0].To != "T1562.001" {
		t.Fatalf("unexpected remapping report: %#v", remappings)
	}
}

func TestWriteNavigatorKeepsATTACK19TechniquesWhenRequested(t *testing.T) {
	report := Report{Techniques: []Technique{{ID: "T1685", Modules: []string{"current.xml"}, Count: 3}}}
	var output bytes.Buffer
	if err := WriteNavigatorWithOptions(&output, report, NavigatorOptions{AttackVersion: "19"}); err != nil {
		t.Fatal(err)
	}
	var layer map[string]any
	if err := json.Unmarshal(output.Bytes(), &layer); err != nil {
		t.Fatal(err)
	}
	if layer["versions"].(map[string]any)["attack"] != "19" {
		t.Fatalf("unexpected versions: %#v", layer["versions"])
	}
	technique := layer["techniques"].([]any)[0].(map[string]any)
	if technique["techniqueID"] != "T1685" {
		t.Fatalf("ATT&CK 19 technique was remapped: %#v", technique)
	}
}

func TestWriteNavigatorRejectsInvalidTemplate(t *testing.T) {
	var output bytes.Buffer
	err := WriteNavigatorWithOptions(&output, Report{}, NavigatorOptions{Template: []byte(`[`)})
	if err == nil {
		t.Fatal("expected invalid template error")
	}
}
