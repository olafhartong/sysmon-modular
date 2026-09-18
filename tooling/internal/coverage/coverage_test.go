package coverage

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func TestBuildCountsDirectEventsAndGroupTechniques(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
	<RuleGroup name="technique_id=T1059.001,technique_name=PowerShell" groupRelation="or"><ProcessCreate onmatch="include"><Rule groupRelation="and"><Image name="technique_id=T1547.001,technique_name=Registry Run Keys / Startup Folder" condition="image">powershell.exe</Image><CommandLine condition="contains">-enc</CommandLine></Rule></ProcessCreate></RuleGroup>
	<NetworkConnect onmatch="exclude"><DestinationPort condition="is">53</DestinationPort></NetworkConnect>
	</EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	report := Build(map[string]*sysmonxml.Document{"module.xml": doc})
	if report.Include != 2 || report.Exclude != 1 || report.Modules["module.xml"] != 3 {
		t.Fatalf("unexpected condition counts: %#v", report)
	}
	if len(report.Techniques) != 2 || report.Techniques[0].ID != "T1059.001" || len(report.Techniques[0].Modules) != 1 {
		t.Fatalf("RuleGroup technique metadata was not counted: %#v", report.Techniques)
	}
	if strings.Join(report.Techniques[0].Tactics, ",") != "execution" || strings.Join(report.Techniques[1].Tactics, ",") != "persistence,privilege-escalation" {
		t.Fatalf("STIX tactic mappings were not preserved: %#v", report.Techniques)
	}
	if report.Tactics["unmapped"] != 0 || report.Tactics["execution"] != 1 || report.Tactics["persistence"] != 1 || report.Tactics["privilege-escalation"] != 1 {
		t.Fatalf("unexpected tactic counts: %#v", report.Tactics)
	}
}

func TestWritersProduceStableParseableOutput(t *testing.T) {
	report := Report{
		Events:     []Event{{Name: "ProcessCreate", Include: 2, Modules: []string{"a.xml"}}},
		Techniques: []Technique{{ID: "T1059.001", Name: "PowerShell", Tactics: []string{"execution"}, Modules: []string{"a.xml"}}},
		Tactics:    map[string]int{"execution": 1}, Modules: map[string]int{"a.xml": 2}, Include: 2,
	}
	var first, second bytes.Buffer
	if err := WriteJSON(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, report); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() || !json.Valid(first.Bytes()) {
		t.Fatalf("JSON output is not stable and valid:\n%s\n%s", first.String(), second.String())
	}
	for name, write := range map[string]func(*bytes.Buffer) error{
		"text":      func(buffer *bytes.Buffer) error { return WriteText(buffer, report) },
		"csv":       func(buffer *bytes.Buffer) error { return WriteCSV(buffer, report) },
		"navigator": func(buffer *bytes.Buffer) error { return WriteNavigator(buffer, report) },
	} {
		var output bytes.Buffer
		if err := write(&output); err != nil {
			t.Fatalf("%s output failed: %v", name, err)
		}
		if output.Len() == 0 {
			t.Fatalf("%s output is empty", name)
		}
	}
}
