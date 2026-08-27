package coverage

import (
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func TestBuildCountsDirectEventsAndGroupTechniques(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
	<RuleGroup name="technique_id=T1059.001,technique_name=PowerShell" groupRelation="or"><ProcessCreate onmatch="include"><Rule groupRelation="and"><Image condition="image">powershell.exe</Image><CommandLine condition="contains">-enc</CommandLine></Rule></ProcessCreate></RuleGroup>
	<NetworkConnect onmatch="exclude"><DestinationPort condition="is">53</DestinationPort></NetworkConnect>
	</EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	report := Build(map[string]*sysmonxml.Document{"module.xml": doc})
	if report.Include != 2 || report.Exclude != 1 || report.Modules["module.xml"] != 3 {
		t.Fatalf("unexpected condition counts: %#v", report)
	}
	if len(report.Techniques) != 1 || report.Techniques[0].ID != "T1059.001" || len(report.Techniques[0].Modules) != 1 {
		t.Fatalf("RuleGroup technique metadata was not counted: %#v", report.Techniques)
	}
}
