package semantic

import (
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func TestComparePreservesExpressionMeaningAndUsesUnknownImpact(t *testing.T) {
	before := extractTestConfig(t, `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or"><ProcessCreate onmatch="include"><Rule groupRelation="and"><Image condition="image">cmd.exe</Image><CommandLine condition="contains">/c</CommandLine></Rule></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`)
	after := extractTestConfig(t, `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or"><ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image><CommandLine condition="contains">/c</CommandLine></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`)
	diff := Compare(before, after)
	if len(diff.Changes) != 2 {
		t.Fatalf("AND and OR expressions must compare as different semantic units: %#v", diff)
	}
	for _, change := range diff.Changes {
		if change.Impact != "unknown" || change.Rule == nil {
			t.Fatalf("diff must not guess widened or narrowed impact: %#v", change)
		}
	}
}

func TestExtractFindsTechniqueOnRuleGroupAndDirectEvents(t *testing.T) {
	doc, err := sysmonxml.Parse([]byte(`<Sysmon schemaversion="4.90"><EventFiltering>
	<RuleGroup name="technique_id=T1059.001,technique_name=PowerShell" groupRelation="or"><ProcessCreate onmatch="include"><Image condition="image">powershell.exe</Image></ProcessCreate></RuleGroup>
	<NetworkConnect onmatch="exclude"><DestinationPort condition="is">53</DestinationPort></NetworkConnect>
	</EventFiltering></Sysmon>`), false)
	if err != nil {
		t.Fatal(err)
	}
	config := Extract(doc)
	if len(config.Rules) != 2 || len(config.Techniques) != 1 || config.Techniques[0] != "T1059.001" {
		t.Fatalf("unexpected semantic extraction: %#v", config)
	}
}

func TestCompareCountsDuplicateExpressions(t *testing.T) {
	before := extractTestConfig(t, `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or">
	<ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image></ProcessCreate>
	<ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image></ProcessCreate>
	</RuleGroup></EventFiltering></Sysmon>`)
	after := extractTestConfig(t, `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or">
	<ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image></ProcessCreate>
	</RuleGroup></EventFiltering></Sysmon>`)
	diff := Compare(before, after)
	if diff.Summary["expression-removed"] != 1 || len(diff.Changes) != 1 {
		t.Fatalf("duplicate expression removal was collapsed: %#v", diff)
	}
}

func extractTestConfig(t *testing.T, input string) Config {
	t.Helper()
	doc, err := sysmonxml.Parse([]byte(input), false)
	if err != nil {
		t.Fatal(err)
	}
	return Extract(doc)
}
