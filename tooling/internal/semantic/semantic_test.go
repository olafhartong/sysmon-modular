package semantic

import (
	"encoding/json"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/expression"
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

func TestCompareOutputIsDeterministicForEquivalentInputOrder(t *testing.T) {
	rules := []expression.Event{
		{Name: "ProcessCreate", Onmatch: "include", GroupName: "z-group", GroupRelation: "or", Line: 20, Expression: expression.Leaf(expression.Condition{Field: "Image", Operator: "image", Value: "cmd.exe"})},
		{Name: "ProcessCreate", Onmatch: "include", GroupName: "a-group", GroupRelation: "or", Line: 10, Expression: expression.Leaf(expression.Condition{Field: "Image", Operator: "image", Value: "cmd.exe"})},
	}
	left, err := json.Marshal(Compare(Config{Rules: rules, Techniques: []string{"T1105", "T1059.001"}}, Config{}))
	if err != nil {
		t.Fatal(err)
	}
	rules[0], rules[1] = rules[1], rules[0]
	right, err := json.Marshal(Compare(Config{Rules: rules, Techniques: []string{"T1059.001", "T1105"}}, Config{}))
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatalf("equivalent input order changed diff output:\n%s\n%s", left, right)
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
