package generate

import (
	"strings"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/validate"
)

func TestFromKQLGeneratesProcessCreateModule(t *testing.T) {
	doc, warnings, err := KQLModule(`DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe")
| where ProcessCommandLine contains " -enc "`)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	out := doc.String()
	if !strings.Contains(out, "<ProcessCreate") || !strings.Contains(out, "powershell.exe") || !strings.Contains(out, " -enc ") {
		t.Fatalf("unexpected module:\n%s", out)
	}
}

func TestKQLProcessCreateMapsInitiatingProcessToParentFields(t *testing.T) {
	result := FromKQL(`DeviceProcessEvents
| where InitiatingProcessFileName == "powershell.exe"
| where InitiatingProcessCommandLine contains " -enc "`)
	if len(result.LossyReasons) != 0 || len(result.Rules) != 1 {
		t.Fatalf("unexpected conversion: %#v", result)
	}
	fields := map[string]bool{}
	for _, condition := range result.Rules[0].Conditions {
		fields[condition.Field] = true
	}
	if !fields["ParentImage"] || !fields["ParentCommandLine"] || fields["Image"] || fields["CommandLine"] {
		t.Fatalf("initiating process fields must map to Sysmon parent fields: %#v", result.Rules[0].Conditions)
	}
}

func TestKQLNetworkCommandLineFailsClosed(t *testing.T) {
	query := `DeviceNetworkEvents
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"`
	result := FromKQL(query)
	if len(result.Rules) != 0 || len(result.LossyReasons) == 0 {
		t.Fatalf("NetworkConnect has no CommandLine field and must be marked lossy: %#v", result)
	}
	if _, warnings, err := KQLModuleNamed(query, "unsafe"); err == nil || !strings.Contains(strings.Join(warnings, " "), "--allow-lossy") {
		t.Fatalf("single-query conversion must fail closed: warnings=%v err=%v", warnings, err)
	}
}

func TestKQLNestedBooleanExpressionIsPreserved(t *testing.T) {
	result := FromKQL(`DeviceProcessEvents | where (FileName == "cmd.exe" and ProcessCommandLine contains "/c") or FileName == "powershell.exe"`)
	if len(result.LossyReasons) != 0 {
		t.Fatalf("representable nested expression was marked lossy: %v", result.LossyReasons)
	}
	if len(result.Rules) != 2 || len(result.Rules[0].Conditions)+len(result.Rules[1].Conditions) != 3 {
		t.Fatalf("expected two exact DNF branches, got %#v", result.Rules)
	}
}

func TestKQLComputedPredicateFailsClosed(t *testing.T) {
	query := `DeviceProcessEvents | where FileName == "cmd.exe" | where tolower(AccountName) == "admin"`
	result := FromKQL(query)
	if len(result.LossyReasons) == 0 {
		t.Fatalf("computed predicate was not marked lossy: %#v", result)
	}
}

func TestKQLTokenMatchingRequiresLossyOptIn(t *testing.T) {
	query := `DeviceProcessEvents | where ProcessCommandLine has "powershell"`
	result := FromKQL(query)
	if len(result.LossyReasons) == 0 {
		t.Fatalf("KQL token matching was not marked lossy: %#v", result)
	}
	if _, warnings, err := KQLModuleNamed(query, "token matching"); err == nil || !strings.Contains(strings.Join(warnings, " "), "--allow-lossy") {
		t.Fatalf("safe conversion must reject token matching: warnings=%v err=%v", warnings, err)
	}
}

func TestKQLSemanticPipelineStageFailsClosed(t *testing.T) {
	query := `DeviceProcessEvents | where FileName == "cmd.exe" | summarize count() by AccountName`
	result := FromKQL(query)
	if len(result.LossyReasons) == 0 || !strings.Contains(strings.Join(result.LossyReasons, " "), "summarize") {
		t.Fatalf("semantic pipeline stage was not marked lossy: %#v", result)
	}
}

func TestKQLGeneratedModulePassesSchemaValidation(t *testing.T) {
	doc, _, err := KQLModule(`DeviceProcessEvents
| where FileName == "cmd.exe"
| where ProcessCommandLine contains "/c"`)
	if err != nil {
		t.Fatal(err)
	}
	if findings := validate.Schema(doc, "generated"); validate.HasErrors(findings) {
		t.Fatalf("generated module failed schema validation: %#v", findings)
	}
}

func TestFromKQLGeneratesNetworkModule(t *testing.T) {
	result := FromKQL(`DeviceNetworkEvents
| where InitiatingProcessFileName == "rundll32.exe"
| where RemotePort == 4444`)
	if result.Event != "NetworkConnect" {
		t.Fatalf("expected NetworkConnect, got %s", result.Event)
	}
	if len(result.Conditions) != 2 {
		t.Fatalf("expected two conditions, got %#v", result.Conditions)
	}
}

func TestFromKQLMapsLocalAndRemoteNetworkPorts(t *testing.T) {
	result := FromKQL(`DeviceNetworkEvents
| where LocalPort == 51515
| where RemotePort == 443`)
	fields := map[string]string{}
	for _, condition := range result.Conditions {
		fields[condition.Field] = condition.Value
	}
	if fields["SourcePort"] != "51515" || fields["DestinationPort"] != "443" {
		t.Fatalf("unexpected port mappings: %#v", result.Conditions)
	}
}

func TestFromKQLResolvesRegistryDynamicList(t *testing.T) {
	result := FromKQL(`let RegistryRunKeys = dynamic ([
    @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"
]);
DeviceRegistryEvents
| where RegistryKey has_any (RegistryRunKeys)`)
	if result.Event != "RegistryEvent" || len(result.Conditions) != 1 {
		t.Fatalf("expected one multi-value registry condition, got %#v", result)
	}
	if result.Conditions[0].Field != "TargetObject" || result.Conditions[0].Operator != "contains any" ||
		!strings.Contains(result.Conditions[0].Value, ";") {
		t.Fatalf("unexpected registry condition: %#v", result.Conditions[0])
	}
}

func TestFromKQLMapsPathOperators(t *testing.T) {
	result := FromKQL(`DeviceImageLoadEvents
| where FolderPath startswith @"C:\Windows"
| where FileName endswith ".dll"`)
	if len(result.Conditions) != 2 {
		t.Fatalf("expected two image-load conditions, got %#v", result.Conditions)
	}
	operators := map[string]bool{}
	for _, condition := range result.Conditions {
		if condition.Field != "ImageLoaded" {
			t.Fatalf("unexpected path field: %#v", condition)
		}
		operators[condition.Operator] = true
	}
	if !operators["begin with"] || !operators["end with"] {
		t.Fatalf("unexpected path conditions: %#v", result.Conditions)
	}
}

func TestKQLListValuesBecomeORBranches(t *testing.T) {
	doc, warnings, err := KQLModuleNamed(`DeviceProcessEvents
| where FileName in~ ("bash.exe", "cmd.exe", "mshta.exe")`, "MSHTA Executions")
	if err != nil || len(warnings) != 0 {
		t.Fatalf("unexpected conversion result: warnings=%v err=%v", warnings, err)
	}
	out := doc.String()
	if strings.Contains(out, `<Rule groupRelation="and"`) {
		t.Fatalf("a pure KQL list must be emitted as OR siblings, got:\n%s", out)
	}
	for _, image := range []string{"bash.exe", "cmd.exe", "mshta.exe"} {
		if !strings.Contains(out, `<Image condition="image" name="MSHTA Executions">`+image+`</Image>`) {
			t.Fatalf("missing OR alternative %s:\n%s", image, out)
		}
	}
}

func TestKQLListCombinedWithPredicateExpandsToOROfANDRules(t *testing.T) {
	result := FromKQL(`DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe")
| where ProcessCommandLine contains " -enc ")`)
	if len(result.Rules) != 2 {
		t.Fatalf("expected two alternative rules, got %#v", result.Rules)
	}
	for _, rule := range result.Rules {
		if rule.GroupRelation != "and" || len(rule.Conditions) != 2 {
			t.Fatalf("expected an AND branch containing image and command line, got %#v", rule)
		}
	}
}

func TestKQLBooleanExpansionLimitSkipsOversizedResult(t *testing.T) {
	var values []string
	for i := 0; i < 17; i++ {
		values = append(values, `"tool`+string(rune('a'+i))+`.exe"`)
	}
	list := strings.Join(values, ", ")
	result := FromKQL("DeviceProcessEvents\n| where FileName in (" + list + ")\n| where InitiatingProcessFileName in (" + list + ")")
	if len(result.Rules) != 0 || !strings.Contains(strings.Join(result.Warnings, " "), "exceeds 256") {
		t.Fatalf("expected oversized expansion to be skipped, got %#v", result)
	}
}

func TestFromKQLIgnoresCommentedPredicates(t *testing.T) {
	result := FromKQL(`let OptionalProcesses = dynamic(["cmd.exe", "powershell.exe"]);
DeviceProcessEvents
| where InitiatingProcessFileName =~ "mshta.exe"
//| where FileName in~ (OptionalProcesses)
/* | where ProcessCommandLine contains "disabled" */`)
	if len(result.Rules) != 1 || len(result.Rules[0].Conditions) != 1 {
		t.Fatalf("commented predicates must not be converted: %#v", result.Rules)
	}
	if result.Rules[0].Conditions[0].Value != "mshta.exe" {
		t.Fatalf("unexpected active condition: %#v", result.Rules[0].Conditions)
	}
}

func TestKQLExplicitORBecomesAlternativeRules(t *testing.T) {
	doc, _, err := KQLModule(`DeviceProcessEvents
| where FileName =~ "cmd.exe" or FileName =~ "powershell.exe"`)
	if err != nil {
		t.Fatal(err)
	}
	out := doc.String()
	if strings.Contains(out, `<Rule groupRelation="and"`) {
		t.Fatalf("explicit KQL OR must not become an AND rule:\n%s", out)
	}
	if !strings.Contains(out, ">cmd.exe</Image>") || !strings.Contains(out, ">powershell.exe</Image>") {
		t.Fatalf("missing explicit OR alternatives:\n%s", out)
	}
}

func TestKQLAnyAndAllUseSysmonMultiValueConditions(t *testing.T) {
	result := FromKQL(`DeviceProcessEvents
| where ProcessCommandLine has_any (" -enc ", "FromBase64String")
| where ProcessCommandLine contains_all ("http", "download")`)
	if len(result.Rules) != 1 || len(result.Rules[0].Conditions) != 2 {
		t.Fatalf("expected one AND rule with two multi-value conditions, got %#v", result.Rules)
	}
	operators := map[string]string{}
	for _, condition := range result.Rules[0].Conditions {
		operators[condition.Operator] = condition.Value
	}
	if operators["contains any"] != " -enc ;FromBase64String" || operators["contains all"] != "http;download" {
		t.Fatalf("unexpected multi-value conditions: %#v", result.Rules[0].Conditions)
	}
	doc := ModuleFromRules(result.Event, result.Onmatch, result.Rules, "4.90")
	if !strings.Contains(doc.String(), `condition="contains any"> -enc ;FromBase64String`) ||
		!strings.Contains(doc.String(), `condition="contains all">http;download`) {
		t.Fatalf("multi-value conditions were not serialized correctly:\n%s", doc.String())
	}
}

func TestKQLMultiValueRejectsEmbeddedSemicolon(t *testing.T) {
	result := FromKQL(`DeviceProcessEvents
| where ProcessCommandLine has_any ("one;two", "three")`)
	if len(result.Rules) != 0 {
		t.Fatalf("an embedded semicolon cannot be represented safely as a Sysmon list: %#v", result.Rules)
	}
}

func TestFromKQLOnlyTranslatesWherePredicates(t *testing.T) {
	result := FromKQL(`let Commands = dynamic(["Get-Content", "Compress-Archive"]);
DeviceProcessEvents
| where ProcessCommandLine has_any (Commands)
| extend CommandParameter = case(
    ProcessCommandLine contains "Get-Content", "Get-Content",
    ProcessCommandLine contains "Compress-Archive", "Compress-Archive",
    "Other")
| summarize count() by CommandParameter`)
	if len(result.Rules) != 1 || len(result.Rules[0].Conditions) != 1 {
		t.Fatalf("non-filter expressions must not become Sysmon conditions: %#v", result.Rules)
	}
	condition := result.Rules[0].Conditions[0]
	if condition.Operator != "contains any" || condition.Value != "Get-Content;Compress-Archive" {
		t.Fatalf("unexpected translated where predicate: %#v", condition)
	}
}
