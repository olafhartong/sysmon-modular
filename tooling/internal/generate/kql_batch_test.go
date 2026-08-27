package generate

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

func TestExtractMarkdownKQLSeparatesPlatformsAndIgnoresOtherFences(t *testing.T) {
	content := `# Suspicious Command

Example:
` + "```PowerShell\nGet-Process\n```" + `

## Defender XDR
` + "```KQL\nDeviceProcessEvents\n| where FileName == \"cmd.exe\"\n```" + `

## Sentinel
` + "```\nDeviceNetworkEvents\n| where RemotePort == 4444\n```" + `
`
	rules := extractMarkdownKQL(content, "rule.md")
	if len(rules) != 2 {
		t.Fatalf("expected two KQL rules, got %#v", rules)
	}
	if rules[0].Name != "Suspicious Command" || rules[0].Platform != "defender" {
		t.Fatalf("unexpected Defender rule: %#v", rules[0])
	}
	if rules[1].Platform != "sentinel" {
		t.Fatalf("unexpected Sentinel rule: %#v", rules[1])
	}
}

func TestGenerateKQLDirectoryWritesOneModulePerDefenderRule(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	subdir := filepath.Join(input, "Threat Hunting")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	markdown := `# Process and Network Rule

## Defender XDR
` + "```KQL\nDeviceProcessEvents\n| where FileName == \"cmd.exe\"\n```" + `

## Sentinel
` + "```KQL\nDeviceNetworkEvents\n| where RemotePort == 4444\n```" + `
`
	if err := os.WriteFile(filepath.Join(subdir, "Mixed Rule.md"), []byte(markdown), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "direct.kql"), []byte("DeviceRegistryEvents\n| where RegistryKey contains \"HKLM\\Software\""), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := GenerateKQLDirectory(KQLDirectoryOptions{InputDir: input, OutputDir: output, Platform: "defender"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.QueriesFound != 3 || result.Stats.QueriesSelected != 2 || result.Stats.QueriesGenerated != 2 {
		t.Fatalf("unexpected stats: %#v", result.Stats)
	}
	processPath := filepath.Join(output, "Threat Hunting", "mixed-rule__defender.xml")
	assertFileContains(t, processPath, "<ProcessCreate", "cmd.exe", "Process and Network Rule (Defender XDR)")
	registryPath := filepath.Join(output, "direct__kql.xml")
	assertFileContains(t, registryPath, "<RegistryEvent", `HKLM\Software`)
	if _, err := os.Stat(filepath.Join(output, "Threat Hunting", "mixed-rule__sentinel.xml")); !os.IsNotExist(err) {
		t.Fatalf("Sentinel output should not be generated in Defender mode: %v", err)
	}
}

func TestGenerateKQLDirectoryPostsAnalyzerPayload(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
			return nil, err
		}
		if err := request.Body.Close(); err != nil {
			t.Errorf("close request body: %v", err)
			return nil, err
		}
		if payload["environment"] != "m365_with_sentinel" || payload["parser_profile"] != "current" {
			t.Errorf("unexpected analyzer payload: %#v", payload)
		}
		if !strings.Contains(payload["query"].(string), "DeviceProcessEvents") {
			t.Errorf("query missing from payload: %#v", payload)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"valid":true}`)),
		}, nil
	})}

	input := t.TempDir()
	if err := os.WriteFile(filepath.Join(input, "rule.kql"), []byte("DeviceProcessEvents\n| where FileName == \"powershell.exe\""), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := GenerateKQLDirectory(KQLDirectoryOptions{
		InputDir:  input,
		OutputDir: t.TempDir(),
		Platform:  "all",
		Analyzer:  &KQLAnalyzerOptions{URL: "http://analyzer.test/api/analyze", HTTPClient: client},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || result.Stats.QueriesAnalyzed != 1 || result.Stats.AnalyzerFailures != 0 {
		t.Fatalf("unexpected analyzer stats/calls: calls=%d stats=%#v warnings=%#v", calls.Load(), result.Stats, result.Warnings)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestGenerateKQLDirectoryContinuesWhenAnalyzerUnavailable(t *testing.T) {
	input := t.TempDir()
	if err := os.WriteFile(filepath.Join(input, "rule.kql"), []byte("DeviceProcessEvents\n| where FileName == \"cmd.exe\""), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := GenerateKQLDirectory(KQLDirectoryOptions{
		InputDir:  input,
		OutputDir: t.TempDir(),
		Analyzer:  &KQLAnalyzerOptions{URL: "http://127.0.0.1:1/api/analyze"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.QueriesGenerated != 1 || result.Stats.AnalyzerFailures != 1 {
		t.Fatalf("expected conversion with analyzer warning, got %#v", result)
	}
}

func TestGenerateKQLDirectoryReadsExtensionlessTextFiles(t *testing.T) {
	input := t.TempDir()
	if err := os.WriteFile(filepath.Join(input, "rule-without-extension"), []byte("DeviceProcessEvents\n| where FileName == \"cmd.exe\""), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := GenerateKQLDirectory(KQLDirectoryOptions{InputDir: input, OutputDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.FilesScanned != 1 || result.Stats.QueriesGenerated != 1 {
		t.Fatalf("expected extensionless KQL to be generated, got %#v", result.Stats)
	}
}

func TestGenerateKQLDirectorySkipsLossyQueriesByDefault(t *testing.T) {
	input := t.TempDir()
	query := "DeviceProcessEvents\n| where FileName == \"cmd.exe\"\n| where AccountName == \"admin\""
	if err := os.WriteFile(filepath.Join(input, "lossy.kql"), []byte(query), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := GenerateKQLDirectory(KQLDirectoryOptions{InputDir: input, OutputDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.QueriesLossy != 1 || result.Stats.QueriesSkipped != 1 || result.Stats.QueriesGenerated != 0 {
		t.Fatalf("lossy query must be skipped by default: %#v", result)
	}
	allowed, err := GenerateKQLDirectory(KQLDirectoryOptions{InputDir: input, OutputDir: t.TempDir(), AllowLossy: true})
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Stats.QueriesGenerated != 1 || allowed.Stats.QueriesLossy != 1 {
		t.Fatalf("explicit opt-in should permit lossy conversion: %#v", allowed)
	}
}

func TestGenerateKQLDirectoryAnnotatesConditionsFromMainTree(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	modules := filepath.Join(t.TempDir(), "1_process_creation")
	if err := os.MkdirAll(modules, 0o755); err != nil {
		t.Fatal(err)
	}
	existingPath := filepath.Join(modules, "include_shells.xml")
	existing := `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup groupRelation="or"><ProcessCreate onmatch="include"><Image condition="image">cmd.exe</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>`
	if err := os.WriteFile(existingPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "rule.kql"), []byte("DeviceProcessEvents\n| where FileName == \"cmd.exe\"\n| where ProcessCommandLine contains \"/c\""), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := GenerateKQLDirectory(KQLDirectoryOptions{
		InputDir: input, OutputDir: output, ExistingModules: []string{existingPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.ConditionsAnnotated != 1 {
		t.Fatalf("expected one existing condition annotation, got %#v", result.Stats)
	}
	generated := filepath.Join(output, "rule__kql.xml")
	assertFileContains(t, generated, `<Image condition="image">cmd.exe</Image> <!-- already present in main tree: 1_process_creation/include_shells.xml -->`)
	assertFileNotContains(t, generated, `<CommandLine condition="contains">/c</CommandLine> <!--`)
	if _, err := sysmonxml.ParseFile(generated, true); err != nil {
		t.Fatalf("annotated output is not valid XML: %v", err)
	}
}
