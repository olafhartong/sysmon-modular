package generate

import (
	"strings"
	"testing"
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
