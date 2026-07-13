package validate

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/olafhartong/sysmon-modular/tooling/internal/sysmonxml"
)

// eventFields is the Sysmon for Windows event filtering schema. Keeping it in
// data form makes field/event validation deterministic and easy to version.
var eventFields = map[string]map[string]bool{
	"ProcessCreate":          fields("RuleName UtcTime ProcessGuid ProcessId Image FileVersion Description Product Company OriginalFileName CommandLine CurrentDirectory User LogonGuid LogonId TerminalSessionId IntegrityLevel Hashes ParentProcessGuid ParentProcessId ParentImage ParentCommandLine ParentUser"),
	"FileCreateTime":         fields("RuleName UtcTime ProcessGuid ProcessId Image TargetFilename CreationUtcTime PreviousCreationUtcTime User"),
	"NetworkConnect":         fields("RuleName UtcTime ProcessGuid ProcessId Image User Protocol Initiated SourceIsIpv6 SourceIp SourceHostname SourcePort SourcePortName DestinationIsIpv6 DestinationIp DestinationHostname DestinationPort DestinationPortName"),
	"ProcessTerminate":       fields("RuleName UtcTime ProcessGuid ProcessId Image User"),
	"DriverLoad":             fields("RuleName UtcTime ImageLoaded Hashes Signed Signature SignatureStatus"),
	"ImageLoad":              fields("RuleName UtcTime ProcessGuid ProcessId Image ImageLoaded FileVersion Description Product Company OriginalFileName Hashes Signed Signature SignatureStatus User"),
	"CreateRemoteThread":     fields("RuleName UtcTime SourceProcessGuid SourceProcessId SourceImage TargetProcessGuid TargetProcessId TargetImage NewThreadId StartAddress StartModule StartFunction SourceUser TargetUser"),
	"RawAccessRead":          fields("RuleName UtcTime ProcessGuid ProcessId Image Device User"),
	"ProcessAccess":          fields("RuleName UtcTime SourceProcessGUID SourceProcessId SourceThreadId SourceImage TargetProcessGUID TargetProcessId TargetImage GrantedAccess CallTrace SourceUser TargetUser"),
	"FileCreate":             fields("RuleName UtcTime ProcessGuid ProcessId Image TargetFilename CreationUtcTime User"),
	"RegistryEvent":          fields("RuleName EventType UtcTime ProcessGuid ProcessId Image TargetObject Details NewName User"),
	"FileCreateStreamHash":   fields("RuleName UtcTime ProcessGuid ProcessId Image TargetFilename CreationUtcTime Hash Contents User"),
	"PipeEvent":              fields("RuleName EventType UtcTime ProcessGuid ProcessId PipeName Image User"),
	"WmiEvent":               fields("RuleName EventType UtcTime Operation User EventNamespace Name Query Type Destination Consumer Filter"),
	"DnsQuery":               fields("RuleName UtcTime ProcessGuid ProcessId QueryName QueryStatus QueryResults Image User"),
	"FileDelete":             fields("RuleName UtcTime ProcessGuid ProcessId User Image TargetFilename Hashes IsExecutable Archived"),
	"ClipboardChange":        fields("RuleName UtcTime ProcessGuid ProcessId Image Session User ClientInfo Hashes Archived"),
	"ProcessTampering":       fields("RuleName UtcTime ProcessGuid ProcessId Image Type User"),
	"FileDeleteDetected":     fields("RuleName UtcTime ProcessGuid ProcessId User Image TargetFilename Hashes IsExecutable"),
	"FileBlockExecutable":    fields("RuleName UtcTime ProcessGuid ProcessId User Image TargetFilename Hashes"),
	"FileBlockShredding":     fields("RuleName UtcTime ProcessGuid ProcessId User Image TargetFilename Hashes IsExecutable"),
	"FileExecutableDetected": fields("RuleName UtcTime ProcessGuid ProcessId User Image TargetFilename Hashes"),
}

var eventMinSchema = map[string]string{
	"DnsQuery": "4.21", "FileDelete": "4.30", "ClipboardChange": "4.40",
	"ProcessTampering": "4.50", "FileDeleteDetected": "4.60",
	"FileBlockExecutable": "4.82", "FileBlockShredding": "4.83", "FileExecutableDetected": "4.90",
}

func fields(s string) map[string]bool {
	m := map[string]bool{}
	for _, field := range strings.Fields(s) {
		m[field] = true
	}
	return m
}

func validateSchemaFields(path, version string, root *sysmonxml.Node) []Finding {
	var out []Finding
	root.Walk(func(event *sysmonxml.Node) {
		allowed, ok := eventFields[event.Name]
		if !ok {
			return
		}
		if min := eventMinSchema[event.Name]; version != "" && min != "" && compareVersion(version, min) < 0 {
			out = append(out, Finding{Code: "SYS201", Severity: Warning, Path: path, Line: event.Line, Message: "event is newer than the declared module schema", Detail: fmt.Sprintf("%s requires schema %s or newer; module declares %s and may rely on the merged config version", event.Name, min, version)})
		}
		validateFieldsRecursive(path, event.Name, event, allowed, &out)
	})
	return out
}

func validateFieldsRecursive(path, event string, parent *sysmonxml.Node, allowed map[string]bool, out *[]Finding) {
	for _, child := range parent.ElementChildren() {
		if child.Name == "Rule" {
			validateFieldsRecursive(path, event, child, allowed, out)
			continue
		}
		if !allowed[child.Name] {
			*out = append(*out, Finding{Code: "SYS202", Severity: Error, Path: path, Line: child.Line, Message: "field is not valid for Sysmon event", Detail: event + "." + child.Name})
		}
		if strings.TrimSpace(child.Text) == "" {
			*out = append(*out, Finding{Code: "SYS203", Severity: Warning, Path: path, Line: child.Line, Message: "filter field has an empty value", Detail: event + "." + child.Name})
		}
	}
}

func compareVersion(a, b string) int {
	parse := func(v string) []int {
		p := strings.Split(v, ".")
		n := make([]int, len(p))
		for i, s := range p {
			n[i], _ = strconv.Atoi(s)
		}
		return n
	}
	aa, bb := parse(a), parse(b)
	for len(aa) < len(bb) {
		aa = append(aa, 0)
	}
	for len(bb) < len(aa) {
		bb = append(bb, 0)
	}
	for i := range aa {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}
