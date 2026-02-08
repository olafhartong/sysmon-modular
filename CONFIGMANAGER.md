# SysmonConfigManager

PowerShell tool for security teams to manage Sysmon XML configurations without hand-editing XML.

## The Problem

Sysmon generates massive log volume. Benign processes like `svchost.exe`, Windows Update, Chrome, Splunk forwarders, and AV products create thousands of events per hour. Teams either:

- Drown in noise and miss real threats
- Blindly copy exclusion rules from the internet without understanding them
- Hand-edit XML configs and break the schema
- Give up and run a config that's too broad or too narrow

## What This Tool Does

Feed it a real Sysmon event log entry. It tells you whether your config would capture or filter it. If it's noise, it generates the exact XML exclusion rule and inserts it into your config safely. No manual XML editing.

### Workflow

```
See noisy event in SIEM  -->  Paste event XML into tool  -->  Tool shows verdict
        |                                                          |
        v                                                          v
  "This is noise"                                    "INCLUDED by rule: Image=powershell.exe"
        |                                                          |
        v                                                          v
  Select fields to filter on  -->  Tool generates exclude rule  -->  Apply to config  -->  Export
```

## Quick Start

```powershell
# Interactive mode (menu-driven)
.\SysmonConfigManager.ps1

# Or dot-source for scripted use
. .\SysmonConfigManager.ps1

# Load your config
$cfg = Import-SysmonConfig -Path .\sysmonconfig.xml

# Import a sample event (paste XML or use the included samples)
$events = Import-SysmonEvent -Path .\samples\SampleEvents.xml

# See what the config does with each event
$events | Test-SysmonEvent -Config $cfg

# Generate an exclusion for a noisy event
$rule = New-SysmonExcludeRule -Event $events[0] -Fields Image,CommandLine
Format-SysmonRule -Rule $rule    # Preview the XML
Add-SysmonRule -Config $cfg -Rule $rule   # Apply it

# Export
Export-SysmonConfig -Config $cfg -Path .\sysmonconfig-tuned.xml
```

## Functions

| Function | Purpose |
|----------|---------|
| `Import-SysmonConfig` | Load a sysmon XML config file |
| `Import-SysmonEvent` | Parse event XML from string, file, or Windows Event Log |
| `Show-SysmonEvent` | Display event fields (highlights filterable fields) |
| `Test-SysmonEvent` | Check if event would be included/excluded by config |
| `New-SysmonExcludeRule` | Generate an exclusion rule from an event |
| `New-SysmonIncludeRule` | Generate an inclusion rule from an event |
| `New-SysmonRuleFromInput` | Create a rule manually (field/condition/value) |
| `Format-SysmonRule` | Preview rule as formatted XML |
| `Add-SysmonRule` | Insert rule into loaded config |
| `Remove-SysmonRule` | Remove matching rules from config |
| `Get-SysmonConfigStats` | Show rule counts per event type |
| `Find-NoisyEvents` | Analyze Windows Event Log for top noise sources |
| `Export-SysmonConfig` | Save modified config (auto-backup) |
| `Start-SysmonConfigManager` | Launch interactive menu |

## Condition Types

The tool auto-selects the best condition when generating rules:

| Condition | Use Case |
|-----------|----------|
| `is` | Exact match - command lines, paths, IPs, ports |
| `image` | Match just the filename from a full path (e.g., `svchost.exe`) |
| `contains` | Substring match - partial command lines |
| `begin with` | Path prefix - registry keys, file paths |
| `end with` | Domain suffixes, file extensions |
| `contains any` | Match any of semicolon-separated values |
| `contains all` | Match all of semicolon-separated values |

Override with `-Condition` parameter on any `New-Sysmon*Rule` function.

## Importing Events

### From the Windows Event Log (requires admin)
```powershell
$events = Import-SysmonEvent -FromEventLog -Count 50
$events = Import-SysmonEvent -FromEventLog -Count 100 -EventId 1  # Just process creation
```

### From copied XML (e.g., from Event Viewer or SIEM)
```powershell
$xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    ...
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\svchost.exe</Data>
    ...
  </EventData>
</Event>
'@
$event = Import-SysmonEvent -XmlString $xml
```

### From the included sample file
```powershell
$events = Import-SysmonEvent -Path .\samples\SampleEvents.xml
```

## Examples

### Silence a noisy process
```powershell
$cfg = Import-SysmonConfig -Path .\sysmonconfig.xml
$evt = Import-SysmonEvent -XmlString $noisyEventXml

# Exclude by process image name only
$rule = New-SysmonExcludeRule -Event $evt -Fields Image
Add-SysmonRule -Config $cfg -Rule $rule

# Exclude by image AND command line (more specific)
$rule = New-SysmonExcludeRule -Event $evt -Fields Image,CommandLine -GroupRelation and
Add-SysmonRule -Config $cfg -Rule $rule
```

### Add detection for suspicious activity
```powershell
$rule = New-SysmonRuleFromInput -EventType ProcessCreate -MatchType include `
    -FieldName CommandLine -Condition 'contains' -Value 'Invoke-Mimikatz' `
    -RuleName 'Mimikatz Detection'
Add-SysmonRule -Config $cfg -Rule $rule
```

### Bulk noise analysis (on a Windows box with Sysmon running)
```powershell
. .\SysmonConfigManager.ps1
Find-NoisyEvents -Count 1000 -TopN 20
```

## Sample Events

The `samples/SampleEvents.xml` file includes 10 realistic events covering:

1. Noisy svchost process creation
2. Suspicious encoded PowerShell execution
3. Windows Update network connection
4. Microsoft telemetry DNS query
5. Chrome cache file creation
6. Registry event log noise
7. Splunk forwarder process (IT tool noise)
8. Signed DLL image load
9. Suspicious LSASS process access (credential dumping)
10. PowerShell named pipe creation

Use these to test the tool before connecting to live event data.

## Requirements

- PowerShell 5.1+ (Windows PowerShell) or PowerShell 7+ (cross-platform for config editing)
- Windows Event Log access requires running as Administrator on a Sysmon-equipped Windows host
- The `sysmonconfig.xml` from this repository (or any Sysmon config using schema 4.30+)
