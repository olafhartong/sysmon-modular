# Contributing to sysmon-modular

Contributions of new detection rules, exclusion tuning, and bug fixes are welcome.

## Adding a New Rule

### 1. Choose the correct event directory

Place your XML file in the directory matching the Sysmon event type:

| Directory | Event Type |
|-----------|-----------|
| `1_process_creation/` | Process Create (Event ID 1) |
| `2_file_create_time/` | File Creation Time Changed (Event ID 2) |
| `3_network_connection_initiated/` | Network Connection (Event ID 3) |
| `5_process_ended/` | Process Terminated (Event ID 5) |
| `6_driver_loaded_into_kernel/` | Driver Loaded (Event ID 6) |
| `7_image_load/` | Image Loaded (Event ID 7) |
| `8_create_remote_thread/` | CreateRemoteThread (Event ID 8) |
| `9_raw_access_read/` | RawAccessRead (Event ID 9) |
| `10_process_access/` | Process Access (Event ID 10) |
| `11_file_create/` | File Create (Event ID 11) |
| `12_13_14_registry_event/` | Registry Events (Event ID 12/13/14) |
| `15_file_create_stream_hash/` | FileCreateStreamHash (Event ID 15) |
| `17_18_pipe_event/` | Pipe Events (Event ID 17/18) |
| `19_20_21_wmi_event/` | WMI Events (Event ID 19/20/21) |
| `22_dns_query/` | DNS Query (Event ID 22) |
| `23_file_delete/` | File Delete (Event ID 23) |

### 2. Name the file

Use the naming convention:
- **Exclusions:** `exclude_<descriptive_name>.xml` (e.g., `exclude_sophos_av.xml`)
- **Inclusions:** `include_<descriptive_name>.xml` (e.g., `include_lolbin_mshta.xml`)

### 3. Follow the XML template

Every rule file must be a valid standalone Sysmon config using schema version 4.30:

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Rule groupRelation="and">
          <Image condition="end with">example.exe</Image>
          <CommandLine condition="contains">expected_args</CommandLine>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Key points:
- Use `onmatch="exclude"` for noise suppression, `onmatch="include"` for detection
- Use `groupRelation="and"` within `<Rule>` blocks to combine conditions (reduces false positives)
- Use specific conditions (`end with`, `contains`, `begin with`) over broad ones where possible
- Replace the event element (`ProcessCreate`, `NetworkConnect`, etc.) to match your event type

### 4. Tag with MITRE ATT&CK (for include rules)

If your rule detects a known technique, add an ATT&CK technique attribute:

```xml
<RuleGroup name="technique_id=T1059.001,technique_name=PowerShell" groupRelation="or">
```

### 5. Test before submitting

Verify the config merges and loads:

```powershell
. .\Merge-SysmonXml.ps1
Merge-AllSysmonXml -Path (Get-ChildItem '[0-9]*\*.xml') -AsString | Out-File sysmonconfig-test.xml
sysmon.exe -c sysmonconfig-test.xml
```

Or use the SysmonConfigManager to test against sample events:

```powershell
. .\SysmonConfigManager.ps1
$cfg = Import-SysmonConfig -Path .\sysmonconfig-test.xml
$events = Import-SysmonEvent -Path .\samples\SampleEvents.xml
$events | Test-SysmonEvent -Config $cfg
```

## Exclusion Rule Guidelines

- Be as specific as possible. Exclude by multiple fields (Image + CommandLine + ParentImage) to avoid hiding real threats.
- Document what you are excluding and why in the PR description.
- Never exclude based solely on a process name that attackers commonly abuse (e.g., `powershell.exe`, `cmd.exe`, `rundll32.exe`).
- Prefer `end with` for executable names over `is` with full paths, since installation paths vary.

## Pull Request Process

1. Fork the repository and create a branch for your changes
2. Add or modify rules following the conventions above
3. Run the merge script to confirm no XML errors
4. Submit a PR with:
   - What the rule detects or excludes
   - Why the exclusion is safe (for exclude rules)
   - Any relevant MITRE ATT&CK technique IDs (for include rules)
   - The environment where this was tested

## Reporting Issues

If you find a rule that causes false positives or misses detections, open an issue with:
- The Sysmon event XML that was incorrectly handled
- The expected behavior (should it be included or excluded?)
- Your Sysmon version
