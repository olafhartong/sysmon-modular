# Legacy generators

The Go tooling is the supported generator for the current release workflow.
The PowerShell and Python scripts remain available for existing integrations.
See the [project README](../../README.md) for the current setup and workflows.

Run the examples on this page from the repository root unless a full path is
shown.

## PowerShell

Load the functions before using them:

```powershell
. ./scripts/Merge-SysmonXml.ps1
```

The PowerShell selection functions were contributed by mbmy.

`Find-RulesInBasePath` - takes a base path (i.e. C:\folder\sysmon-modular\) and finds all candidate xml rule files based upon regex pattern

Example:

```powershell
Find-RulesInBasePath -BasePath C:\users\sysmon\sysmon-modular\ -OutputRules | Out-File available_rules.txt
```

**Merge-AllSysmonXml selection parameters:**

`-BasePath` - finds all candidate xml rule files from a provided path based upon regex pattern and merges them

Example:

```powershell
Merge-AllSysmonXml -AsString -BasePath C:\Users\sysmon\sysmon-modular\
```


`-ExcludeList` - Combined with -BasePath, takes a list of rules and excludes them from found rules prior to merge

Example:

```powershell
Merge-AllSysmonXml -AsString -BasePath C:\Users\sysmon\sysmon-modular\ -ExcludeList C:\users\sysmon\sysmon-modular\exclude_rules.txt
```


`-IncludeList` - Combined with -BasePath, finds all available rules from base path but only merges those defined in a list

Example:

```powershell
Merge-AllSysmonXml -AsString -BasePath C:\Users\sysmon\sysmon-modular\ -IncludeList C:\users\sysmon\sysmon-modular\include_rules.txt
```


**NOTE** The BasePath needs to be the full path to the sysmon-modular files (for example c:\tools\sysmon-modular), otherwise PowerShell will not be able to locate them, resulting in a default config.

Include/Exclude List Format Example:

```text
1_process_creation\include_living_off_the_land.xml
3_network_connection_initiated\include_native_windows_tools.xml
11_file_create\include_ai_skill_files.xml
```


**Building a config with all sysmon-modular rules for certain event IDs (include whole directory) and then disabling all event ids without imported rules**

Create `include.txt` in the repository root with the event directories to
select, using the list format below. Then run:

```powershell
$workingFolder = (Get-Location).Path
# generate the config
$sysmonconfig = Merge-AllSysmonXml -BasePath $workingFolder -IncludeList $workingFolder\include.txt -VerboseLogging -PreserveComments

# flip off any rule groups where rules were not imported
foreach($rg in $sysmonconfig.SelectNodes("/Sysmon/EventFiltering/RuleGroup [*/@onmatch]"))
{
    $ruleNodes = $rg.SelectNodes("./* [@onmatch]")

    if(     $ruleNodes -eq $null `
        -or $ruleNodes.ChildNodes.count -gt 0)
    {
        # no rule nodes found (unlikely) or more than one rule found
        continue
    }

    # RuleGroup with only one rule node
    $ruleNode = $ruleNodes[0]

    if($ruleNode.onmatch -eq "exclude" -and $ruleNode.ChildNodes.count -eq 0 )
    {
        $message = "{0} {1} has no matching conditions.  Toggled to 'include' to limit output" -f $ruleNode.Name,$rg.Name
        Write-Warning $message

        $ruleNode.onmatch = "include"
        $comment = $sysmonconfig.CreateComment($message)
        $rg.AppendChild($comment) | Out-Null
    }
}
```

Include/Exclude List Format Example (for entire rule/event families):

```text
1_process_creation
5_process_ended
11_file_create
23_file_delete
7_image_load
17_18_pipe_event
```

## Python priority-list generator

The Python merger was contributed by [cnnrshd](https://github.com/cnnrshd).
It accepts CSV, TSV, or JSON priority lists with `filepath` and `priority`
fields, preserves XML comments, and writes indented XML. It can apply a base
configuration and derives the schema version from the input modules.

Review the paths in the bundled historical priority list and update them for
your checkout before using it. From the repository root:

```bash
python scripts/merge_sysmon_configs.py \
  scripts/config_lists/default_list/default_list.csv \
  -f csv \
  -b templates/sysmon_template.xml \
  -o test.xml
```

The script forces `RuleGroup` relations to `or` by default. Use
`--no-force-grouprelation-or` to preserve them. This differs from the Go
merger's default, which preserves each source group's relation.

This older script does not implement the Go workflow's target-version handling
or dedicated MDE-augment and excludes-only profiles. Review its output before
using it with a different Sysmon version.
