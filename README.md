# sysmon-modular | A Sysmon configuration repository for everybody to customise

[![license](https://img.shields.io/github/license/olafhartong/sysmon-modular.svg?style=flat-square)](https://github.com/olafhartong/sysmon-modular/blob/master/license.md)
![Maintenance](https://img.shields.io/maintenance/yes/2023.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/olafhartong/sysmon-modular.svg?style=flat-square)](https://github.com/olafhartong/sysmon-modular/commit/master)
![Build Sysmon config with all modules](https://github.com/olafhartong/sysmon-modular/workflows/Build%20Sysmon%20config%20with%20all%20modules/badge.svg)
[![Twitter](https://img.shields.io/twitter/follow/olafhartong.svg?style=social&label=Follow)](https://twitter.com/olafhartong)
[![Discord Shield](https://discordapp.com/api/guilds/715302469751668787/widget.png?style=shield)](https://discord.gg/B5n6skNTwy)

This is a Microsoft Sysinternals Sysmon [download here](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) configuration repository, set up modular for easier maintenance and generation of specific configs. 

Please keep in mind that any of these configurations should be considered a starting point, tuning per environment is **strongly** recommended.

The sysmonconfig.xml within the repo is automatically generated after a successful merge by the PowerShell script and a successful load by Sysmon in an Azure Pipeline run. More info on how to generate a custom config, incorporating your own modules [here](https://github.com/olafhartong/sysmon-modular/wiki/Configuration-options#generating-custom-configs)

## Pre-Grenerated configurations
| Type | Config | Description|
| --- | --- | --- |
| default | [sysmonconfig.xml](https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml) | This is the balanced configuration, most used, more information [here](https://github.com/olafhartong/sysmon-modular/wiki/Configuration-options#generating-the-default-configuration) |
| verbose | [sysmonconfig-excludes-only.xml](https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig-excludes-only.xml) |  This is the very verbose configuration, all events are included, only the exclusion modules are applied. This should not be used in production without validation, will generate a significant amount of data and might impact performance. More information [here](https://github.com/olafhartong/sysmon-modular/wiki/Configuration-options#generating-custom-configs)|
| super verbose | [sysmonconfig-research.xml](https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig-research.xml) | A configuration with extreme verbosity. The log volume expected from this file is significantly high, really DO NOT USE IN PRODUCTION! This config is only for research, this will use way more CPU/Memory. Only enable prior to running the to be investigated technique, when done load a lighter config. |
| MDE augment | [sysmonconfig-mde-augmentation.xml](https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig-mde-augment.xml) | A configuration to augment Defender for Endpoint, intended to augment the information and have as little overlap as possible. This is based on the default/balanced config and will *not generate all events* for Sysmon, there are comments in the config. In the benefit of IR, consider using the excludes only config and only ingest the enriching events. (Blog with more rationale soon)|

---

### Index

  * [Required actions](#required-actions)
    + [Customization](#customization)
    + [Generating a config](#generating-a-config)
      - [PowerShell](#powershell)
    + [Generating custom configs](#generating-custom-configs)
  * [Use](#use)
    + [Install](#install)
    + [Update existing configuration](#update-existing-configuration)
  * [Sysmon Community](#sysmon-community)
  * [Contributing](#contributing)
  * [More information](#more-information)
  * [Mitre ATT&CK](#mitre-attack)
  * [NOTICE Sysmon below 13 will not completely be compatible with this configuration](#notice-sysmon-below-13-will-not-completely-be-compatible-with-this-configuration)    
  
---

Next to the documentation below, there is also [a video](https://youtu.be/Cx_zrM8Hu7Y) on how to use this project.

[![how to use this project](https://img.youtube.com/vi/Cx_zrM8Hu7Y/0.jpg)](https://www.youtube.com/watch?v=Cx_zrM8Hu7Y)

---

## NOTICE; Sysmon below 13 will not completely be compatible with this configuration

Older versions are still available in the branches, but are not as complete as the current branch

- V8.x >> [here](https://github.com/olafhartong/sysmon-modular/tree/version-8)
- V9.x >> [here](https://github.com/olafhartong/sysmon-modular/tree/version-9)
- V10.4 >> [here](https://github.com/olafhartong/sysmon-modular/tree/v10.4)
- V12.x >> [here](https://github.com/olafhartong/sysmon-modular/tree/version-12)

To understand added features in the latest version, have a look at my [small blog post](https://medium.com/falconforce/sysmon-11-dns-improvements-and-filedelete-events-7a74f17ca842) or watch my [DerbyCon talk](http://www.irongeek.com/i.php?page=videos/derbycon9/stable-36-endpoint-detection-super-powers-on-the-cheap-with-sysmon-olaf-hartong)

**Note:**
I do recommend using a minimal number of configurations within your environment for multiple obvious reasons, like; maintenance, output equality, manageability and so on. But do make tailored configurations for Domain Controllers, Servers and workstations.

## Sysmon Community

There are three major Sysmon configurations:

- [@SwiftOnSecurity](https://twitter/com/SwiftOnSecurity):  great introductory walkthrough of many of the settings. Get started with 1 command **[https://github.com/SwiftOnSecurity/sysmon-config/](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)**.

- [@cyb3rops](https://twitter.com/cyb3rops):  A fork of SwiftOnSecurity, bleeding-edge and proactive. **[https://github.com/Neo23x0/sysmon-config](https://github.com/Neo23x0/sysmon-config)

- [@olafhartong](https://twitter.com/olafhartong): This repo, which focuses on being very maintainable with detailed rule notes for guided response and SIEM.
 
- An excellent community guide by [@Carlos_Perez](https:twitter.com/Carlos_Perez):
 [https://github.com/trustedsec/SysmonCommunityGuide](https://github.com/trustedsec/SysmonCommunityGuide)

## Contributing

Pull requests / issue tickets and new additions will be greatly appreciated!

## More information

I started a series of blog posts covering this repo;
- [Endpoint detection Superpowers on the cheap - part1 - MITRE ATT&CK, Sysmon and my modular configuration](https://medium.com/@olafhartong/endpoint-detection-superpowers-on-the-cheap-part-1-e9c28201ac47)
- [Endpoint detection Superpowers on the cheap — part 2 — Deploy and Maintain](https://medium.com/@olafhartong/endpoint-detection-superpowers-on-the-cheap-part-2-deploy-and-maintain-d06580329fe8)
- [Endpoint detection Superpowers on the cheap — part 3 — Sysmon Tampering](https://medium.com/@olafhartong/endpoint-detection-superpowers-on-the-cheap-part-3-sysmon-tampering-49c2dc9bf6d9)

- [A comparison between Sysmon and Microsoft Defender for Endpoint](https://medium.com/falconforce/sysmon-vs-microsoft-defender-for-endpoint-mde-internals-0x01-1e5663b10347) 

## MITRE ATTACK

I strive to map all configurations to the ATT&CK framework whenever Sysmon is able to detect it.
Please note this is a possible log entry that might lead to a detection, not in all cases is this the only telemetry for that technique. Additionally there might be more techniques releated to that rule, the one mapped is the one I deemed most likely.

---

## Required actions

I highly recommend looking at the configs before implementing them in your production environment. This enables you to have as actionable logging as possible and as litte noise as possible.

### Customization

You will need to install and observe the results of the configuration in your own environment before deploying it widely.
For example, you will need to exclude actions of your antivirus, which will otherwise likely fill up your logs with useless information.

### Generating a config

#### PowerShell

    $> git clone https://github.com/olafhartong/sysmon-modular.git
    $> cd sysmon modular
    $> . .\Merge-SysmonXml.ps1
    $> Merge-AllSysmonXml -Path ( Get-ChildItem '[0-9]*\*.xml') -AsString | Out-File sysmonconfig.xml

### Generating custom configs

Below functions with great thanks to mbmy

**New Function:** 
`Find-RulesInBasePath` - takes a base path (i.e. C:\folder\sysmon-modular\) and finds all candidate xml rule files based upon regex pattern

Example:
```PS C:\Users\sysmon\sysmon-modular> Find-RulesInBasePath -BasePath C:\users\sysmon\sysmon-modular\ -OutputRules | Out-File available_rules.txt```

**Merge-AllSysmonXml New Parameters:**

`-BasePath` - finds all candidate xml rule files from a provided path based upon regex pattern and merges them

Example:
```PS C:\Users\sysmon\sysmon-modular> Merge-AllSysmonXml -AsString -BasePath C:\Users\sysmon\sysmon-modular\```


`-ExcludeList` - Combined with -BasePath, takes a list of rules and excludes them from found rules prior to merge

Example:
```PS C:\Users\sysmon\sysmon-modular> Merge-AllSysmonXml -AsString -BasePath C:\Users\sysmon\sysmon-modular\ -ExcludeList C:\users\sysmon\sysmon-modular\exclude_rules.txt```


`-IncludeList` - Combined with -BasePath, finds all available rules from base path but only merges those defined in a list

Example:
```PS C:\Users\sysmon\sysmon-modular> Merge-AllSysmonXml -AsString -BasePath C:\Users\sysmon\sysmon-modular\ -IncludeList C:\users\sysmon\sysmon-modular\include_rules.txt```


**NOTE** The BasePath needs to be the full path to the sysmon-modular files (for example c:\tools\sysmon-modular), otherwise PowerShell will not be able to locate them, resulting in a default config.

Include/Exclude List Format Example:

```1_process_creation\exclude_adobe_acrobat.xml
3_network_connection_initiated\include_native_windows_tools.xml
12_13_14_registry_event\exclude_internet_explorer_settings.xml
12_13_14_registry_event\exclude_webroot.xml
17_18_pipe_event\include_winreg.xml
19_20_21_wmi_event\include_wmi_create.xml
2_file_create_time\exclude_chrome.xml
3_network_connection_initiated\include_native_windows_tools.xml
3_network_connection_initiated\include_ports_proxies.xml
8_create_remote_thread\include_general_commment.xml
8_create_remote_thread\include_psinject.xml
9_raw_access_read\include_general_commment.xml
```


**Building a config with all sysmon-modular rules for certain event IDs (include whole directory) and then disabling all event ids without imported rules**

Example:
```
# generate the config
$sysmonconfig =  Merge-AllSysmonXml  -BasePath . -IncludeList $workingFolder\include.txt -VerboseLogging -PreserveComments

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

```
1_process_creation
5_process_ended
11_file_create
23_file_delete
7_image_load
17_18_pipe_event
```

## Use

### Install

Run with administrator rights

    sysmon.exe -accepteula -i sysmonconfig.xml

### Update existing configuration

Run with administrator rights

    sysmon.exe -c sysmonconfig.xml
