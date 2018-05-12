# sysmon-modular | A Sysmon configuration repository for everybody to customise

[![license](https://img.shields.io/github/license/olafhartong/sysmon-modular.svg?style=flat-square)](https://github.com/olafhartong/sysmon-modular/blob/master/license.md)
![Maintenance](https://img.shields.io/maintenance/yes/2018.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/olafhartong/sysmon-modular.svg?style=flat-square)](https://github.com/olafhartong/sysmon-modular/commit/master)

This is a Microsoft Sysinternals Sysmon configuration repository, set up modular for easier maintenance and generation of specific configs.

**Note:**
I do recommend using a minimal number of configurations within your environment for multiple obvious reasons, like; maintenance, output equality, manageability and so on.

Big credit goes out to SwiftOnSecurity for laying a great foundation and making this repo possible!
**[sysmonconfig-export.xml](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)**.

Equally a huge shoutout to **[Roberto Rodriguez](https://twitter.com/cyb3rward0g)** for his amazing work on the **[ThreatHunter-Playbook](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook.git)** and his contribution to the community on his **[blog](https://cyberwardog.blogspot.nl)**.

Final thanks to **[Matt Graeber](https://twitter.com/mattifestation)** for his PowerShell Modules, without them, this project would not have worked as well.

Pull requests / issue tickets and new additions will be greatly appreciated!

## Mitre ATT&CK

I strive to map all configurations to the ATT&CK framework whenever Sysmon is able to detect it.
A current ATT&CK navigator map of all linked configurations is found [here](attack_matrix/Sysmon-modular.json)
![Mapping](attack_matrix/sysmon-modular.png)

## Required actions

I highly recommend looking at the configs before implementing them in your production environment. This enables you to have as actionable logging as possible and as litte noise as possible.

### Prerequisites

Install the PowerShell modules from **[PSSysmonTools](https://github.com/mattifestation/PSSysmonTools)**

    git clone https://github.com/mattifestation/PSSysmonTools.git
    cd PSSysmonTools
    Import-Module .\PSSysmonTools.psm1

### Customization

You will need to install and observe the results of the configuration in your own environment before deploying it widely.
For example, you will need to exclude actions of your antivirus, which will otherwise likely fill up your logs with useless information.

### Generating a config

#### PowerShell

    git clone https://github.com/olafhartong/sysmon-modular.git
    cd sysmon modular
    Get-ChildItem -Path . -Filter *.xml -Recurse -ErrorAction SilentlyContinue | Merge-SysmonXMLConfiguration -ReferencePolicyPath .\baseconfig.xml | Out-File sysmonconfig.xml

Optionally you can omit the comments from the merged config with the “-ExcludeMergeComments” switch.

You can test your config if it's schema compliant

    Test-SysmonConfiguration .\sysmonconfig.xml

#### SysmonShell

This repository also was made available within **[SysmonShell](https://github.com/nshalabi/SysmonTools)** a great tool by **[Nader Shalabi](https://twitter.com/nader_shalabi)**

## Use

### Install

Run with administrator rights

    sysmon.exe -accepteula -i sysmonconfig.xml

### Update existing configuration

Run with administrator rights

    sysmon.exe -c sysmonconfig.xml

### Todo

- Link more indicators to Mitre ATT&CK techniques.
- Add / Improve comments
- Extend, extend, extend.
