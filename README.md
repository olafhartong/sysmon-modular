# sysmon-modular | A Sysmon configuration repository for everybody to customize

[![license](https://img.shields.io/github/license/olafhartong/sysmon-modular.svg?style=flat-square)](https://github.com/olafhartong/sysmon-modular/blob/master/license.md)

This is a Microsoft Sysinternals Sysmon configuration repository, set up modular for easier maintenance and generation of specific configs.

The sysmonconfig.xml within the repo is automatically generated after a successful merge by the PowerShell script and a successful load by Sysmon in an Azure Pipeline run.

This is a publicly available and maintained fork that should **NOT** be used in production unless it has been thoroughly tested in your environment and tuned to your needs. While the original fork from [Olaf Hartong](https://github.com/olafhartong/sysmon-modular/) is reliable and stable, this should be considered unstable with new features pushed more often as we make changes in our testing, but untested for tuning. 

**Note:**
We do recommend using a minimal number of configurations within your environment for multiple obvious reasons, like; maintenance, output equality, manageability, and so on.

## Credits
Most of this work was started and is still maintained by **[Olaf Hartong](https://github.com/olafhartong)**. He is creating stable and reliable configs on a very stable schedule as new versions of Sysmon are released.

Big credit goes out to SwiftOnSecurity for laying a great foundation and making this repo possible!
**[sysmonconfig-export.xml](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)**.

Equally a huge shoutout to **[Roberto Rodriguez](https://twitter.com/cyb3rward0g)** for his amazing work on the **[ThreatHunter-Playbook](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook.git)** and his contribution to the community on his **[blog](https://cyberwardog.blogspot.nl)**.

Final thanks to **[Mathias Jessen](https://twitter.com/iisresetme)** for his Merge script, without it, this project would not have worked as well.

## Contributing

Pull requests/issue tickets and new additions will be greatly appreciated!

## More information

We started a series of blog posts covering this repo;

- [Endpoint detection Superpowers on the cheap - part1 - MITRE ATT&CK, Sysmon and my modular configuration](https://medium.com/@olafhartong/endpoint-detection-superpowers-on-the-cheap-part-1-e9c28201ac47)
- [Endpoint detection Superpowers on the cheap — part 2 — Deploy and Maintain](https://medium.com/@olafhartong/endpoint-detection-superpowers-on-the-cheap-part-2-deploy-and-maintain-d06580329fe8)
- [Endpoint detection Superpowers on the cheap — part 3 — Sysmon Tampering](https://medium.com/@olafhartong/endpoint-detection-superpowers-on-the-cheap-part-3-sysmon-tampering-49c2dc9bf6d9)

## Mitre ATT&CK

We strive to map all configurations to the ATT&CK framework whenever Sysmon is able to detect it.
A current ATT&CK navigator export of all linked configurations is found [here](attack_matrix/Sysmon-modular.json) and can be viewed [here](https://mitre.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Folafhartong%2Fsysmon-modular%2Fmaster%2Fattack_matrix%2FSysmon-modular.json&scoring=false&clear_annotations=false)
![Mapping](attack_matrix/sysmon-modular.png)

## Required actions

We highly recommend looking at the configs before implementing them in your production environment. This enables you to have as actionable logging as possible and as little noise as possible.

### Customization

You will need to install and observe the results of the configuration in your own environment before deploying it widely.
For example, you will need to exclude actions of your antivirus, which will otherwise likely fill up your logs with useless information.

### Generating a config

#### PowerShell

    $> git clone https://github.com/olafhartong/sysmon-modular.git
    $> cd sysmon modular
    $> . .\Merge-SysmonXml.ps1
    $> Merge-AllSysmonXml -Path ( Get-ChildItem '[0-9]*\*.xml') -AsString | Out-File sysmonconfig.xml

## Use

### Install

Run with administrator rights

    sysmon.exe -accepteula -i sysmonconfig.xml

### Update existing configuration

Run with administrator rights

    sysmon.exe -c sysmonconfig.xml
