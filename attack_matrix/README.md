# MITRE ATT&CK matrix

Sysmon Modular rule metadata maps detections to the [MITRE ATT&CK knowledge base](https://attack.mitre.org/). The Go coverage command reads technique names and tactic assignments from embedded Enterprise ATT&CK 19.1 STIX data.

`Sysmon-modular.json` is the ATT&CK Navigator layer template. The configuration workflow fills the template from the validated Sysmon 15.21 default configuration and publishes `attack-matrix-15.21.json` with each release. The published layer is the exact file validated by the workflow and covered by the release checksum manifest.

Open the published layer in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to explore the current coverage matrix.

![docs](https://github.com/olafhartong/sysmon-modular/blob/master/attack_matrix/demo.gif)
