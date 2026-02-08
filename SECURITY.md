# Security Policy

## Reporting a Vulnerability

If you discover a security issue with the Sysmon configuration rules in this repository (e.g., an exclusion rule that could be abused by attackers to evade detection), please report it responsibly.

**Do not open a public issue for security vulnerabilities.**

Instead, please email the maintainers directly or use GitHub's private vulnerability reporting feature.

### What qualifies as a security issue

- Exclusion rules that can be trivially abused to hide malicious activity
- Include rules that generate false confidence (appear to detect a technique but have easily bypassed conditions)
- Configuration settings that weaken Sysmon's detection capabilities
- Merge script issues that could produce an incorrect or incomplete config

### Response

We will acknowledge reports within 72 hours and aim to provide a fix or mitigation within 7 days for confirmed issues.

## Supported Versions

Only the latest version on the `master` branch is actively maintained. Older version branches (v8, v9, v10.4) are provided as-is.
