## Summary

What does this PR add or change?

## Rule Type

- [ ] New detection rule (include)
- [ ] New exclusion rule (exclude)
- [ ] Rule modification
- [ ] Bug fix
- [ ] Documentation
- [ ] Tooling (scripts, CI/CD)

## MITRE ATT&CK

Technique IDs (if applicable):

## Testing

- [ ] Config merges successfully with `Merge-SysmonXml.ps1`
- [ ] Tested with `SysmonConfigManager.ps1` against sample events
- [ ] Tested with Sysmon on a live/lab system

## Checklist

- [ ] XML follows the schema version 4.30 format
- [ ] File is named correctly (`include_*` or `exclude_*`)
- [ ] File is placed in the correct event type directory
- [ ] Exclusion rules are specific enough to not hide attacker activity
- [ ] PR description explains the rationale
