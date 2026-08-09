# Verify Rules

`sysmon-modular verify` is an alias for `sysmon-modular validate`. It checks XML
syntax first and, for files that parse successfully, runs structural Sysmon and
MITRE ATT&CK validation by default. Compatibility rules are added when
`--sysmon-version` is provided.

Errors always make verification fail. Warnings are reported but only make the
command fail when `--warnings-as-errors` is used.

| Rule | Severity | Enabled when | Description |
| --- | --- | --- | --- |
| `XML001` | Error | Always | The file cannot be read or parsed as well-formed XML. When possible, the finding includes the XML parser's line number and error. No further rules are evaluated for that file. |
| `SYS001` | Error | `--schema=true` (default) | The parsed XML document has no root element. |
| `SYS002` | Error | `--schema=true` (default) | The root element is not `<Sysmon>`. |
| `SYS003` | Warning | `--schema=true` (default) | The `<Sysmon>` root is missing its `schemaversion` attribute. |
| `SYS004` | Warning | `--schema=true` (default) | `<EventFiltering>` is missing, but the document still contains legacy-layout `<RuleGroup>` elements. The rule groups continue to be validated. |
| `SYS005` | Error | `--schema=true` (default) | `<EventFiltering>` is missing and no legacy-layout `<RuleGroup>` elements are present. |
| `SYS101` | Error | `--schema=true` (default) | A `<RuleGroup>` has a `groupRelation` other than `and`, `or`, or an omitted value. Matching is case-insensitive. |
| `SYS102` | Error | `--schema=true` (default) | A child of `<RuleGroup>` is not a recognized Sysmon event-filtering element. |
| `SYS103` | Error | `--schema=true` (default) | A Sysmon event has an `onmatch` value other than `include`, `exclude`, or an omitted value. Matching is case-insensitive. |
| `SYS104` | Error | `--schema=true` (default) | `<EventFiltering>` contains a direct child other than `<RuleGroup>`. |
| `SYS105` | Error | `--schema=true` (default) | A nested `<Rule>` has a `groupRelation` other than `and`, `or`, or an omitted value. Matching is case-insensitive. |
| `SYS106` | Warning | `--schema=true` (default) | A filter field uses an unknown condition operator. |
| `SYS107` | Error | `--schema=true` (default) | A filter value contains `;`, indicating multiple values, but its condition is not multi-value capable. Accepted multi-value conditions are `is any`, `contains any`, `contains all`, `excludes any`, and `excludes all`. |
| `SYS201` | Warning | `--schema=true` (default) | An event requires a newer schema than the module's declared `schemaversion`. |
| `SYS202` | Error | `--schema=true` (default) | A filter field is not valid for the Sysmon event that contains it. |
| `SYS203` | Warning | `--schema=true` (default) | A filter field has an empty or whitespace-only value. |
| `SYS204` | Warning | `--sysmon-version` is set | An event is unsupported by the selected Sysmon executable. With `--unsupported=exclude`, the message reports that the event would be excluded. |
| `SYS205` | Warning | `--sysmon-version` is set | A field is unsupported by the selected Sysmon executable. With `--unsupported=exclude`, the message reports that the field would be excluded. |
| `SYS206` | Warning | `--sysmon-version` and `--unsupported=exclude` | Removing unsupported fields would leave a previously filtered event empty, so the event would also be excluded to avoid an unintended match-all rule. Verification is a dry run and does not rewrite the source file. |
| `MITRE_MALFORMED` | Error | `--mitre=true` (default) | A `name` attribute that appears to contain ATT&CK metadata has a missing, incomplete, or malformed `technique_id`, or is missing `technique_name`. IDs must use `T####` or `T####.###`. |
| `MITRE_UNKNOWN_ID` | Error | `--mitre=true` (default) | A technique ID is not present in the embedded Enterprise ATT&CK table. |
| `MITRE_RETIRED_ID` | Error | `--mitre=true` (default) | A technique ID is revoked or deprecated. The finding includes a replacement when one is known. |
| `MITRE_ATTRIBUTE_KEY` | Error | `--mitre=true` (default) | ATT&CK metadata uses `technique=` instead of the required `technique_id=` key. |
| `MITRE_NAME_MISMATCH` | Error | `--mitre=true` (default) | `technique_name` does not match the current Enterprise ATT&CK name for the supplied ID. Parent-and-sub-technique name forms using a colon or hyphen are also accepted. |

## Running verification

Verify all source modules and fail on warnings:

```bash
./sysmon-modular verify --all --warnings-as-errors
```

Include compatibility checks for a target Sysmon release:

```bash
./sysmon-modular verify \
  --all \
  --sysmon-version 15.21 \
  --warnings-as-errors
```

Disable an optional validation family when troubleshooting:

```bash
./sysmon-modular verify --all --schema=false
./sysmon-modular verify --all --mitre=false
```

Use `--verbose` to print the source XML line associated with each finding.
