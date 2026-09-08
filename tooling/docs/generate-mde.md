# `generate-mde`

`generate-mde` reads an MDE JSON configuration and creates Sysmon modules that approximate its collection filters. Positive filter expressions become include rules. Negative expressions and configured exclusions become exclude rules. The command reports anything it cannot map exactly.

```text
sysmon-modular generate-mde [flags] [config.json]
```

`--mde-config <file>`

Sets the MDE JSON input. The default is `mde-config.json`. You may instead supply one positional path after all flags. Do not use both forms, and do not supply more than one positional path.

`--output-dir <directory>`

Sets the directory for generated modules. The default is `0_custom_configuration/generated_mde`. Files are split by Sysmon event and match direction, with names such as `include_mde_processcreate.xml` and `exclude_mde_processcreate.xml`.

`--area <name>`

Restricts generation to one telemetry area. Repeat it to select several. With no `--area`, every supported area is processed. Names are case-insensitive, and underscores may replace hyphens.

The [telemetry area table](#telemetry-areas) lists every accepted value and its
Sysmon event. The same selectors are available in `generate-mde-unfiltered`
and `generate-mde-inverse`.

`--allow-lossy`

Allows a fallback when an MDE filter cannot be translated exactly. Without this flag, the command skips that rule and prints why. With it, the command generates the available approximation and marks the rule as lossy in its summary. Some MDE telemetry, such as file-open visibility, has no exact Sysmon equivalent even when paths can be mapped to `FileCreate`.

`--dedup`

Loads current repository modules and omits generated rules with the same event, match direction, and normalized expression. It also removes duplicates produced during the current run. The command fails if no modules are found below `--base-path`.

`--base-path <directory>`

Sets the repository root used by `--dedup` to discover XML modules in numbered directories. It has no effect without `--dedup`.

## Telemetry areas

| Area | Sysmon event |
| --- | --- |
| `clipboard` | `ClipboardChange` |
| `dns-query` | `DnsQuery` |
| `driver-load` | `DriverLoad` |
| `file-create` | `FileCreate` |
| `file-delete` | `FileDeleteDetected` |
| `file-executable` | `FileExecutableDetected` |
| `file-stream-hash` | `FileCreateStreamHash` |
| `image-load` | `ImageLoad` |
| `named-pipe` | `PipeEvent` |
| `network-connection` | `NetworkConnect` |
| `process-access` | `ProcessAccess` |
| `process-creation` | `ProcessCreate` |
| `process-tampering` | `ProcessTampering` |
| `process-termination` | `ProcessTerminate` |
| `registry` | `RegistryEvent` |
| `remote-thread` | `CreateRemoteThread` |
| `wmi` | `WmiEvent` |

## Conversion behavior and limits

Known filter objects are decoded into typed recursive expressions. Supported
positive `and`/`or` expressions retain their grouping, and a single negated
predicate can become an exclusion. A process-and-path exclusion remains a
combined AND rule. Malformed objects, compound or embedded negation,
unsupported fields and operators, and expansions over 256 rules are skipped
by default with a concrete reason.

Sysmon cannot reproduce MDE aggregation, capping, some ETW-only providers,
memory details, signature-validation actions or file-open/read monitoring.
The summary records unsupported approximations as `lossy_rules`.
`--allow-lossy` permits fallback output for manual review. Every generated
module is schema-validated before writing.

Deduplication compares complete expressions, including the event, `onmatch`,
rule relations, fields, operators and values. Matching is case-insensitive,
ignores surrounding whitespace, display names and ATT&CK metadata, and does
not discard a multi-condition rule just because one condition already exists.
Duplicates within the current generation run are also removed; the summary
reports `duplicate_rules`.

All three MDE modes leave files from previous runs in place. Use a fresh or
area-specific output directory when changing selections or relying on
deduplication. The input is a JSON configuration you supply; these commands
do not retrieve tenant settings or deploy MDE collection rules.

## Examples

Convert the default configuration:

```bash
./sysmon-modular generate-mde
```

Generate process, registry, and DNS rules from a selected file:

```bash
./sysmon-modular generate-mde \
  --area process-creation \
  --area registry \
  --area dns-query \
  --output-dir ../0_custom_configuration/generated_mde \
  ./mde-settings.json
```

Allow fallback conversion and omit rules already present in the repository:

```bash
./sysmon-modular generate-mde \
  --mde-config ./mde-settings.json \
  --allow-lossy \
  --dedup \
  --base-path ..
```
