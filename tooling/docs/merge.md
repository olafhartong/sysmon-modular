# `merge`

`merge` combines Sysmon module XML files while keeping each `RuleGroup` intact. It can select modules directly, through text include and exclude lists, or from a priority file. By default it validates source syntax and the merged Sysmon structure, targets Sysmon 15, and writes XML to standard output.

```text
sysmon-modular merge [flags]
```

## Input selection

`--path <file>`

Adds an XML module. Repeat the flag to add more than one file. Relative paths are resolved below `--base-path` after list processing. When neither `--path` nor `--include-list` supplies input, the command discovers every `*.xml` file directly inside numbered directories below the base path.

`--base-path <directory>`

Sets the repository root used for automatic module discovery and relative module paths. It also supplies the default template location. See [the shared path rules](README.md#paths-and-output).

`--include-list <file>`

Reads module selections from a newline-delimited text file. Supplying this flag replaces any files selected with `--path` or `--file-list`. Empty lines and lines beginning with `#` are ignored. Each entry may name a file or a directory relative to `--base-path`. A directory entry selects the XML files directly inside that directory.

`--exclude-list <file>`

Removes matching files after input selection. It uses the same line format and path resolution as `--include-list`. If both lists select the same file, the exclude list wins and the command prints a warning.

`--file-list <file>`

Reads a priority-ordered list in CSV, TSV, or JSON form. CSV and TSV input must have `filepath` and `priority` headers. JSON input must be an array of objects with those fields. Higher integer priorities are merged first. Use `--format` when the file extension does not identify the format.

Example CSV:

```csv
filepath,priority
1_process_creation/include_living_off_the_land.xml,100
3_network_connection_initiated/include_native_windows_tools.xml,50
```

Example JSON:

```json
[
  {"filepath": "1_process_creation/include_living_off_the_land.xml", "priority": 100},
  {"filepath": "3_network_connection_initiated/include_native_windows_tools.xml", "priority": 50}
]
```

`--format <csv|tsv|json>`

Sets the `--file-list` format. The default is inferred from the file extension. This flag has no effect without `--file-list`.

## Merge behavior

`--template <file>`

Uses the supplied Sysmon configuration as the output base. The merger keeps the template's root settings, replaces its `EventFiltering` contents with merged rule groups, and updates `schemaversion`. Without this flag, it uses `<base-path>/templates/sysmon_template.xml` when that file exists. Otherwise it uses the built-in template.

`--preserve-comments`

Keeps XML comments from source modules and the template. The default is `false`, so comments are discarded while parsing.

`--force-grouprelation-or`

Changes every merged `RuleGroup` to `groupRelation="or"`. The default preserves each group's original relation. Use this only when you deliberately want to change how conditions inside all groups combine.

## Validation and compatibility

`--validate <bool>`

Runs XML syntax validation on every selected source before merging. The default is `true`. Use `--validate=false` to skip this pass.

`--schema-validate <bool>`

Checks the merged result for valid Sysmon events, fields, conditions, and structure. The default is `true`. This check runs after target-version processing.

`--sysmon-version <12|13|14|15>`

Targets a Sysmon executable version. The default is `15`. The command sets the output `schemaversion` to the schema associated with the selected executable and checks events and fields against that version.

`--unsupported <warn|exclude>`

Controls target-version incompatibilities. `warn`, the default, keeps unsupported events or fields and emits findings. `exclude` removes unsupported items from the merged document before output. This flag requires a valid `--sysmon-version`.

`--analyze`

Runs the configuration analyzer on the merged document. It adds recommendations, conflict findings, and performance findings to the normal validation output.

`--verbose`

Prints the source XML line for findings when the finding refers to a source file. Findings against the in-memory merged document have no source line to display.

`--warnings-as-errors`

Returns exit code `4` if the merge emits any finding or warning, including recommendations and list-resolution warnings. Without this flag, errors still fail the command, while non-error findings do not.

## Output

`--output <file|->`

Writes the merged XML to a file. The default, `-`, writes it to standard output.

## Supported Sysmon versions

The target is a Sysmon executable version, not the internal `binaryversion`
attribute in its manifest. The supplied Sysmon 14 and 15 manifests, for
example, use internal binary versions 17 and 18.

| Sysmon executable | Configuration schema | Notable additions |
| --- | --- | --- |
| 12.x | 4.40 | `ClipboardChange` |
| 13.0 | 4.50 | `ProcessTampering` |
| 13.1+ | 4.60 | `FileDeleteDetected` |
| 14.0 | 4.82 | `FileBlockExecutable` and user-attribution fields |
| 14.1+ | 4.83 | `FileBlockShredding` |
| 15.0–15.19 | 4.90 | `FileExecutableDetected` |
| 15.20+ | 4.91 | `DriverQueueSize` and `SigningQueueSize`; no event-filter changes |

Unsupported events and fields produce `SYS204`/`SYS205` warnings by default.
With `--unsupported exclude`, the merger removes incompatible items and drops
an event filter if compatibility processing removes all of its conditions.
Read the warnings and review the resulting collection before deployment.

Schema provenance: [Sysmon 13](https://gist.github.com/olafhartong/51eebe84b24c7f07069103945ce3ecbc),
[13.1](https://gist.github.com/olafhartong/42b93050b6e0f49742cc3ea151d97f12),
[14](https://gist.github.com/olafhartong/f3b68a92541758ec3990cda749fb091f),
[15](https://gist.github.com/olafhartong/328474bf273842c20a162c015f09bd61),
and Microsoft's [Sysmon 14.1 release notes](https://techcommunity.microsoft.com/blog/sysinternals-blog/sysmon-v14-1-coreinfo-v3-6-accessenum-v1-35-bginfo-v4-32-and-notmyfault-v4-21/3641271).

## Examples

Merge every repository module into a Sysmon 15 configuration:

```bash
./sysmon-modular merge --base-path .. --output ../sysmonconfig.xml
```

This selects `23_file_delete` along with the other modules. The balanced
release profile explicitly excludes that directory to avoid FileDelete
archiving.

Use the example include and exclude lists after editing them for your needs:

```bash
./sysmon-modular merge \
  --base-path .. \
  --include-list ../0_custom_configuration/example_include_rules.txt \
  --exclude-list ../0_custom_configuration/example_exclude_rules.txt \
  --output ../custom.xml
```

Save the CSV example above as `rules.csv`, then merge its selected modules:

```bash
./sysmon-modular merge \
  --base-path .. \
  --file-list rules.csv \
  --format csv \
  --template ../templates/sysmon_template.xml \
  --output ../custom.xml
```

Build a Sysmon 13 configuration and remove fields that version cannot consume:

```bash
./sysmon-modular merge \
  --base-path .. \
  --sysmon-version 13 \
  --unsupported exclude \
  --output ../sysmon-13.xml
```

Merge two selected modules and run the additional analyzer:

```bash
./sysmon-modular merge \
  --base-path .. \
  --path 1_process_creation/include_living_off_the_land.xml \
  --path 3_network_connection_initiated/include_native_windows_tools.xml \
  --analyze \
  --output ../selected.xml
```
