# sysmon-modular Go CLI

`sysmon-modular` is a Go implementation of the Sysmon-Modular merge, validation, analysis, and generation workflows. It uses only the Go standard library.

The Go module lives in the repository's `tooling` directory. Commands below
assume that `tooling` is the current directory; repository data is therefore
addressed through `..`.

When launched from `tooling`, repository-oriented commands automatically use
`..` as their default base path, so `verify --all` and `coverage --all` work
without an explicit `--base-path`.

## Build

```bash
go build ./cmd/sysmon-modular
```

Run without building:

```bash
go run ./cmd/sysmon-modular help
```

## Commands

Every command supports its own help, for example `sysmon-modular merge --help`.
Exit codes are stable: `0` success, `1` internal failure, `2` usage error,
`3` invalid input, and `4` validation or policy findings.

Interactive output uses color and grouped, wrapped findings. Set `NO_COLOR=1`
to disable ANSI colors, or `FORCE_COLOR=1` to retain them when output is not
connected directly to a terminal.

Use `--verbose` with `verify`, `validate`, `merge`, or `analyze` to print the
source XML line that triggered each finding.

### Merge modules

Merge all repository modules below numbered event folders:

```bash
go run ./cmd/sysmon-modular merge --base-path .. --output ../sysmonconfig.xml
```

Merge selected modules:

```bash
go run ./cmd/sysmon-modular merge \
	--base-path .. \
	--path 1_process_creation/include_living_off_the_land.xml \
	--path 3_network_connection_initiated/include_native_windows_tools.xml \
	--output ../custom.xml
```

Merge from include/exclude lists:

```bash
go run ./cmd/sysmon-modular merge \
	--base-path .. \
	--include-list ../0_custom_configuration/all_modules.txt \
	--exclude-list ../exclusions.txt \
	--output ../custom.xml
```

Merge from a priority CSV/TSV/JSON list:

```bash
go run ./cmd/sysmon-modular merge \
	--base-path .. \
	--file-list ../config_lists/default_list/default_list.csv \
  --format csv \
	--template ../templates/sysmon_template.xml \
	--output ../sysmonconfig.xml
```

Useful merge flags:

- `--validate`: run XML syntax validation before merge, default `true`.
- `--schema-validate`: run versioned Sysmon event and field validation on merged output, default `true`.
- `--sysmon-version`: target a Sysmon executable version from 12 through 15 (for example `12`, `13.1`, `14.1`, `15`, or `15.21`); merge defaults to Sysmon 15/schema 4.90.
- `--unsupported`: handle events and fields unavailable in the target version as `warn` (the default) or `exclude`.
- `--analyze`: emit conflict, best-practice, path, and performance recommendations.
- `--warnings-as-errors`: exit non-zero when validation or analysis findings are emitted.
- `--preserve-comments`: retain XML comments from source modules.
- `--force-grouprelation-or`: explicitly override every source `RuleGroup` relation with `or`; source grouping is preserved by default.

Merge always writes the schema version matching its target binary. With no
version flag it targets Sysmon 15.x and writes schema 4.90. For example,
`--sysmon-version 12` writes schema 4.40. The default `--unsupported warn`
behavior retains incompatible rules and
prints `SYS204`/`SYS205` warnings. `--unsupported exclude` removes incompatible
events and fields. If removing fields would leave a previously filtered event
empty, the event is also removed so it cannot become an unintended match-all
rule.

Known executable/schema snapshots:

| Sysmon executable | Configuration schema | Notable additions |
| --- | --- | --- |
| 12.x | 4.40 | `ClipboardChange` |
| 13.0 | 4.50 | `ProcessTampering` |
| 13.1+ | 4.60 | `FileDeleteDetected` |
| 14.0 | 4.82 | `FileBlockExecutable` and user-attribution fields |
| 14.1+ | 4.83 | `FileBlockShredding` |
| 15.0-15.19 | 4.90 | `FileExecutableDetected` |
| 15.20+ | 4.91 | `DriverQueueSize` and `SigningQueueSize` configuration options; no event-filter changes |

These are executable versions, not the internal `binaryversion` attribute from
the printed manifest. For example, the supplied Sysmon 14 and 15 manifests use
internal binary versions 17 and 18 respectively.

Schema provenance: [Sysmon 13](https://gist.github.com/olafhartong/51eebe84b24c7f07069103945ce3ecbc),
[13.1](https://gist.github.com/olafhartong/42b93050b6e0f49742cc3ea151d97f12),
[14](https://gist.github.com/olafhartong/f3b68a92541758ec3990cda749fb091f),
[15](https://gist.github.com/olafhartong/328474bf273842c20a162c015f09bd61),
and Microsoft's [Sysmon 14.1 release notes](https://techcommunity.microsoft.com/blog/sysinternals-blog/sysmon-v14-1-coreinfo-v3-6-accessenum-v1-35-bginfo-v4-32-and-notmyfault-v4-21/3641271).

### Validate modules

Validate all modules discovered below numbered event folders:

```bash
go run ./cmd/sysmon-modular validate --all --base-path ..
```

Validate every XML file below the repository, including generated configs:

```bash
go run ./cmd/sysmon-modular validate --all-xml --base-path ..
```

Validate specific files:

```bash
go run ./cmd/sysmon-modular validate \
  --path 1_process_creation/include_living_off_the_land.xml \
  --path 3_network_connection_initiated/include_native_windows_tools.xml
```

Check modules against an older installed binary:

```bash
go run ./cmd/sysmon-modular validate --all --base-path .. --sysmon-version 12
```

Validation uses warning mode by default. Passing `--unsupported exclude` is a
dry run: it reports the items that merge exclusion would remove but never
rewrites the input files. Pass `--warnings-as-errors` to make any finding
return a non-zero exit status, as used by the repository's PR workflow.

When validating generated directories, pass one `--path` per file:

```bash
args=()
for f in 0_custom_configuration/generated_mde/*.xml; do
  args+=(--path "$f")
done
go run ./cmd/sysmon-modular validate "${args[@]}"
```

MITRE ATT&CK technique metadata validation is enabled by default. It checks `name`
attributes containing `technique_id=...` and `technique_name=...` against the
embedded Enterprise ATT&CK table, flags retired or unknown IDs, catches
`technique=` typos, and verifies current technique names. Disable it with
`--mitre=false` when only XML/schema validation is needed.

### Fix MITRE metadata

Fix clear MITRE ATT&CK metadata issues in place:

```bash
go run ./cmd/sysmon-modular fix-mitre --all-xml --base-path ..
```

In an interactive terminal, each proposed replacement shows its file, line,
old value, and new value. Choose `y` or `n` for an individual change, `a` to
apply all remaining changes, or `q` to stop. Pressing Enter selects the default
of applying all remaining fixes. For scripts and CI, use `--yes` to apply all
fixes without prompting.

```bash
go run ./cmd/sysmon-modular fix-mitre --all --yes
```

Preview changes without writing:

```bash
go run ./cmd/sysmon-modular fix-mitre --all-xml --base-path .. --dry-run
```

`fix-mitre` updates retired IDs to their ATT&CK replacements, changes
`technique=` to `technique_id=`, and rewrites stale `technique_name` values to
the current Enterprise ATT&CK name. Incomplete placeholders such as
`technique_id=T,technique_name=` are reported for manual review.

### Analyze a config

```bash
go run ./cmd/sysmon-modular analyze --config ../sysmonconfig.xml
```

The analyzer reports:

- identical include/exclude conditions that can cancel visibility;
- best-practice recommendations such as hash configuration;
- native Windows binaries matched only by image name where full paths may be stronger;
- potentially high-volume or performance-impacting rules.

### Generate from KQL

Convert one MDE advanced hunting KQL file into a Sysmon module:

```bash
go run ./cmd/sysmon-modular generate-kql \
  --kql ../detections/suspicious_process.kql \
  --output ../generated_kql_module.xml
```

To crawl a directory recursively and write one module per translatable rule:

```bash
go run ./cmd/sysmon-modular generate-kql \
  --directory ./Hunting-Queries-Detection-Rules \
  --platform defender \
  --output-dir ../0_custom_configuration/generated_kql
```

Markdown files are split by fenced KQL block and by Defender XDR or Sentinel
section. Other UTF-8 text files, including extensionless query files, are
treated as standalone KQL. `--platform` accepts `defender` (the default),
`sentinel`, or `all`; unknown/unlabelled standalone queries are included in
every mode.

Optionally validate every selected query with an HTTP analyzer before local
conversion. Analyzer failures are reported but do not stop the remaining
files:

```bash
go run ./cmd/sysmon-modular generate-kql \
  --directory ./Hunting-Queries-Detection-Rules \
  --output-dir ../0_custom_configuration/generated_kql \
  --analyzer \
  --analyzer-url http://localhost:8080/api/analyze \
  --analyzer-environment m365_with_sentinel \
  --analyzer-profile current
```

The exact KQL subset is deliberately small. It supports Sysmon-relevant MDE
tables; literal `==`, `=~`, `in`, `in~`, `contains`, `contains_any`,
`contains_all`, `startswith`, and `endswith` predicates on fields that have an
event-specific Sysmon equivalent; literal `let` arrays; multiple `where`
stages; and nested `and`/`or` expressions with parentheses. Boolean precedence
and grouping are preserved. Expressions are normalized into Sysmon rules, with
a hard limit of 256 expanded branches.

KQL token operators (`has`, `has_any`, and `has_all`) are not in the exact
subset: KQL token matching is not equivalent to Sysmon substring matching.
Negation, computed predicates, unresolved lists, unsupported fields, joins,
aggregations, and row-changing pipeline operators are also lossy. These inputs
are skipped by default with the precise reason. `--allow-lossy` explicitly opts
into the legacy best-effort preview for output that will be reviewed manually.
Only `where` stages become Sysmon filters; later projection or display stages
do not create conditions. Every generated module is schema-validated before it
is written, and the command prints totals and a warning for each skipped query.

Use `--dedup` to compare generated conditions with the current repository
modules. Unlike MDE rule deduplication, KQL conditions are retained and receive
an inline XML comment identifying the existing module:

```bash
go run ./cmd/sysmon-modular generate-kql \
  --directory ./Hunting-Queries-Detection-Rules \
  --output-dir ../0_custom_configuration/generated_kql \
  --dedup \
  --base-path ..
```

The comparison includes the Sysmon event, include/exclude scope, field,
condition operator, and normalized value. The summary reports the number as
`conditions_annotated`.

### Generate from MDE config

The MDE generators analyze the full `mde-config.json` and emit Sysmon modules for Sysmon-supported telemetry families. Sysmon cannot express every MDE source, ETW provider, field, cap, aggregation, or file-open/read semantic, so unsupported rules and predicates are counted in the command summary.

Generate MDE-filtered visibility:

```bash
go run ./cmd/sysmon-modular generate-mde \
  --mde-config mde-config.json \
  --output-dir ../0_custom_configuration/generated_mde
```

This creates include and exclude modules. Known MDE filter objects are decoded
into typed recursive expressions before conversion. Positive `and`/`or`
expressions become Sysmon includes while preserving their Boolean meaning; a
single negated predicate can become a Sysmon exclude. A process-and-path
exclusion remains one AND rule. Malformed objects, compound or embedded
negation, unsupported fields or operators, and expansions over 256 rules are
skipped by default with a concrete reason. `--allow-lossy` opts into fallback
conversion for manual review.

#### Select MDE telemetry areas

Pass `--area` to process only one telemetry family instead of the complete MDE
configuration:

```bash
go run ./cmd/sysmon-modular generate-mde \
  --mde-config mde-config.json \
  --area process-creation \
  --output-dir ../0_custom_configuration/generated_mde_process
```

The flag is repeatable when a small set of areas is needed:

```bash
go run ./cmd/sysmon-modular generate-mde \
  --mde-config mde-config.json \
  --area image-load \
  --area registry \
  --output-dir ../0_custom_configuration/generated_mde_selected
```

When `--area` is omitted, all supported areas are processed. The selector is
available for `generate-mde`, `generate-mde-unfiltered`, and
`generate-mde-inverse`. Generation does not remove files left by an earlier
run, so use an empty or area-specific output directory when changing the
selection.

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

#### Deduplicate against current modules

Pass `--dedup` to write only generated rules that are not already represented
by the current repository modules. `--base-path` selects the repository whose
numbered module directories are searched and defaults to the repository found
from the current working directory.

```bash
go run ./cmd/sysmon-modular generate-mde \
  --mde-config mde-config.json \
  --area registry \
  --dedup \
  --base-path .. \
  --output-dir ../0_custom_configuration/generated_mde_registry_new
```

Deduplication requires an exact normalized semantic match of the event,
`onmatch` scope, rule relation, fields, condition operators, and values. Matching
is case-insensitive and ignores surrounding whitespace, display names, and ATT&CK metadata.
It deliberately does not remove a generated multi-condition rule when an
existing module contains only one of its conditions. The command reports the
number removed as `duplicate_rules`.

The option is available for `generate-mde`, `generate-mde-unfiltered`, and
`generate-mde-inverse`. Generation does not delete stale files in the output
directory; use a fresh output directory when relying on the deduplicated set.

Generate unfiltered MDE-style telemetry:

```bash
go run ./cmd/sysmon-modular generate-mde-unfiltered \
  --mde-config mde-config.json \
  --output-dir ../0_custom_configuration/generated_mde_unfiltered
```

This creates include-only modules for supported MDE telemetry families, without applying MDE filters.

Generate inverse MDE blind-spot coverage:

```bash
go run ./cmd/sysmon-modular generate-mde-inverse \
  --output-dir ../0_custom_configuration/generated_mde_inverse \
  /path/to/senseConfig.json
```

This creates include-only modules for supported MDE filter conditions. The intent is to surface telemetry that MDE filters out.

All three MDE generator commands accept the config path either as their single positional argument or through `--mde-config`. If neither is supplied, they read `mde-config.json`.

Generated MDE modules use `RuleGroup` elements and nested `Rule groupRelation="and"` entries where translated MDE filters require grouped conditions.

### List available rules

```bash
go run ./cmd/sysmon-modular list-rules --base-path ..
```

### Compare configurations

Produce a semantic comparison that identifies added and removed complete
expressions and reports changed ATT&CK technique coverage. Expression changes
are labelled with `unknown` impact unless the Boolean context proves whether
telemetry widened or narrowed:

```bash
go run ./cmd/sysmon-modular diff \
  --before ../sysmonconfig-old.xml \
  --after ../sysmonconfig.xml \
  --format json \
  --output ../diff.json
```

### Report coverage

Report coverage by Sysmon event, ATT&CK technique and tactic, source module,
and include/exclude balance. Formats are `text`, `json`, `csv`, and
`navigator` (an ATT&CK Navigator layer):

```bash
go run ./cmd/sysmon-modular coverage --base-path .. --path ../sysmonconfig.xml
go run ./cmd/sysmon-modular coverage --base-path .. --all --format csv --output ../coverage.csv
go run ./cmd/sysmon-modular coverage --base-path .. --all --format navigator --output ../coverage-layer.json
```

Technique names and tactics come from the embedded Enterprise ATT&CK 19.1 STIX
bundle. Techniques assigned to more than one tactic retain every assignment.
`unmapped` is reserved for unknown IDs or STIX techniques without a tactic.

## MDE Conversion Limits

The generator maps only what Sysmon can represent with its event schema and filtering model. Examples:

- MDE create process rules map to `ProcessCreate`.
- MDE network connection rules map to `NetworkConnect`.
- MDE image/module load rules map to `ImageLoad` or `DriverLoad`.
- MDE file path rules map primarily to `FileCreate`, `FileDeleteDetected`, or `FileExecutableDetected`.
- MDE registry monitoring maps to `RegistryEvent`.
- MDE DNS rules map to `DnsQuery`.

MDE features such as aggregation, capping, compound negation, some ETW-only
providers, memory details, signature-validation actions, file-open/read
monitoring, and many internal MDE fields do not have exact Sysmon equivalents.
Unsafe filter approximations and Boolean expansions over 256 rules are skipped
by default, explained in warnings, and counted as `lossy_rules`.
`--allow-lossy` permits fallback output when a manual review is planned.

## Test

```bash
go test ./...
```
