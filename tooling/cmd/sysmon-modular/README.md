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
rewrites the input files.

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

Convert simple MDE advanced hunting KQL conditions into a Sysmon module:

```bash
go run ./cmd/sysmon-modular generate-kql \
  --kql ../detections/suspicious_process.kql \
  --output ../generated_kql_module.xml
```

The KQL converter supports common table and predicate patterns such as `DeviceProcessEvents`, `DeviceNetworkEvents`, equality, `in`, `contains`, `has`, and basic port/path/registry predicates. Complex KQL logic may need manual tuning after generation.

### Generate from MDE config

The MDE generators analyze the full `mde-config.json` and emit Sysmon modules for Sysmon-supported telemetry families. Sysmon cannot express every MDE source, ETW provider, field, cap, aggregation, or file-open/read semantic, so unsupported rules and predicates are counted in the command summary.

Generate MDE-filtered visibility:

```bash
go run ./cmd/sysmon-modular generate-mde \
  --mde-config mde-config.json \
  --output-dir ../0_custom_configuration/generated_mde
```

This creates include and exclude modules. Positive MDE predicates become Sysmon includes. MDE negative filters and exclusions become Sysmon excludes where the event and fields are supported.

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
  --mde-config mde-config.json \
  --output-dir ../0_custom_configuration/generated_mde_inverse
```

This creates include-only modules for supported MDE filter conditions. The intent is to surface telemetry that MDE filters out.

Generated MDE modules use `RuleGroup` elements and nested `Rule groupRelation="and"` entries where translated MDE filters require grouped conditions.

### List available rules

```bash
go run ./cmd/sysmon-modular list-rules --base-path ..
```

### Compare configurations

Produce a semantic comparison that identifies added and removed filters,
classifies their telemetry impact as widened or narrowed, and reports changed
ATT&CK technique coverage:

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

## MDE Conversion Limits

The generator maps only what Sysmon can represent with its event schema and filtering model. Examples:

- MDE create process rules map to `ProcessCreate`.
- MDE network connection rules map to `NetworkConnect`.
- MDE image/module load rules map to `ImageLoad` or `DriverLoad`.
- MDE file path rules map primarily to `FileCreate`, `FileDeleteDetected`, or `FileExecutableDetected`.
- MDE registry monitoring maps to `RegistryEvent`.
- MDE DNS rules map to `DnsQuery`.

MDE features such as aggregation, capping, some ETW-only providers, memory details, signature-validation actions, file-open/read monitoring, and many internal MDE fields do not have exact Sysmon equivalents. Those are skipped or approximated with warnings and summary counters.

## Test

```bash
go test ./...
```
