# Sysmon-Modular Go Tooling

The `sysmon-modular` command-line tool validates, merges, analyzes, compares,
and reports on the XML modules in this repository. It can also generate Sysmon
modules from supported KQL and Microsoft Defender for Endpoint (MDE) inputs.

The tool requires Go 1.22 or newer and uses only the Go standard library.

## Build

From the repository root:

```bash
cd tooling
go test ./...
go build -o sysmon-modular ./cmd/sysmon-modular
```

This creates `tooling/sysmon-modular`. Confirm the build and list the available
commands with:

```bash
./sysmon-modular help
```

You can also run the tool without creating a binary:

```bash
go run ./cmd/sysmon-modular help
```

The examples below assume the current directory is `tooling`. Repository paths
therefore start with `..`. When run here, repository-oriented commands also use
`..` as their default base path.

## Common workflows

Validate every source module:

```bash
./sysmon-modular validate --all --warnings-as-errors
```

Validate all XML files, including complete generated configurations:

```bash
./sysmon-modular validate --all-xml --warnings-as-errors
```

Validate one file against a specific Sysmon version:

```bash
./sysmon-modular validate \
  --path ../1_process_creation/include_living_off_the_land.xml \
  --sysmon-version 15.21
```

Merge all source modules into a configuration:

```bash
./sysmon-modular merge \
  --base-path .. \
  --template ../templates/sysmon_template.xml \
  --sysmon-version 15.21 \
  --preserve-comments \
  --output ../sysmonconfig.xml
```

Merge only selected modules by repeating `--path`:

```bash
./sysmon-modular merge \
  --base-path .. \
  --path 1_process_creation/include_living_off_the_land.xml \
  --path 3_network_connection_initiated/include_native_windows_tools.xml \
  --output ../custom.xml
```

Analyze a complete configuration for conflicts, noisy rules, and recommended
improvements:

```bash
./sysmon-modular analyze --config ../sysmonconfig.xml
```

Compare two configurations semantically:

```bash
./sysmon-modular diff \
  --before ../sysmonconfig-old.xml \
  --after ../sysmonconfig.xml
```

Report coverage across all source modules:

```bash
./sysmon-modular coverage --all
```

List the source modules discovered by the tool:

```bash
./sysmon-modular list-rules
```

Generate modules for only one MDE telemetry area:

```bash
./sysmon-modular generate-mde \
  --mde-config mde-config.json \
  --area process-creation \
  --output-dir ../0_custom_configuration/generated_mde_process
```

`--area` is optional and may be repeated. Without it, every supported area is
processed. Common values include `process-creation`, `image-load`, `registry`,
`network-connection`, `dns-query`, and `file-create`. Run
`./sysmon-modular generate-mde --help` for flag details; the complete list is
in the [command reference](cmd/sysmon-modular/README.md#select-mde-telemetry-areas).
Generation does not delete old files, so use an empty or area-specific output
directory when changing the selection.

Add `--dedup` to omit rules already present in the repository's current
numbered module directories:

```bash
./sysmon-modular generate-mde \
  --mde-config mde-config.json \
  --area registry \
  --dedup \
  --base-path .. \
  --output-dir ../0_custom_configuration/generated_mde_registry_new
```

Deduplication compares complete normalized rules, including their Sysmon event
and include/exclude scope. It ignores rule display names and ATT&CK annotations.

KQL and filtered MDE conversion fail closed when a filter cannot be represented
without changing its meaning. The command reports the skipped input. Use
`--allow-lossy` only when partial or fallback output is intentional and will be
reviewed manually. Every generated module is schema-validated before it is
written.

## Command help

Each command has its own help output. Consult it before scripting less common
workflows or generation commands:

```bash
./sysmon-modular merge --help
./sysmon-modular validate --help
./sysmon-modular generate-kql --help
./sysmon-modular generate-mde --help
```

The available commands are:

- `merge`: combine module XML files into a complete configuration.
- `validate` / `verify`: check XML syntax, Sysmon schema, compatibility, and
  MITRE ATT&CK metadata.
- `fix-mitre`: preview or apply supported ATT&CK metadata corrections.
- `analyze`: find conflicts and configuration or performance concerns.
- `generate-kql`: convert one KQL file, or recursively extract fenced and
  standalone KQL from a directory and write one Sysmon module per supported
  rule. Directory mode can select Defender, Sentinel, or all query sections
  and can optionally validate queries with a configurable HTTP analyzer. Its
  deduplication check annotates conditions already present in the main tree.
- `generate-mde`, `generate-mde-unfiltered`, and `generate-mde-inverse`:
  generate modules from an MDE configuration.
- `list-rules`: list discovered repository modules.
- `diff`: compare the effective filters and ATT&CK coverage of two configs.
- `coverage`: report event, module, include/exclude, and ATT&CK coverage.

Use `--verbose` with validation and analysis commands to include the relevant
source XML line in each finding. Use `NO_COLOR=1` to disable colored terminal
output.

Exit codes are stable for automation:

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 1 | Internal failure |
| 2 | Invalid command usage |
| 3 | Invalid input |
| 4 | Validation or policy findings |

For the complete command and generator reference, see
[`cmd/sysmon-modular/README.md`](cmd/sysmon-modular/README.md). For a complete
table of checks performed by `validate` and its `verify` alias, see
[`rules.md`](rules.md).
