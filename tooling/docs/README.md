# Command-line reference

This is the detailed reference for the `sysmon-modular` tooling. Start with the
[project README](../../README.md) for downloads, installation, build version
1.0, common workflows and guidance on tuning a configuration for your
organisation.

## Using these examples

Examples in this directory run from **`tooling`**, unless a page explicitly
says otherwise. This differs from the repository-root examples in the project
README. After [building or downloading the binary](../../README.md#get-the-tooling),
change directory:

```bash
cd tooling
./sysmon-modular --version
```

On Windows, use `./sysmon-modular.exe`. If you prefer to build from within
`tooling`, use:

```bash
go build -o sysmon-modular ./cmd/sysmon-modular
```

Use `-o sysmon-modular.exe` on Windows. You can also replace
`./sysmon-modular` in these examples with `go run ./cmd/sysmon-modular`.
The separate `generate-mitre` utility has its own [build and update
instructions](generate-mitre.md).

## Commands

| Command | Purpose |
| --- | --- |
| [`merge`](merge.md) | Combine module XML files into one Sysmon configuration. |
| [`validate`](validate.md) | Check XML syntax, Sysmon structure, ATT&CK metadata, and executable compatibility. |
| [`verify`](verify.md) | Run `validate` through its compatibility alias. |
| [`fix-mitre`](fix-mitre.md) | Repair ATT&CK IDs and names in XML rule metadata. |
| [`analyze`](analyze.md) | Find invalid rules, conflicts, and performance risks in a configuration. |
| [`generate-kql`](generate-kql.md) | Convert supported KQL detections into Sysmon modules. |
| [`generate-mde`](generate-mde.md) | Convert MDE configuration filters into Sysmon include and exclude rules. |
| [`generate-mde-unfiltered`](generate-mde-unfiltered.md) | Create broad include-only rules for MDE telemetry areas. |
| [`generate-mde-inverse`](generate-mde-inverse.md) | Create include-only rules for telemetry hidden by MDE filters. |
| [`list-rules`](list-rules.md) | Print the module files discovered below a repository base path. |
| [`diff`](diff.md) | Compare two configurations by rule meaning rather than XML layout. |
| [`coverage`](coverage.md) | Report event, module, ATT&CK technique, and tactic coverage. |
| [`generate-mitre`](generate-mitre.md) | Rebuild the embedded ATT&CK technique table from STIX data. |
| [`version`](version.md) | Print the tool build version; also available as `--version`. |
| [`help`](help.md) | Print the command list or command-specific flag help. |

## Guides

- [Custom configuration examples](../../0_custom_configuration/README.md):
  include and exclude lists, Windows examples and the MDE-augment helper.
- [Supported Sysmon versions](merge.md#supported-sysmon-versions): executable
  and schema boundaries, with their source references.
- [Validation checks](validate-rules.md): finding codes, severities and when
  each check runs.
- [KQL conversion limits](generate-kql.md#supported-kql): exact operators,
  Boolean grouping and handling of lossy input.
- [MDE conversion limits](generate-mde.md#conversion-behavior-and-limits):
  telemetry areas, Boolean handling and deduplication.
- [Legacy generators](legacy-generators.md): the earlier PowerShell and Python
  workflows.
- [ATT&CK Navigator usage](../../attack_matrix/README.md).

## Flag syntax

The command parser accepts one or two leading hyphens, so `-output` and `--output` are equivalent. The documentation uses the two-hyphen form.

Boolean flags become true when supplied without a value. To turn off a flag whose default is true, use an explicit value:

```bash
./sysmon-modular validate --path ../module.xml --schema=false --mitre=false
```

Repeatable flags must appear once per value:

```bash
./sysmon-modular validate --path ../first.xml --path ../second.xml
```

Each command accepts `-h` or `--help`. Flags must appear after the command name.
For the MDE generators, place the optional positional config path after all flags. The parser stops reading flags when it reaches that path.

Top-level `--version` is an alias for the `version` command. The version is
also shown in top-level and command-specific help. `analyze`, `validate`, and
`verify` show finding line numbers by default; directory and multiple-file
validation also include the filename. `analyze` includes the affected source XML
by default. Use `--verbose` with `merge`, `validate`, or `verify` to include source
XML, or `--verbose=false` with `analyze` to omit it.

## Paths and output

`--base-path` defaults to the current directory when it contains numbered module directories. When the current directory does not contain them but its parent does, the default is the parent. This makes repository commands work from either the repository root or `tooling`.

Commands with `--output` use `-` for standard output. A file output is written through a temporary file and then renamed into place. Parent directories are created when needed.

Diagnostic messages, warnings, summaries, and generated-file lists go to standard error. This keeps standard output safe for XML, JSON, CSV, or text data that you want to pipe elsewhere.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | The command completed successfully. |
| `1` | An internal or unclassified error occurred. |
| `2` | The command or flag usage was invalid. |
| `3` | An input file, version, or other supplied value was invalid. |
| `4` | Validation, policy, or analysis findings caused failure. |

Set `NO_COLOR=1` to disable colored diagnostics. Set `FORCE_COLOR=1` to keep color when standard error is not attached to a terminal.
