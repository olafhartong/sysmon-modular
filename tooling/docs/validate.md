# `validate`

`validate` checks one or more XML files. Syntax validation always runs. Structural Sysmon validation and ATT&CK metadata validation run by default, while executable-version compatibility is opt-in.

```text
sysmon-modular validate [flags]
```

At least one of `--path`, `--all`, or `--all-xml` is required. Selections are combined and duplicate paths are removed.

## File selection

`--path <file>`

Selects one XML file. Repeat it to validate several files. A directory is rejected with guidance to use `--all --base-path <directory>`.

`--all`

Selects repository modules only. These are `*.xml` files directly inside numbered directories below `--base-path`. The command fails when it finds no modules.

`--all-xml`

Recursively selects every file with an `.xml` extension below `--base-path`, except files inside `.git`. Use this for templates and other XML that does not follow the numbered module layout.

`--base-path <directory>`

Sets the root used by `--all` and `--all-xml`. It does not rewrite paths supplied through `--path`.

## Checks

`--schema <bool>`

Checks Sysmon structure, event names, fields, condition names, schema-version compatibility, and related structural rules. The default is `true`. Use `--schema=false` when you only want syntax, ATT&CK, or executable-version checks.

`--mitre <bool>`

Checks ATT&CK technique IDs and names stored in rule metadata. It reports unknown IDs, mismatched names, deprecated or revoked techniques, and other metadata issues. The default is `true`.

The full list of validation codes is in [`validate-rules.md`](validate-rules.md).

`--sysmon-version <12|13|14|15>`

Checks whether each document's events and fields are supported by the selected Sysmon executable. The default is empty, which skips executable-version compatibility checks.

`--unsupported <warn|exclude>`

Sets compatibility handling for `--sysmon-version`. `warn`, the default, reports unsupported items. `exclude` performs a dry-run removal and reports what would be excluded without writing the input file. `exclude` is invalid unless `--sysmon-version` is also supplied.

`--preserve-comments`

Keeps comments in the parsed document. This mainly matters when line mapping or rules depend on XML around comments. The command never rewrites the input.

## Reporting and failure policy

`--verbose`

Prints the relevant XML source line below each finding. Without it, findings include the file, code, message, and detail but omit source text.

`--warnings-as-errors`

Returns exit code `4` when any finding is present, not only an error-severity finding. This is useful for a strict CI policy. Without it, warnings, recommendations, and performance findings are reported but do not fail validation.

After processing, the command prints a severity summary and the number of validated files to standard error.

## Examples

Validate two modules with the default checks:

```bash
./sysmon-modular validate \
  --path ../1_process_creation/include_cmd.xml \
  --path ../3_network_connection_initiated/include_powershell.xml
```

Validate all repository modules against Sysmon 14 and fail on warnings:

```bash
./sysmon-modular validate \
  --base-path .. \
  --all \
  --sysmon-version 14 \
  --warnings-as-errors
```

Check syntax and ATT&CK metadata without structural schema checks:

```bash
./sysmon-modular validate --path ../module.xml --schema=false
```
