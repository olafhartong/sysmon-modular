# `generate-mde-inverse`

`generate-mde-inverse` turns MDE exclusions and negative filter branches into Sysmon include rules. The output highlights activity that MDE filtering may hide. It writes include-only modules and is intended for blind-spot review, not as a byte-for-byte recreation of MDE behavior.

```text
sysmon-modular generate-mde-inverse [flags] [config.json]
```

`--mde-config <file>`

Sets the MDE JSON input. The default is `mde-config.json`. You may supply one positional path after all flags instead. Using both input forms is an error.

`--output-dir <directory>`

Sets the generated-module directory. The default is `0_custom_configuration/generated_mde_inverse`. Every generated file uses `onmatch="include"`.

`--area <name>`

Restricts processing to one area and may be repeated. With no flags, every supported area is considered. Accepted values are `clipboard`, `dns-query`, `driver-load`, `file-create`, `file-delete`, `file-executable`, `file-stream-hash`, `image-load`, `named-pipe`, `network-connection`, `process-access`, `process-creation`, `process-tampering`, `process-termination`, `registry`, `remote-thread`, and `wmi`. Values are case-insensitive, and underscores are normalized to hyphens.

`--allow-lossy`

Allows a fallback when the inverse of an MDE filter cannot be represented exactly. Without it, the affected rule is skipped. With it, the generated approximation may cover more or less activity than the source filter, so review the warning and XML together.

`--dedup`

Omits generated include rules that already exist in repository modules below `--base-path`. The command fails if it cannot find any modules for comparison.

`--base-path <directory>`

Sets the repository root for `--dedup`. It is unused when deduplication is disabled.

See the shared [telemetry area mappings](generate-mde.md#telemetry-areas) and
[conversion limits](generate-mde.md#conversion-behavior-and-limits) for details.
Use a fresh output directory: files from previous runs are not removed.

## Example

Generate Sysmon coverage for process and file activity excluded by MDE:

```bash
./sysmon-modular generate-mde-inverse \
  --mde-config ./mde-settings.json \
  --area process-creation \
  --area file-create \
  --allow-lossy \
  --output-dir ../0_custom_configuration/generated_mde_inverse
```
