# `generate-mde-unfiltered`

`generate-mde-unfiltered` reads the same MDE JSON input as [`generate-mde`](generate-mde.md), but creates broad include-only Sysmon modules for the telemetry families it finds. It ignores the narrowing effect of MDE filters. This is useful when the goal is maximum Sysmon collection for the selected event types.

```text
sysmon-modular generate-mde-unfiltered [flags] [config.json]
```

`--mde-config <file>`

Sets the input JSON. The default is `mde-config.json`. One positional path is accepted after all flags, but it cannot be combined with `--mde-config`.

`--output-dir <directory>`

Sets the generated-module directory. The default is `0_custom_configuration/generated_mde_unfiltered`. This mode writes include files only.

`--area <name>`

Restricts output to selected telemetry areas and may be repeated. With no area flags, all supported areas are processed. Accepted names are `clipboard`, `dns-query`, `driver-load`, `file-create`, `file-delete`, `file-executable`, `file-stream-hash`, `image-load`, `named-pipe`, `network-connection`, `process-access`, `process-creation`, `process-tampering`, `process-termination`, `registry`, `remote-thread`, and `wmi`. Matching is case-insensitive and accepts underscores in place of hyphens.

`--allow-lossy`

Is accepted for a consistent generator interface. In the current unfiltered mode, MDE rule filters are deliberately replaced with broad include rules, so this flag does not change their conversion.

`--dedup`

Omits generated rules already present in modules found below `--base-path`. The comparison includes the Sysmon event, include direction, and normalized expression. The command fails when module discovery returns no files.

`--base-path <directory>`

Sets the module discovery root for `--dedup`. It has no effect without that flag.

See the shared [telemetry area mappings](generate-mde.md#telemetry-areas) and
[deduplication details](generate-mde.md#conversion-behavior-and-limits).
Use a fresh output directory: files from previous runs are not removed.

## Example

Generate broad process and network collection modules:

```bash
./sysmon-modular generate-mde-unfiltered \
  --area process-creation \
  --area network-connection \
  --output-dir ../0_custom_configuration/generated_mde_unfiltered \
  ./mde-settings.json
```
