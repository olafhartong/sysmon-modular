# Custom configuration examples

These files show how to select modules with the `sysmon-modular` merger. Paths are relative to the repository root. Blank lines and lines beginning with `#` are ignored.

## Small custom configuration

`example_include_rules.txt` selects a small set of useful modules. It also demonstrates that a directory entry selects every XML module directly inside that event directory.

`example_exclude_rules.txt` removes noisy modules or whole event families from the selection.

Run this command from the repository root when Go is installed:

```bash
go -C tooling run ./cmd/sysmon-modular merge \
  --base-path "$PWD" \
  --template "$PWD/templates/sysmon_template.xml" \
  --include-list "$PWD/0_custom_configuration/example_include_rules.txt" \
  --exclude-list "$PWD/0_custom_configuration/example_exclude_rules.txt" \
  --preserve-comments \
  --sysmon-version 15.21 \
  --unsupported exclude \
  --output "$PWD/0_custom_configuration/sysmonconfig-example.xml"
```

Edit the lists before deployment. They are examples, not a production tuning policy.

### Using a prebuilt binary

The release workflow publishes these standalone binaries to the
[latest release](https://github.com/olafhartong/sysmon-modular/releases/latest).
They do not require Go:

| Operating system | Binary |
| --- | --- |
| Windows x64 | `sysmon-modular-windows-amd64.exe` |
| Windows ARM64 | `sysmon-modular-windows-arm64.exe` |
| Linux x64 | `sysmon-modular-linux-amd64` |
| Linux ARM64 | `sysmon-modular-linux-arm64` |
| macOS Intel | `sysmon-modular-darwin-amd64` |
| macOS Apple silicon | `sysmon-modular-darwin-arm64` |

Download the matching file and save it as `tooling/sysmon-modular`. On Windows,
save it as `tooling/sysmon-modular.exe`. Linux and macOS users must make it
executable once:

```bash
chmod +x tooling/sysmon-modular
```

Run the same merge without Go:

```bash
"$PWD/tooling/sysmon-modular" merge \
  --base-path "$PWD" \
  --template "$PWD/templates/sysmon_template.xml" \
  --include-list "$PWD/0_custom_configuration/example_include_rules.txt" \
  --exclude-list "$PWD/0_custom_configuration/example_exclude_rules.txt" \
  --preserve-comments \
  --sysmon-version 15.21 \
  --unsupported exclude \
  --output "$PWD/0_custom_configuration/sysmonconfig-example.xml"
```

From PowerShell on Windows:

```powershell
& "$PWD\tooling\sysmon-modular.exe" merge `
  --base-path "$PWD" `
  --template "$PWD\templates\sysmon_template.xml" `
  --include-list "$PWD\0_custom_configuration\example_include_rules.txt" `
  --exclude-list "$PWD\0_custom_configuration\example_exclude_rules.txt" `
  --preserve-comments `
  --sysmon-version 15.21 `
  --unsupported exclude `
  --output "$PWD\0_custom_configuration\sysmonconfig-example.xml"
```

## MDE augment configuration

`mde_covered_modules.txt` restores the repository's original MDE-covered exclusion profile with stale paths removed. The MDE augment build merges all normal repository modules except the ones in that list.

New modules are not classified automatically. Review this list when modules are added to an event family that MDE already covers.

Run the helper from any directory:

```bash
./0_custom_configuration/generate-sysmonconfig-mde-augment.sh
```

The helper uses `tooling/sysmon-modular` or `tooling/sysmon-modular.exe` when
present. It checks `PATH` next, then falls back to `go run` when Go is
installed.

By default it writes `sysmonconfig-mde-augment.xml` in the repository root. Pass another output path as the first argument when testing:

```bash
./0_custom_configuration/generate-sysmonconfig-mde-augment.sh /tmp/sysmonconfig-mde-augment.xml
```

The current Go merger preserves each source `RuleGroup`. The generated XML can therefore differ in layout from the older PowerShell-generated file even when it selects the same modules.
