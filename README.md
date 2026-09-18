# sysmon-modular | A Sysmon configuration repository for everybody to customise

[![license](https://img.shields.io/github/license/olafhartong/sysmon-modular.svg?style=flat-square)](https://github.com/olafhartong/sysmon-modular/blob/master/license.md)
![Maintenance](https://img.shields.io/maintenance/yes/2026.svg?style=flat-square)
[![GitHub last commit](https://img.shields.io/github/last-commit/olafhartong/sysmon-modular.svg?style=flat-square)](https://github.com/olafhartong/sysmon-modular/commit/master)
![Build Sysmon configurations](https://github.com/olafhartong/sysmon-modular/actions/workflows/config-build.yml/badge.svg)
[![Twitter](https://img.shields.io/twitter/follow/olafhartong.svg?style=social&label=Follow)](https://twitter.com/olafhartong)
[![Discord Shield](https://discordapp.com/api/guilds/715302469751668787/widget.png?style=shield)](https://discord.gg/B5n6skNTwy)

Sysmon Modular is a configuration repository for [Microsoft Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Small XML modules make it easier to select, review and maintain the telemetry that is useful to your organisation. The `sysmon-modular` Go tool builds configurations from those modules and helps validate, analyse and compare them.

**Every configuration is a starting point.** Review and tune it for your applications, endpoint roles, detection needs and logging budget before deploying it widely. Use a manageable set of profiles for workstations, servers and domain controllers, and measure their behaviour on representative machines.

This project would not have been possible without [SwiftOnSecurity's original configuration](https://github.com/SwiftOnSecurity/sysmon-config/), which inspired Sysmon Modular and remains part of its foundation.

## Contents

- [Pre-generated configurations](#pre-generated-configurations)
- [Get the tooling](#get-the-tooling)
- [Generating a config](#generating-a-config)
- [Validate, analyse and compare](#validate-analyse-and-compare)
- [Generate modules from KQL and MDE](#generate-modules-from-kql-and-mde)
- [Use](#use)
- [CI/CD and releases](#cicd-and-releases)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Sysmon community](#sysmon-community)
- [More information](#more-information)

## Pre-generated configurations

Download the regular starting configurations from the [latest GitHub Release](https://github.com/olafhartong/sysmon-modular/releases/latest). These consolidated XML files are generated from the source modules and distributed as release assets instead of being stored in the repository.

| Profile | Download | Collection goal |
| --- | --- | --- |
| Balanced | [sysmonconfig.xml](https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig.xml) | The regular starting configuration, without FileDelete archiving. |
| Balanced with FileDelete | [sysmonconfig-with-filedelete.xml](https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig-with-filedelete.xml) | Adds FileDelete collection and file archiving. Account for the archive's disk requirements. |
| Excludes only | [sysmonconfig-excludes-only.xml](https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig-excludes-only.xml) | A very verbose profile built from exclusion modules. Expect substantial event volume and tune before production use. |

All three profiles are generated for **Sysmon 15.21, 14.16, 13.34 and 12.03**. Versioned filenames include the target, such as `sysmonconfig-14.16.xml`; the unversioned names above are aliases for 15.21. Select the version installed on your endpoints. For controlled rollouts, pin a specific release rather than automatically deploying `latest`.

Two profiles remain separate examples in the repository:

- [Research configuration](sysmonconfig-research.xml): extremely verbose collection for short, controlled research sessions. It can consume substantial CPU, memory and logging capacity; load a lighter configuration when the investigation is complete.
- [MDE-augment configuration](sysmonconfig-mde-augment.xml): selected collection intended to complement Microsoft Defender for Endpoint with less overlap. It does not enable every Sysmon event. See the [MDE-augment generation guide](0_custom_configuration/README.md#mde-augment-configuration) to rebuild and review its exclusion list.

The release also includes prebuilt tools, [an ATT&CK Navigator layer](https://github.com/olafhartong/sysmon-modular/releases/latest/download/attack-matrix-15.21.json) derived from the balanced 15.21 configuration, and a `SHA256SUMS` manifest.

## Get the tooling

The Go CLI is the supported generator. The examples in this README run from the **repository root** and use a binary saved in `tooling`. Start with a local checkout if you want to generate configurations from the source modules:

```bash
git clone https://github.com/olafhartong/sysmon-modular.git
cd sysmon-modular
```

### Prebuilt binaries

Download the binary for your operating system and architecture from [GitHub Releases](https://github.com/olafhartong/sysmon-modular/releases/latest). Go is not required to use these binaries.

| System | Release asset |
| --- | --- |
| Windows x64 | `sysmon-modular-windows-amd64.exe` |
| Windows ARM64 | `sysmon-modular-windows-arm64.exe` |
| Linux x64 | `sysmon-modular-linux-amd64` |
| Linux ARM64 | `sysmon-modular-linux-arm64` |
| macOS Intel | `sysmon-modular-darwin-amd64` |
| macOS Apple silicon | `sysmon-modular-darwin-arm64` |

Save the download as `tooling/sysmon-modular`, or `tooling/sysmon-modular.exe` on Windows. On Linux and macOS, make it executable once:

```bash
chmod +x tooling/sysmon-modular
```

### Build

Building from source requires **Go 1.22 or newer** and uses only the Go standard library.

From the repository root on Linux or macOS:

```bash
go -C tooling build -o "$PWD/tooling/sysmon-modular" ./cmd/sysmon-modular
```

From PowerShell on Windows:

```powershell
go -C tooling build -o "$PWD\tooling\sysmon-modular.exe" ./cmd/sysmon-modular
```

You can also run commands directly with Go. For example:

```bash
go -C tooling run ./cmd/sysmon-modular --version
```

`go -C tooling run` runs the program from the `tooling` directory. Use absolute paths when adapting repository-root examples to that form, or follow the `tooling`-relative examples in the [command reference](tooling/docs/README.md).

### Version and help

The tooling starts at build version **1.0**:

```bash
./tooling/sysmon-modular --version
./tooling/sysmon-modular help
./tooling/sysmon-modular merge --help
```

`version` and `--version` print `sysmon-modular 1.0`. The build version also appears in top-level and command-specific help. It identifies the tooling; `--sysmon-version` selects the target Sysmon executable instead.

The default is defined in [version.go](tooling/cmd/sysmon-modular/version.go). Local and release builds include it automatically. To override it for a particular build:

```bash
go -C tooling build -ldflags="-X main.buildVersion=1.1" \
  -o "$PWD/tooling/sysmon-modular" ./cmd/sysmon-modular
```

On Windows, use `./tooling/sysmon-modular.exe` in the commands below. Multi-line PowerShell examples are available in the [custom configuration guide](0_custom_configuration/README.md).

## Generating a config

Edit the [example include list](0_custom_configuration/example_include_rules.txt) and [example exclude list](0_custom_configuration/example_exclude_rules.txt) to select the collection you need, then generate a configuration:

```bash
./tooling/sysmon-modular merge \
  --base-path "$PWD" \
  --template "$PWD/templates/sysmon_template.xml" \
  --include-list "$PWD/0_custom_configuration/example_include_rules.txt" \
  --exclude-list "$PWD/0_custom_configuration/example_exclude_rules.txt" \
  --sysmon-version 15.21 \
  --unsupported exclude \
  --preserve-comments \
  --output "$PWD/0_custom_configuration/sysmonconfig-example.xml"
```

The supplied lists demonstrate selection; they are not a production tuning policy. List entries can name individual modules or numbered directories, and the exclude list wins if a module appears in both. You can also repeat `--path` for individual modules or use `--file-list` with a CSV, TSV or JSON priority list.

Without an explicit selection, `merge` discovers every module in the numbered directories. That includes `23_file_delete`, so it enables archiving that the balanced release profile leaves out. The merger preserves source `RuleGroup` relationships by default. A custom template retains your global settings while its event filters are replaced by the selected modules.

The default target is Sysmon 15/schema 4.90. Select `--sysmon-version 15.21` for schema 4.91, or another supported executable version from 12 through 15. Unsupported events and fields remain in the output with warnings by default. `--unsupported exclude` removes known incompatible content; review those removals because they change collection. The [merge reference](tooling/docs/merge.md) contains the complete selection rules, flags, examples and [schema compatibility table](tooling/docs/merge.md#supported-sysmon-versions).

For additional driver-related visibility, consider adding the current LOLdrivers configuration to `29_file_executable_detected` before generating your configuration, then review the merged result.

## Validate, analyse and compare

Check all source modules and treat warnings as failures:

```bash
./tooling/sysmon-modular validate \
  --all --base-path "$PWD" --sysmon-version 15.21 --warnings-as-errors
```

Use `--all-xml` to include other repository XML, such as templates and complete configurations. Use repeated `--path` flags to select individual files. `verify` is an alias for `validate`; both check XML, Sysmon structure and Enterprise ATT&CK metadata by default. The [validation reference](tooling/docs/validate.md) explains the flags, and the [validation checks](tooling/docs/validate-rules.md) explain each finding code.

Review a generated configuration before deployment:

```bash
./tooling/sysmon-modular analyze --config 0_custom_configuration/sysmonconfig-example.xml
./tooling/sysmon-modular diff \
  --before old.xml --after 0_custom_configuration/sysmonconfig-example.xml
./tooling/sysmon-modular coverage --path 0_custom_configuration/sysmonconfig-example.xml
```

The analyser flags issues such as identical include/exclude expressions, risky executable-name exclusions and configuration costs. The semantic comparison preserves complete rule expressions and reports changes in ATT&CK mappings. These tools help with review; pilot on representative machines and measure event volume, endpoint resource use and investigative value before a wider rollout.

Coverage supports text, JSON, CSV and ATT&CK Navigator output:

```bash
./tooling/sysmon-modular coverage \
  --path 0_custom_configuration/sysmonconfig-example.xml \
  --format navigator \
  --template attack_matrix/Sysmon-modular.json \
  --output 0_custom_configuration/attack-navigator.json
```

Technique names and tactics come from the embedded Enterprise ATT&CK catalogue. Navigator output defaults to ATT&CK 18 for compatibility, with documented ID mappings; `--attack-version 19` retains current IDs for a compatible viewer. See the [coverage reference](tooling/docs/coverage.md).

ATT&CK mappings identify potentially useful telemetry. They do not guarantee that every implementation of a technique is recorded or that a detection exists for it. Review metadata repairs with `fix-mitre --dry-run` before applying them; [fix-mitre](tooling/docs/fix-mitre.md) supports interactive review and `--yes` for automated workflows.

## Generate modules from KQL and MDE

The tooling can reuse supported KQL filters and MDE collection configuration when creating collection modules:

| Command | Purpose |
| --- | --- |
| [`generate-kql`](tooling/docs/generate-kql.md) | Convert a supported query or scan a directory of queries and Markdown KQL blocks. |
| [`generate-mde`](tooling/docs/generate-mde.md) | Approximate supported MDE include and exclude filters. |
| [`generate-mde-unfiltered`](tooling/docs/generate-mde-unfiltered.md) | Generate broad include-only collection for supported telemetry families. |
| [`generate-mde-inverse`](tooling/docs/generate-mde-inverse.md) | Generate includes based on MDE exclusions and negative filter branches. |

For example:

```bash
./tooling/sysmon-modular generate-kql \
  --kql detection.kql --output 0_custom_configuration/generated-query.xml
./tooling/sysmon-modular generate-mde \
  --mde-config tooling/mde-config.json \
  --area process-creation --area registry \
  --dedup --base-path "$PWD" \
  --output-dir 0_custom_configuration/generated-mde
```

Supply your own query or MDE JSON configuration. The generators do not retrieve tenant settings. MDE `--area` selection is repeatable; omitting it processes all supported areas. Use a fresh output directory when changing selections because generation does not remove earlier files.

KQL and filtered MDE conversion reject or skip input that cannot be represented faithfully. `--allow-lossy` explicitly enables approximations for manual review. MDE deduplication omits complete equivalent rules; KQL deduplication retains conditions and adds comments identifying existing coverage. The command docs explain supported operators, Boolean limits, MDE event mappings and optional KQL analyzer requests.

## Use

### Install

After reviewing and tuning a configuration, install Sysmon from an elevated terminal:

```powershell
sysmon.exe -accepteula -i sysmonconfig.xml
```

### Update existing configuration

Apply a reviewed configuration from an elevated terminal:

```powershell
sysmon.exe -c sysmonconfig.xml
```

Replace `sysmonconfig.xml` with the path to your downloaded or generated file.

## CI/CD and releases

The [configuration workflow](.github/workflows/config-build.yml) runs on pull requests, pushes to `master` and manual runs. It runs the Go tests, builds the tool, validates source XML and generates the three release profiles for each target Sysmon version. It also checks generated XML against its target version, generates and checks the Navigator JSON, and builds the six platform binaries.

The workflow creates and verifies `SHA256SUMS` before uploading the resulting artifacts. Only successful pushes to `master` publish a release. The publication job downloads those same artifacts and verifies their checksums again, so the files it publishes are the files produced and checked by the build job. Existing releases for the same commit are left in place.

These checks cover structure, metadata and known compatibility rules. They do not measure the event volume or endpoint cost in your organisation.

## Documentation

The [documentation index](tooling/docs/README.md) is the reference for every command, flag, output format and exit code. It also links to:

- [Custom configuration examples](0_custom_configuration/README.md), including Windows commands and MDE-augment generation.
- [Validation checks and finding codes](tooling/docs/validate-rules.md).
- [Updating the embedded ATT&CK catalogue](tooling/docs/generate-mitre.md).
- [Legacy PowerShell and Python generators](tooling/docs/legacy-generators.md), including the earlier selection and priority-list examples.
- [ATT&CK Navigator usage](attack_matrix/README.md).

Older snapshots remain available in the [version-8](https://github.com/olafhartong/sysmon-modular/tree/version-8), [version-9](https://github.com/olafhartong/sysmon-modular/tree/version-9), [v10.4](https://github.com/olafhartong/sysmon-modular/tree/v10.4), [version-12](https://github.com/olafhartong/sysmon-modular/tree/version-12) and [version-13-14](https://github.com/olafhartong/sysmon-modular/tree/version-13-14) branches. For the current module set on Sysmon 12 through 15, use the versioned release assets or target-version generation described above.

## Contributing

Issues, pull requests and new modules are welcome. Include the tool build version, target Sysmon version and a small reproducible example when reporting a problem. Missing visibility, unexpected event volume and conversions that change the intended logic are particularly useful reports.

Run the tooling tests from the repository root when changing the Go implementation:

```bash
go -C tooling test ./...
```

When adding modules, review their event volume, comments and ATT&CK metadata. The [validation checks](tooling/docs/validate-rules.md) describe the checks used by `validate` and `verify`.

## Sysmon community

- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config/) provides the original configuration and introductory explanations that inspired this project.
- [Neo23x0/sysmon-config](https://github.com/Neo23x0/sysmon-config) is Florian Roth's fork of SwiftOnSecurity's configuration.
- This repository focuses on modular maintenance and detailed rule notes for investigations and SIEM use.
- The [Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide) by Carlos Perez / TrustedSec provides additional guidance.

## More information

- [Video introduction to this project](https://www.youtube.com/watch?v=Cx_zrM8Hu7Y).
- [Endpoint detection superpowers on the cheap — part 1: ATT&CK, Sysmon and the modular configuration](https://medium.com/@olafhartong/endpoint-detection-superpowers-on-the-cheap-part-1-e9c28201ac47).
- [Part 2: Deploy and maintain](https://medium.com/@olafhartong/endpoint-detection-superpowers-on-the-cheap-part-2-deploy-and-maintain-d06580329fe8).
- [Part 3: Sysmon tampering](https://medium.com/@olafhartong/endpoint-detection-superpowers-on-the-cheap-part-3-sysmon-tampering-49c2dc9bf6d9).
- [Sysmon and Microsoft Defender for Endpoint compared](https://medium.com/falconforce/sysmon-vs-microsoft-defender-for-endpoint-mde-internals-0x01-1e5663b10347).
- [Sysmon 11 DNS improvements and FileDelete events](https://medium.com/falconforce/sysmon-11-dns-improvements-and-filedelete-events-7a74f17ca842).
- [DerbyCon: Endpoint detection superpowers on the cheap with Sysmon](http://www.irongeek.com/i.php?page=videos/derbycon9/stable-36-endpoint-detection-super-powers-on-the-cheap-with-sysmon-olaf-hartong).
- [Configuration options wiki](https://github.com/olafhartong/sysmon-modular/wiki/Configuration-options).
