# `analyze`

`analyze` checks a complete Sysmon configuration for structural errors, contradictory rules, broad filters, and performance risks. It does not modify the file.

```text
sysmon-modular analyze --config <file> [flags]
```

`--config <file>`

Selects the Sysmon configuration XML to analyze. This flag is required. Unlike `validate`, `analyze` accepts one configuration at a time and has no repository discovery mode.

`--preserve-comments`

Keeps XML comments while parsing. The default is `false`.

`--verbose`

Prints the source XML line for each finding when a line is available.

The command first runs structural Sysmon validation, then adds analyzer findings. It prints `no findings` when both passes are clean. Error-severity findings return exit code `4`. Recommendations and performance findings remain successful so they can be reviewed without breaking automation.

Findings include complete expressions present in both include and exclude
rules, hash-configuration recommendations, known Windows executables excluded
by name alone where full paths may be stronger, and settings that can add
collection or lookup costs. These are review signals; the tool does not
measure endpoint performance or event volume in your environment.

## Example

```bash
./sysmon-modular analyze --config ../sysmonconfig.xml --verbose
```
