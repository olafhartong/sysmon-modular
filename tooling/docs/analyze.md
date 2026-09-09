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

Prints the source XML line for each finding when a line is available. This is
enabled by default; use `--verbose=false` to omit source text while keeping line
numbers.

Findings include the line number and affected XML by default, including warnings,
errors, recommendations, and performance findings. Line numbers refer to the
opening line of the affected element. A missing setting points to the root element
where it belongs. XML syntax errors show the line reported by the parser; errors
without a source location, such as an unreadable or empty file, omit the line.

```text
  [ANL003] line 3: DnsLookup=True can add resolver overhead
    3 │ <DnsLookup>true</DnsLookup>
```

The command first runs structural Sysmon validation, then adds analyzer findings. It prints `no findings` when both passes are clean. Error-severity findings return exit code `4`. Recommendations and performance findings remain successful so they can be reviewed without breaking automation.

Findings include complete expressions present in both include and exclude
rules, hash-configuration recommendations, known Windows executables excluded
by name alone where full paths may be stronger, and settings that can add
collection or lookup costs. These are review signals; the tool does not
measure endpoint performance or event volume in your environment.

## Example

```bash
./sysmon-modular analyze --config ../sysmonconfig.xml
```
