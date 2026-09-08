# `help`

`help`, `-h`, and `--help` at the top level print the tool build version and command list and return success.

```bash
./sysmon-modular help
./sysmon-modular --help
```

For command-specific help, place `-h` or `--help` after the command:

```bash
./sysmon-modular merge --help
```

Command-specific help prints the tool build version, available flags and their parser defaults. It does not include the behavioral detail and examples in this directory.

Use [`version`](version.md) or `--version` to print just the tool name and build version.
