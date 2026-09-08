# `version`

Print the tool name and build version to standard output and return success:

```bash
./sysmon-modular version
./sysmon-modular --version
```

Both commands print:

```text
sysmon-modular 1.0
```

`-version` is also accepted. There are no command-specific options or positional
arguments. `version --help` prints usage information.

The build version also appears in top-level and command-specific help. It
identifies the tooling, independently of the target Sysmon executable and XML
schema versions.

The default is defined in `cmd/sysmon-modular/version.go` and included in local
and release builds. A build can override it with the Go linker:

```bash
go build -ldflags="-X main.buildVersion=1.1" -o sysmon-modular ./cmd/sysmon-modular
```
