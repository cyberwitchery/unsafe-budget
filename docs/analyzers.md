# analyzers

## built-in analyzers

### rustc_unsafe_lint

default analyzer for rust projects.

**backend**: `cargo check --message-format=json` with `RUSTFLAGS=-Wunsafe_code`

**features**:
- counts `unsafe {}` blocks via compiler diagnostics
- distinguishes workspace vs dependency crates
- provides line-level occurrence details
- no additional tools required

**usage**:
```bash
unsafe-budget scan --analyzer rustc_unsafe_lint
```

### cargo_geiger

alternative rust analyzer using cargo-geiger.

**backend**: `cargo geiger --output-format json`

**features**:
- counts unsafe functions, expressions, impls, traits, methods
- more granular than rustc lint
- requires `cargo install cargo-geiger`

**usage**:
```bash
cargo install cargo-geiger
unsafe-budget scan --analyzer cargo_geiger
```

### go_geiger

analyzer for go projects.

**backend**: `go-geiger ./...`

**features**:
- counts `unsafe.Pointer`, `unsafe.Sizeof`, etc.
- distinguishes workspace vs vendor/module cache
- provides line-level occurrence details
- requires go-geiger installation

**usage**:
```bash
go install github.com/preeve9534/go-geiger@latest
unsafe-budget scan --analyzer go_geiger
```

## auto-detection

when `--analyzer auto` (the default):

1. checks for `go.mod` → uses `go_geiger`
2. checks for `Cargo.toml` → uses `rustc_unsafe_lint`
3. falls back to `rustc_unsafe_lint`

## external plugins

plugins are executables named `unsafe-budget-plugin-<id>` on PATH.

### protocol

plugins receive options via environment variables:

| variable | description |
|----------|-------------|
| `UNSAFE_BUDGET_WORKSPACE_ONLY` | "true" or "false" |
| `UNSAFE_BUDGET_INCLUDE_DEPS` | "true" or "false" |
| `UNSAFE_BUDGET_FEATURES` | comma-separated features |
| `UNSAFE_BUDGET_ALL_FEATURES` | "true" or "false" |
| `UNSAFE_BUDGET_NO_DEFAULT_FEATURES` | "true" or "false" |
| `UNSAFE_BUDGET_ALL_TARGETS` | "true" or "false" |
| `UNSAFE_BUDGET_TARGETS` | comma-separated targets |
| `UNSAFE_BUDGET_MANIFEST_PATH` | path to manifest |

plugins output json to stdout:

```json
{
  "tool_version": "1.0.0",
  "analyzer_id": "my_plugin",
  "language": "cpp",
  "scope": { ... },
  "units": [ ... ],
  "totals": { ... },
  "details": [ ... ]
}
```

### plugin info

plugins can respond to `--info` with:

```json
{
  "language": "cpp"
}
```

this is used by `unsafe-budget plugins` to show the language.

### example plugin

```bash
#!/bin/bash
# unsafe-budget-plugin-example

cat <<EOF
{
  "tool_version": "1.0.0",
  "analyzer_id": "example",
  "language": "example",
  "scope": {
    "workspace_only": false,
    "include_deps": true,
    "features": [],
    "all_targets": false,
    "targets": []
  },
  "units": [],
  "totals": {
    "workspace_unsafe": 0,
    "deps_unsafe": 0,
    "overall_unsafe": 0
  }
}
EOF
```
