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
- counts `unsafe.Pointer`, `unsafe.Sizeof`, `unsafe.Offsetof`, `unsafe.Alignof`, and other unsafe operations
- distinguishes workspace vs vendor/module cache dependencies
- provides line-level occurrence details
- requires go-geiger installation

**workspace vs dependency detection**:
- files under `vendor/` or the Go module cache (`go/pkg/mod/`) are classified as dependencies
- all other files are treated as workspace code

**usage**:
```bash
go install github.com/preeve9534/go-geiger@latest
unsafe-budget scan --analyzer go_geiger
```

**example** (scanning a go project):
```bash
# auto-detects go from go.mod
cd my-go-project
unsafe-budget scan

# explicit analyzer selection
unsafe-budget scan --analyzer go_geiger

# with details
unsafe-budget scan --analyzer go_geiger --details

# skip dependencies (vendor/ and module cache)
unsafe-budget scan --analyzer go_geiger --workspace-only
```

**example output**:
```
unsafe-budget scan
==================
Analyzer: go_geiger
Language: go

Totals:
  Workspace: 3 unsafe
  Dependencies: 12 unsafe
  Overall: 15 unsafe

Per-unit breakdown:
  UNIT                           KIND           UNSAFE
  ----------------------------------------------------
  github.com/pkg/errors          dep                12
  mypackage                      workspace           3
```

### sarif

language-agnostic analyzer that reads SARIF 2.1.0 files produced by any
static analysis tool.

**backend**: reads a `.sarif` file from disk

**features**:
- ingests SARIF output from any tool (clippy, go-geiger, semgrep, codeql, etc.)
- infers language from the SARIF tool driver name
- groups results into units based on file paths
- provides line-level occurrence details from SARIF locations
- no external tools required beyond the one that produced the SARIF file

**usage**:
```bash
# first, produce a sarif file with your tool of choice
clippy-sarif > results.sarif

# then analyze it with unsafe-budget
unsafe-budget scan --analyzer sarif --manifest-path results.sarif

# apply budget checking
unsafe-budget check --analyzer sarif --manifest-path results.sarif

# output as sarif again (round-trip)
unsafe-budget scan --analyzer sarif --manifest-path results.sarif --format sarif --details
```

**unit grouping**: results are grouped by the parent directory of each
artifact URI. for example, `src/lib.rs` and `src/main.rs` both map to
the unit `src`.

**language inference**: the language is inferred from the SARIF tool
driver name. names containing "rust", "cargo", or "clippy" map to
`rust`; names containing "go" map to `go`; names containing "gcc" or
"clang" map to `c`; everything else maps to `unknown`.

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
