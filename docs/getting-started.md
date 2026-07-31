# getting started

## installation

```bash
# from source
cargo install --path .

# or build locally
cargo build --release
```

## first scan

run a scan on your rust project:

```bash
cd your-project
unsafe-budget scan
```

output:

```
unsafe-budget scan
==================
Analyzer: rustc_unsafe_lint
Language: rust

Totals:
  Workspace: 5 unsafe
  Dependencies: 42 unsafe
  Overall: 47 unsafe

Per-unit breakdown:
  UNIT                           KIND           UNSAFE
  ----------------------------------------------------
  libc                           dep            42
  my_crate                       workspace       5
```

## establish a baseline

once you're happy with the current state, create a baseline:

```bash
unsafe-budget update
```

this creates `unsafe-budget.lock` with the current counts.

## check in ci

add to your ci pipeline:

```bash
unsafe-budget check
```

exits with code 2 if any unit exceeds its baseline.

## scanning a go project

```bash
# install go-geiger
go install github.com/jlauinger/go-geiger@latest

# scan (auto-detected from go.mod)
cd your-go-project
unsafe-budget scan
```

## using sarif

unsafe-budget can both produce and consume SARIF 2.1.0 files:

```bash
# emit sarif from a scan
unsafe-budget scan --format sarif > results.sarif

# ingest sarif from another tool
unsafe-budget scan --analyzer sarif --manifest-path results.sarif
```

## next steps

- [usage guide](usage.md) - all cli options
- [architecture](architecture.md) - how it works
- [analyzers](analyzers.md) - available backends
