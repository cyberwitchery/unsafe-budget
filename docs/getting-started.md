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

## next steps

- [usage guide](usage.md) - all cli options
- [architecture](architecture.md) - how it works
- [analyzers](analyzers.md) - available backends
