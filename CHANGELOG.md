# changelog

## Unreleased

- warn to stderr when `[[ignore]]` entries are configured but the analyzer did not produce occurrence details (so users know their ignore rules are silently inert).
- `--include-deps` and `--no-deps` now conflict at the CLI level, preventing contradictory invocations that previously had undefined behavior.
- fix: `run_cargo_check` no longer swallows unexpected cargo failures (missing toolchain, linker errors, network failures); any non-zero exit with empty stdout is now an error instead of a silent false-negative.

## [0.4.1] - 2026-06-08

- fix: `caps.default` now applies to workspace crates that have no explicit `[caps.workspace]` entry, instead of silently skipping them from budget checks.
- the `check` command now rejects a baseline created with a different analyzer (e.g. a `rustc_unsafe_lint` baseline checked with `cargo_geiger`), which previously caused false passes/failures from mismatched unit names.
- the `go_geiger` analyzer now warns (to stderr, via `ParseWarning`) on malformed output instead of silently mishandling it: lines with bad line/col numbers or fewer than three colon-delimited parts are skipped, and a fallback to an `"unknown"` package is surfaced.

## [0.4.0] - 2026-05-06

- show individual unsafe occurrences in text output with `--details` (grouped by unit, sorted by file/line/col), matching the detail already available in JSON and SARIF.
- `--details` is now respected by the `check` command, not just `scan`.
- SARIF `budget_violation`/`budget_warning` results now carry file-level locations, so GitHub code scanning points to specific files instead of repo-level alerts; near-budget threshold warnings are also emitted (previously dropped).
- track `all_features`/`no_default_features` in the scan scope, and warn to stderr when a `check` scope differs from the baseline (e.g. `--all-features` used during `update` but not `check`), listing which fields changed.
- fix: SARIF language inference no longer misclassifies tools whose names merely contain "go" (django, errgo) as Go; it now requires a word boundary.
- fix: text output no longer panics when truncating unit names that contain multi-byte characters.
- fix: `[[ignore]]` entries no longer zero out all unit counts for analyzers that produce no line-level occurrences (e.g. `cargo_geiger`).
- fix: a failure to read the current directory is now reported as an error instead of silently falling back to `.`.
- remove `Baseline::get_unit()` (superseded by `unit_map()` in 0.3.0).

## [0.3.0] - 2026-04-17

- add an `[[ignore]]` config table to suppress specific file+line occurrences.
- add `plugin_timeout_secs` (config) and `--plugin-timeout` (CLI) to kill hanging plugin subprocesses.
- fix: the SARIF analyzer no longer collapses every `*/src/*.rs` path into a single `src` unit; it now uses the crate/package directory name.
- fix stale `unsafe-gate` references in the SARIF `information_uri` and the Cargo.toml repository URL.

## [0.2.0] - 2026-02-19

- publish pre-built release binaries for Linux/macOS/Windows on version tags, and ship a CycloneDX SBOM with each release.
- add a GitHub composite action (`cyberwitchery/unsafe-budget@v1`) for CI use.
- add optional near-budget threshold warnings (`[warnings].threshold`).
- `Analyzer::id` and `Analyzer::language` now return `&str` instead of `&'static str` (relevant to custom analyzer/plugin authors).

## [0.1.1] - 2026-01-29

- SARIF 2.1.0 output (`--format sarif`) for GitHub Code Scanning and IDE integration.
- built-in SARIF analyzer (`--analyzer sarif`) to ingest `.sarif` files from any static analysis tool.

## [0.1.0] - 2026-01-27

initial release.

- unsafe-code budget gate for CI pipelines, in ratchet mode (baseline comparison) or caps mode (explicit limits).
- built-in analyzers (`rustc_unsafe_lint`, `cargo_geiger`, `go_geiger`) with project-type auto-detection from `Cargo.toml`/`go.mod`, plus a plugin system for custom analyzers (`unsafe-budget-plugin-*`).
- works standalone or as a cargo subcommand (`cargo unsafe-budget`).
- text and JSON output; baseline file (`unsafe-budget.lock`) and configuration via `unsafe-budget.toml`.

[0.4.1]: https://github.com/cyberwitchery/unsafe-budget/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/cyberwitchery/unsafe-budget/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/cyberwitchery/unsafe-budget/releases/tag/v0.3.0
[0.2.0]: https://github.com/cyberwitchery/unsafe-budget/releases/tag/v0.2.0
[0.1.1]: https://github.com/cyberwitchery/unsafe-budget/releases/tag/v0.1.1
[0.1.0]: https://github.com/cyberwitchery/unsafe-budget/releases/tag/v0.1.0
[unreleased]: https://github.com/cyberwitchery/unsafe-budget/compare/v0.4.1...HEAD
