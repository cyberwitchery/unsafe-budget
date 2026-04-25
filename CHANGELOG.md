# changelog

## [unreleased]

- warn to stderr when `check` scope differs from baseline scope (e.g. `--all-features` used during `update` but not `check`), listing which fields changed
- add threshold warnings (near-budget) to SARIF output as note-level `budget_warning` results; previously these were silently dropped
- fix `infer_language` in SARIF analyzer producing false Go classifications for tools whose names contain "go" as a substring (e.g. django, errgo); now requires "go" at a word boundary
- refactor `go_geiger` analyzer to use the shared `aggregate_units` helper, consistent with the other analyzers
- fix `truncate()` in text output panicking on unit names containing multi-byte (non-ASCII) characters
- fix `apply_ignore_filter` silently zeroing all unit counts when the analyzer produces no detail occurrences (e.g. `cargo_geiger`); `[[ignore]]` entries are now correctly skipped when there are no line-level details to filter
- extract shared `aggregate_units` helper in `analyzer/mod.rs` so rustc, cargo-geiger, and SARIF analyzers share one filter/sort path instead of three
- propagate `current_dir()` failure as an error instead of silently falling back to `"."` in `get_project_dir()` and `detect_analyzer()`

## [0.3.0] - 2026-04-17

- fix SARIF analyzer collapsing all `*/src/*.rs` paths into a single "src" unit; now extracts the crate/package directory name instead
- add `plugin_timeout_secs` config option and `--plugin-timeout` CLI flag to kill hanging plugin subprocesses
- add `[[ignore]]` config table for suppressing specific file+line occurrences
- fix stale `information_uri` in SARIF output pointing to old repo name `unsafe-gate`
- fix changelog release URLs (unsafe-gate → unsafe-budget)
- fix repository URL in Cargo.toml

## [0.2.0] - 2026-02-19

- add release SBOM generation and upload (CycloneDX)
- publish pre-built release binaries for Linux/macOS/Windows on version tags
- add optional threshold warnings for near-budget units (`[warnings].threshold`)
- add a GitHub composite action (`cyberwitchery/unsafe-budget@v1`) for CI usage
- fix `Analyzer::id` and `Analyzer::language` to return `&str` instead of `&'static str`, removing the `Box::leak` workaround in the plugin analyzer
- fix release workflow SBOM collection to handle cargo-cyclonedx output landing next to the manifest rather than in `/tmp`

## [0.1.1] - 2026-01-29

- SARIF 2.1.0 output format (`--format sarif`) for GitHub Code Scanning and IDE integration
- built-in SARIF analyzer (`--analyzer sarif`) to ingest `.sarif` files from any static analysis tool

## [0.1.0] - 2026-01-27

initial release

- unsafe code budget gate for CI pipelines
- ratchet mode (baseline comparison) and caps mode (explicit limits)
- built-in analyzers: rustc_unsafe_lint, cargo_geiger, go_geiger
- auto-detection of project type from Cargo.toml or go.mod
- plugin system for custom analyzers via `unsafe-budget-plugin-*` executables
- works standalone or as cargo subcommand (`cargo unsafe-budget`)
- text and json output formats
- baseline file (`unsafe-budget.lock`) for tracking unsafe counts over time
- configuration via `unsafe-budget.toml`

[0.3.0]: https://github.com/cyberwitchery/unsafe-budget/releases/tag/v0.3.0
[0.2.0]: https://github.com/cyberwitchery/unsafe-budget/releases/tag/v0.2.0
[0.1.1]: https://github.com/cyberwitchery/unsafe-budget/releases/tag/v0.1.1
[0.1.0]: https://github.com/cyberwitchery/unsafe-budget/releases/tag/v0.1.0
[unreleased]: https://github.com/cyberwitchery/unsafe-budget/compare/v0.3.0...HEAD
