# changelog

## [unreleased]

- add release SBOM generation and upload (CycloneDX)
- publish pre-built release binaries for Linux/macOS/Windows on version tags

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

[0.1.1]: https://github.com/cyberwitchery/unsafe-gate/releases/tag/v0.1.1
[0.1.0]: https://github.com/cyberwitchery/unsafe-gate/releases/tag/v0.1.0
[unreleased]: https://github.com/cyberwitchery/unsafe-gate/compare/v0.1.1...HEAD
