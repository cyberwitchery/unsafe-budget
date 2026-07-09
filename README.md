# unsafe-budget

*keeps the unsafety demons out*

an unsafe code budget gate for ci pipelines. tracks unsafe code usage in rust and go projects and fails ci when the budget is exceeded.

## quick start

```bash
# install
cargo install --path .

# scan current project (auto-detects language)
unsafe-budget scan

# establish baseline
unsafe-budget update

# check against baseline (fails if budget exceeded)
unsafe-budget check
```

github actions can also run via the pre-built binary action:

```yaml
- uses: cyberwitchery/unsafe-budget@v1
  with:
    mode: check
```

## features

- **multi-language**: rust (rustc lint, cargo-geiger) and go (go-geiger)
- **sarif support**: emit SARIF 2.1.0 for github code scanning, or ingest SARIF from any tool
- **auto-detection**: detects project type from `Cargo.toml` or `go.mod`
- **two modes**: ratchet (baseline comparison) or caps (explicit limits)
- **plugin system**: extend with custom analyzers via `unsafe-budget-plugin-*` executables
- **ci-friendly**: deterministic output, json/sarif format, meaningful exit codes

## usage

works both standalone and as a cargo subcommand:

```bash
# standalone
unsafe-budget scan
unsafe-budget check
unsafe-budget update

# cargo plugin
cargo unsafe-budget scan
cargo unsafe-budget check
cargo unsafe-budget update
```

### commands

| command | description |
|---------|-------------|
| `scan` | run analyzers and print results |
| `check` | compare to baseline, exit 2 on violation |
| `update` | write/update baseline from current scan |
| `plugins` | list available analyzers |

### flags

```bash
unsafe-budget scan --format json          # json output
unsafe-budget scan --format sarif --details # sarif output for code scanning
unsafe-budget scan --analyzer cargo_geiger # explicit analyzer
unsafe-budget scan --workspace-only       # skip dependencies
unsafe-budget scan --details              # show line-level occurrences
unsafe-budget scan --timeout 300          # bound external analyzer/plugin subprocesses (seconds)
```

## exit codes

| code | meaning |
|------|---------|
| 0 | success (or check passed) |
| 1 | runtime error |
| 2 | budget violation |

## configuration

create `unsafe-budget.toml`:

```toml
mode = "ratchet"  # or "caps"
include_deps = true
ignore_units = ["test_crate"]
timeout_secs = 300  # optional: kill hung external analyzers/plugins after N seconds

# ignore specific occurrences by file + line (optional reason for reviewers)
[[ignore]]
file = "src/ffi.rs"
line = 42
reason = "ffi boundary, reviewed 2026-04-12"

[[ignore]]
file = "src/platform/windows.rs"
line = 7

[caps]
default = 100
[caps.workspace]
my_crate = 10

[warnings]
threshold = 0.8
```

## built-in analyzers

| id | language | backend |
|----|----------|---------|
| `rustc_unsafe_lint` | rust | `cargo check -Wunsafe_code` |
| `cargo_geiger` | rust | `cargo-geiger` |
| `go_geiger` | go | `go-geiger` |
| `sarif` | any | reads `.sarif` files |

## library usage

```rust
use unsafe_budget::analyzer::{get_analyzer, detect_analyzer};
use unsafe_budget::model::ScanOpts;
use unsafe_budget::budget;

let opts = ScanOpts::default();
let analyzer = detect_analyzer(&opts);
let result = analyzer.run(&opts)?;

println!("total unsafe: {}", result.totals.overall_unsafe);
```

## documentation

- [getting started](docs/getting-started.md)
- [ci integration](docs/ci-integration.md)
- [architecture](docs/architecture.md)
- [usage guide](docs/usage.md)
- [analyzers](docs/analyzers.md)

## license

MIT
