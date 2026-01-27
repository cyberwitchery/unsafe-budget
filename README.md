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

## features

- **multi-language**: rust (rustc lint, cargo-geiger) and go (go-geiger)
- **auto-detection**: detects project type from `Cargo.toml` or `go.mod`
- **two modes**: ratchet (baseline comparison) or caps (explicit limits)
- **plugin system**: extend with custom analyzers via `unsafe-budget-plugin-*` executables
- **ci-friendly**: deterministic output, json format, meaningful exit codes

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
unsafe-budget scan --analyzer cargo_geiger # explicit analyzer
unsafe-budget scan --workspace-only       # skip dependencies
unsafe-budget scan --details              # show line-level occurrences
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

[caps]
default = 100
[caps.workspace]
my_crate = 10
```

## built-in analyzers

| id | language | backend |
|----|----------|---------|
| `rustc_unsafe_lint` | rust | `cargo check -Wunsafe_code` |
| `cargo_geiger` | rust | `cargo-geiger` |
| `go_geiger` | go | `go-geiger` |

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
