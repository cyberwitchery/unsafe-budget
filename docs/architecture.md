# architecture

## overview

unsafe-budget is a library with two thin binaries, `unsafe-budget` and `cargo-unsafe-budget`, that orchestrate unsafe code analysis across multiple languages and tools.

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│   cli.rs    │────▶│   app.rs     │────▶│   pipeline   │────▶│   analyzer  │
│   (argv)    │     │ (exit codes) │     │ (commands)   │     │   (trait)   │
└─────────────┘     └──────────────┘     └──────────────┘     └─────────────┘
                           │                    │                    │
                           ▼                    ▼                    ▼
                    ┌─────────────┐      ┌─────────────┐   rustc · cargo geiger
                    │   output    │      │   budget    │   go geiger · sarif
                    │ (renderers) │      │  (engine)   │   external plugins
                    └─────────────┘      └─────────────┘
                                                │
                                                ▼
                                         ┌─────────────┐
                                         │   config    │
                                         │  baseline   │
                                         └─────────────┘
```

`cli.rs` and `app.rs` belong to the binaries: `src/main.rs` and `src/cargo_unsafe_budget.rs` each declare them as their own modules, so they are not part of the library's api.

## data flow

1. **cli** parses arguments; **app** loads the config and builds `ScanOpts`
2. **pipeline** runs the command (`scan`, `check` or `update`)
3. **analyzer** runs external tools and normalizes output to `ScanResult`
4. **budget** subtracts `[[ignore]]` entries and compares the `ScanResult` against baseline/caps
5. **output** renders results as text, json, or sarif to any writer
6. **app** prints scope differences, the rendered result and the exit code

## core types

### ScanOpts

options passed from cli to analyzer:

```rust
pub struct ScanOpts {
    pub include_deps: bool,
    pub features: Vec<String>,
    pub manifest_path: Option<PathBuf>,
    // ...
}
```

### ScanResult

normalized output from any analyzer:

```rust
pub struct ScanResult {
    pub tool_version: String,
    pub analyzer_id: String,
    pub language: String,
    pub scope: Scope,
    pub units: Vec<Unit>,
    pub totals: Totals,
    pub details: Vec<Occurrence>,
    pub parse_warnings: Vec<ParseWarning>,
}
```

### Unit

a compilation unit (crate, package, module):

```rust
pub struct Unit {
    pub name: String,
    pub kind: UnitKind,  // Workspace | Dep
    pub unsafe_count: u64,
}
```

### Occurrence

one unsafe site, listed in `details`:

```rust
pub struct Occurrence {
    pub unit: String,
    pub file: PathBuf,
    pub line: u32,  // 1-indexed, 0 when unknown
    pub col: u32,   // 1-indexed, 0 when unknown
    pub message: Option<String>,
}
```

## analyzer trait

all analyzers implement:

```rust
pub trait Analyzer {
    fn id(&self) -> &str;
    fn language(&self) -> &str;
    fn run(&self, opts: &ScanOpts) -> Result<ScanResult>;
}
```

## budget modes

### ratchet

compares each unit against its baseline count. fails if any unit increased.

### caps

compares against explicit limits in config. fails if any unit exceeds its cap.

`[[ignore]]` entries are subtracted before either comparison, and checking against a baseline written by another analyzer is an error.

## plugin discovery

external plugins are executables named `unsafe-budget-plugin-*` on PATH. they receive options via environment variables and output json to stdout. the host overrides `analyzer_id` and `scope`, filters dependency units per scope, and recomputes `totals` from the surviving units.
