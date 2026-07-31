# architecture

## overview

unsafe-budget is a single binary that orchestrates unsafe code analysis across multiple languages and tools.

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   cli.rs    │────▶│   analyzer   │────▶│   budget    │
│  (commands) │     │   (trait)    │     │  (engine)   │
└─────────────┘     └──────────────┘     └─────────────┘
                           │                    │
                           ▼                    ▼
                  rustc · cargo geiger     ┌─────────┐
                  go geiger · sarif        │ config  │
                  external plugins         │baseline │
                                           └─────────┘
```

## data flow

1. **cli** parses arguments into `ScanOpts`
2. **analyzer** runs external tools and normalizes output to `ScanResult`
3. **budget** compares `ScanResult` against baseline/caps
4. **output** renders results as text, json, or sarif

## core types

### ScanOpts

options passed from cli to analyzer:

```rust
pub struct ScanOpts {
    pub workspace_only: bool,
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

## plugin discovery

external plugins are executables named `unsafe-budget-plugin-*` on PATH. they receive options via environment variables and output json to stdout. the host overrides `analyzer_id` and `scope`, filters dependency units per scope, and recomputes `totals` from the surviving units.
