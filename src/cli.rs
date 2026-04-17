use crate::output::Format;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "unsafe-budget")]
#[command(about = "keeps the unsafety demons out. an unsafe code budget gate for CI pipelines.")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run analyzers and print results
    Scan(ScanArgs),

    /// Check against baseline/budget, exit non-zero on violation
    Check(ScanArgs),

    /// Update baseline from current scan
    Update(ScanArgs),

    /// List available analyzers
    Plugins(PluginsArgs),
}

#[derive(Args, Clone)]
pub struct ScanArgs {
    /// Output format
    #[arg(long, default_value = "text")]
    pub format: Format,

    /// Analyzer to use (rustc_unsafe_lint, cargo_geiger, go_geiger, sarif, or auto)
    #[arg(long, default_value = "auto")]
    pub analyzer: String,

    /// Only scan workspace crates (exclude dependencies)
    #[arg(long)]
    pub workspace_only: bool,

    /// Include dependencies in scan (default: from config or true)
    #[arg(long)]
    pub include_deps: bool,

    /// Exclude dependencies from scan
    #[arg(long)]
    pub no_deps: bool,

    /// Cargo features to enable
    #[arg(long, value_delimiter = ',')]
    pub features: Vec<String>,

    /// Enable all features
    #[arg(long)]
    pub all_features: bool,

    /// Disable default features
    #[arg(long)]
    pub no_default_features: bool,

    /// Build all targets
    #[arg(long)]
    pub all_targets: bool,

    /// Target triple(s) to build
    #[arg(long, value_delimiter = ',')]
    pub targets: Vec<String>,

    /// Path to Cargo.toml
    #[arg(long)]
    pub manifest_path: Option<PathBuf>,

    /// Path to config file (default: unsafe-budget.toml)
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Show detailed occurrences
    #[arg(long)]
    pub details: bool,

    /// Timeout in seconds for plugin execution (overrides config)
    #[arg(long)]
    pub plugin_timeout: Option<u64>,
}

#[derive(Args)]
pub struct PluginsArgs {
    /// Output format
    #[arg(long, default_value = "text")]
    pub format: Format,
}

/// Parse CLI, handling both standalone and cargo plugin invocation.
/// - Standalone: `unsafe-budget scan`
/// - Cargo plugin: `cargo unsafe-budget scan` (cargo passes "unsafe-budget" as first arg)
pub fn parse() -> Cli {
    let mut args: Vec<String> = std::env::args().collect();

    // If invoked as cargo plugin, first arg after binary is "unsafe-budget" - skip it
    if args.len() > 1 && args[1] == "unsafe-budget" {
        args.remove(1);
    }

    Cli::parse_from(args)
}
