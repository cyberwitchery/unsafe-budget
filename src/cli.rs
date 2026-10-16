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
    /// run analyzers and print results
    Scan(ScanArgs),

    /// check against baseline/budget, exit non-zero on violation
    Check(ScanArgs),

    /// update baseline from current scan
    Update(ScanArgs),

    /// list available analyzers
    Plugins(PluginsArgs),
}

#[derive(Args, Clone)]
pub struct ScanArgs {
    /// output format
    #[arg(long, default_value = "text")]
    pub format: Format,

    /// analyzer to use (rustc_unsafe_lint, cargo_geiger, go_geiger, sarif, or auto)
    #[arg(long, default_value = "auto")]
    pub analyzer: String,

    /// only scan workspace crates (exclude dependencies)
    #[arg(long)]
    pub workspace_only: bool,

    /// include dependencies in scan (default: from config or true)
    #[arg(long, conflicts_with = "no_deps")]
    pub include_deps: bool,

    /// exclude dependencies from scan
    #[arg(long)]
    pub no_deps: bool,

    /// Cargo features to enable
    #[arg(long, value_delimiter = ',')]
    pub features: Vec<String>,

    /// enable all features
    #[arg(long)]
    pub all_features: bool,

    /// disable default features
    #[arg(long)]
    pub no_default_features: bool,

    /// build all targets
    #[arg(long)]
    pub all_targets: bool,

    /// target triple(s) to build
    #[arg(long, value_delimiter = ',')]
    pub targets: Vec<String>,

    /// path to Cargo.toml, go.mod, or a .sarif file (sarif analyzer)
    #[arg(long)]
    pub manifest_path: Option<PathBuf>,

    /// path to config file (default: unsafe-budget.toml)
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// show detailed occurrences
    #[arg(long)]
    pub details: bool,

    /// timeout in seconds for plugin execution (overrides config)
    #[arg(long)]
    pub plugin_timeout: Option<u64>,

    /// timeout in seconds for external analyzer/plugin subprocesses (overrides
    /// config; default: no timeout). `--plugin-timeout` still takes precedence
    /// for plugins.
    #[arg(long)]
    pub timeout: Option<u64>,
}

#[derive(Args)]
pub struct PluginsArgs {
    /// output format
    #[arg(long, default_value = "text")]
    pub format: Format,
}

/// parse CLI, handling both standalone and cargo plugin invocation.
/// - Standalone: `unsafe-budget scan`
/// - Cargo plugin: `cargo unsafe-budget scan` (cargo passes "unsafe-budget" as first arg)
pub fn parse() -> Cli {
    let mut args: Vec<String> = std::env::args().collect();

    // if invoked as cargo plugin, first arg after binary is "unsafe-budget" - skip it
    if args.len() > 1 && args[1] == "unsafe-budget" {
        args.remove(1);
    }

    Cli::parse_from(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn include_deps_and_no_deps_flags() {
        // flags -> Some((include_deps, no_deps)), or None for a conflict
        type Case<'a> = (&'a [&'a str], Option<(bool, bool)>);
        let cases: [Case; 3] = [
            (&["--include-deps", "--no-deps"], None),
            (&["--include-deps"], Some((true, false))),
            (&["--no-deps"], Some((false, true))),
        ];
        for (flags, expected) in cases {
            let argv = ["unsafe-budget", "scan"].iter().chain(flags);
            match (Cli::try_parse_from(argv), expected) {
                (Err(e), None) => assert_eq!(e.kind(), ErrorKind::ArgumentConflict, "{flags:?}"),
                (Ok(cli), Some(expected)) => match cli.command {
                    Command::Scan(args) => {
                        assert_eq!((args.include_deps, args.no_deps), expected, "{flags:?}")
                    }
                    _ => panic!("expected scan command"),
                },
                (result, _) => panic!("{flags:?}: unexpected {:?}", result.map(|_| ())),
            }
        }
    }
}
