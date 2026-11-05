use std::io;
use std::process::ExitCode;

use unsafe_budget::analyzer::{detect_analyzer, get_analyzer, list_analyzers, Analyzer};
use unsafe_budget::config::Config;
use unsafe_budget::error::{Error, Result};
use unsafe_budget::model::ScanOpts;
use unsafe_budget::output::{self, Format};
use unsafe_budget::pipeline;

use crate::cli::{self, Command, ScanArgs};

pub fn run_cli() -> ExitCode {
    let cli = cli::parse();

    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::from(1)
        }
    }
}

fn run(cli: cli::Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Scan(args) => cmd_scan(args),
        Command::Check(args) => cmd_check(args),
        Command::Update(args) => cmd_update(args),
        Command::Plugins(args) => cmd_plugins(args),
    }
}

// text output drops occurrence details without --details; machine formats always keep them
fn should_retain_details(details_flag: bool, format: Format) -> bool {
    details_flag || format != Format::Text
}

fn cmd_scan(args: ScanArgs) -> Result<ExitCode> {
    let config = load_config(&args)?;
    let opts = build_scan_opts(&args, &config);
    let analyzer = get_analyzer_for_args(&args, &opts)?;

    let mut result = pipeline::scan(analyzer.as_ref(), &opts, &config)?;

    if !should_retain_details(args.details, args.format) {
        result.details.clear();
    }

    output::write_scan(&mut io::stdout().lock(), &result, args.format).map_err(stdout_error)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_check(args: ScanArgs) -> Result<ExitCode> {
    let config = load_config(&args)?;
    let opts = build_scan_opts(&args, &config);
    let analyzer = get_analyzer_for_args(&args, &opts)?;

    let outcome = pipeline::check(analyzer.as_ref(), &opts, &config, &get_project_dir(&args)?)?;

    if !outcome.scope_differences.is_empty() {
        eprintln!("warning: scan scope differs from baseline:");
        for d in &outcome.scope_differences {
            eprintln!("  - {}", d);
        }
    }

    let mut check_result = outcome.result;
    if !should_retain_details(args.details, args.format) {
        check_result.scan.details.clear();
    }

    output::write_check(&mut io::stdout().lock(), &check_result, args.format)
        .map_err(stdout_error)?;

    if check_result.passed {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(2))
    }
}

fn cmd_update(args: ScanArgs) -> Result<ExitCode> {
    let config = load_config(&args)?;
    let opts = build_scan_opts(&args, &config);
    let analyzer = get_analyzer_for_args(&args, &opts)?;

    let result = pipeline::update(analyzer.as_ref(), &opts, &config, &get_project_dir(&args)?)?;

    if args.format == Format::Text {
        eprintln!(
            "Baseline updated: {} workspace unsafe, {} deps unsafe",
            result.totals.workspace_unsafe, result.totals.deps_unsafe
        );
    } else {
        output::write_scan(&mut io::stdout().lock(), &result, args.format).map_err(stdout_error)?;
    }

    Ok(ExitCode::SUCCESS)
}

fn cmd_plugins(args: cli::PluginsArgs) -> Result<ExitCode> {
    // a configured timeout also bounds the discovery probe, so a hung plugin's
    // `--info` cannot wedge the listing
    let config = Config::load_from_dir(&current_dir()?)?;
    let timeout = config.plugin_timeout_secs.or(config.timeout_secs);
    let plugins = list_analyzers(timeout);
    output::write_plugins(&mut io::stdout().lock(), &plugins, args.format).map_err(stdout_error)?;
    Ok(ExitCode::SUCCESS)
}

fn stdout_error(e: std::io::Error) -> Error {
    Error::io("stdout", e)
}

fn current_dir() -> Result<std::path::PathBuf> {
    std::env::current_dir().map_err(|e| Error::io("current directory", e))
}

fn get_analyzer_for_args(args: &ScanArgs, opts: &ScanOpts) -> Result<Box<dyn Analyzer>> {
    if args.analyzer == "auto" {
        detect_analyzer(opts)
    } else {
        get_analyzer(&args.analyzer, opts.plugin_timeout_secs)
    }
}

fn load_config(args: &ScanArgs) -> Result<Config> {
    let dir = get_project_dir(args)?;
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| dir.join("unsafe-budget.toml"));

    Config::load(&config_path)
}

fn get_project_dir(args: &ScanArgs) -> Result<std::path::PathBuf> {
    match args.manifest_path.as_ref().and_then(|p| p.parent()) {
        Some(p) => Ok(p.to_path_buf()),
        None => current_dir(),
    }
}

fn build_scan_opts(args: &ScanArgs, config: &Config) -> ScanOpts {
    let include_deps = if args.no_deps {
        false
    } else if args.include_deps {
        true
    } else {
        config.include_deps
    };

    // the general timeout bounds the built-in external analyzers and, unless a
    // plugin-specific override is set, plugins too
    let general_timeout = args.timeout.or(config.timeout_secs);

    ScanOpts {
        include_deps,
        features: args.features.clone(),
        all_features: args.all_features,
        no_default_features: args.no_default_features,
        all_targets: args.all_targets,
        targets: args.targets.clone(),
        manifest_path: args.manifest_path.clone(),
        plugin_timeout_secs: args
            .plugin_timeout
            .or(config.plugin_timeout_secs)
            .or(general_timeout),
        analyzer_timeout_secs: general_timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_retain_details_keeps_machine_output_intact() {
        // --details retains occurrences for every format
        assert!(should_retain_details(true, Format::Text));
        assert!(should_retain_details(true, Format::Json));
        assert!(should_retain_details(true, Format::Sarif));
        // without --details, only text drops them; JSON and SARIF keep them
        assert!(!should_retain_details(false, Format::Text));
        assert!(should_retain_details(false, Format::Json));
        assert!(should_retain_details(false, Format::Sarif));
    }

    fn scan_args(argv: &[&str]) -> ScanArgs {
        use clap::Parser;
        match cli::Cli::try_parse_from(argv).unwrap().command {
            Command::Scan(a) => a,
            _ => panic!("expected scan command"),
        }
    }

    #[test]
    fn timeouts_resolve_from_flags_and_config() {
        // --plugin-timeout bounds only plugins, never the built-in analyzers.
        // flags, config timeout, config plugin timeout -> (plugin, analyzer)
        type Case<'a> = (
            &'a [&'a str],
            Option<u64>,
            Option<u64>,
            (Option<u64>, Option<u64>),
        );
        let cases: [Case; 6] = [
            (&[], None, None, (None, None)),
            (&["--plugin-timeout", "5"], None, None, (Some(5), None)),
            (&["--timeout", "9"], None, None, (Some(9), Some(9))),
            (
                &["--timeout", "9", "--plugin-timeout", "3"],
                None,
                None,
                (Some(3), Some(9)),
            ),
            (&[], Some(30), None, (Some(30), Some(30))),
            (&["--timeout", "12"], Some(30), Some(7), (Some(7), Some(12))),
        ];
        for (flags, timeout_secs, plugin_timeout_secs, expected) in cases {
            let argv: Vec<&str> = ["unsafe-budget", "scan"]
                .iter()
                .chain(flags)
                .copied()
                .collect();
            let config = Config {
                timeout_secs,
                plugin_timeout_secs,
                ..Config::default()
            };
            let opts = build_scan_opts(&scan_args(&argv), &config);
            assert_eq!(
                (opts.plugin_timeout_secs, opts.analyzer_timeout_secs),
                expected,
                "{flags:?} {timeout_secs:?} {plugin_timeout_secs:?}"
            );
        }
    }
}
