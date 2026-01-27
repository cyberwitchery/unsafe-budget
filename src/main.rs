use std::process::ExitCode;

use unsafe_budget::analyzer::{detect_analyzer, get_analyzer, list_analyzers, Analyzer};
use unsafe_budget::budget;
use unsafe_budget::cli::{self, Command, ScanArgs};
use unsafe_budget::config::{Baseline, BaselineUnit, Config};
use unsafe_budget::error::Result;
use unsafe_budget::model::{ScanOpts, ScanResult};
use unsafe_budget::output::{self, Format};

fn main() -> ExitCode {
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

fn cmd_scan(args: ScanArgs) -> Result<ExitCode> {
    let config = load_config(&args)?;
    let opts = build_scan_opts(&args, &config);
    let analyzer = get_analyzer_for_args(&args, &opts)?;

    let mut result = analyzer.run(&opts)?;

    // Filter details if not requested
    if !args.details {
        result.details.clear();
    }

    output::print_scan(&result, args.format)?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_check(args: ScanArgs) -> Result<ExitCode> {
    let config = load_config(&args)?;
    let opts = build_scan_opts(&args, &config);
    let analyzer = get_analyzer_for_args(&args, &opts)?;

    let result = analyzer.run(&opts)?;

    // Load baseline for ratchet mode
    let baseline = match config.mode {
        unsafe_budget::config::Mode::Ratchet => {
            let dir = get_project_dir(&args);
            Some(Baseline::load_from_dir(&dir)?)
        }
        unsafe_budget::config::Mode::Caps => None,
    };

    let check_result = budget::check(&result, baseline.as_ref(), &config)?;

    output::print_check(&check_result, baseline.as_ref(), args.format)?;

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

    let result = analyzer.run(&opts)?;

    let baseline = build_baseline(&result, analyzer.as_ref());
    let dir = get_project_dir(&args);
    baseline.save_to_dir(&dir)?;

    if args.format == Format::Text {
        eprintln!(
            "Baseline updated: {} workspace unsafe, {} deps unsafe",
            result.totals.workspace_unsafe, result.totals.deps_unsafe
        );
    } else {
        output::print_scan(&result, args.format)?;
    }

    Ok(ExitCode::SUCCESS)
}

fn cmd_plugins(args: unsafe_budget::cli::PluginsArgs) -> Result<ExitCode> {
    let plugins = list_analyzers();
    output::print_plugins(&plugins, args.format)?;
    Ok(ExitCode::SUCCESS)
}

fn get_analyzer_for_args(args: &ScanArgs, opts: &ScanOpts) -> Result<Box<dyn Analyzer>> {
    if args.analyzer == "auto" {
        Ok(detect_analyzer(opts))
    } else {
        get_analyzer(&args.analyzer)
    }
}

fn load_config(args: &ScanArgs) -> Result<Config> {
    let dir = get_project_dir(args);
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| dir.join("unsafe-budget.toml"));

    Config::load(&config_path)
}

fn get_project_dir(args: &ScanArgs) -> std::path::PathBuf {
    args.manifest_path
        .as_ref()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()))
}

fn build_scan_opts(args: &ScanArgs, config: &Config) -> ScanOpts {
    // CLI flags override config
    let include_deps = if args.no_deps {
        false
    } else if args.include_deps {
        true
    } else {
        config.include_deps
    };

    let workspace_only = args.workspace_only || config.workspace_only;

    ScanOpts {
        workspace_only,
        include_deps,
        features: args.features.clone(),
        all_features: args.all_features,
        no_default_features: args.no_default_features,
        all_targets: args.all_targets,
        targets: args.targets.clone(),
        manifest_path: args.manifest_path.clone(),
    }
}

fn build_baseline(result: &ScanResult, analyzer: &dyn Analyzer) -> Baseline {
    Baseline {
        tool_version: env!("CARGO_PKG_VERSION").into(),
        analyzer_id: analyzer.id().into(),
        scope: result.scope.clone(),
        totals: result.totals.clone(),
        units: result.units.iter().map(BaselineUnit::from).collect(),
    }
}
