use std::collections::{HashMap, HashSet};
use std::process::ExitCode;

use crate::analyzer::{detect_analyzer, get_analyzer, list_analyzers, Analyzer};
use crate::budget;
use crate::cli::{self, Command, ScanArgs};
use crate::config::{Baseline, BaselineUnit, Config, IgnoreEntry};
use crate::error::Result;
use crate::model::{ScanOpts, ScanResult, Scope, Totals};
use crate::output::{self, Format};

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

fn cmd_scan(args: ScanArgs) -> Result<ExitCode> {
    let config = load_config(&args)?;
    let opts = build_scan_opts(&args, &config);
    let analyzer = get_analyzer_for_args(&args, &opts)?;

    let mut result = analyzer.run(&opts)?;

    result = apply_ignore_filter(result, &config.ignore);

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
    let result = apply_ignore_filter(result, &config.ignore);

    // Load baseline for ratchet mode
    let baseline = match config.mode {
        crate::config::Mode::Ratchet => {
            let dir = get_project_dir(&args)?;
            Some(Baseline::load_from_dir(&dir)?)
        }
        crate::config::Mode::Caps => None,
    };

    // Warn when the current scan scope differs from the baseline scope
    if let Some(bl) = baseline.as_ref() {
        let current_scope = Scope::from(&opts);
        let diffs = bl.scope.diff_fields(&current_scope);
        if !diffs.is_empty() {
            eprintln!("warning: scan scope differs from baseline:");
            for d in &diffs {
                eprintln!("  - {}", d);
            }
        }
    }

    let mut check_result = budget::check(&result, baseline.as_ref(), &config)?;

    // Filter details if not requested
    if !args.details {
        check_result.scan.details.clear();
    }

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
    let result = apply_ignore_filter(result, &config.ignore);

    let baseline = build_baseline(&result, analyzer.as_ref());
    let dir = get_project_dir(&args)?;
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

fn cmd_plugins(args: crate::cli::PluginsArgs) -> Result<ExitCode> {
    let plugins = list_analyzers();
    output::print_plugins(&plugins, args.format)?;
    Ok(ExitCode::SUCCESS)
}

fn get_analyzer_for_args(args: &ScanArgs, opts: &ScanOpts) -> Result<Box<dyn Analyzer>> {
    if args.analyzer == "auto" {
        detect_analyzer(opts)
    } else {
        get_analyzer(&args.analyzer)
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
        None => Ok(std::env::current_dir()?),
    }
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
        plugin_timeout_secs: args.plugin_timeout.or(config.plugin_timeout_secs),
    }
}

/// Remove occurrences that match an `[[ignore]]` config entry and recompute unit
/// counts and totals. A match requires both the file path and line number to be
/// equal; the `reason` field is documentation only.
///
/// If `ignores` is empty this is a no-op. If the scan result has no detail
/// occurrences (e.g. cargo_geiger only provides aggregate counts), this is also
/// a no-op — there are no individual occurrences to match against.
fn apply_ignore_filter(mut result: ScanResult, ignores: &[IgnoreEntry]) -> ScanResult {
    if ignores.is_empty() || result.details.is_empty() {
        return result;
    }

    let ignore_set: HashSet<(&std::path::Path, u32)> = ignores
        .iter()
        .map(|rule| (rule.file.as_path(), rule.line))
        .collect();

    result
        .details
        .retain(|occ| !ignore_set.contains(&(occ.file.as_path(), occ.line)));

    // Recompute per-unit counts from the filtered details.
    let mut counts: HashMap<&str, u64> = HashMap::new();
    for occ in &result.details {
        *counts.entry(occ.unit.as_str()).or_default() += 1;
    }
    for unit in &mut result.units {
        unit.unsafe_count = counts.get(unit.name.as_str()).copied().unwrap_or(0);
    }

    // Recompute totals.
    result.totals = Totals::from_units(&result.units);

    result
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Occurrence, Scope, Unit, UnitKind};
    use std::path::PathBuf;

    fn make_scope() -> Scope {
        Scope {
            workspace_only: false,
            include_deps: true,
            features: vec![],
            all_features: false,
            no_default_features: false,
            all_targets: false,
            targets: vec![],
            manifest_path: None,
        }
    }

    fn make_result_with_details() -> ScanResult {
        ScanResult {
            tool_version: "0.1.0".into(),
            analyzer_id: "rustc_unsafe_lint".into(),
            language: "rust".into(),
            scope: make_scope(),
            units: vec![
                Unit {
                    name: "my_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 3,
                },
                Unit {
                    name: "other_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 1,
                },
            ],
            totals: Totals {
                workspace_unsafe: 4,
                deps_unsafe: 0,
                overall_unsafe: 4,
            },
            details: vec![
                Occurrence {
                    unit: "my_crate".into(),
                    file: PathBuf::from("src/lib.rs"),
                    line: 10,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "my_crate".into(),
                    file: PathBuf::from("src/lib.rs"),
                    line: 20,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "my_crate".into(),
                    file: PathBuf::from("src/ffi.rs"),
                    line: 42,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "other_crate".into(),
                    file: PathBuf::from("other/src/lib.rs"),
                    line: 5,
                    col: 1,
                    message: None,
                },
            ],
        }
    }

    fn make_result_without_details() -> ScanResult {
        ScanResult {
            tool_version: "0.1.0".into(),
            analyzer_id: "cargo_geiger".into(),
            language: "rust".into(),
            scope: make_scope(),
            units: vec![
                Unit {
                    name: "my_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 10,
                },
                Unit {
                    name: "libc".into(),
                    kind: UnitKind::Dep,
                    unsafe_count: 200,
                },
            ],
            totals: Totals {
                workspace_unsafe: 10,
                deps_unsafe: 200,
                overall_unsafe: 210,
            },
            details: vec![],
        }
    }

    #[test]
    fn ignore_filter_empty_ignores_is_noop() {
        let result = make_result_with_details();
        let filtered = apply_ignore_filter(result.clone(), &[]);
        assert_eq!(filtered.totals.overall_unsafe, 4);
        assert_eq!(filtered.details.len(), 4);
    }

    #[test]
    fn ignore_filter_removes_matching_occurrence() {
        let result = make_result_with_details();
        let ignores = vec![IgnoreEntry {
            file: PathBuf::from("src/ffi.rs"),
            line: 42,
            reason: Some("reviewed".into()),
        }];
        let filtered = apply_ignore_filter(result, &ignores);

        assert_eq!(filtered.details.len(), 3);
        assert_eq!(filtered.units[0].unsafe_count, 2); // my_crate: 3 -> 2
        assert_eq!(filtered.units[1].unsafe_count, 1); // other_crate unchanged
        assert_eq!(filtered.totals.workspace_unsafe, 3);
        assert_eq!(filtered.totals.overall_unsafe, 3);
    }

    #[test]
    fn ignore_filter_removes_multiple_occurrences() {
        let result = make_result_with_details();
        let ignores = vec![
            IgnoreEntry {
                file: PathBuf::from("src/lib.rs"),
                line: 10,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("src/ffi.rs"),
                line: 42,
                reason: None,
            },
        ];
        let filtered = apply_ignore_filter(result, &ignores);

        assert_eq!(filtered.details.len(), 2);
        assert_eq!(filtered.units[0].unsafe_count, 1); // my_crate: 3 -> 1
        assert_eq!(filtered.units[1].unsafe_count, 1); // other_crate unchanged
        assert_eq!(filtered.totals.overall_unsafe, 2);
    }

    #[test]
    fn ignore_filter_nonmatching_rule_changes_nothing() {
        let result = make_result_with_details();
        let ignores = vec![IgnoreEntry {
            file: PathBuf::from("src/nonexistent.rs"),
            line: 999,
            reason: None,
        }];
        let filtered = apply_ignore_filter(result, &ignores);

        assert_eq!(filtered.details.len(), 4);
        assert_eq!(filtered.totals.overall_unsafe, 4);
    }

    #[test]
    fn ignore_filter_requires_both_file_and_line_to_match() {
        let result = make_result_with_details();
        // Right file, wrong line
        let ignores = vec![IgnoreEntry {
            file: PathBuf::from("src/ffi.rs"),
            line: 99,
            reason: None,
        }];
        let filtered = apply_ignore_filter(result, &ignores);

        assert_eq!(filtered.details.len(), 4);
        assert_eq!(filtered.totals.overall_unsafe, 4);
    }

    #[test]
    fn ignore_filter_no_details_preserves_counts() {
        // This is the cargo_geiger bug: aggregate counts with no details.
        let result = make_result_without_details();
        let ignores = vec![IgnoreEntry {
            file: PathBuf::from("src/lib.rs"),
            line: 10,
            reason: None,
        }];
        let filtered = apply_ignore_filter(result, &ignores);

        // Counts must NOT be zeroed.
        assert_eq!(filtered.units[0].unsafe_count, 10);
        assert_eq!(filtered.units[1].unsafe_count, 200);
        assert_eq!(filtered.totals.workspace_unsafe, 10);
        assert_eq!(filtered.totals.deps_unsafe, 200);
        assert_eq!(filtered.totals.overall_unsafe, 210);
    }

    #[test]
    fn ignore_filter_no_details_multiple_ignores_preserves_counts() {
        let result = make_result_without_details();
        let ignores = vec![
            IgnoreEntry {
                file: PathBuf::from("src/lib.rs"),
                line: 10,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("src/ffi.rs"),
                line: 42,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("vendor/libc/src/lib.rs"),
                line: 1,
                reason: None,
            },
        ];
        let filtered = apply_ignore_filter(result, &ignores);

        assert_eq!(filtered.units[0].unsafe_count, 10);
        assert_eq!(filtered.units[1].unsafe_count, 200);
        assert_eq!(filtered.totals.overall_unsafe, 210);
    }

    #[test]
    fn ignore_filter_removes_all_occurrences_zeros_counts() {
        // When details ARE present and all are filtered, counts should go to 0.
        let result = make_result_with_details();
        let ignores = vec![
            IgnoreEntry {
                file: PathBuf::from("src/lib.rs"),
                line: 10,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("src/lib.rs"),
                line: 20,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("src/ffi.rs"),
                line: 42,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("other/src/lib.rs"),
                line: 5,
                reason: None,
            },
        ];
        let filtered = apply_ignore_filter(result, &ignores);

        assert!(filtered.details.is_empty());
        assert_eq!(filtered.units[0].unsafe_count, 0);
        assert_eq!(filtered.units[1].unsafe_count, 0);
        assert_eq!(filtered.totals.overall_unsafe, 0);
    }

    #[test]
    fn ignore_filter_recomputes_dep_totals() {
        let mut result = make_result_with_details();
        // Add a dep unit with a detail occurrence.
        result.units.push(Unit {
            name: "dep_crate".into(),
            kind: UnitKind::Dep,
            unsafe_count: 1,
        });
        result.details.push(Occurrence {
            unit: "dep_crate".into(),
            file: PathBuf::from("dep/src/lib.rs"),
            line: 3,
            col: 1,
            message: None,
        });
        result.totals = Totals::from_units(&result.units);

        let ignores = vec![IgnoreEntry {
            file: PathBuf::from("dep/src/lib.rs"),
            line: 3,
            reason: None,
        }];
        let filtered = apply_ignore_filter(result, &ignores);

        assert_eq!(filtered.units[2].unsafe_count, 0); // dep_crate filtered
        assert_eq!(filtered.totals.deps_unsafe, 0);
        assert_eq!(filtered.totals.workspace_unsafe, 4); // unchanged
        assert_eq!(filtered.totals.overall_unsafe, 4);
    }

    #[test]
    fn ignore_filter_many_ignores_scales_linearly() {
        // Regression: ensure that a large number of ignore rules does not cause
        // quadratic behaviour. With O(n*m) filtering this would iterate
        // 4 * 1000 = 4000 times; with a HashSet it's 4 lookups + 1000 inserts.
        let result = make_result_with_details();
        let mut ignores: Vec<IgnoreEntry> = (0..1000)
            .map(|i| IgnoreEntry {
                file: PathBuf::from(format!("nonexistent/{}.rs", i)),
                line: i,
                reason: None,
            })
            .collect();
        // Slip in one real match.
        ignores.push(IgnoreEntry {
            file: PathBuf::from("src/ffi.rs"),
            line: 42,
            reason: None,
        });
        let filtered = apply_ignore_filter(result, &ignores);

        assert_eq!(filtered.details.len(), 3);
        assert_eq!(filtered.totals.overall_unsafe, 3);
    }
}
