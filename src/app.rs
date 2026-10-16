use std::collections::{HashMap, HashSet};
use std::process::ExitCode;

use crate::analyzer::{detect_analyzer, get_analyzer, list_analyzers, Analyzer};
use crate::budget;
use crate::cli::{self, Command, ScanArgs};
use crate::config::{Baseline, BaselineUnit, Config, IgnoreEntry};
use crate::error::{Error, Result};
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

// text output drops occurrence details without --details; machine formats always keep them
fn should_retain_details(details_flag: bool, format: Format) -> bool {
    details_flag || format != Format::Text
}

fn cmd_scan(args: ScanArgs) -> Result<ExitCode> {
    let config = load_config(&args)?;
    let opts = build_scan_opts(&args, &config);
    let analyzer = get_analyzer_for_args(&args, &opts)?;

    let mut result = analyzer.run(&opts)?;

    result = apply_ignore_filter(result, &config.ignore);

    if !should_retain_details(args.details, args.format) {
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

    let baseline = match config.mode {
        crate::config::Mode::Ratchet => {
            let dir = get_project_dir(&args)?;
            Some(Baseline::load_from_dir(&dir)?)
        }
        crate::config::Mode::Caps => None,
    };

    if let Some(bl) = baseline.as_ref() {
        if bl.analyzer_id != result.analyzer_id {
            return Err(Error::Baseline(format!(
                "analyzer mismatch: baseline was created with '{}' but current analyzer is '{}'\n\
                 hint: re-run `unsafe-budget update` with the current analyzer to regenerate the baseline",
                bl.analyzer_id, result.analyzer_id
            )));
        }
    }

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

    if !should_retain_details(args.details, args.format) {
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
    // a configured timeout also bounds the discovery probe, so a hung plugin's
    // `--info` cannot wedge the listing
    let config = Config::load_from_dir(&std::env::current_dir()?)?;
    let timeout = config.plugin_timeout_secs.or(config.timeout_secs);
    let plugins = list_analyzers(timeout);
    output::print_plugins(&plugins, args.format)?;
    Ok(ExitCode::SUCCESS)
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
        None => Ok(std::env::current_dir()?),
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

    let workspace_only = args.workspace_only || config.workspace_only;

    // the general timeout bounds the built-in external analyzers and, unless a
    // plugin-specific override is set, plugins too
    let general_timeout = args.timeout.or(config.timeout_secs);

    ScanOpts {
        workspace_only,
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

/// remove occurrences that match an `[[ignore]]` config entry and subtract them
/// from the owning unit's count and from the totals. A match requires both the
/// file path and line number to be equal; the `reason` field is documentation
/// only.
///
/// if `ignores` is empty, or the scan result has no detail occurrences (e.g.
/// cargo_geiger only provides aggregate counts), this is a no-op.
fn apply_ignore_filter(mut result: ScanResult, ignores: &[IgnoreEntry]) -> ScanResult {
    if ignores.is_empty() || result.details.is_empty() {
        return result;
    }

    let ignore_set: HashSet<(&std::path::Path, u32)> = ignores
        .iter()
        .map(|rule| (rule.file.as_path(), rule.line))
        .collect();

    let mut removed: HashMap<String, u64> = HashMap::new();
    result.details.retain(|occ| {
        if ignore_set.contains(&(occ.file.as_path(), occ.line)) {
            *removed.entry(occ.unit.clone()).or_default() += 1;
            false
        } else {
            true
        }
    });

    for unit in &mut result.units {
        if let Some(n) = removed.get(&unit.name) {
            unit.unsafe_count = unit.unsafe_count.saturating_sub(*n);
        }
    }

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
            parse_warnings: vec![],
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
            parse_warnings: vec![],
        }
    }

    /// a plugin's self-reported counts alongside an incomplete occurrence list.
    fn make_result_with_partial_details() -> ScanResult {
        ScanResult {
            tool_version: "0.1.0".into(),
            analyzer_id: "my_plugin".into(),
            language: "rust".into(),
            scope: make_scope(),
            units: vec![
                Unit {
                    name: "plugin_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 12,
                },
                Unit {
                    name: "other_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 1,
                },
            ],
            totals: Totals {
                workspace_unsafe: 13,
                deps_unsafe: 0,
                overall_unsafe: 13,
            },
            details: vec![
                Occurrence {
                    unit: "plugin_crate".into(),
                    file: PathBuf::from("src/a.rs"),
                    line: 1,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "plugin_crate".into(),
                    file: PathBuf::from("src/a.rs"),
                    line: 2,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "plugin_crate".into(),
                    file: PathBuf::from("src/b.rs"),
                    line: 3,
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
            parse_warnings: vec![],
        }
    }

    #[test]
    fn ignore_filter_no_details_preserves_counts() {
        // aggregate counts with no details (cargo_geiger's output shape)
        let ignore = |file: &str, line| IgnoreEntry {
            file: PathBuf::from(file),
            line,
            reason: None,
        };
        let cases = [
            vec![ignore("src/lib.rs", 10)],
            vec![
                ignore("src/lib.rs", 10),
                ignore("src/ffi.rs", 42),
                ignore("vendor/libc/src/lib.rs", 1),
            ],
        ];
        for ignores in cases {
            let filtered = apply_ignore_filter(make_result_without_details(), &ignores);

            // counts must not be zeroed
            assert_eq!(filtered.units[0].unsafe_count, 10);
            assert_eq!(filtered.units[1].unsafe_count, 200);
            assert_eq!(filtered.totals.workspace_unsafe, 10);
            assert_eq!(filtered.totals.deps_unsafe, 200);
            assert_eq!(filtered.totals.overall_unsafe, 210);
        }
    }

    #[test]
    fn ignore_filter_keeps_count_of_unit_with_partial_details() {
        let result = make_result_with_partial_details();
        let ignores = vec![IgnoreEntry {
            file: PathBuf::from("other/src/lib.rs"),
            line: 5,
            reason: None,
        }];
        let filtered = apply_ignore_filter(result, &ignores);

        assert_eq!(filtered.units[0].unsafe_count, 12); // untouched by the ignore
        assert_eq!(filtered.units[1].unsafe_count, 0); // its only occurrence removed
        assert_eq!(filtered.totals.overall_unsafe, 12);
    }

    #[test]
    fn ignore_filter_subtracts_from_unit_with_partial_details() {
        let result = make_result_with_partial_details();
        let ignores = vec![IgnoreEntry {
            file: PathBuf::from("src/a.rs"),
            line: 2,
            reason: None,
        }];
        let filtered = apply_ignore_filter(result, &ignores);

        assert_eq!(filtered.details.len(), 3);
        assert_eq!(filtered.units[0].unsafe_count, 11); // 12 - 1
        assert_eq!(filtered.units[1].unsafe_count, 1);
        assert_eq!(filtered.totals.overall_unsafe, 12);
    }

    #[test]
    fn ignore_filter_saturates_when_occurrences_exceed_count() {
        let mut result = make_result_with_partial_details();
        result.units[0].unsafe_count = 2;
        let ignores = vec![
            IgnoreEntry {
                file: PathBuf::from("src/a.rs"),
                line: 1,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("src/a.rs"),
                line: 2,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("src/b.rs"),
                line: 3,
                reason: None,
            },
        ];
        let filtered = apply_ignore_filter(result, &ignores);

        assert_eq!(filtered.units[0].unsafe_count, 0);
        assert_eq!(filtered.totals.overall_unsafe, 1);
    }

    #[test]
    fn ignore_filter_subtraction_equals_recompute_when_details_complete() {
        let result = make_result_with_details();
        let ignores = vec![
            IgnoreEntry {
                file: PathBuf::from("src/lib.rs"),
                line: 20,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("other/src/lib.rs"),
                line: 5,
                reason: None,
            },
        ];
        let filtered = apply_ignore_filter(result, &ignores);

        let mut surviving: HashMap<&str, u64> = HashMap::new();
        for occ in &filtered.details {
            *surviving.entry(occ.unit.as_str()).or_default() += 1;
        }
        for unit in &filtered.units {
            assert_eq!(
                unit.unsafe_count,
                surviving.get(unit.name.as_str()).copied().unwrap_or(0),
                "unit {}",
                unit.name
            );
        }
        assert_eq!(filtered.totals.overall_unsafe, 2);
    }

    #[test]
    fn ignore_filter_recomputes_dep_totals() {
        let mut result = make_result_with_details();
        // add a dep unit with a detail occurrence.
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
    fn ignore_filter_matches_file_and_line() {
        let ignore = |file: &str, line| IgnoreEntry {
            file: PathBuf::from(file),
            line,
            reason: None,
        };
        // name, ignores -> details left, per-unit counts, (workspace, deps, overall)
        type Case<'a> = (&'a str, Vec<IgnoreEntry>, usize, [u64; 2], (u64, u64, u64));
        let cases: Vec<Case> = vec![
            ("no ignores", vec![], 4, [3, 1], (4, 0, 4)),
            (
                "one match",
                vec![IgnoreEntry {
                    file: PathBuf::from("src/ffi.rs"),
                    line: 42,
                    reason: Some("reviewed".into()),
                }],
                3,
                [2, 1],
                (3, 0, 3),
            ),
            (
                "two matches",
                vec![ignore("src/lib.rs", 10), ignore("src/ffi.rs", 42)],
                2,
                [1, 1],
                (2, 0, 2),
            ),
            (
                "wrong file and line",
                vec![ignore("src/nonexistent.rs", 999)],
                4,
                [3, 1],
                (4, 0, 4),
            ),
            (
                "right file, wrong line",
                vec![ignore("src/ffi.rs", 99)],
                4,
                [3, 1],
                (4, 0, 4),
            ),
            (
                "every occurrence",
                vec![
                    ignore("src/lib.rs", 10),
                    ignore("src/lib.rs", 20),
                    ignore("src/ffi.rs", 42),
                    ignore("other/src/lib.rs", 5),
                ],
                0,
                [0, 0],
                (0, 0, 0),
            ),
        ];
        for (name, ignores, details, counts, totals) in cases {
            let filtered = apply_ignore_filter(make_result_with_details(), &ignores);
            assert_eq!(filtered.details.len(), details, "{name}");
            assert_eq!(
                [
                    filtered.units[0].unsafe_count,
                    filtered.units[1].unsafe_count
                ],
                counts,
                "{name}"
            );
            assert_eq!(
                (
                    filtered.totals.workspace_unsafe,
                    filtered.totals.deps_unsafe,
                    filtered.totals.overall_unsafe
                ),
                totals,
                "{name}"
            );
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
