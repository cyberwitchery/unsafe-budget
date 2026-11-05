pub mod cargo_geiger;
pub mod go_geiger;
pub mod plugin;
pub(crate) mod process;
pub mod rustc;
pub mod sarif;

use crate::error::{Error, Result};
use crate::model::{Occurrence, ScanOpts, ScanResult, Scope, Totals, Unit, UnitKind};
use std::collections::{HashMap, HashSet};
use std::process::Command;

/// trait for unsafe code analyzers.
pub trait Analyzer {
    /// unique identifier for this analyzer.
    fn id(&self) -> &str;

    /// language this analyzer targets.
    fn language(&self) -> &str;

    /// run the analysis with the given options.
    fn run(&self, opts: &ScanOpts) -> Result<ScanResult>;
}

/// information about an available analyzer.
#[derive(Debug, Clone)]
pub struct AnalyzerInfo {
    pub id: String,
    pub language: String,
    pub builtin: bool,
    pub path: Option<std::path::PathBuf>,
}

/// built-in analyzer IDs.
pub const RUSTC_UNSAFE_LINT: &str = "rustc_unsafe_lint";
pub const CARGO_GEIGER: &str = "cargo_geiger";
pub const GO_GEIGER: &str = "go_geiger";
pub const SARIF: &str = "sarif";

/// get an analyzer by ID.
///
/// `timeout` (seconds) bounds the plugin discovery probe when the requested ID
/// is not a built-in analyzer; `None` leaves it unbounded.
pub fn get_analyzer(id: &str, timeout: Option<u64>) -> Result<Box<dyn Analyzer>> {
    match id {
        RUSTC_UNSAFE_LINT => Ok(Box::new(rustc::RustcAnalyzer)),
        CARGO_GEIGER => Ok(Box::new(cargo_geiger::CargoGeigerAnalyzer)),
        GO_GEIGER => Ok(Box::new(go_geiger::GoGeigerAnalyzer)),
        SARIF => Ok(Box::new(sarif::SarifAnalyzer)),
        _ => {
            let plugins = plugin::discover_plugins(timeout);
            if let Some(info) = plugins.iter().find(|p| p.id == id) {
                if let Some(ref path) = info.path {
                    return Ok(Box::new(plugin::PluginAnalyzer {
                        id: info.id.clone(),
                        language: info.language.clone(),
                        path: path.clone(),
                    }));
                }
            }
            Err(Error::analyzer(id, format!("unknown analyzer: {}", id)))
        }
    }
}

/// get the default analyzer (rustc unsafe lint).
pub fn default_analyzer() -> Box<dyn Analyzer> {
    Box::new(rustc::RustcAnalyzer)
}

/// auto-detect analyzer based on project files.
pub fn detect_analyzer(opts: &ScanOpts) -> Result<Box<dyn Analyzer>> {
    let dir = match opts.manifest_path.as_ref().and_then(|p| p.parent()) {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir().map_err(|e| Error::io("current directory", e))?,
    };

    if dir.join("go.mod").exists() || dir.join("go.sum").exists() {
        return Ok(Box::new(go_geiger::GoGeigerAnalyzer));
    }

    if dir.join("Cargo.toml").exists() {
        return Ok(Box::new(rustc::RustcAnalyzer));
    }

    // no project marker found; fall back to rustc
    Ok(Box::new(rustc::RustcAnalyzer))
}

/// list all available analyzers (built-in + discovered plugins).
///
/// `timeout` (seconds) bounds each plugin's discovery probe; `None` leaves it
/// unbounded.
pub fn list_analyzers(timeout: Option<u64>) -> Vec<AnalyzerInfo> {
    let mut analyzers = vec![
        AnalyzerInfo {
            id: RUSTC_UNSAFE_LINT.into(),
            language: "rust".into(),
            builtin: true,
            path: None,
        },
        AnalyzerInfo {
            id: CARGO_GEIGER.into(),
            language: "rust".into(),
            builtin: true,
            path: None,
        },
        AnalyzerInfo {
            id: GO_GEIGER.into(),
            language: "go".into(),
            builtin: true,
            path: None,
        },
        AnalyzerInfo {
            id: SARIF.into(),
            language: "any".into(),
            builtin: true,
            path: None,
        },
    ];

    analyzers.extend(plugin::discover_plugins(timeout));
    analyzers
}

/// run `analyzer` and apply [`normalize`] to its result, as the CLI does.
pub fn scan(analyzer: &dyn Analyzer, opts: &ScanOpts) -> Result<ScanResult> {
    Ok(normalize(analyzer.id(), opts, analyzer.run(opts)?))
}

/// the host's post-run step: analyzer `id` and the scope of `opts`, dependency units dropped unless
/// `opts` includes them, repeated units summed, units and details sorted, and totals recomputed.
pub fn normalize(id: &str, opts: &ScanOpts, result: ScanResult) -> ScanResult {
    let mut counts: HashMap<String, (UnitKind, u64)> = HashMap::new();
    for unit in result.units {
        if opts.includes(unit.kind) {
            add_unit_count(&mut counts, unit.name, unit.kind, unit.unsafe_count);
        }
    }
    let (units, details) = aggregate_units(counts, result.details, opts);

    ScanResult {
        tool_version: result.tool_version,
        analyzer_id: id.to_string(),
        language: result.language,
        scope: Scope::from(opts),
        totals: Totals::from_units(&units),
        units,
        details,
        parse_warnings: result.parse_warnings,
    }
}

/// the manifest a cargo command reads for `opts`, as its errors name it.
pub(crate) fn manifest(opts: &ScanOpts) -> std::path::Display<'_> {
    opts.manifest_path
        .as_deref()
        .unwrap_or(std::path::Path::new("Cargo.toml"))
        .display()
}

/// apply common cargo CLI flags from `ScanOpts` to a command.
///
/// adds `--all-features`, `--no-default-features`, `--features`,
/// `--all-targets`, `--target`, and `--manifest-path` flags as appropriate.
pub(crate) fn apply_cargo_flags(cmd: &mut Command, opts: &ScanOpts) {
    if opts.all_features {
        cmd.arg("--all-features");
    }
    if opts.no_default_features {
        cmd.arg("--no-default-features");
    }
    for feature in &opts.features {
        cmd.arg("--features").arg(feature);
    }

    if opts.all_targets {
        cmd.arg("--all-targets");
    }
    for target in &opts.targets {
        cmd.arg("--target").arg(target);
    }

    if let Some(ref path) = opts.manifest_path {
        cmd.arg("--manifest-path").arg(path);
    }
}

/// add `count` to the unit `name`; a workspace row makes the unit workspace code.
pub(crate) fn add_unit_count(
    counts: &mut HashMap<String, (UnitKind, u64)>,
    name: String,
    kind: UnitKind,
    count: u64,
) {
    let entry = counts.entry(name).or_insert((kind, 0));
    if kind == UnitKind::Workspace {
        entry.0 = kind;
    }
    entry.1 += count;
}

/// aggregate pre-collected unit counts and occurrences into sorted, filtered
/// results.
///
/// filters out dependency units unless `opts.include_deps` is set, converts
/// the count map into sorted [`Unit`] values, and sorts the detail occurrences
/// for deterministic output.
pub(crate) fn aggregate_units(
    counts: HashMap<String, (UnitKind, u64)>,
    details: Vec<Occurrence>,
    opts: &ScanOpts,
) -> (Vec<Unit>, Vec<Occurrence>) {
    let mut units: Vec<Unit> = counts
        .into_iter()
        .filter(|(_, (kind, _))| opts.includes(*kind))
        .map(|(name, (kind, count))| Unit {
            name,
            kind,
            unsafe_count: count,
        })
        .collect();

    units.sort_by(|a, b| a.name.cmp(&b.name));

    let mut details = if !opts.includes(UnitKind::Dep) && !details.is_empty() {
        let retained: HashSet<&str> = units.iter().map(|u| u.name.as_str()).collect();
        details
            .into_iter()
            .filter(|occ| retained.contains(occ.unit.as_str()))
            .collect()
    } else {
        details
    };

    details.sort();

    (units, details)
}

/// Test-only lock serializing every test (across analyzer submodules) that
/// spawns a subprocess or writes-then-execs a script.
///
/// A child spawned in its own process group takes the fork+exec path, which
/// transiently inherits a write fd to another test's not-yet-exec'd script;
/// that script's `execve` then fails with `ETXTBSY`. Serializing each test's
/// whole write+spawn critical section removes the overlap. Poison-resistant so
/// one test's panic can't cascade a `PoisonError` into the next.
#[cfg(test)]
pub(crate) fn test_spawn_guard() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, PoisonError};
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[test]
    fn test_get_analyzer_unknown() {
        match get_analyzer("unknown_analyzer", None) {
            Err(Error::Analyzer { analyzer, message }) => {
                assert_eq!(analyzer, "unknown_analyzer");
                assert_eq!(message, "unknown analyzer: unknown_analyzer");
            }
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    fn host_scope() -> Scope {
        Scope {
            include_deps: true,
            features: vec![],
            all_features: false,
            no_default_features: false,
            all_targets: false,
            targets: vec![],
            manifest_path: None,
        }
    }

    fn reported(
        scope: Scope,
        units: Vec<Unit>,
        totals: Totals,
        details: Vec<Occurrence>,
    ) -> ScanResult {
        ScanResult {
            tool_version: "9.9.9".into(),
            analyzer_id: "self-reported".into(),
            language: "cpp".into(),
            scope,
            units,
            totals,
            details,
            parse_warnings: vec![],
        }
    }

    #[test]
    fn normalize_drops_dep_units_when_deps_excluded() {
        let opts = ScanOpts {
            include_deps: false,
            ..Default::default()
        };
        let units = vec![
            Unit {
                name: "app".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 3,
            },
            Unit {
                name: "libc".into(),
                kind: UnitKind::Dep,
                unsafe_count: 10,
            },
        ];
        let details = vec![
            Occurrence {
                unit: "app".into(),
                file: "src/lib.rs".into(),
                line: 1,
                col: 1,
                message: None,
            },
            Occurrence {
                unit: "libc".into(),
                file: "libc/lib.rs".into(),
                line: 2,
                col: 1,
                message: None,
            },
        ];
        let totals = Totals {
            workspace_unsafe: 3,
            deps_unsafe: 10,
            overall_unsafe: 13,
        };
        let out = normalize(
            "host",
            &opts,
            reported(host_scope(), units, totals, details),
        );

        assert_eq!(out.units.len(), 1);
        assert_eq!(out.units[0].name, "app");
        assert_eq!(out.totals.deps_unsafe, 0);
        assert_eq!(out.totals.overall_unsafe, 3);
        assert!(
            out.details.iter().all(|d| d.unit == "app"),
            "dependency occurrences must be dropped"
        );
    }

    #[test]
    fn normalize_sums_repeated_units_and_workspace_wins() {
        let with_deps = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let no_deps = ScanOpts {
            include_deps: false,
            ..Default::default()
        };
        let cases = [
            (
                "dep rows",
                &with_deps,
                vec![("lodash", UnitKind::Dep, 5), ("lodash", UnitKind::Dep, 2)],
                vec![("lodash", UnitKind::Dep, 7)],
            ),
            (
                "workspace then dep",
                &with_deps,
                vec![("app", UnitKind::Workspace, 5), ("app", UnitKind::Dep, 2)],
                vec![("app", UnitKind::Workspace, 7)],
            ),
            (
                "dep then workspace",
                &with_deps,
                vec![("app", UnitKind::Dep, 2), ("app", UnitKind::Workspace, 5)],
                vec![("app", UnitKind::Workspace, 7)],
            ),
            (
                "workspace then dep, no deps",
                &no_deps,
                vec![("app", UnitKind::Workspace, 5), ("app", UnitKind::Dep, 2)],
                vec![("app", UnitKind::Workspace, 5)],
            ),
            (
                "dep then workspace, no deps",
                &no_deps,
                vec![("app", UnitKind::Dep, 2), ("app", UnitKind::Workspace, 5)],
                vec![("app", UnitKind::Workspace, 5)],
            ),
            (
                "dep rows, no deps",
                &no_deps,
                vec![("lodash", UnitKind::Dep, 5), ("lodash", UnitKind::Dep, 2)],
                vec![],
            ),
        ];
        for (case, opts, rows, expected) in cases {
            let units = rows
                .into_iter()
                .map(|(name, kind, unsafe_count)| Unit {
                    name: name.into(),
                    kind,
                    unsafe_count,
                })
                .collect();
            let out = normalize(
                "host",
                opts,
                reported(host_scope(), units, Totals::default(), vec![]),
            );
            let got: Vec<_> = out
                .units
                .iter()
                .map(|u| (u.name.as_str(), u.kind, u.unsafe_count))
                .collect();
            assert_eq!(got, expected, "{case}");
        }
    }

    #[test]
    fn normalize_recomputes_totals_from_units() {
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let units = vec![
            Unit {
                name: "app".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 4,
            },
            Unit {
                name: "dep".into(),
                kind: UnitKind::Dep,
                unsafe_count: 6,
            },
        ];
        let totals = Totals {
            workspace_unsafe: 999,
            deps_unsafe: 999,
            overall_unsafe: 999,
        };
        let out = normalize("host", &opts, reported(host_scope(), units, totals, vec![]));

        assert_eq!(out.totals.workspace_unsafe, 4);
        assert_eq!(out.totals.deps_unsafe, 6);
        assert_eq!(out.totals.overall_unsafe, 10);
    }

    #[test]
    fn normalize_overrides_scope_with_host_scope() {
        let opts = ScanOpts {
            features: vec!["hostfeat".into()],
            ..Default::default()
        };
        let wrong = Scope {
            include_deps: true,
            features: vec!["pluginfeat".into()],
            all_features: true,
            no_default_features: true,
            all_targets: true,
            targets: vec!["wrong-target".into()],
            manifest_path: Some("/wrong/Cargo.toml".into()),
        };
        let out = normalize(
            "host",
            &opts,
            reported(wrong, vec![], Totals::default(), vec![]),
        );

        assert_eq!(out.scope, Scope::from(&opts));
        assert!(!out.scope.include_deps);
        assert_eq!(out.scope.features, vec!["hostfeat"]);
    }

    #[test]
    fn normalize_overrides_analyzer_id_with_host_id() {
        let opts = ScanOpts::default();
        let out = normalize(
            "host",
            &opts,
            reported(host_scope(), vec![], Totals::default(), vec![]),
        );
        assert_eq!(out.analyzer_id, "host");
    }

    #[test]
    fn normalize_preserves_reported_tool_version_and_language() {
        let opts = ScanOpts::default();
        let out = normalize(
            "host",
            &opts,
            reported(host_scope(), vec![], Totals::default(), vec![]),
        );
        assert_eq!(out.tool_version, "9.9.9");
        assert_eq!(out.language, "cpp");
    }

    #[test]
    fn scan_normalizes_a_library_analyzer() {
        struct Library;
        impl Analyzer for Library {
            fn id(&self) -> &str {
                "library"
            }
            fn language(&self) -> &str {
                "c"
            }
            fn run(&self, _: &ScanOpts) -> Result<ScanResult> {
                let units = vec![
                    Unit {
                        name: "app".into(),
                        kind: UnitKind::Workspace,
                        unsafe_count: 2,
                    },
                    Unit {
                        name: "libc".into(),
                        kind: UnitKind::Dep,
                        unsafe_count: 5,
                    },
                ];
                let totals = Totals {
                    workspace_unsafe: 9,
                    deps_unsafe: 9,
                    overall_unsafe: 9,
                };
                Ok(reported(host_scope(), units, totals, vec![]))
            }
        }

        let opts = ScanOpts {
            include_deps: false,
            ..Default::default()
        };
        let out = scan(&Library, &opts).unwrap();

        assert_eq!(out.analyzer_id, "library");
        assert_eq!(out.scope, Scope::from(&opts));
        let units: Vec<_> = out
            .units
            .iter()
            .map(|u| (u.name.as_str(), u.kind, u.unsafe_count))
            .collect();
        assert_eq!(units, [("app", UnitKind::Workspace, 2)]);
        assert_eq!(
            out.totals,
            Totals {
                workspace_unsafe: 2,
                deps_unsafe: 0,
                overall_unsafe: 2,
            }
        );
    }

    #[test]
    fn test_default_analyzer() {
        let analyzer = default_analyzer();
        assert_eq!(analyzer.id(), "rustc_unsafe_lint");
        assert_eq!(analyzer.language(), "rust");
    }

    #[test]
    fn test_aggregate_units_basic() {
        let mut counts = HashMap::new();
        counts.insert("alpha".to_string(), (UnitKind::Workspace, 3));
        counts.insert("beta".to_string(), (UnitKind::Dep, 5));

        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };

        let (units, details) = aggregate_units(counts, vec![], &opts);

        assert_eq!(units.len(), 2);
        assert_eq!(units[0].name, "alpha");
        assert_eq!(units[0].unsafe_count, 3);
        assert_eq!(units[1].name, "beta");
        assert_eq!(units[1].unsafe_count, 5);
        assert!(details.is_empty());
    }

    #[test]
    fn test_aggregate_units_filters_deps_include_deps_false() {
        let mut counts = HashMap::new();
        counts.insert("my_crate".to_string(), (UnitKind::Workspace, 2));
        counts.insert("libc".to_string(), (UnitKind::Dep, 10));

        let details = vec![
            Occurrence {
                unit: "my_crate".into(),
                file: PathBuf::from("src/lib.rs"),
                line: 1,
                col: 1,
                message: None,
            },
            Occurrence {
                unit: "libc".into(),
                file: PathBuf::from("lib.rs"),
                line: 1,
                col: 1,
                message: None,
            },
        ];

        let opts = ScanOpts {
            include_deps: false,
            ..Default::default()
        };

        let (units, filtered) = aggregate_units(counts, details, &opts);

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "my_crate");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].unit, "my_crate");
    }

    #[test]
    fn test_aggregate_units_sorts_deterministically() {
        let mut counts = HashMap::new();
        counts.insert("zebra".to_string(), (UnitKind::Workspace, 1));
        counts.insert("alpha".to_string(), (UnitKind::Workspace, 2));
        counts.insert("middle".to_string(), (UnitKind::Workspace, 3));

        let details = vec![
            Occurrence {
                unit: "zebra".into(),
                file: PathBuf::from("z.rs"),
                line: 10,
                col: 1,
                message: Some("tie".into()),
            },
            Occurrence {
                unit: "zebra".into(),
                file: PathBuf::from("z.rs"),
                line: 10,
                col: 1,
                message: None,
            },
            Occurrence {
                unit: "alpha".into(),
                file: PathBuf::from("a.rs"),
                line: 5,
                col: 1,
                message: None,
            },
            Occurrence {
                unit: "alpha".into(),
                file: PathBuf::from("a.rs"),
                line: 1,
                col: 1,
                message: None,
            },
        ];

        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };

        let (units, sorted_details) = aggregate_units(counts, details, &opts);

        assert_eq!(units[0].name, "alpha");
        assert_eq!(units[1].name, "middle");
        assert_eq!(units[2].name, "zebra");

        assert_eq!(sorted_details[0].unit, "alpha");
        assert_eq!(sorted_details[0].line, 1);
        assert_eq!(sorted_details[1].unit, "alpha");
        assert_eq!(sorted_details[1].line, 5);
        assert_eq!(sorted_details[2].unit, "zebra");
        assert_eq!(sorted_details[3].message.as_deref(), Some("tie"));
    }

    #[test]
    fn test_aggregate_units_empty() {
        let counts = HashMap::new();
        let opts = ScanOpts::default();

        let (units, details) = aggregate_units(counts, vec![], &opts);

        assert!(units.is_empty());
        assert!(details.is_empty());
    }

    #[test]
    fn test_get_analyzer_builtins() {
        let cases = [
            (RUSTC_UNSAFE_LINT, "rustc_unsafe_lint", "rust"),
            (CARGO_GEIGER, "cargo_geiger", "rust"),
            (GO_GEIGER, "go_geiger", "go"),
            (SARIF, "sarif", "unknown"),
        ];
        for (id, expected_id, language) in cases {
            let analyzer = get_analyzer(id, None).unwrap();
            assert_eq!(
                (analyzer.id(), analyzer.language()),
                (expected_id, language)
            );
        }
    }

    #[test]
    fn test_list_analyzers_includes_builtins() {
        let analyzers = list_analyzers(None);
        for (id, language) in [
            ("rustc_unsafe_lint", "rust"),
            ("cargo_geiger", "rust"),
            ("go_geiger", "go"),
            ("sarif", "any"),
        ] {
            let analyzer = analyzers
                .iter()
                .find(|a| a.id == id)
                .unwrap_or_else(|| panic!("{id} is listed"));
            assert_eq!(analyzer.language, language, "{id}");
            assert!(analyzer.builtin, "{id}");
            assert_eq!(analyzer.path, None, "{id}");
        }
    }

    #[test]
    fn test_apply_cargo_flags() {
        let cases: [(ScanOpts, &[&str]); 4] = [
            (ScanOpts::default(), &[]),
            (
                ScanOpts {
                    all_features: true,
                    no_default_features: true,
                    features: vec!["feat1".into(), "feat2".into()],
                    all_targets: true,
                    targets: vec!["x86_64-unknown-linux-gnu".into()],
                    manifest_path: Some(PathBuf::from("/path/to/Cargo.toml")),
                    ..Default::default()
                },
                &[
                    "--all-features",
                    "--no-default-features",
                    "--features",
                    "feat1",
                    "--features",
                    "feat2",
                    "--all-targets",
                    "--target",
                    "x86_64-unknown-linux-gnu",
                    "--manifest-path",
                    "/path/to/Cargo.toml",
                ],
            ),
            (
                ScanOpts {
                    features: vec!["serde".into()],
                    ..Default::default()
                },
                &["--features", "serde"],
            ),
            (
                ScanOpts {
                    manifest_path: Some(PathBuf::from("sub/Cargo.toml")),
                    ..Default::default()
                },
                &["--manifest-path", "sub/Cargo.toml"],
            ),
        ];
        for (opts, expected) in cases {
            let mut cmd = Command::new("cargo");
            apply_cargo_flags(&mut cmd, &opts);
            let args: Vec<_> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().to_string())
                .collect();
            // cargo does not care about flag order, only that each value stays
            // with its flag.
            assert_eq!(flag_units(&args), flag_units(expected), "{expected:?}");
        }
    }

    fn flag_units<S: AsRef<str>>(args: &[S]) -> Vec<Vec<String>> {
        let mut units = Vec::new();
        let mut args = args.iter().map(|a| a.as_ref().to_string());
        while let Some(flag) = args.next() {
            let takes_value =
                matches!(flag.as_str(), "--features" | "--target" | "--manifest-path");
            let mut unit = vec![flag];
            if takes_value {
                unit.extend(args.next());
            }
            units.push(unit);
        }
        units.sort();
        units
    }
}
