pub mod cargo_geiger;
pub mod go_geiger;
pub mod plugin;
pub(crate) mod process;
pub mod rustc;
pub mod sarif;

use crate::error::{Error, Result};
use crate::model::{Occurrence, ScanOpts, ScanResult, Unit, UnitKind};
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
            Err(Error::Analyzer {
                analyzer: id.into(),
                message: format!("unknown analyzer: {}", id),
            })
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
        None => std::env::current_dir()?,
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

/// classify a source-file path as a workspace unit or an external dependency.
///
/// returns [`UnitKind::Dep`] when the path contains an unambiguous
/// dependency-cache marker for one of the ecosystems this tool targets, and
/// [`UnitKind::Workspace`] otherwise.
pub(crate) fn classify_unit_kind(path: &std::path::Path) -> UnitKind {
    const DEP_MARKERS: &[&str] = &[
        "/.cargo/registry/", // Rust: crates.io / registry download cache
        "/.cargo/git/",      // Rust: git-dependency checkout cache
        "/vendor/",          // Go: vendored dependencies
        "/go/pkg/mod/",      // Go: module download cache
    ];

    let path = path.to_string_lossy();
    if DEP_MARKERS.iter().any(|marker| path.contains(marker)) || path.starts_with("vendor/") {
        UnitKind::Dep
    } else {
        UnitKind::Workspace
    }
}

/// aggregate pre-collected unit counts and occurrences into sorted, filtered
/// results.
///
/// filters out dependency units when `opts.workspace_only` is set or
/// `opts.include_deps` is false, converts the count map into sorted [`Unit`]
/// values, and sorts the detail occurrences for deterministic output.
pub(crate) fn aggregate_units(
    counts: HashMap<String, (UnitKind, u64)>,
    details: Vec<Occurrence>,
    opts: &ScanOpts,
) -> (Vec<Unit>, Vec<Occurrence>) {
    let exclude_deps = opts.workspace_only || !opts.include_deps;

    let mut units: Vec<Unit> = counts
        .into_iter()
        .filter(|(_, (kind, _))| !exclude_deps || *kind != UnitKind::Dep)
        .map(|(name, (kind, count))| Unit {
            name,
            kind,
            unsafe_count: count,
        })
        .collect();

    units.sort_by(|a, b| a.name.cmp(&b.name));

    let mut details = if exclude_deps && !details.is_empty() {
        let retained: HashSet<&str> = units.iter().map(|u| u.name.as_str()).collect();
        details
            .into_iter()
            .filter(|occ| retained.contains(occ.unit.as_str()))
            .collect()
    } else {
        details
    };

    details.sort_by(|a, b| {
        a.unit
            .cmp(&b.unit)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.col.cmp(&b.col))
    });

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
    use std::path::{Path, PathBuf};

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
    fn test_aggregate_units_filters_deps_workspace_only() {
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
            workspace_only: true,
            include_deps: true,
            ..Default::default()
        };

        let (units, filtered) = aggregate_units(counts, details, &opts);

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "my_crate");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].unit, "my_crate");
    }

    #[test]
    fn test_aggregate_units_filters_deps_include_deps_false() {
        let mut counts = HashMap::new();
        counts.insert("my_crate".to_string(), (UnitKind::Workspace, 2));
        counts.insert("libc".to_string(), (UnitKind::Dep, 10));

        let opts = ScanOpts {
            include_deps: false,
            ..Default::default()
        };

        let (units, _) = aggregate_units(counts, vec![], &opts);

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "my_crate");
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
    fn test_classify_unit_kind() {
        let cases = [
            (
                "/home/user/.cargo/registry/src/index.crates.io-abc/libc-0.2.0/src/lib.rs",
                UnitKind::Dep,
            ),
            (
                "/home/user/.cargo/git/checkouts/some-crate-abc/rev/src/lib.rs",
                UnitKind::Dep,
            ),
            (
                "/home/user/project/vendor/github.com/pkg/errors/errors.go",
                UnitKind::Dep,
            ),
            (
                "/home/user/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go",
                UnitKind::Dep,
            ),
            ("crate_a/src/lib.rs", UnitKind::Workspace),
            ("/home/user/project/src/main.rs", UnitKind::Workspace),
            ("vendor-tools/gen.go", UnitKind::Workspace),
        ];
        for (path, kind) in cases {
            assert_eq!(classify_unit_kind(Path::new(path)), kind, "{path}");
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
