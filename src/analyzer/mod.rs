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
pub fn get_analyzer(id: &str) -> Result<Box<dyn Analyzer>> {
    match id {
        RUSTC_UNSAFE_LINT => Ok(Box::new(rustc::RustcAnalyzer)),
        CARGO_GEIGER => Ok(Box::new(cargo_geiger::CargoGeigerAnalyzer)),
        GO_GEIGER => Ok(Box::new(go_geiger::GoGeigerAnalyzer)),
        SARIF => Ok(Box::new(sarif::SarifAnalyzer)),
        _ => {
            // check for external plugin
            let plugins = plugin::discover_plugins();
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

    // check for Go project
    if dir.join("go.mod").exists() || dir.join("go.sum").exists() {
        return Ok(Box::new(go_geiger::GoGeigerAnalyzer));
    }

    // check for Rust project (default)
    if dir.join("Cargo.toml").exists() {
        return Ok(Box::new(rustc::RustcAnalyzer));
    }

    // default to rustc
    Ok(Box::new(rustc::RustcAnalyzer))
}

/// list all available analyzers (built-in + discovered plugins).
pub fn list_analyzers() -> Vec<AnalyzerInfo> {
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

    analyzers.extend(plugin::discover_plugins());
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
    use std::path::PathBuf;

    #[test]
    fn test_get_analyzer_rustc() {
        let analyzer = get_analyzer(RUSTC_UNSAFE_LINT).unwrap();
        assert_eq!(analyzer.id(), "rustc_unsafe_lint");
        assert_eq!(analyzer.language(), "rust");
    }

    #[test]
    fn test_get_analyzer_cargo_geiger() {
        let analyzer = get_analyzer(CARGO_GEIGER).unwrap();
        assert_eq!(analyzer.id(), "cargo_geiger");
        assert_eq!(analyzer.language(), "rust");
    }

    #[test]
    fn test_get_analyzer_go_geiger() {
        let analyzer = get_analyzer(GO_GEIGER).unwrap();
        assert_eq!(analyzer.id(), "go_geiger");
        assert_eq!(analyzer.language(), "go");
    }

    #[test]
    fn test_get_analyzer_sarif() {
        let analyzer = get_analyzer(SARIF).unwrap();
        assert_eq!(analyzer.id(), "sarif");
        assert_eq!(analyzer.language(), "unknown");
    }

    #[test]
    fn test_get_analyzer_unknown() {
        let result = get_analyzer("unknown_analyzer");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_analyzer() {
        let analyzer = default_analyzer();
        assert_eq!(analyzer.id(), "rustc_unsafe_lint");
        assert_eq!(analyzer.language(), "rust");
    }

    #[test]
    fn test_list_analyzers_has_builtins() {
        let analyzers = list_analyzers();

        // should have at least the 4 built-in analyzers
        assert!(analyzers.len() >= 4);

        let ids: Vec<_> = analyzers.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"rustc_unsafe_lint"));
        assert!(ids.contains(&"cargo_geiger"));
        assert!(ids.contains(&"go_geiger"));
        assert!(ids.contains(&"sarif"));
    }

    #[test]
    fn test_list_analyzers_builtins_are_marked() {
        let analyzers = list_analyzers();

        let rustc = analyzers
            .iter()
            .find(|a| a.id == RUSTC_UNSAFE_LINT)
            .unwrap();
        assert!(rustc.builtin);
        assert!(rustc.path.is_none());

        let cargo_geiger = analyzers.iter().find(|a| a.id == CARGO_GEIGER).unwrap();
        assert!(cargo_geiger.builtin);

        let go_geiger = analyzers.iter().find(|a| a.id == GO_GEIGER).unwrap();
        assert!(go_geiger.builtin);
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
    fn test_apply_cargo_flags_default_opts() {
        let opts = ScanOpts::default();
        let mut cmd = Command::new("cargo");
        apply_cargo_flags(&mut cmd, &opts);

        let args: Vec<_> = cmd.get_args().collect::<Vec<_>>();
        assert!(args.is_empty());
    }

    #[test]
    fn test_apply_cargo_flags_all_flags() {
        let opts = ScanOpts {
            all_features: true,
            no_default_features: true,
            features: vec!["feat1".into(), "feat2".into()],
            all_targets: true,
            targets: vec!["x86_64-unknown-linux-gnu".into()],
            manifest_path: Some(PathBuf::from("/path/to/Cargo.toml")),
            ..Default::default()
        };
        let mut cmd = Command::new("cargo");
        apply_cargo_flags(&mut cmd, &opts);

        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(args.contains(&"--all-features".to_string()));
        assert!(args.contains(&"--no-default-features".to_string()));
        assert!(args.contains(&"--all-targets".to_string()));
        assert!(args.contains(&"--manifest-path".to_string()));
        assert!(args.contains(&"/path/to/Cargo.toml".to_string()));

        // check features are paired correctly
        let feat_positions: Vec<_> = args
            .iter()
            .enumerate()
            .filter(|(_, a)| a.as_str() == "--features")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(feat_positions.len(), 2);
        assert_eq!(args[feat_positions[0] + 1], "feat1");
        assert_eq!(args[feat_positions[1] + 1], "feat2");

        // check target is paired correctly
        let target_pos = args.iter().position(|a| a == "--target").unwrap();
        assert_eq!(args[target_pos + 1], "x86_64-unknown-linux-gnu");
    }

    #[test]
    fn test_apply_cargo_flags_features_only() {
        let opts = ScanOpts {
            features: vec!["serde".into()],
            ..Default::default()
        };
        let mut cmd = Command::new("cargo");
        apply_cargo_flags(&mut cmd, &opts);

        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(args, vec!["--features", "serde"]);
    }

    #[test]
    fn test_apply_cargo_flags_manifest_path_only() {
        let opts = ScanOpts {
            manifest_path: Some(PathBuf::from("sub/Cargo.toml")),
            ..Default::default()
        };
        let mut cmd = Command::new("cargo");
        apply_cargo_flags(&mut cmd, &opts);

        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert_eq!(args, vec!["--manifest-path", "sub/Cargo.toml"]);
    }
}
