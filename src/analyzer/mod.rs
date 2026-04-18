pub mod cargo_geiger;
pub mod go_geiger;
pub mod plugin;
pub mod rustc;
pub mod sarif;

use crate::error::{Error, Result};
use crate::model::{Occurrence, ScanOpts, ScanResult, Unit, UnitKind};
use std::collections::{HashMap, HashSet};

/// Trait for unsafe code analyzers.
pub trait Analyzer {
    /// Unique identifier for this analyzer.
    fn id(&self) -> &str;

    /// Language this analyzer targets.
    fn language(&self) -> &str;

    /// Run the analysis with the given options.
    fn run(&self, opts: &ScanOpts) -> Result<ScanResult>;
}

/// Information about an available analyzer.
#[derive(Debug, Clone)]
pub struct AnalyzerInfo {
    pub id: String,
    pub language: String,
    pub builtin: bool,
    pub path: Option<std::path::PathBuf>,
}

/// Built-in analyzer IDs.
pub const RUSTC_UNSAFE_LINT: &str = "rustc_unsafe_lint";
pub const CARGO_GEIGER: &str = "cargo_geiger";
pub const GO_GEIGER: &str = "go_geiger";
pub const SARIF: &str = "sarif";

/// Get an analyzer by ID.
pub fn get_analyzer(id: &str) -> Result<Box<dyn Analyzer>> {
    match id {
        RUSTC_UNSAFE_LINT => Ok(Box::new(rustc::RustcAnalyzer)),
        CARGO_GEIGER => Ok(Box::new(cargo_geiger::CargoGeigerAnalyzer)),
        GO_GEIGER => Ok(Box::new(go_geiger::GoGeigerAnalyzer)),
        SARIF => Ok(Box::new(sarif::SarifAnalyzer)),
        _ => {
            // Check for external plugin
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

/// Get the default analyzer (rustc unsafe lint).
pub fn default_analyzer() -> Box<dyn Analyzer> {
    Box::new(rustc::RustcAnalyzer)
}

/// Auto-detect analyzer based on project files.
pub fn detect_analyzer(opts: &ScanOpts) -> Result<Box<dyn Analyzer>> {
    let dir = match opts.manifest_path.as_ref().and_then(|p| p.parent()) {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };

    // Check for Go project
    if dir.join("go.mod").exists() || dir.join("go.sum").exists() {
        return Ok(Box::new(go_geiger::GoGeigerAnalyzer));
    }

    // Check for Rust project (default)
    if dir.join("Cargo.toml").exists() {
        return Ok(Box::new(rustc::RustcAnalyzer));
    }

    // Default to rustc
    Ok(Box::new(rustc::RustcAnalyzer))
}

/// List all available analyzers (built-in + discovered plugins).
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

/// Aggregate pre-collected unit counts and occurrences into sorted, filtered
/// results.
///
/// Filters out dependency units when `opts.workspace_only` is set or
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

        // Should have at least the 4 built-in analyzers
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
}
