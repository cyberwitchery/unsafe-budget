//! core data types for unsafe-budget.
//!
//! this module defines the normalized data model that all analyzers produce
//! and the budget engine consumes.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// scan options passed from cli to analyzers.
///
/// controls what gets scanned and how.
///
/// # example
///
/// ```
/// use unsafe_budget::model::ScanOpts;
///
/// let opts = ScanOpts {
///     workspace_only: true,
///     include_deps: false,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct ScanOpts {
    /// only scan workspace crates, not dependencies.
    pub workspace_only: bool,
    /// include dependencies in scan results.
    pub include_deps: bool,
    /// cargo features to enable.
    pub features: Vec<String>,
    /// enable all cargo features.
    pub all_features: bool,
    /// disable default cargo features.
    pub no_default_features: bool,
    /// build all targets (lib, bins, tests, etc).
    pub all_targets: bool,
    /// specific target triples to build for.
    pub targets: Vec<String>,
    /// path to Cargo.toml or go.mod.
    pub manifest_path: Option<PathBuf>,
    /// timeout in seconds for external plugin execution.
    pub plugin_timeout_secs: Option<u64>,
    /// timeout in seconds for the built-in external analyzer subprocesses
    /// (`cargo geiger`, `go-geiger`, `cargo check`). `None` leaves them
    /// unbounded.
    pub analyzer_timeout_secs: Option<u64>,
}

/// scope captured in results for reproducibility.
///
/// records what options were used for a scan so baselines can be compared
/// with matching scopes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scope {
    pub workspace_only: bool,
    pub include_deps: bool,
    pub features: Vec<String>,
    /// whether `--all-features` was passed.
    #[serde(default)]
    pub all_features: bool,
    /// whether `--no-default-features` was passed.
    #[serde(default)]
    pub no_default_features: bool,
    pub all_targets: bool,
    pub targets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<PathBuf>,
}

impl Scope {
    /// compare two scopes and return human-readable descriptions of fields that differ.
    ///
    /// returns an empty vec when both scopes are equal.
    pub fn diff_fields(&self, other: &Scope) -> Vec<String> {
        let mut diffs = Vec::new();

        if self.workspace_only != other.workspace_only {
            diffs.push(format!(
                "workspace_only: baseline={}, current={}",
                self.workspace_only, other.workspace_only
            ));
        }
        if self.include_deps != other.include_deps {
            diffs.push(format!(
                "include_deps: baseline={}, current={}",
                self.include_deps, other.include_deps
            ));
        }
        if self.features != other.features {
            diffs.push(format!(
                "features: baseline={:?}, current={:?}",
                self.features, other.features
            ));
        }
        if self.all_features != other.all_features {
            diffs.push(format!(
                "all_features: baseline={}, current={}",
                self.all_features, other.all_features
            ));
        }
        if self.no_default_features != other.no_default_features {
            diffs.push(format!(
                "no_default_features: baseline={}, current={}",
                self.no_default_features, other.no_default_features
            ));
        }
        if self.all_targets != other.all_targets {
            diffs.push(format!(
                "all_targets: baseline={}, current={}",
                self.all_targets, other.all_targets
            ));
        }
        if self.targets != other.targets {
            diffs.push(format!(
                "targets: baseline={:?}, current={:?}",
                self.targets, other.targets
            ));
        }
        if self.manifest_path != other.manifest_path {
            diffs.push(format!(
                "manifest_path: baseline={:?}, current={:?}",
                self.manifest_path, other.manifest_path
            ));
        }

        diffs
    }
}

impl From<&ScanOpts> for Scope {
    fn from(opts: &ScanOpts) -> Self {
        Scope {
            workspace_only: opts.workspace_only,
            include_deps: opts.include_deps,
            features: opts.features.clone(),
            all_features: opts.all_features,
            no_default_features: opts.no_default_features,
            all_targets: opts.all_targets,
            targets: opts.targets.clone(),
            manifest_path: opts.manifest_path.clone(),
        }
    }
}

/// whether a unit is part of the workspace or a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnitKind {
    /// a crate/package in the current workspace.
    Workspace,
    /// an external dependency.
    Dep,
}

impl std::fmt::Display for UnitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnitKind::Workspace => write!(f, "workspace"),
            UnitKind::Dep => write!(f, "dep"),
        }
    }
}

/// a compilation unit (crate, package, or module).
///
/// represents a single unit of code that can contain unsafe code.
///
/// # example
///
/// ```
/// use unsafe_budget::model::{Unit, UnitKind};
///
/// let unit = Unit {
///     name: "my_crate".into(),
///     kind: UnitKind::Workspace,
///     unsafe_count: 5,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Unit {
    /// name of the unit (crate name, package name, etc).
    pub name: String,
    /// whether this is a workspace member or dependency.
    pub kind: UnitKind,
    /// number of unsafe occurrences in this unit.
    pub unsafe_count: u64,
}

/// detail for a single unsafe occurrence.
///
/// provides line-level information about where unsafe code was found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Occurrence {
    /// name of the unit containing this occurrence.
    pub unit: String,
    /// file path relative to the project root.
    pub file: PathBuf,
    /// line number (1-indexed).
    pub line: u32,
    /// column number (1-indexed).
    pub col: u32,
    /// optional message describing the unsafe usage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// summary totals for a scan.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Totals {
    /// total unsafe count in workspace crates.
    pub workspace_unsafe: u64,
    /// total unsafe count in dependencies.
    pub deps_unsafe: u64,
    /// overall total (workspace + deps).
    pub overall_unsafe: u64,
}

impl Totals {
    pub fn from_units(units: &[Unit]) -> Self {
        let workspace_unsafe: u64 = units
            .iter()
            .filter(|u| u.kind == UnitKind::Workspace)
            .map(|u| u.unsafe_count)
            .sum();

        let deps_unsafe: u64 = units
            .iter()
            .filter(|u| u.kind == UnitKind::Dep)
            .map(|u| u.unsafe_count)
            .sum();

        Self {
            workspace_unsafe,
            deps_unsafe,
            overall_unsafe: workspace_unsafe + deps_unsafe,
        }
    }
}

/// the main scan result - normalized output from any analyzer.
///
/// this is the core data structure that all analyzers produce.
/// it provides a language-agnostic view of unsafe code usage.
///
/// # example
///
/// ```
/// use unsafe_budget::model::{ScanResult, Scope, Totals, Unit, UnitKind};
///
/// let result = ScanResult {
///     tool_version: "0.1.0".into(),
///     analyzer_id: "rustc_unsafe_lint".into(),
///     language: "rust".into(),
///     scope: Scope {
///         workspace_only: false,
///         include_deps: true,
///         features: vec![],
///         all_features: false,
///         no_default_features: false,
///         all_targets: false,
///         targets: vec![],
///         manifest_path: None,
///     },
///     units: vec![
///         Unit {
///             name: "my_crate".into(),
///             kind: UnitKind::Workspace,
///             unsafe_count: 5,
///         },
///     ],
///     totals: Totals {
///         workspace_unsafe: 5,
///         deps_unsafe: 0,
///         overall_unsafe: 5,
///     },
///     details: vec![],
///     parse_warnings: vec![],
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// version of the tool that produced this result.
    pub tool_version: String,
    /// identifier of the analyzer used.
    pub analyzer_id: String,
    /// programming language analyzed.
    pub language: String,
    /// scan options used.
    pub scope: Scope,
    /// per-unit unsafe counts.
    pub units: Vec<Unit>,
    /// summary totals.
    pub totals: Totals,
    /// optional line-level details.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<Occurrence>,
    /// warnings emitted while parsing analyzer output.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parse_warnings: Vec<ParseWarning>,
}

impl ScanResult {
    /// build a `ScanResult` from pre-aggregated parts.
    ///
    /// sets `tool_version` to this crate's version, computes `totals` from
    /// `units`, and derives `scope` from `opts`.
    pub fn from_parts(
        analyzer_id: impl Into<String>,
        language: impl Into<String>,
        opts: &ScanOpts,
        units: Vec<Unit>,
        details: Vec<Occurrence>,
    ) -> Self {
        let totals = Totals::from_units(&units);
        Self {
            tool_version: env!("CARGO_PKG_VERSION").into(),
            analyzer_id: analyzer_id.into(),
            language: language.into(),
            scope: Scope::from(opts),
            units,
            totals,
            details,
            parse_warnings: Vec::new(),
        }
    }
}

/// a warning emitted during output parsing.
///
/// records when an analyzer encounters a line it cannot fully parse
/// but can safely skip.  these are accumulated in [`ScanResult`] so
/// they flow through json/sarif output instead of being written to
/// stderr.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParseWarning {
    /// human-readable description of what went wrong.
    pub message: String,
}

/// a budget violation.
///
/// records when a unit exceeds its allowed unsafe count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// name of the violating unit.
    pub unit: String,
    /// whether this is a workspace member or dependency.
    pub kind: UnitKind,
    /// the allowed count (from baseline or cap).
    pub baseline: u64,
    /// the actual count found.
    pub actual: u64,
    /// difference (actual - baseline).
    pub delta: i64,
}

/// a budget warning.
///
/// records when a unit is near its configured budget threshold but has not
/// exceeded it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warning {
    /// name of the warned unit.
    pub unit: String,
    /// whether this is a workspace member or dependency.
    pub kind: UnitKind,
    /// the allowed count (from baseline or cap).
    pub budget: u64,
    /// the actual count found.
    pub actual: u64,
}

/// result of a budget check.
///
/// combines the scan result with any violations found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// the scan result that was checked.
    pub scan: ScanResult,
    /// list of violations (empty if passed).
    pub violations: Vec<Violation>,
    /// list of threshold warnings (empty if none configured or triggered).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
    /// whether the check passed (no violations).
    pub passed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unit_kind_display_workspace() {
        assert_eq!(format!("{}", UnitKind::Workspace), "workspace");
    }

    #[test]
    fn test_unit_kind_display_dep() {
        assert_eq!(format!("{}", UnitKind::Dep), "dep");
    }

    #[test]
    fn test_scope_from_scan_opts() {
        let opts = ScanOpts {
            workspace_only: true,
            include_deps: false,
            features: vec!["feature1".into(), "feature2".into()],
            all_features: true,
            no_default_features: true,
            all_targets: true,
            targets: vec!["x86_64-unknown-linux-gnu".into()],
            manifest_path: Some(PathBuf::from("/path/to/Cargo.toml")),
            ..Default::default()
        };

        let scope = Scope::from(&opts);

        assert!(scope.workspace_only);
        assert!(!scope.include_deps);
        assert_eq!(scope.features, vec!["feature1", "feature2"]);
        assert!(scope.all_features);
        assert!(scope.no_default_features);
        assert!(scope.all_targets);
        assert_eq!(scope.targets, vec!["x86_64-unknown-linux-gnu"]);
        assert_eq!(
            scope.manifest_path,
            Some(PathBuf::from("/path/to/Cargo.toml"))
        );
    }

    #[test]
    fn test_scope_from_scan_opts_defaults() {
        let opts = ScanOpts::default();
        let scope = Scope::from(&opts);

        assert!(!scope.workspace_only);
        assert!(!scope.include_deps);
        assert!(scope.features.is_empty());
        assert!(!scope.all_features);
        assert!(!scope.no_default_features);
        assert!(!scope.all_targets);
        assert!(scope.targets.is_empty());
        assert!(scope.manifest_path.is_none());
    }

    #[test]
    fn test_scan_opts_default() {
        let opts = ScanOpts::default();

        assert!(!opts.workspace_only);
        assert!(!opts.include_deps);
        assert!(opts.features.is_empty());
        assert!(!opts.all_features);
        assert!(!opts.no_default_features);
        assert!(!opts.all_targets);
        assert!(opts.targets.is_empty());
        assert!(opts.manifest_path.is_none());
    }

    #[test]
    fn test_totals_default() {
        let totals = Totals::default();

        assert_eq!(totals.workspace_unsafe, 0);
        assert_eq!(totals.deps_unsafe, 0);
        assert_eq!(totals.overall_unsafe, 0);
    }

    #[test]
    fn test_totals_from_units_empty() {
        let totals = Totals::from_units(&[]);
        assert_eq!(totals.workspace_unsafe, 0);
        assert_eq!(totals.deps_unsafe, 0);
        assert_eq!(totals.overall_unsafe, 0);
    }

    #[test]
    fn test_totals_from_units_workspace_only() {
        let units = vec![
            Unit {
                name: "crate_a".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 5,
            },
            Unit {
                name: "crate_b".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 3,
            },
        ];
        let totals = Totals::from_units(&units);
        assert_eq!(totals.workspace_unsafe, 8);
        assert_eq!(totals.deps_unsafe, 0);
        assert_eq!(totals.overall_unsafe, 8);
    }

    #[test]
    fn test_totals_from_units_mixed() {
        let units = vec![
            Unit {
                name: "my_crate".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 10,
            },
            Unit {
                name: "libc".into(),
                kind: UnitKind::Dep,
                unsafe_count: 100,
            },
            Unit {
                name: "serde".into(),
                kind: UnitKind::Dep,
                unsafe_count: 5,
            },
        ];
        let totals = Totals::from_units(&units);
        assert_eq!(totals.workspace_unsafe, 10);
        assert_eq!(totals.deps_unsafe, 105);
        assert_eq!(totals.overall_unsafe, 115);
    }

    #[test]
    fn test_scope_diff_fields_equal() {
        let a = Scope {
            workspace_only: false,
            include_deps: true,
            features: vec!["f1".into()],
            all_features: false,
            no_default_features: false,
            all_targets: false,
            targets: vec![],
            manifest_path: None,
        };
        assert!(a.diff_fields(&a.clone()).is_empty());
    }

    #[test]
    fn test_scope_diff_fields_all_different() {
        let baseline = Scope {
            workspace_only: false,
            include_deps: true,
            features: vec!["f1".into()],
            all_features: false,
            no_default_features: false,
            all_targets: false,
            targets: vec![],
            manifest_path: None,
        };
        let current = Scope {
            workspace_only: true,
            include_deps: false,
            features: vec!["f1".into(), "f2".into()],
            all_features: true,
            no_default_features: true,
            all_targets: true,
            targets: vec!["aarch64-unknown-linux-gnu".into()],
            manifest_path: Some(PathBuf::from("Cargo.toml")),
        };
        let diffs = baseline.diff_fields(&current);
        assert_eq!(diffs.len(), 8);
        assert!(diffs[0].contains("workspace_only"));
        assert!(diffs[1].contains("include_deps"));
        assert!(diffs[2].contains("features"));
        assert!(diffs[3].contains("all_features"));
        assert!(diffs[4].contains("no_default_features"));
        assert!(diffs[5].contains("all_targets"));
        assert!(diffs[6].contains("targets"));
        assert!(diffs[7].contains("manifest_path"));
    }

    #[test]
    fn test_scope_diff_fields_single_change() {
        let baseline = Scope {
            workspace_only: false,
            include_deps: true,
            features: vec!["f1".into()],
            all_features: false,
            no_default_features: false,
            all_targets: false,
            targets: vec![],
            manifest_path: None,
        };
        let mut current = baseline.clone();
        current.features = vec![];
        let diffs = baseline.diff_fields(&current);
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].contains("features"));
        assert!(diffs[0].contains(r#"baseline=["f1"]"#));
        assert!(diffs[0].contains("current=[]"));
    }

    #[test]
    fn test_unit_kind_serialization() {
        let workspace = UnitKind::Workspace;
        let dep = UnitKind::Dep;

        assert_eq!(serde_json::to_string(&workspace).unwrap(), "\"workspace\"");
        assert_eq!(serde_json::to_string(&dep).unwrap(), "\"dep\"");
    }

    #[test]
    fn test_unit_kind_deserialization() {
        let workspace: UnitKind = serde_json::from_str("\"workspace\"").unwrap();
        let dep: UnitKind = serde_json::from_str("\"dep\"").unwrap();

        assert_eq!(workspace, UnitKind::Workspace);
        assert_eq!(dep, UnitKind::Dep);
    }
}
