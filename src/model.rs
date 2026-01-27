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
    pub all_targets: bool,
    pub targets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<PathBuf>,
}

impl From<&ScanOpts> for Scope {
    fn from(opts: &ScanOpts) -> Self {
        Scope {
            workspace_only: opts.workspace_only,
            include_deps: opts.include_deps,
            features: opts.features.clone(),
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

/// result of a budget check.
///
/// combines the scan result with any violations found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// the scan result that was checked.
    pub scan: ScanResult,
    /// list of violations (empty if passed).
    pub violations: Vec<Violation>,
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
        };

        let scope = Scope::from(&opts);

        assert!(scope.workspace_only);
        assert!(!scope.include_deps);
        assert_eq!(scope.features, vec!["feature1", "feature2"]);
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
