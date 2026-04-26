use crate::error::{Error, Result};
use crate::model::{Scope, Totals, Unit, UnitKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Budget enforcement mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Ratchet,
    Caps,
}

/// Caps configuration for explicit limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Caps {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<u64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub workspace: HashMap<String, u64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub deps: HashMap<String, u64>,
}

/// A single occurrence to ignore when counting unsafe code.
///
/// Matches a specific file and line number in the scan output. The `reason`
/// field is optional documentation for reviewers.
///
/// # Example (unsafe-budget.toml)
///
/// ```toml
/// [[ignore]]
/// file = "src/ffi.rs"
/// line = 42
/// reason = "ffi boundary, reviewed 2026-04-12"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IgnoreEntry {
    /// File path relative to the project root.
    pub file: PathBuf,
    /// Line number (1-indexed).
    pub line: u32,
    /// Optional human-readable reason for the ignore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Warning configuration for near-budget usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warnings {
    /// Warn when usage reaches this fraction of budget, e.g. 0.8 for 80%.
    pub threshold: f64,
}

/// Main configuration from unsafe-budget.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "default_true")]
    pub include_deps: bool,
    #[serde(default)]
    pub workspace_only: bool,
    #[serde(default)]
    pub ignore_units: Vec<String>,
    /// Specific occurrences to exclude from counts.
    ///
    /// Each entry matches a file path and line number. Matched occurrences are
    /// removed before budgets are checked, so they do not count toward any unit's
    /// unsafe total.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<IgnoreEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caps: Option<Caps>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Warnings>,
    /// Timeout in seconds for external plugin execution.
    ///
    /// When set, plugin subprocesses that exceed this duration are killed and
    /// reported as errors. Prevents hanging plugins from blocking CI pipelines
    /// indefinitely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_timeout_secs: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::default(),
            include_deps: true,
            workspace_only: false,
            ignore_units: Vec::new(),
            ignore: Vec::new(),
            caps: None,
            warnings: None,
            plugin_timeout_secs: None,
        }
    }
}

impl Config {
    /// Load config from file, or return defaults if not found.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load config from the standard location in a directory.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        Self::load(&dir.join("unsafe-budget.toml"))
    }
}

/// Baseline data from unsafe-budget.lock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub tool_version: String,
    pub analyzer_id: String,
    pub scope: Scope,
    pub totals: Totals,
    pub units: Vec<BaselineUnit>,
}

/// Unit entry in baseline file (uses string kind for TOML compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineUnit {
    pub name: String,
    pub kind: UnitKind,
    pub unsafe_count: u64,
}

impl From<&Unit> for BaselineUnit {
    fn from(u: &Unit) -> Self {
        BaselineUnit {
            name: u.name.clone(),
            kind: u.kind,
            unsafe_count: u.unsafe_count,
        }
    }
}

impl Baseline {
    /// Load baseline from file.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::BaselineNotFound {
                path: path.to_path_buf(),
            });
        }
        let content = fs::read_to_string(path)?;
        let baseline: Baseline = toml::from_str(&content)
            .map_err(|e| Error::Baseline(format!("failed to parse {}: {}", path.display(), e)))?;
        Ok(baseline)
    }

    /// Load baseline from the standard location in a directory.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        Self::load(&dir.join("unsafe-budget.lock"))
    }

    /// Write baseline to file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        let header = "# Auto-generated by unsafe-budget. Do not edit manually.\n\n";
        fs::write(path, format!("{}{}", header, content))?;
        Ok(())
    }

    /// Save baseline to the standard location in a directory.
    pub fn save_to_dir(&self, dir: &Path) -> Result<()> {
        self.save(&dir.join("unsafe-budget.lock"))
    }

    /// Build a lookup map from unit name to unsafe count.
    pub fn unit_map(&self) -> HashMap<&str, u64> {
        self.units
            .iter()
            .map(|u| (u.name.as_str(), u.unsafe_count))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = Config::default();
        assert_eq!(config.mode, Mode::Ratchet);
        assert!(config.include_deps);
        assert!(!config.workspace_only);
        assert!(config.ignore_units.is_empty());
    }

    #[test]
    fn test_config_parse() {
        let toml = r#"
mode = "caps"
include_deps = false
workspace_only = true
ignore_units = ["foo", "bar"]

[caps]
default = 10

[caps.workspace]
my_crate = 5

[caps.deps]
libc = 100

[warnings]
threshold = 0.8
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.mode, Mode::Caps);
        assert!(!config.include_deps);
        assert!(config.workspace_only);
        assert_eq!(config.ignore_units, vec!["foo", "bar"]);

        let caps = config.caps.as_ref().unwrap();
        assert_eq!(caps.default, Some(10));
        assert_eq!(caps.workspace.get("my_crate"), Some(&5));
        assert_eq!(caps.deps.get("libc"), Some(&100));
        assert_eq!(config.warnings.as_ref().unwrap().threshold, 0.8);
    }

    #[test]
    fn test_config_ignore_parse() {
        let toml = r#"
[[ignore]]
file = "src/ffi.rs"
line = 42
reason = "ffi boundary"

[[ignore]]
file = "src/platform.rs"
line = 7
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.ignore.len(), 2);

        assert_eq!(
            config.ignore[0].file,
            std::path::PathBuf::from("src/ffi.rs")
        );
        assert_eq!(config.ignore[0].line, 42);
        assert_eq!(config.ignore[0].reason.as_deref(), Some("ffi boundary"));

        assert_eq!(
            config.ignore[1].file,
            std::path::PathBuf::from("src/platform.rs")
        );
        assert_eq!(config.ignore[1].line, 7);
        assert!(config.ignore[1].reason.is_none());
    }

    #[test]
    fn test_config_ignore_empty_by_default() {
        let config = Config::default();
        assert!(config.ignore.is_empty());
    }

    #[test]
    fn test_baseline_roundtrip() {
        let baseline = Baseline {
            tool_version: "0.1.0".into(),
            analyzer_id: "rustc_unsafe_lint".into(),
            scope: Scope {
                workspace_only: false,
                include_deps: true,
                features: vec![],
                all_targets: false,
                targets: vec![],
                manifest_path: None,
            },
            totals: Totals {
                workspace_unsafe: 10,
                deps_unsafe: 20,
                overall_unsafe: 30,
            },
            units: vec![
                BaselineUnit {
                    name: "my_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 10,
                },
                BaselineUnit {
                    name: "libc".into(),
                    kind: UnitKind::Dep,
                    unsafe_count: 20,
                },
            ],
        };

        let serialized = toml::to_string_pretty(&baseline).unwrap();
        let parsed: Baseline = toml::from_str(&serialized).unwrap();

        assert_eq!(parsed.tool_version, baseline.tool_version);
        assert_eq!(parsed.units.len(), 2);
        assert_eq!(parsed.units[0].name, "my_crate");
    }

    #[test]
    fn test_baseline_unit_map_found() {
        let baseline = Baseline {
            tool_version: "0.1.0".into(),
            analyzer_id: "test".into(),
            scope: Scope {
                workspace_only: false,
                include_deps: true,
                features: vec![],
                all_targets: false,
                targets: vec![],
                manifest_path: None,
            },
            totals: Totals::default(),
            units: vec![BaselineUnit {
                name: "my_crate".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 10,
            }],
        };

        let map = baseline.unit_map();
        assert_eq!(map.get("my_crate"), Some(&10));
    }

    #[test]
    fn test_baseline_unit_map_not_found() {
        let baseline = Baseline {
            tool_version: "0.1.0".into(),
            analyzer_id: "test".into(),
            scope: Scope {
                workspace_only: false,
                include_deps: true,
                features: vec![],
                all_targets: false,
                targets: vec![],
                manifest_path: None,
            },
            totals: Totals::default(),
            units: vec![],
        };

        let map = baseline.unit_map();
        assert_eq!(map.get("nonexistent"), None);
    }

    #[test]
    fn test_baseline_unit_from_unit() {
        use crate::model::Unit;

        let unit = Unit {
            name: "test_crate".into(),
            kind: UnitKind::Workspace,
            unsafe_count: 42,
        };

        let baseline_unit = BaselineUnit::from(&unit);

        assert_eq!(baseline_unit.name, "test_crate");
        assert_eq!(baseline_unit.kind, UnitKind::Workspace);
        assert_eq!(baseline_unit.unsafe_count, 42);
    }

    #[test]
    fn test_mode_default() {
        let mode = Mode::default();
        assert_eq!(mode, Mode::Ratchet);
    }

    #[test]
    fn test_caps_default() {
        let caps = Caps::default();
        assert!(caps.default.is_none());
        assert!(caps.workspace.is_empty());
        assert!(caps.deps.is_empty());
    }

    #[test]
    fn test_config_mode_parse() {
        let ratchet_toml = r#"mode = "ratchet""#;
        let caps_toml = r#"mode = "caps""#;

        let ratchet: Config = toml::from_str(ratchet_toml).unwrap();
        let caps: Config = toml::from_str(caps_toml).unwrap();

        assert_eq!(ratchet.mode, Mode::Ratchet);
        assert_eq!(caps.mode, Mode::Caps);
    }

    #[test]
    fn test_config_load_missing_file_returns_defaults() {
        use std::path::Path;
        let result = Config::load(Path::new("/nonexistent/path/config.toml"));
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.mode, Mode::Ratchet);
    }
}
