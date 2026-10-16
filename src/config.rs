use crate::error::{Error, Result};
use crate::model::{Scope, Totals, Unit, UnitKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// budget enforcement mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Ratchet,
    Caps,
}

/// caps configuration for explicit limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caps {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<u64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub workspace: HashMap<String, u64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub deps: HashMap<String, u64>,
}

/// a single occurrence to ignore when counting unsafe code.
///
/// matches a specific file and line number in the scan output. The `reason`
/// field is optional documentation for reviewers.
///
/// # example (unsafe-budget.toml)
///
/// ```toml
/// [[ignore]]
/// file = "src/ffi.rs"
/// line = 42
/// reason = "ffi boundary, reviewed 2026-04-12"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IgnoreEntry {
    /// file path relative to the project root.
    pub file: PathBuf,
    /// line number (1-indexed).
    pub line: u32,
    /// optional human-readable reason for the ignore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// warning configuration for near-budget usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Warnings {
    /// warn when usage reaches this fraction of budget, e.g. 0.8 for 80%.
    pub threshold: f64,
}

/// main configuration from unsafe-budget.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "default_true")]
    pub include_deps: bool,
    #[serde(default)]
    pub workspace_only: bool,
    #[serde(default)]
    pub ignore_units: Vec<String>,
    /// specific occurrences to exclude from counts.
    ///
    /// each entry matches a file path and line number. Matched occurrences are
    /// removed before budgets are checked, so they do not count toward any unit's
    /// unsafe total.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<IgnoreEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caps: Option<Caps>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Warnings>,
    /// timeout in seconds for external plugin execution.
    ///
    /// when set, plugin subprocesses that exceed this duration are killed and
    /// reported as errors. Prevents hanging plugins from blocking CI pipelines
    /// indefinitely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_timeout_secs: Option<u64>,
    /// timeout in seconds for external analyzer and plugin subprocesses.
    ///
    /// bounds the built-in external analyzers (`cargo geiger`, `go-geiger`,
    /// `cargo check`) as well as plugins. `plugin_timeout_secs` takes
    /// precedence for plugins. unset means no timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
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
            timeout_secs: None,
        }
    }
}

impl Config {
    /// load config from file, or return defaults if not found.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// load config from the standard location in a directory.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        Self::load(&dir.join("unsafe-budget.toml"))
    }
}

/// baseline data from unsafe-budget.lock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub tool_version: String,
    pub analyzer_id: String,
    pub scope: Scope,
    pub totals: Totals,
    pub units: Vec<BaselineUnit>,
}

/// unit entry in baseline file (uses string kind for TOML compatibility).
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
    /// load baseline from file.
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

    /// load baseline from the standard location in a directory.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        Self::load(&dir.join("unsafe-budget.lock"))
    }

    /// write baseline to file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        let header = "# Auto-generated by unsafe-budget. Do not edit manually.\n\n";
        fs::write(path, format!("{}{}", header, content))?;
        Ok(())
    }

    /// save baseline to the standard location in a directory.
    pub fn save_to_dir(&self, dir: &Path) -> Result<()> {
        self.save(&dir.join("unsafe-budget.lock"))
    }

    /// build a lookup map from unit name to unsafe count.
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
    fn test_baseline_roundtrip() {
        let baseline = Baseline {
            tool_version: "0.1.0".into(),
            analyzer_id: "rustc_unsafe_lint".into(),
            scope: Scope {
                workspace_only: false,
                include_deps: true,
                features: vec![],
                all_features: false,
                no_default_features: false,
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
        assert_eq!(
            serialized,
            r#"tool_version = "0.1.0"
analyzer_id = "rustc_unsafe_lint"

[scope]
workspace_only = false
include_deps = true
features = []
all_features = false
no_default_features = false
all_targets = false
targets = []

[totals]
workspace_unsafe = 10
deps_unsafe = 20
overall_unsafe = 30

[[units]]
name = "my_crate"
kind = "workspace"
unsafe_count = 10

[[units]]
name = "libc"
kind = "dep"
unsafe_count = 20
"#
        );

        let parsed: Baseline = toml::from_str(&serialized).unwrap();
        assert_eq!(parsed.tool_version, baseline.tool_version);
        assert_eq!(parsed.analyzer_id, baseline.analyzer_id);
        assert_eq!(parsed.scope, baseline.scope);
        assert_eq!(parsed.totals, baseline.totals);
        let units = |b: &Baseline| -> Vec<(String, UnitKind, u64)> {
            b.units
                .iter()
                .map(|u| (u.name.clone(), u.kind, u.unsafe_count))
                .collect()
        };
        assert_eq!(units(&parsed), units(&baseline));
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

    #[test]
    fn test_full_valid_config_parses() {
        let toml = r#"
mode = "ratchet"
include_deps = true
workspace_only = false
ignore_units = ["test_crate"]
plugin_timeout_secs = 30
timeout_secs = 300

[[ignore]]
file = "src/ffi.rs"
line = 42
reason = "ffi boundary"

[caps]
default = 100

[caps.workspace]
my_crate = 10

[caps.deps]
libc = 100

[warnings]
threshold = 0.8
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.plugin_timeout_secs, Some(30));
        assert_eq!(config.timeout_secs, Some(300));
        assert_eq!(config.ignore.len(), 1);
        assert_eq!(config.caps.as_ref().unwrap().deps.get("libc"), Some(&100));
        assert_eq!(config.warnings.as_ref().unwrap().threshold, 0.8);
    }

    #[test]
    fn test_config_load_rejects_unknown_key() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("unsafe-budget.toml");
        std::fs::write(&path, "include_deps = true\nunknown_key = 1\n").unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn test_baseline_tolerates_unknown_field() {
        let baseline = Baseline {
            tool_version: "0.1.0".into(),
            analyzer_id: "test".into(),
            scope: Scope {
                workspace_only: false,
                include_deps: true,
                features: vec![],
                all_features: false,
                no_default_features: false,
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
        let serialized = toml::to_string_pretty(&baseline).unwrap();
        let with_unknown = format!("future_field = \"written by a newer tool\"\n{}", serialized);
        let parsed: Baseline = toml::from_str(&with_unknown).unwrap();
        assert_eq!(parsed.tool_version, "0.1.0");
        assert_eq!(parsed.units.len(), 1);
    }

    #[test]
    fn test_config_rejects_unknown_keys() {
        let cases = [
            ("mode = \"caps\"\nworkspce_only = true\n", "workspce_only"),
            ("[caps]\ndefualt = 10\n", "defualt"),
            (
                "[warnings]\nthreshold = 0.8\nthreshhold = 0.9\n",
                "threshhold",
            ),
            (
                "[[ignore]]\nfile = \"src/ffi.rs\"\nline = 42\nresaon = \"typo\"\n",
                "resaon",
            ),
        ];
        for (toml, key) in cases {
            let err = toml::from_str::<Config>(toml).unwrap_err().to_string();
            assert!(
                err.contains(&format!("unknown field `{key}`")),
                "{key}: {err}"
            );
        }
    }
}
