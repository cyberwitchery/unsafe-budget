pub mod cargo_geiger;
pub mod go_geiger;
pub mod plugin;
pub mod rustc;
pub mod sarif;

use crate::error::{Error, Result};
use crate::model::{ScanOpts, ScanResult};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
