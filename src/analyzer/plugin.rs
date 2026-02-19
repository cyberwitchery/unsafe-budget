use crate::analyzer::{Analyzer, AnalyzerInfo};
use crate::error::{Error, Result};
use crate::model::{ScanOpts, ScanResult};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const PLUGIN_PREFIX: &str = "unsafe-budget-plugin-";

/// External plugin analyzer.
pub struct PluginAnalyzer {
    pub id: String,
    pub language: String,
    pub path: PathBuf,
}

impl Analyzer for PluginAnalyzer {
    fn id(&self) -> &str {
        &self.id
    }

    fn language(&self) -> &str {
        &self.language
    }

    fn run(&self, opts: &ScanOpts) -> Result<ScanResult> {
        run_plugin(&self.path, opts)
    }
}

/// Discover plugin executables on PATH.
pub fn discover_plugins() -> Vec<AnalyzerInfo> {
    let path_var = match std::env::var("PATH") {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let mut plugins = Vec::new();

    for dir in std::env::split_paths(&path_var) {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with(PLUGIN_PREFIX) && is_executable(&path) {
                        let id = name.strip_prefix(PLUGIN_PREFIX).unwrap_or(name);
                        // Try to get language from plugin
                        let language =
                            probe_plugin_language(&path).unwrap_or_else(|| "unknown".into());
                        plugins.push(AnalyzerInfo {
                            id: id.into(),
                            language,
                            builtin: false,
                            path: Some(path),
                        });
                    }
                }
            }
        }
    }

    plugins.sort_by(|a, b| a.id.cmp(&b.id));
    plugins.dedup_by(|a, b| a.id == b.id);
    plugins
}

/// Check if a path is executable.
#[cfg(unix)]
fn is_executable(path: &PathBuf) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &PathBuf) -> bool {
    path.is_file()
}

/// Try to get plugin language by running with --info.
fn probe_plugin_language(path: &PathBuf) -> Option<String> {
    let output = Command::new(path)
        .arg("--info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    #[derive(serde::Deserialize)]
    struct PluginInfo {
        language: String,
    }

    let info: PluginInfo = serde_json::from_slice(&output.stdout).ok()?;
    Some(info.language)
}

/// Run an external plugin and parse its output.
pub fn run_plugin(path: &PathBuf, opts: &ScanOpts) -> Result<ScanResult> {
    let mut cmd = Command::new(path);
    cmd.arg("--format").arg("json");

    // Pass options via environment
    cmd.env(
        "UNSAFE_BUDGET_WORKSPACE_ONLY",
        opts.workspace_only.to_string(),
    );
    cmd.env("UNSAFE_BUDGET_INCLUDE_DEPS", opts.include_deps.to_string());
    cmd.env("UNSAFE_BUDGET_ALL_FEATURES", opts.all_features.to_string());
    cmd.env(
        "UNSAFE_BUDGET_NO_DEFAULT_FEATURES",
        opts.no_default_features.to_string(),
    );
    cmd.env("UNSAFE_BUDGET_ALL_TARGETS", opts.all_targets.to_string());

    if !opts.features.is_empty() {
        cmd.env("UNSAFE_BUDGET_FEATURES", opts.features.join(","));
    }
    if !opts.targets.is_empty() {
        cmd.env("UNSAFE_BUDGET_TARGETS", opts.targets.join(","));
    }
    if let Some(ref manifest) = opts.manifest_path {
        cmd.env("UNSAFE_BUDGET_MANIFEST_PATH", manifest);
    }

    let output = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Plugin(format!(
            "plugin {} exited with {}: {}",
            path.display(),
            output.status,
            stderr
        )));
    }

    let result: ScanResult = serde_json::from_slice(&output.stdout).map_err(|e| {
        Error::Plugin(format!(
            "failed to parse plugin output from {}: {}",
            path.display(),
            e
        ))
    })?;

    Ok(result)
}
