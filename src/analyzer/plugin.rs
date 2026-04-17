use crate::analyzer::{Analyzer, AnalyzerInfo};
use crate::error::{Error, Result};
use crate::model::{ScanOpts, ScanResult};
use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

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

/// Build a [`Command`] for an external plugin, setting the shared flags and
/// environment variables derived from [`ScanOpts`].
fn build_plugin_cmd(path: &PathBuf, opts: &ScanOpts) -> Command {
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

    cmd
}

/// Run an external plugin and parse its output.
pub fn run_plugin(path: &PathBuf, opts: &ScanOpts) -> Result<ScanResult> {
    let mut cmd = build_plugin_cmd(path, opts);

    match opts.plugin_timeout_secs {
        Some(secs) => run_with_timeout(&mut cmd, path, Duration::from_secs(secs)),
        None => run_blocking(&mut cmd, path),
    }
}

/// Run a plugin command with no timeout (original behaviour).
fn run_blocking(cmd: &mut Command, path: &std::path::Path) -> Result<ScanResult> {
    let output = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;
    parse_plugin_output(path, output.status, &output.stdout, &output.stderr)
}

/// Run a plugin command with a timeout, killing the child if it exceeds the
/// deadline.
fn run_with_timeout(
    cmd: &mut Command,
    path: &std::path::Path,
    timeout: Duration,
) -> Result<ScanResult> {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    // Drain stdout and stderr on background threads so a plugin that produces
    // lots of output cannot deadlock by filling the OS pipe buffer.
    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stdout_pipe.read_to_end(&mut buf).ok();
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stderr_pipe.read_to_end(&mut buf).ok();
        buf
    });

    match child.wait_timeout(timeout)? {
        Some(status) => {
            let stdout = stdout_thread.join().unwrap_or_default();
            let stderr = stderr_thread.join().unwrap_or_default();
            parse_plugin_output(path, status, &stdout, &stderr)
        }
        None => {
            // Timed out — kill the child and clean up.
            child.kill().ok();
            child.wait().ok();
            stdout_thread.join().ok();
            stderr_thread.join().ok();
            Err(Error::Plugin(format!(
                "plugin {} timed out after {}s",
                path.display(),
                timeout.as_secs()
            )))
        }
    }
}

/// Parse a completed plugin's output into a [`ScanResult`].
fn parse_plugin_output(
    path: &std::path::Path,
    status: std::process::ExitStatus,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<ScanResult> {
    if !status.success() {
        let stderr_str = String::from_utf8_lossy(stderr);
        return Err(Error::Plugin(format!(
            "plugin {} exited with {}: {}",
            path.display(),
            status,
            stderr_str
        )));
    }

    let result: ScanResult = serde_json::from_slice(stdout).map_err(|e| {
        Error::Plugin(format!(
            "failed to parse plugin output from {}: {}",
            path.display(),
            e
        ))
    })?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // discover_plugins reads PATH and probe_plugin_language spawns children
    // that inherit the environment. Serialize tests that touch either to
    // avoid races from concurrent set_var calls.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn make_file(dir: &std::path::Path, name: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, "").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    fn make_script(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        use std::io::Write;
        let p = dir.join(name);
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(format!("#!/bin/sh\n{body}").as_bytes())
            .unwrap();
        f.sync_all().unwrap();
        drop(f);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    // --- is_executable ---

    #[test]
    fn executable_file_returns_true() {
        let tmp = TempDir::new().unwrap();
        let p = make_file(tmp.path(), "exe", 0o755);
        assert!(is_executable(&p));
    }

    #[test]
    fn non_executable_file_returns_false() {
        let tmp = TempDir::new().unwrap();
        let p = make_file(tmp.path(), "noexe", 0o644);
        assert!(!is_executable(&p));
    }

    #[test]
    fn directory_returns_false() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("subdir");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!is_executable(&dir));
    }

    #[test]
    fn nonexistent_path_returns_false() {
        assert!(!is_executable(&PathBuf::from("/no/such/path")));
    }

    #[test]
    fn group_execute_only_returns_true() {
        let tmp = TempDir::new().unwrap();
        let p = make_file(tmp.path(), "gexe", 0o610);
        assert!(is_executable(&p));
    }

    #[test]
    fn other_execute_only_returns_true() {
        let tmp = TempDir::new().unwrap();
        let p = make_file(tmp.path(), "oexe", 0o601);
        assert!(is_executable(&p));
    }

    // --- probe_plugin_language ---

    #[test]
    fn probe_parses_language_from_info_json() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "plugin", r#"echo '{"language":"python"}'"#);
        assert_eq!(probe_plugin_language(&p), Some("python".into()));
    }

    #[test]
    fn probe_returns_none_on_missing_field() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "plugin", r#"echo '{"version":"1"}'"#);
        assert_eq!(probe_plugin_language(&p), None);
    }

    #[test]
    fn probe_returns_none_on_non_zero_exit() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "plugin", "exit 1");
        assert_eq!(probe_plugin_language(&p), None);
    }

    #[test]
    fn probe_returns_none_for_nonexistent_binary() {
        let _lock = ENV_LOCK.lock().unwrap();
        assert_eq!(
            probe_plugin_language(&PathBuf::from("/no/such/binary")),
            None
        );
    }

    // --- discover_plugins ---

    #[test]
    fn discover_finds_plugin_on_path() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        make_script(
            tmp.path(),
            "unsafe-budget-plugin-demo",
            r#"echo '{"language":"demo-lang"}'"#,
        );

        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", tmp.path().display()));

        let plugins = discover_plugins();

        std::env::set_var("PATH", &old_path);

        let found = plugins.iter().find(|p| p.id == "demo");
        assert!(found.is_some(), "plugin 'demo' should be discovered");
        let info = found.unwrap();
        assert_eq!(info.language, "demo-lang");
        assert!(!info.builtin);
        assert!(info.path.is_some());
    }

    #[test]
    fn discover_ignores_non_executable_plugin() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        make_file(tmp.path(), "unsafe-budget-plugin-noexe", 0o644);

        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", tmp.path().display()));

        let plugins = discover_plugins();

        std::env::set_var("PATH", &old_path);

        assert!(
            plugins.iter().all(|p| p.id != "noexe"),
            "non-executable file should not be discovered"
        );
    }

    #[test]
    fn discover_ignores_files_without_prefix() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        make_script(tmp.path(), "some-other-tool", r#"echo '{}'"#);

        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", tmp.path().display()));

        let plugins = discover_plugins();

        std::env::set_var("PATH", &old_path);

        assert!(
            plugins.iter().all(|p| p.id != "some-other-tool"),
            "files without the plugin prefix should be ignored"
        );
    }

    #[test]
    fn discover_falls_back_to_unknown_language() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        make_script(tmp.path(), "unsafe-budget-plugin-bad", "exit 1");

        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", tmp.path().display()));

        let plugins = discover_plugins();

        std::env::set_var("PATH", &old_path);

        let found = plugins.iter().find(|p| p.id == "bad");
        assert!(found.is_some());
        assert_eq!(found.unwrap().language, "unknown");
    }

    // --- run_with_timeout ---

    #[test]
    fn timeout_kills_slow_plugin() {
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "slow-plugin", "sleep 60");
        let mut cmd = Command::new(&p);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let result = run_with_timeout(&mut cmd, &p, Duration::from_secs(1));
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("timed out"),
            "expected timeout error, got: {msg}"
        );
    }

    #[test]
    fn timeout_allows_fast_plugin() {
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "fast-plugin", "echo ok");
        let mut cmd = Command::new(&p);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        // The plugin exits quickly — the error here is a JSON parse failure, not
        // a timeout, proving it ran to completion.
        let result = run_with_timeout(&mut cmd, &p, Duration::from_secs(10));
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("failed to parse"),
            "expected parse error (not timeout), got: {msg}"
        );
    }

    #[test]
    fn discover_returns_sorted_and_deduped() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();
        make_script(tmp1.path(), "unsafe-budget-plugin-zzz", "exit 1");
        make_script(tmp1.path(), "unsafe-budget-plugin-aaa", "exit 1");
        make_script(tmp2.path(), "unsafe-budget-plugin-aaa", "exit 1");

        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var(
            "PATH",
            format!(
                "{}:{}:{old_path}",
                tmp1.path().display(),
                tmp2.path().display()
            ),
        );

        let plugins = discover_plugins();

        std::env::set_var("PATH", &old_path);

        let ids: Vec<&str> = plugins.iter().map(|p| p.id.as_str()).collect();
        let aaa_count = ids.iter().filter(|&&id| id == "aaa").count();
        assert_eq!(aaa_count, 1, "duplicates should be removed");

        if let Some(aaa_pos) = ids.iter().position(|&id| id == "aaa") {
            if let Some(zzz_pos) = ids.iter().position(|&id| id == "zzz") {
                assert!(aaa_pos < zzz_pos, "plugins should be sorted by id");
            }
        }
    }
}
