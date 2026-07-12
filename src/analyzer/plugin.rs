use crate::analyzer::process::{self, Run};
use crate::analyzer::{Analyzer, AnalyzerInfo};
use crate::error::{Error, Result};
use crate::model::{ScanOpts, ScanResult};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const PLUGIN_PREFIX: &str = "unsafe-budget-plugin-";

/// external plugin analyzer.
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

/// discover plugin executables on PATH.
///
/// `timeout` (seconds) bounds each plugin's `--info` probe; `None` leaves the
/// probe unbounded, matching the crate's opt-in timeout philosophy.
pub fn discover_plugins(timeout: Option<u64>) -> Vec<AnalyzerInfo> {
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
                        // try to get language from plugin
                        let language = probe_plugin_language(&path, timeout)
                            .unwrap_or_else(|| "unknown".into());
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

/// check if a path is executable.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// try to get plugin language by running with --info.
///
/// `timeout` (seconds) bounds the probe through the shared [`process::run_process`]
/// runner; `None` keeps the historical unbounded spawn. A probe that fails to
/// run, exits non-zero, or exceeds the deadline yields `None`, so a hung plugin
/// falls back to an "unknown" language instead of blocking discovery.
fn probe_plugin_language(path: &Path, timeout: Option<u64>) -> Option<String> {
    let mut cmd = Command::new(path);
    cmd.arg("--info");

    let output = match process::run_process(&mut cmd, timeout.map(Duration::from_secs)).ok()? {
        Run::Completed(out) => out,
        Run::TimedOut => return None,
    };

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

/// build a [`Command`] for an external plugin, setting the shared flags and
/// environment variables derived from [`ScanOpts`].
fn build_plugin_cmd(path: &Path, opts: &ScanOpts) -> Command {
    let mut cmd = Command::new(path);
    cmd.arg("--format").arg("json");

    // pass options via environment
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

/// run an external plugin and parse its output.
pub fn run_plugin(path: &Path, opts: &ScanOpts) -> Result<ScanResult> {
    let mut cmd = build_plugin_cmd(path, opts);
    let timeout_secs = opts.plugin_timeout_secs;

    match process::run_process(&mut cmd, timeout_secs.map(Duration::from_secs))? {
        Run::Completed(out) => parse_plugin_output(path, out.status, &out.stdout, &out.stderr),
        Run::TimedOut => Err(Error::Plugin(format!(
            "plugin {} timed out after {}s",
            path.display(),
            timeout_secs.unwrap_or_default()
        ))),
    }
}

/// parse a completed plugin's output into a [`ScanResult`].
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
    use crate::analyzer::test_spawn_guard;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

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
        let _lock = test_spawn_guard();
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "plugin", r#"echo '{"language":"python"}'"#);
        assert_eq!(probe_plugin_language(&p, None), Some("python".into()));
    }

    #[test]
    fn probe_returns_none_on_missing_field() {
        let _lock = test_spawn_guard();
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "plugin", r#"echo '{"version":"1"}'"#);
        assert_eq!(probe_plugin_language(&p, None), None);
    }

    #[test]
    fn probe_returns_none_on_non_zero_exit() {
        let _lock = test_spawn_guard();
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "plugin", "exit 1");
        assert_eq!(probe_plugin_language(&p, None), None);
    }

    #[test]
    fn probe_returns_none_for_nonexistent_binary() {
        let _lock = test_spawn_guard();
        assert_eq!(
            probe_plugin_language(&PathBuf::from("/no/such/binary"), None),
            None
        );
    }

    #[test]
    fn probe_times_out_slow_plugin() {
        // serialize spawns to avoid the ETXTBSY fork-race (see the run_plugin
        // timeout tests below).
        let _lock = test_spawn_guard();
        // `exec sleep` replaces the shell in place so the child *is* sleep;
        // killing it on timeout closes the pipes directly (no orphaned
        // grandchild holding them open).
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "unsafe-budget-plugin-slow", "exec sleep 60\n");
        // the probe outlives the 1s deadline, so it is killed and reported as a
        // failed probe (None) rather than hanging for the full 60s.
        assert_eq!(probe_plugin_language(&p, Some(1)), None);
    }

    #[test]
    fn probe_fast_plugin_completes_within_timeout() {
        let _lock = test_spawn_guard();
        // a plugin that answers immediately finishes well inside the deadline,
        // so a set timeout does not interfere with a normal probe.
        let tmp = TempDir::new().unwrap();
        let p = make_script(
            tmp.path(),
            "unsafe-budget-plugin-fast",
            r#"echo '{"language":"python"}'"#,
        );
        assert_eq!(probe_plugin_language(&p, Some(10)), Some("python".into()));
    }

    // --- discover_plugins ---

    #[test]
    fn discover_finds_plugin_on_path() {
        let _lock = test_spawn_guard();
        let tmp = TempDir::new().unwrap();
        make_script(
            tmp.path(),
            "unsafe-budget-plugin-demo",
            r#"echo '{"language":"demo-lang"}'"#,
        );

        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", tmp.path().display()));

        let plugins = discover_plugins(None);

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
        let _lock = test_spawn_guard();
        let tmp = TempDir::new().unwrap();
        make_file(tmp.path(), "unsafe-budget-plugin-noexe", 0o644);

        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", tmp.path().display()));

        let plugins = discover_plugins(None);

        std::env::set_var("PATH", &old_path);

        assert!(
            plugins.iter().all(|p| p.id != "noexe"),
            "non-executable file should not be discovered"
        );
    }

    #[test]
    fn discover_ignores_files_without_prefix() {
        let _lock = test_spawn_guard();
        let tmp = TempDir::new().unwrap();
        make_script(tmp.path(), "some-other-tool", r#"echo '{}'"#);

        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", tmp.path().display()));

        let plugins = discover_plugins(None);

        std::env::set_var("PATH", &old_path);

        assert!(
            plugins.iter().all(|p| p.id != "some-other-tool"),
            "files without the plugin prefix should be ignored"
        );
    }

    #[test]
    fn discover_falls_back_to_unknown_language() {
        let _lock = test_spawn_guard();
        let tmp = TempDir::new().unwrap();
        make_script(tmp.path(), "unsafe-budget-plugin-bad", "exit 1");

        let old_path = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old_path}", tmp.path().display()));

        let plugins = discover_plugins(None);

        std::env::set_var("PATH", &old_path);

        let found = plugins.iter().find(|p| p.id == "bad");
        assert!(found.is_some());
        assert_eq!(found.unwrap().language, "unknown");
    }

    // --- run_plugin timeout ---

    #[test]
    fn run_plugin_times_out_slow_plugin() {
        // serialize with the other script-writing tests: the timeout path spawns
        // the child in its own process group (the fork path), and that fork must
        // not overlap another test's freshly-written-but-not-yet-exec'd plugin
        // file, or that test's exec races with our inherited write fd (ETXTBSY).
        let _lock = test_spawn_guard();
        // `exec sleep` replaces the shell in place, so the spawned child *is*
        // sleep: killing it on timeout closes the pipes directly, leaving no
        // orphaned grandchild holding them open (which would hang the drain
        // threads).
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "unsafe-budget-plugin-slow", "exec sleep 60\n");
        let opts = ScanOpts {
            plugin_timeout_secs: Some(1),
            ..Default::default()
        };
        let err = run_plugin(&p, &opts).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("timed out"),
            "expected timeout error, got: {msg}"
        );
    }

    #[test]
    fn run_plugin_allows_fast_plugin() {
        // serialize spawns to avoid the ETXTBSY fork-race (see the slow-plugin
        // test above).
        let _lock = test_spawn_guard();
        // the plugin exits quickly — the error is a JSON parse failure, not a
        // timeout, proving it ran to completion within the deadline.
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "unsafe-budget-plugin-fast", "echo not-json\n");
        let opts = ScanOpts {
            plugin_timeout_secs: Some(10),
            ..Default::default()
        };
        let err = run_plugin(&p, &opts).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("failed to parse"),
            "expected parse error (not timeout), got: {msg}"
        );
    }

    #[test]
    fn discover_returns_sorted_and_deduped() {
        let _lock = test_spawn_guard();
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

        let plugins = discover_plugins(None);

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
