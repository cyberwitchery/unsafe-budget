use crate::analyzer::process::{self, Run};
use crate::analyzer::{normalize, Analyzer, AnalyzerInfo};
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
        run_plugin(&self.id, &self.path, opts)
    }
}

/// discover plugin executables on PATH.
///
/// `timeout` (seconds) bounds each plugin's `--info` probe; `None` leaves the
/// probe unbounded.
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
/// `timeout` (seconds) bounds the probe; `None` leaves it unbounded. A probe
/// that fails to run, exits non-zero, or exceeds the deadline yields `None`,
/// so a hung plugin falls back to an "unknown" language instead of blocking
/// discovery.
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

    cmd.env(
        "UNSAFE_BUDGET_WORKSPACE_ONLY",
        (!opts.include_deps).to_string(),
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

/// run an external plugin, parse its output, and enforce the host contract.
pub fn run_plugin(id: &str, path: &Path, opts: &ScanOpts) -> Result<ScanResult> {
    let mut cmd = build_plugin_cmd(path, opts);
    let command = path.display().to_string();
    let output = process::run_tool(id, &command, &mut cmd, opts.plugin_timeout_secs)?;
    let result: ScanResult = serde_json::from_slice(&output.stdout).map_err(|e| {
        Error::analyzer(id, format!("failed to parse the output of {command}: {e}"))
    })?;
    Ok(normalize(id, opts, result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::test_spawn_guard;
    use crate::model::Scope;
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
    fn is_executable_needs_any_execute_bit_on_a_file() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("subdir");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let cases = [
            ("owner execute", make_file(tmp.path(), "exe", 0o755), true),
            ("no execute", make_file(tmp.path(), "noexe", 0o644), false),
            (
                "group execute only",
                make_file(tmp.path(), "gexe", 0o610),
                true,
            ),
            (
                "other execute only",
                make_file(tmp.path(), "oexe", 0o601),
                true,
            ),
            ("directory", dir, false),
            ("nonexistent", PathBuf::from("/no/such/path"), false),
        ];
        for (name, path, expected) in cases {
            assert_eq!(is_executable(&path), expected, "{name}");
        }
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
    fn probe_returns_none_when_info_is_unusable() {
        let _lock = test_spawn_guard();
        let tmp = TempDir::new().unwrap();
        let cases = [
            (
                "missing field",
                make_script(tmp.path(), "missing", r#"echo '{"version":"1"}'"#),
            ),
            ("non-zero exit", make_script(tmp.path(), "fails", "exit 1")),
            ("nonexistent binary", PathBuf::from("/no/such/binary")),
        ];
        for (name, path) in cases {
            assert_eq!(probe_plugin_language(&path, None), None, "{name}");
        }
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
        assert_eq!(
            info.path.as_deref(),
            Some(tmp.path().join("unsafe-budget-plugin-demo").as_path())
        );
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
        let err = run_plugin("slow", &p, &opts).unwrap_err();
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
        // the plugin exits quickly; the error is a JSON parse failure, not a
        // timeout, proving it ran to completion within the deadline.
        let tmp = TempDir::new().unwrap();
        let p = make_script(tmp.path(), "unsafe-budget-plugin-fast", "echo not-json\n");
        let opts = ScanOpts {
            plugin_timeout_secs: Some(10),
            ..Default::default()
        };
        let err = run_plugin("fast", &p, &opts).unwrap_err();
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

        let ours: Vec<_> = plugins
            .iter()
            .filter(|p| p.id == "aaa" || p.id == "zzz")
            .collect();
        let ids: Vec<&str> = ours.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["aaa", "zzz"], "sorted by id, duplicates removed");
        // the earlier PATH entry wins
        assert_eq!(
            ours[0].path.as_deref(),
            Some(tmp1.path().join("unsafe-budget-plugin-aaa").as_path())
        );
    }

    #[test]
    fn plugin_env_sets_both_dependency_variables_from_include_deps() {
        for include_deps in [true, false] {
            let opts = ScanOpts {
                include_deps,
                ..Default::default()
            };
            let cmd = build_plugin_cmd(Path::new("plugin"), &opts);
            let var = |name: &str| {
                cmd.get_envs()
                    .find(|&(key, _)| key == name)
                    .and_then(|(_, value)| value)
                    .map(|value| value.to_string_lossy().into_owned())
            };
            assert_eq!(
                var("UNSAFE_BUDGET_INCLUDE_DEPS"),
                Some(include_deps.to_string())
            );
            assert_eq!(
                var("UNSAFE_BUDGET_WORKSPACE_ONLY"),
                Some((!include_deps).to_string())
            );
        }
    }

    #[test]
    fn run_plugin_sanitizes_output_end_to_end() {
        let _lock = test_spawn_guard();
        let tmp = TempDir::new().unwrap();
        let body = r#"cat <<'EOF'
{"tool_version":"2.0.0","analyzer_id":"self","language":"cpp",
 "scope":{"workspace_only":true,"include_deps":false,"features":[],"all_targets":false,"targets":[]},
 "units":[{"name":"app","kind":"workspace","unsafe_count":2},{"name":"dep","kind":"dep","unsafe_count":9}],
 "totals":{"workspace_unsafe":100,"deps_unsafe":100,"overall_unsafe":200}}
EOF
"#;
        let p = make_script(tmp.path(), "unsafe-budget-plugin-e2e", body);
        let opts = ScanOpts {
            include_deps: false,
            ..Default::default()
        };
        let out = run_plugin("e2e", &p, &opts).unwrap();

        assert_eq!(out.analyzer_id, "e2e");
        assert_eq!(out.tool_version, "2.0.0");
        assert_eq!(out.units.len(), 1);
        assert_eq!(out.units[0].name, "app");
        assert_eq!(out.totals.overall_unsafe, 2);
        assert_eq!(out.scope, Scope::from(&opts));
    }
}
