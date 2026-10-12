use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_path() -> PathBuf {
    project_root().join("tests/fixtures/sample_workspace")
}

fn multi_member_fixture_path() -> PathBuf {
    project_root().join("tests/fixtures/multi_member_workspace")
}

#[test]
#[ignore = "requires cargo build first"]
fn test_scan_sample_workspace() {
    let binary = project_root().join("target/debug/unsafe-budget");
    if !binary.exists() {
        eprintln!("Skipping integration test - binary not built");
        return;
    }

    let output = Command::new(&binary)
        .arg("scan")
        .arg("--manifest-path")
        .arg(fixture_path().join("Cargo.toml"))
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run unsafe-budget");

    assert!(output.status.success(), "scan failed: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout).expect("invalid json output");

    assert_eq!(result["analyzer_id"], "rustc_unsafe_lint");
    assert_eq!(result["language"], "rust");

    // Should have found the member crate
    let units = result["units"].as_array().expect("units should be array");
    let member = units.iter().find(|u| u["name"] == "member");
    assert!(member.is_some(), "should find member crate");

    // Should have found unsafe code (at least 2 blocks)
    let member = member.unwrap();
    let count = member["unsafe_count"].as_u64().unwrap();
    assert!(
        count >= 2,
        "should find at least 2 unsafe blocks, found {}",
        count
    );
}

#[test]
#[ignore = "requires cargo build first"]
fn test_workspace_only_scans_sibling_members() {
    // `--workspace-only` compiles every workspace member, not just the root
    // package; a sibling crate's unsafe code must be counted.
    let binary = project_root().join("target/debug/unsafe-budget");
    if !binary.exists() {
        eprintln!("Skipping integration test - binary not built");
        return;
    }

    let output = Command::new(&binary)
        .arg("scan")
        .arg("--manifest-path")
        .arg(multi_member_fixture_path().join("Cargo.toml"))
        .arg("--workspace-only")
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run unsafe-budget");

    assert!(output.status.success(), "scan failed: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout).expect("invalid json output");

    let units = result["units"].as_array().expect("units should be array");
    let sibling = units
        .iter()
        .find(|u| u["name"] == "sibling")
        .expect("workspace-only scan should include the sibling member");

    let count = sibling["unsafe_count"].as_u64().unwrap();
    assert!(
        count >= 1,
        "sibling member's unsafe code must be counted in --workspace-only mode, found {}",
        count
    );
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run git");
    assert!(output.status.success(), "git {args:?} failed: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn git_crate(root: &Path, name: &str, lib: &str) -> PathBuf {
    let dir = root.join(name);
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join("Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )
    .unwrap();
    fs::write(dir.join("src/lib.rs"), lib).unwrap();
    git(&dir, &["init", "-q"]);
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-q", "-m", "initial"]);
    dir
}

/// `app` consumes `gitdep` and the `rev`-pinned `revdep` from `file://` git
/// sources, which cargo caps like registry dependencies. `app` and `gitdep` have
/// two unsafe blocks each, one of app's allowed; `revdep` has one.
fn write_capped_dependency_fixture(root: &Path) -> PathBuf {
    let dep = git_crate(
        root,
        "gitdep",
        r#"pub fn one() -> u8 {
    let x = 1u8;
    unsafe { *(&x as *const u8) }
}

pub fn two() -> u8 {
    let x = 2u8;
    unsafe { *(&x as *const u8) }
}
"#,
    );
    let revdep = git_crate(
        root,
        "revdep",
        r#"pub fn three() -> u8 {
    let x = 3u8;
    unsafe { *(&x as *const u8) }
}
"#,
    );
    let rev = git(&revdep, &["rev-parse", "HEAD"]);

    let app = root.join("app");
    fs::create_dir_all(app.join("src")).unwrap();
    fs::write(
        app.join("Cargo.toml"),
        format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\ngitdep = {{ git = \"file://{}\" }}\n\
             revdep = {{ git = \"file://{}\", rev = \"{rev}\" }}\n",
            dep.display(),
            revdep.display()
        ),
    )
    .unwrap();
    fs::write(
        app.join("src/lib.rs"),
        r#"pub fn counted() -> u8 {
    let x = gitdep::one();
    unsafe { *(&x as *const u8) }
}

#[allow(unsafe_code)]
pub fn allowed() -> u8 {
    let x = gitdep::two();
    unsafe { *(&x as *const u8) }
}
"#,
    )
    .unwrap();
    app.join("Cargo.toml")
}

fn unsafe_budget(root: &Path, manifest: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_unsafe-budget"));
    cmd.args(args)
        .arg("--manifest-path")
        .arg(manifest)
        .current_dir(root)
        .env("CARGO_HOME", root.join("cargo-home"));
    cmd
}

fn run_ok(cmd: &mut Command) -> Vec<u8> {
    let output = cmd.output().expect("failed to run unsafe-budget");
    assert!(output.status.success(), "{cmd:?} failed: {output:?}");
    output.stdout
}

fn scan_fixture(root: &Path, manifest: &Path, extra_args: &[&str]) -> serde_json::Value {
    let stdout =
        run_ok(unsafe_budget(root, manifest, &["scan", "--format", "json"]).args(extra_args));
    serde_json::from_slice(&stdout).expect("invalid json output")
}

fn capped_fixture_units() -> Vec<(String, String, u64)> {
    [
        ("app", "workspace", 2),
        ("gitdep", "dep", 2),
        ("revdep", "dep", 1),
    ]
    .into_iter()
    .map(|(name, kind, count)| (name.to_string(), kind.to_string(), count))
    .collect()
}

fn unit_counts(result: &serde_json::Value) -> Vec<(String, String, u64)> {
    result["units"]
        .as_array()
        .expect("units should be array")
        .iter()
        .map(|u| {
            (
                u["name"].as_str().unwrap().to_string(),
                u["kind"].as_str().unwrap().to_string(),
                u["unsafe_count"].as_u64().unwrap(),
            )
        })
        .collect()
}

#[test]
#[ignore = "runs cargo and git"]
fn test_scan_counts_capped_dependency_and_allowed_unsafe() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = write_capped_dependency_fixture(tmp.path());

    for run in ["cold", "warm"] {
        let result = scan_fixture(tmp.path(), &manifest, &[]);
        assert_eq!(unit_counts(&result), capped_fixture_units(), "{run} scan");
        assert_eq!(result["totals"]["workspace_unsafe"], 2, "{run} scan");
        assert_eq!(result["totals"]["deps_unsafe"], 3, "{run} scan");
    }
}

#[test]
#[ignore = "runs cargo and git"]
fn test_rev_bump_passes_check_with_empty_encoded_rustflags() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = write_capped_dependency_fixture(tmp.path());
    let run = |args: &[&str]| {
        run_ok(unsafe_budget(tmp.path(), &manifest, args).env("CARGO_ENCODED_RUSTFLAGS", ""))
    };

    let result: serde_json::Value =
        serde_json::from_slice(&run(&["scan", "--format", "json"])).unwrap();
    assert_eq!(unit_counts(&result), capped_fixture_units());

    run(&["update"]);
    let revdep = tmp.path().join("revdep");
    let old_rev = git(&revdep, &["rev-parse", "HEAD"]);
    git(&revdep, &["commit", "-q", "--allow-empty", "-m", "bump"]);
    let new_rev = git(&revdep, &["rev-parse", "HEAD"]);
    let app_toml = fs::read_to_string(&manifest).unwrap();
    assert!(app_toml.contains(&old_rev), "{app_toml}");
    fs::write(&manifest, app_toml.replace(&old_rev, &new_rev)).unwrap();
    run(&["check"]);
}

#[test]
#[ignore = "runs cargo and git"]
fn test_workspace_only_and_no_deps_exclude_dependency_units() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = write_capped_dependency_fixture(tmp.path());

    for flag in ["--workspace-only", "--no-deps"] {
        let result = scan_fixture(tmp.path(), &manifest, &[flag]);
        assert_eq!(
            unit_counts(&result),
            vec![("app".to_string(), "workspace".to_string(), 2)],
            "{flag}"
        );
        assert_eq!(result["totals"]["deps_unsafe"], 0, "{flag}");
        let details = result["details"]
            .as_array()
            .expect("details should be array");
        assert!(
            details.iter().all(|d| d["unit"] == "app"),
            "{flag}: {details:?}"
        );
    }
}

#[cfg(unix)]
fn write_geiger_workspace(root: &Path) -> PathBuf {
    let ws = root.join("ws");
    for (name, manifest) in [
        (
            "alpha",
            "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[features]\nextra = []\nmore = []\n",
        ),
        (
            "beta",
            "[package]\nname = \"beta\"\nversion = \"0.2.0\"\nedition = \"2021\"\n\n[dependencies]\na2 = { path = \"../alpha\", package = \"alpha\" }\n",
        ),
    ] {
        fs::create_dir_all(ws.join(name).join("src")).unwrap();
        fs::write(ws.join(name).join("Cargo.toml"), manifest).unwrap();
        fs::write(ws.join(name).join("src/lib.rs"), "").unwrap();
    }
    fs::write(
        ws.join("Cargo.toml"),
        "[workspace]\nmembers = [\"alpha\", \"beta\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    ws.join("Cargo.toml")
}

/// a `PATH` whose `cargo-geiger` logs its tab-joined argv and prints the report given for the member directory it scans.
#[cfg(unix)]
fn write_cargo_geiger_stub(root: &Path, reports: &[(&str, PathBuf)]) -> std::ffi::OsString {
    use std::os::unix::fs::PermissionsExt;

    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let cases: String = reports
        .iter()
        .map(|(dir, report)| format!("*/{dir}/Cargo.toml) cat \"{}\" ;;\n", report.display()))
        .collect();
    let stub = bin.join("cargo-geiger");
    fs::write(
        &stub,
        format!(
            r#"#!/bin/sh
(IFS=$(printf '\t'); printf '%s\n' "$*") >> "{log}"
case "$*" in
{cases}*) exit 1 ;;
esac
"#,
            log = root.join("geiger.log").display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
    let mut path = vec![bin];
    path.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    std::env::join_paths(path).unwrap()
}

#[cfg(unix)]
#[test]
fn test_cargo_geiger_scans_each_member_and_counts_shared_dependencies_once() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let manifest = write_geiger_workspace(&root);
    let reports = project_root().join("tests/fixtures/cargo_geiger");
    let path = write_cargo_geiger_stub(
        &root,
        &[
            ("alpha", reports.join("alpha.json")),
            ("beta", reports.join("beta.json")),
        ],
    );
    let geiger = |args: &[&str]| {
        let mut cmd = unsafe_budget(
            &root,
            &manifest,
            &["scan", "--analyzer", "cargo_geiger", "--format", "json"],
        );
        cmd.args(args).env("PATH", &path);
        cmd
    };

    let stdout = run_ok(&mut geiger(&["--include-deps", "--features", "extra,more"]));
    let result: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(
        unit_counts(&result),
        [
            ("alpha", "workspace", 8),
            ("beta", "workspace", 4),
            ("itoa", "dep", 146),
        ]
        .map(|(name, kind, count)| (name.to_string(), kind.to_string(), count))
    );

    let log = fs::read_to_string(root.join("geiger.log")).unwrap();
    let mut calls: Vec<&str> = log.lines().collect();
    calls.sort();
    let alpha = root.join("ws/alpha/Cargo.toml");
    let beta = root.join("ws/beta/Cargo.toml");
    assert_eq!(
        calls,
        [
            format!(
                "geiger\t--output-format\tJson\t--build-dependencies\t--features\textra more\t--manifest-path\t{}",
                alpha.display()
            ),
            format!(
                "geiger\t--output-format\tJson\t--build-dependencies\t--manifest-path\t{}",
                beta.display()
            ),
        ]
    );

    fs::remove_file(root.join("geiger.log")).unwrap();
    run_ok(&mut geiger(&["--features", "extra more"]));
    let log = fs::read_to_string(root.join("geiger.log")).unwrap();
    assert!(
        log.lines().any(|call| call
            == format!(
                "geiger\t--output-format\tJson\t--build-dependencies\t--features\textra more\t--manifest-path\t{}",
                alpha.display()
            )),
        "{log}"
    );

    let stdout = run_ok(&mut geiger(&["--workspace-only"]));
    let result: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(
        unit_counts(&result),
        [("alpha", "workspace", 8), ("beta", "workspace", 4)].map(|(name, kind, count)| (
            name.to_string(),
            kind.to_string(),
            count
        ))
    );

    for (feature, member) in [
        ("alpha/extra", &alpha),
        ("a2/extra", &beta),
        ("a2?/extra", &beta),
    ] {
        fs::remove_file(root.join("geiger.log")).unwrap();
        run_ok(&mut geiger(&["--features", feature]));
        let log = fs::read_to_string(root.join("geiger.log")).unwrap();
        let mut calls: Vec<&str> = log.lines().filter(|c| c.contains("--features")).collect();
        calls.sort();
        assert_eq!(
            calls,
            [format!(
                "geiger\t--output-format\tJson\t--build-dependencies\t--features\t{feature}\t--manifest-path\t{}",
                member.display()
            )],
            "{feature}"
        );
    }

    let output = geiger(&["--features", "nope"]).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no workspace member has the feature `nope`"),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_cargo_geiger_subtracts_a_nested_member_and_warns_about_generated_unsafe_code() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let ws = root.join("ws");
    for (dir, manifest) in [
        (
            ws.clone(),
            "[package]\nname = \"rootpkg\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsibling = { path = \"sibling\" }\n\n[workspace]\nmembers = [\"sibling\"]\n",
        ),
        (
            ws.join("sibling"),
            "[package]\nname = \"sibling\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
    ] {
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("Cargo.toml"), manifest).unwrap();
        fs::write(dir.join("src/lib.rs"), "").unwrap();
    }
    let reports = project_root().join("tests/fixtures/cargo_geiger");
    let mut report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(reports.join("multi_member_root_on_sibling.json")).unwrap(),
    )
    .unwrap();
    // rootpkg gains 2 unsafe expressions of its own, sibling 3 in code that isn't compiled
    report["packages"][0]["unsafety"]["used"]["exprs"]["unsafe_"] = 7.into();
    for package in report["packages"].as_array_mut().unwrap() {
        package["unsafety"]["unused"]["exprs"]["unsafe_"] = 3.into();
    }
    let root_report = root.join("rootpkg.json");
    fs::write(&root_report, report.to_string()).unwrap();
    let out = ws.join("target/debug/build/gen-0123/out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("gen.rs"), "pub unsafe fn f() {}\n").unwrap();
    let path = write_cargo_geiger_stub(
        &root,
        &[
            ("sibling", reports.join("multi_member_sibling.json")),
            ("ws", root_report),
        ],
    );

    let mut cmd = unsafe_budget(
        &root,
        &ws.join("Cargo.toml"),
        &[
            "scan",
            "--analyzer",
            "cargo_geiger",
            "--format",
            "json",
            "--workspace-only",
        ],
    );
    cmd.env("PATH", &path)
        .env("CARGO_TARGET_DIR", ws.join("target"));
    let result: serde_json::Value = serde_json::from_slice(&run_ok(&mut cmd)).unwrap();

    assert_eq!(
        unit_counts(&result),
        [("rootpkg", "workspace", 2), ("sibling", "workspace", 5)].map(|(name, kind, count)| (
            name.to_string(),
            kind.to_string(),
            count
        ))
    );
    let warnings = result["parse_warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0]["message"]
            .as_str()
            .unwrap()
            .starts_with(&format!(
                "cargo-geiger: rootpkg may be credited with the unsafe code a build script generated in {};",
                out.join("gen.rs").display()
            )),
        "{warnings:?}"
    );
}

#[test]
fn test_budget_logic() {
    use unsafe_budget::budget;
    use unsafe_budget::config::{Baseline, BaselineUnit, Config, Mode};
    use unsafe_budget::model::{ScanResult, Scope, Totals, Unit, UnitKind};

    let scan = ScanResult {
        tool_version: "0.1.0".into(),
        analyzer_id: "test".into(),
        language: "rust".into(),
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
        units: vec![
            Unit {
                name: "my_crate".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 15,
            },
            Unit {
                name: "dep".into(),
                kind: UnitKind::Dep,
                unsafe_count: 10,
            },
        ],
        totals: Totals {
            workspace_unsafe: 15,
            deps_unsafe: 10,
            overall_unsafe: 25,
        },
        details: vec![],
        parse_warnings: vec![],
    };

    let baseline = Baseline {
        tool_version: "0.1.0".into(),
        analyzer_id: "test".into(),
        scope: scan.scope.clone(),
        totals: Totals {
            workspace_unsafe: 10,
            deps_unsafe: 10,
            overall_unsafe: 20,
        },
        units: vec![
            BaselineUnit {
                name: "my_crate".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 10,
            },
            BaselineUnit {
                name: "dep".into(),
                kind: UnitKind::Dep,
                unsafe_count: 10,
            },
        ],
    };

    let config = Config {
        mode: Mode::Ratchet,
        ..Config::default()
    };

    let result = budget::check(&scan, Some(&baseline), &config).unwrap();

    assert!(!result.passed);
    assert_eq!(result.violations.len(), 1);
    assert_eq!(result.violations[0].unit, "my_crate");
    assert_eq!(result.violations[0].delta, 5);
}

#[test]
fn test_config_parsing() {
    use unsafe_budget::config::{Config, Mode};

    let toml = r#"
mode = "caps"
include_deps = false
ignore_units = ["test_crate"]

[caps]
default = 50

[caps.workspace]
my_crate = 10
"#;

    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.mode, Mode::Caps);
    assert!(!config.include_deps);
    assert_eq!(config.ignore_units, vec!["test_crate"]);

    let caps = config.caps.unwrap();
    assert_eq!(caps.default, Some(50));
    assert_eq!(caps.workspace.get("my_crate"), Some(&10));
}
