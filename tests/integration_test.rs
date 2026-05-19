use std::path::PathBuf;
use std::process::Command;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_path() -> PathBuf {
    project_root().join("tests/fixtures/sample_workspace")
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
