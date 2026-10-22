#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn resolve_version(manifest: &str, version: &str, gh_body: &str) -> (Output, String, String) {
    let tmp = tempfile::tempdir().unwrap();
    let action = tmp.path().join("action checkout");
    fs::create_dir_all(action.join("scripts")).unwrap();
    fs::write(action.join("Cargo.toml"), manifest).unwrap();
    fs::write(
        action.join("scripts/action-version.sh"),
        include_str!("../scripts/action-version.sh"),
    )
    .unwrap();

    let consumer = tmp.path().join("consumer");
    fs::create_dir(&consumer).unwrap();
    fs::write(
        consumer.join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"99.0.0\"\n",
    )
    .unwrap();

    let bin = tmp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let gh = bin.join("gh");
    fs::write(
        &gh,
        format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$GH_CALLS\"\n{gh_body}\n"),
    )
    .unwrap();
    fs::set_permissions(gh, fs::Permissions::from_mode(0o755)).unwrap();
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let output_path = tmp.path().join("output");
    let calls_path = tmp.path().join("calls");
    let output = Command::new("bash")
        .arg(action.join("scripts/action-version.sh"))
        .current_dir(consumer)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("INPUT_VERSION", version)
        .env("INPUT_REPOSITORY", "example/releases")
        .env("GITHUB_OUTPUT", &output_path)
        .env("GH_CALLS", &calls_path)
        .output()
        .unwrap();
    (
        output,
        read_if_exists(&output_path),
        read_if_exists(&calls_path),
    )
}

fn read_if_exists(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => panic!("failed to read test output: {err}"),
    }
}

#[test]
fn default_version_follows_the_action_checkout_without_querying_releases() {
    for (manifest, expected) in [
        (include_str!("../Cargo.toml"), env!("CARGO_PKG_VERSION")),
        (
            "[package]\nname = \"unsafe-budget\"\nversion = \"9.8.7-rc.1\"\n\n[dependencies.other]\nversion = \"1.0\"\n",
            "9.8.7-rc.1",
        ),
    ] {
        let (output, tag, calls) = resolve_version(manifest, "", "exit 1");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(tag, format!("tag=v{expected}\n"));
        assert!(calls.is_empty(), "default version queried releases");
    }
}

#[test]
fn explicit_versions_and_latest_remain_available() {
    for (version, expected, expected_calls) in [
        ("v0.5.1", "v0.5.1", ""),
        (
            "latest",
            "v8.0.0",
            "api repos/example/releases/releases/latest --jq .tag_name\n",
        ),
    ] {
        let (output, tag, calls) = resolve_version("", version, "printf 'v8.0.0\\n'");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(tag, format!("tag={expected}\n"));
        assert_eq!(calls, expected_calls);
    }
}

#[test]
fn latest_fails_without_emitting_a_tag_when_the_api_fails_or_returns_empty() {
    for gh_body in ["exit 1", "exit 0"] {
        let (output, tag, calls) = resolve_version("", "latest", gh_body);
        assert!(!output.status.success(), "{output:?}");
        assert!(tag.is_empty());
        assert!(!calls.is_empty());
    }
}

#[test]
fn default_fails_if_the_action_has_no_package_version() {
    let (output, tag, calls) = resolve_version(
        "[package]\nname = \"unsafe-budget\"\n\n[dependencies.other]\nversion = \"1.0\"\n",
        "",
        "exit 1",
    );
    assert!(!output.status.success(), "{output:?}");
    assert!(tag.is_empty());
    assert!(calls.is_empty());
}
