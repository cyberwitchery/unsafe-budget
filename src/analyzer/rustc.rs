use crate::analyzer::process::{self, Run};
use crate::analyzer::Analyzer;
use crate::error::{Error, Result};
use crate::model::{Occurrence, ScanOpts, ScanResult, Unit, UnitKind};
use cargo_metadata::{Message, MetadataCommand, Package, PackageId};
use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

pub struct RustcAnalyzer;

impl Analyzer for RustcAnalyzer {
    fn id(&self) -> &str {
        "rustc_unsafe_lint"
    }

    fn language(&self) -> &str {
        "rust"
    }

    fn run(&self, opts: &ScanOpts) -> Result<ScanResult> {
        let members = get_workspace_members(opts)?;
        let (stdout, _stderr) = run_cargo_check(opts)?;
        let occurrences = parse_diagnostics(&stdout, &members.ids)?;
        let (units, details) = aggregate_occurrences(occurrences, &members.names, opts);

        Ok(ScanResult::from_parts(
            self.id(),
            self.language(),
            opts,
            units,
            details,
        ))
    }
}

struct WorkspaceMembers {
    ids: HashSet<PackageId>,
    names: HashSet<String>,
}

/// get workspace member package ids and names.
fn get_workspace_members(opts: &ScanOpts) -> Result<WorkspaceMembers> {
    let mut cmd = MetadataCommand::new();
    // the same binary as `cargo check`, so their package ids compare equal.
    cmd.cargo_path("cargo");

    if let Some(ref manifest_path) = opts.manifest_path {
        cmd.manifest_path(manifest_path);
    }

    let metadata = cmd.exec()?;

    // pre-build an id -> package lookup so member resolution is linear rather
    // than O(members x packages) via a nested `.find()`.
    let package_by_id: HashMap<&PackageId, &Package> =
        metadata.packages.iter().map(|p| (&p.id, p)).collect();

    let names: HashSet<String> = metadata
        .workspace_members
        .iter()
        .filter_map(|id| package_by_id.get(id).map(|p| p.name.to_string()))
        .collect();

    Ok(WorkspaceMembers {
        ids: metadata.workspace_members.iter().cloned().collect(),
        names,
    })
}

/// overrides both `#[allow(unsafe_code)]` in source and cargo's `--cap-lints allow`.
const UNSAFE_CODE_LINT: &str = "--force-warn=unsafe_code";

/// build the `cargo check` command used to collect unsafe_code diagnostics.
fn build_cargo_check_command(opts: &ScanOpts) -> Command {
    let mut cmd = Command::new("cargo");
    // `-vv` stops cargo capping dependency lints and makes it replay their cached diagnostics.
    cmd.arg("check").arg("--message-format=json").arg("-vv");

    let (var, flags) = rustflags_with_unsafe_lint(
        std::env::var("CARGO_ENCODED_RUSTFLAGS").ok(),
        std::env::var("RUSTFLAGS").ok(),
    );
    cmd.env(var, flags);

    super::apply_cargo_flags(&mut cmd, opts);

    // always compile the whole workspace so every member emits diagnostics.
    // omitting `--workspace` would build only the current package, leaving
    // sibling members unseen and silently counted as zero. dependency exclusion
    // (for `workspace_only`) happens later in aggregation, not by narrowing the
    // compile set.
    cmd.arg("--workspace");

    cmd
}

/// append [`UNSAFE_CODE_LINT`] to the rustflags variable cargo will read,
/// returning that variable's name and new value.
fn rustflags_with_unsafe_lint(
    encoded: Option<String>,
    plain: Option<String>,
) -> (&'static str, String) {
    // cargo ignores RUSTFLAGS whenever CARGO_ENCODED_RUSTFLAGS is set, even to "".
    let (var, existing, separator) = match encoded {
        Some(flags) => ("CARGO_ENCODED_RUSTFLAGS", flags, '\x1f'),
        None => ("RUSTFLAGS", plain.unwrap_or_default(), ' '),
    };
    let flags = if existing.is_empty() {
        UNSAFE_CODE_LINT.to_string()
    } else {
        format!("{existing}{separator}{UNSAFE_CODE_LINT}")
    };
    (var, flags)
}

/// run cargo check and capture output.
fn run_cargo_check(opts: &ScanOpts) -> Result<(Vec<u8>, String)> {
    let mut cmd = build_cargo_check_command(opts);

    let timeout_secs = opts.analyzer_timeout_secs;
    let output = match process::run_process(&mut cmd, timeout_secs.map(Duration::from_secs))? {
        Run::Completed(output) => output,
        Run::TimedOut => {
            return Err(Error::Cargo {
                message: format!(
                    "cargo check timed out after {}s",
                    timeout_secs.unwrap_or_default()
                ),
                stderr: String::new(),
            })
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    check_cargo_output(&output.status, &output.stdout, &stderr)?;
    Ok((output.stdout, stderr))
}

/// check whether cargo's output indicates an infrastructure failure.
/// warnings cause non-zero exit but still produce JSON diagnostics on stdout,
/// so a non-zero exit alone isn't an error. but empty stdout with a non-zero exit
/// means cargo itself broke (missing toolchain, linker error, network failure)
/// and must not be silently treated as zero violations.
fn check_cargo_output(
    status: &std::process::ExitStatus,
    stdout: &[u8],
    stderr: &str,
) -> Result<()> {
    if !status.success() && stdout.is_empty() {
        return Err(Error::Cargo {
            message: "cargo check failed".into(),
            stderr: stderr.to_string(),
        });
    }
    Ok(())
}

/// parse cargo JSON messages and extract unsafe_code diagnostics.
fn parse_diagnostics(
    stdout: &[u8],
    workspace_member_ids: &HashSet<PackageId>,
) -> Result<Vec<(Occurrence, UnitKind)>> {
    let mut occurrences = Vec::new();
    let mut seen: HashSet<(String, PathBuf, u32, u32)> = HashSet::new();

    for line in stdout.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        let message: Message = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(_) => continue, // skip non-JSON lines
        };

        if let Message::CompilerMessage(compiler_msg) = message {
            let diag = &compiler_msg.message;

            let is_unsafe = diag.code.as_ref().is_some_and(|c| c.code == "unsafe_code");

            if !is_unsafe {
                continue;
            }

            let span = diag.spans.iter().find(|s| s.is_primary);

            let (file, line, col) = if let Some(span) = span {
                (
                    PathBuf::from(&span.file_name),
                    span.line_start as u32,
                    span.column_start as u32,
                )
            } else {
                continue;
            };

            let unit_name = extract_package_name(&compiler_msg.package_id.repr);

            let key = (unit_name.clone(), file.clone(), line, col);
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);

            let kind = if workspace_member_ids.contains(&compiler_msg.package_id) {
                UnitKind::Workspace
            } else {
                UnitKind::Dep
            };

            occurrences.push((
                Occurrence {
                    unit: unit_name,
                    file,
                    line,
                    col,
                    message: Some(diag.message.clone()),
                },
                kind,
            ));
        }
    }

    Ok(occurrences)
}

/// extract the package name from a cargo package id: either a package id spec,
/// `[kind+]proto://host/path[?query][#name|#version|#name@version]` (cargo 1.77+),
/// or the older `name version (source)`.
fn extract_package_name(package_id: &str) -> String {
    let name = if package_id.contains("://") && !package_id.contains(char::is_whitespace) {
        let (url, fragment) = package_id.split_once('#').unwrap_or((package_id, ""));
        let path = url.split_once('?').map_or(url, |(path, _query)| path);
        let last_segment = path.rsplit('/').next().unwrap_or_default();
        match fragment.split_once(['@', ':']) {
            Some((name, _version)) => name,
            None if fragment.starts_with(char::is_alphabetic) => fragment,
            // cargo leaves the name out when it equals the url's last path segment.
            None => last_segment,
        }
    } else {
        let spec = package_id.split_whitespace().next().unwrap_or_default();
        spec.split_once(['@', ':'])
            .map_or(spec, |(name, _version)| name)
    };

    if name.is_empty() {
        "unknown".to_string()
    } else {
        name.to_string()
    }
}

/// aggregate occurrences into units.
fn aggregate_occurrences(
    occurrences: Vec<(Occurrence, UnitKind)>,
    workspace_members: &HashSet<String>,
    opts: &ScanOpts,
) -> (Vec<Unit>, Vec<Occurrence>) {
    let mut counts: HashMap<String, (UnitKind, u64)> = HashMap::new();
    let mut details = Vec::new();
    let exclude_deps = opts.workspace_only || !opts.include_deps;

    for (occ, kind) in occurrences {
        // units are keyed by name, so a dependency may share a member's unit.
        if exclude_deps && kind == UnitKind::Dep {
            continue;
        }
        let entry = counts.entry(occ.unit.clone()).or_insert((kind, 0));
        if kind == UnitKind::Workspace {
            entry.0 = kind;
        }
        entry.1 += 1;
        details.push(occ);
    }

    // ensure workspace members appear with 0 count when deps are excluded
    if opts.workspace_only || !opts.include_deps {
        for member in workspace_members {
            counts
                .entry(member.clone())
                .or_insert((UnitKind::Workspace, 0));
        }
    }

    super::aggregate_units(counts, details, opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    mod cargo_output_checks {
        use super::*;
        use std::os::unix::process::ExitStatusExt;

        fn exit_success() -> std::process::ExitStatus {
            std::process::ExitStatus::from_raw(0)
        }

        fn exit_failure() -> std::process::ExitStatus {
            // waitpid raw status: exit code in bits 8-15
            std::process::ExitStatus::from_raw(1 << 8)
        }

        #[test]
        fn success_is_ok() {
            assert!(check_cargo_output(&exit_success(), b"output", "").is_ok());
        }

        #[test]
        fn nonzero_exit_with_stdout_is_ok() {
            // warnings cause non-zero exit but produce JSON on stdout
            assert!(check_cargo_output(
                &exit_failure(),
                b"{\"reason\":\"compiler-message\"}",
                "warning: unused variable"
            )
            .is_ok());
        }

        #[test]
        fn nonzero_exit_empty_stdout_is_err() {
            let result =
                check_cargo_output(&exit_failure(), b"", "error: no such command: 'check'");
            assert!(result.is_err());
        }

        #[test]
        fn nonzero_exit_empty_stdout_empty_stderr_is_err() {
            // even with empty stderr, empty stdout + failure = error
            let result = check_cargo_output(&exit_failure(), b"", "");
            assert!(result.is_err());
        }

        #[test]
        fn nonzero_exit_empty_stdout_unknown_error_is_err() {
            // empty stdout + failure is an error regardless of stderr content
            let result = check_cargo_output(&exit_failure(), b"", "error: linker `cc` not found");
            assert!(result.is_err());
        }

        #[test]
        fn preserves_stderr_in_error() {
            let stderr = "error: toolchain 'nightly' is not installed";
            let result = check_cargo_output(&exit_failure(), b"", stderr);
            let err = result.unwrap_err();
            let msg = format!("{}", err);
            assert!(msg.contains(stderr));
        }
    }

    #[test]
    fn test_extract_package_name() {
        let cases = [
            // path members
            ("path+file:///home/user/project/my_crate#0.1.0", "my_crate"),
            ("path+file:///Users/dev/workspace/foo-bar#1.2.3", "foo-bar"),
            ("path+file:///abs/workspace/sub-member#0.2.0", "sub-member"),
            ("path+file:///C:/Users/dev/my_crate#0.1.0", "my_crate"),
            // registries
            ("registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0", "serde"),
            ("registry+https://github.com/rust-lang/crates.io-index#tokio@1.28.0", "tokio"),
            ("registry+https://my.alt.registry/index#alt_crate@0.5.0", "alt_crate"),
            ("sparse+https://index.crates.io/#serde@1.0.0", "serde"),
            ("sparse+https://registry.example.com/index/#private_crate@2.3.4", "private_crate"),
            // git, name omitted because it equals the last path segment
            ("git+https://github.com/owner/revdep#0.1.0", "revdep"),
            ("git+https://github.com/owner/revdep?rev=b257e79de6d48f559c3a39851f8e372c96d9d972#0.1.0", "revdep"),
            ("git+https://github.com/owner/revdep?tag=v1#0.1.0", "revdep"),
            ("git+https://github.com/owner/revdep?branch=master#0.1.0", "revdep"),
            ("git+https://github.com/owner/revdep#1.0.0-alpha.1", "revdep"),
            // git, name present
            ("git+https://github.com/owner/repo#mycrate@0.1.0", "mycrate"),
            ("git+https://github.com/rust-lang/log?rev=abc123#log@0.4.20", "log"),
            ("git+https://github.com/owner/repo-x?tag=v1#namedcrate@0.1.0", "namedcrate"),
            ("git+https://github.com/owner/foo.git#foo@0.1.0", "foo"),
            // specs cargo accepts but never prints
            ("git+https://github.com/owner/repo#mycrate", "mycrate"),
            ("git+https://github.com/owner/repo#mycrate:0.1.0", "mycrate"),
            ("git+https://github.com/owner/revdep?rev=abc123", "revdep"),
            ("serde@1.0.0", "serde"),
            // cargo before 1.77
            ("serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)", "serde"),
            ("app2 0.2.0 (path+file:///ws/app2)", "app2"),
            ("namedcrate 0.1.0 (git+https://github.com/owner/repo-x?tag=v1#39ddb5ec904f39f4687564720dca9b60e00b852f)", "namedcrate"),
            ("my_crate 0.1.0", "my_crate"),
            ("unknown", "unknown"),
            ("", "unknown"),
        ];
        for (package_id, name) in cases {
            assert_eq!(extract_package_name(package_id), name, "{package_id}");
        }
    }

    #[test]
    fn test_aggregate_occurrences_basic() {
        let workspace_members: HashSet<String> = ["my_crate".to_string()].into_iter().collect();
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };

        let occurrences = vec![
            (
                Occurrence {
                    unit: "my_crate".into(),
                    file: "src/lib.rs".into(),
                    line: 10,
                    col: 5,
                    message: None,
                },
                UnitKind::Workspace,
            ),
            (
                Occurrence {
                    unit: "my_crate".into(),
                    file: "src/lib.rs".into(),
                    line: 20,
                    col: 5,
                    message: None,
                },
                UnitKind::Workspace,
            ),
            (
                Occurrence {
                    unit: "libc".into(),
                    file: "src/lib.rs".into(),
                    line: 100,
                    col: 1,
                    message: None,
                },
                UnitKind::Dep,
            ),
        ];

        let (units, details) = aggregate_occurrences(occurrences, &workspace_members, &opts);

        assert_eq!(units.len(), 2);
        let my_crate = units.iter().find(|u| u.name == "my_crate").unwrap();
        assert_eq!(my_crate.unsafe_count, 2);
        assert_eq!(my_crate.kind, UnitKind::Workspace);

        let libc = units.iter().find(|u| u.name == "libc").unwrap();
        assert_eq!(libc.unsafe_count, 1);
        assert_eq!(libc.kind, UnitKind::Dep);

        assert_eq!(details.len(), 3);
    }

    #[test]
    fn test_aggregate_occurrences_workspace_only() {
        let workspace_members: HashSet<String> = ["my_crate".to_string()].into_iter().collect();
        let opts = ScanOpts {
            workspace_only: true,
            include_deps: true,
            ..Default::default()
        };

        let occurrences = vec![
            (
                Occurrence {
                    unit: "my_crate".into(),
                    file: "src/lib.rs".into(),
                    line: 10,
                    col: 5,
                    message: None,
                },
                UnitKind::Workspace,
            ),
            (
                Occurrence {
                    unit: "libc".into(),
                    file: "src/lib.rs".into(),
                    line: 100,
                    col: 1,
                    message: None,
                },
                UnitKind::Dep,
            ),
        ];

        let (units, details) = aggregate_occurrences(occurrences, &workspace_members, &opts);

        // should only have workspace crate, deps filtered out
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "my_crate");
        assert_eq!(details.len(), 1);
    }

    #[test]
    fn test_aggregate_occurrences_no_deps() {
        let workspace_members: HashSet<String> = ["my_crate".to_string()].into_iter().collect();
        let opts = ScanOpts {
            include_deps: false,
            ..Default::default()
        };

        let occurrences = vec![
            (
                Occurrence {
                    unit: "my_crate".into(),
                    file: "src/lib.rs".into(),
                    line: 10,
                    col: 5,
                    message: None,
                },
                UnitKind::Workspace,
            ),
            (
                Occurrence {
                    unit: "libc".into(),
                    file: "src/lib.rs".into(),
                    line: 100,
                    col: 1,
                    message: None,
                },
                UnitKind::Dep,
            ),
        ];

        let (units, details) = aggregate_occurrences(occurrences, &workspace_members, &opts);

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "my_crate");
        assert_eq!(details.len(), 1);
    }

    #[test]
    fn test_aggregate_occurrences_deterministic_order() {
        let workspace_members: HashSet<String> = HashSet::new();
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };

        let occurrences = vec![
            (
                Occurrence {
                    unit: "zebra".into(),
                    file: "z.rs".into(),
                    line: 1,
                    col: 1,
                    message: None,
                },
                UnitKind::Dep,
            ),
            (
                Occurrence {
                    unit: "alpha".into(),
                    file: "a.rs".into(),
                    line: 1,
                    col: 1,
                    message: None,
                },
                UnitKind::Dep,
            ),
            (
                Occurrence {
                    unit: "beta".into(),
                    file: "b.rs".into(),
                    line: 1,
                    col: 1,
                    message: None,
                },
                UnitKind::Dep,
            ),
        ];

        let (units, _) = aggregate_occurrences(occurrences, &workspace_members, &opts);

        // units should be sorted alphabetically
        assert_eq!(units[0].name, "alpha");
        assert_eq!(units[1].name, "beta");
        assert_eq!(units[2].name, "zebra");
    }

    fn unsafe_message(package_id: &str, file: &str) -> String {
        serde_json::json!({
            "reason": "compiler-message",
            "package_id": package_id,
            "target": {"name": "app2", "kind": ["lib"], "src_path": file},
            "message": {
                "message": "usage of an `unsafe` block",
                "code": {"code": "unsafe_code", "explanation": null},
                "level": "warning",
                "spans": [{
                    "file_name": file,
                    "byte_start": 0,
                    "byte_end": 1,
                    "line_start": 1,
                    "line_end": 1,
                    "column_start": 1,
                    "column_end": 2,
                    "is_primary": true,
                    "text": [],
                    "label": null,
                    "suggested_replacement": null,
                    "suggestion_applicability": null,
                    "expansion": null
                }],
                "children": [],
                "rendered": null
            }
        })
        .to_string()
    }

    #[test]
    fn test_parse_diagnostics_classifies_by_package_id() {
        let member = PackageId {
            repr: "path+file:///ws/app2#0.2.0".into(),
        };
        let stdout = [
            unsafe_message(
                "git+https://example.com/old#app2@0.1.0",
                "/cargo/git/checkouts/old/src/lib.rs",
            ),
            unsafe_message(&member.repr, "src/lib.rs"),
        ]
        .join("\n");

        let occurrences = parse_diagnostics(stdout.as_bytes(), &HashSet::from([member])).unwrap();
        let kinds: Vec<(&str, UnitKind)> = occurrences
            .iter()
            .map(|(occ, kind)| (occ.unit.as_str(), *kind))
            .collect();
        assert_eq!(
            kinds,
            [("app2", UnitKind::Dep), ("app2", UnitKind::Workspace)]
        );
    }

    #[test]
    fn test_aggregate_occurrences_dependency_sharing_a_member_name() {
        let workspace_members: HashSet<String> = ["app2".to_string()].into_iter().collect();
        let occurrence = |file: &str| Occurrence {
            unit: "app2".into(),
            file: file.into(),
            line: 1,
            col: 1,
            message: None,
        };
        let dep = (
            occurrence("/cargo/git/checkouts/old/src/lib.rs"),
            UnitKind::Dep,
        );
        let member = (occurrence("src/lib.rs"), UnitKind::Workspace);
        let app2 = |kind, unsafe_count| Unit {
            name: "app2".into(),
            kind,
            unsafe_count,
        };
        let all = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let workspace_only = ScanOpts {
            workspace_only: true,
            ..all.clone()
        };

        let (units, _) =
            aggregate_occurrences(vec![dep.clone(), member.clone()], &workspace_members, &all);
        assert_eq!(units, [app2(UnitKind::Workspace, 2)]);

        let (units, _) = aggregate_occurrences(vec![dep.clone()], &workspace_members, &all);
        assert_eq!(units, [app2(UnitKind::Dep, 1)]);

        let (units, details) = aggregate_occurrences(
            vec![dep.clone(), member.clone()],
            &workspace_members,
            &workspace_only,
        );
        assert_eq!(units, [app2(UnitKind::Workspace, 1)]);
        assert_eq!(details, [member.0]);

        let (units, details) =
            aggregate_occurrences(vec![dep], &workspace_members, &workspace_only);
        assert_eq!(units, [app2(UnitKind::Workspace, 0)]);
        assert!(details.is_empty(), "{details:?}");
    }

    #[test]
    fn test_cargo_check_command_always_scans_whole_workspace() {
        // `--workspace` is added regardless of `--workspace-only`; narrowing
        // the compile set would leave sibling members counted as zero.
        for workspace_only in [false, true] {
            let opts = ScanOpts {
                workspace_only,
                ..Default::default()
            };
            let cmd = build_cargo_check_command(&opts);
            let args: Vec<String> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            assert!(
                args.contains(&"--workspace".to_string()),
                "cargo check must pass --workspace (workspace_only={workspace_only}), got {args:?}"
            );
        }
    }

    #[test]
    fn test_cargo_check_command_forces_unsafe_lint_and_lints_dependencies() {
        let cmd = build_cargo_check_command(&ScanOpts::default());
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"-vv".to_string()), "got {args:?}");

        let rustflags: Vec<String> = cmd
            .get_envs()
            .filter(|(k, _)| *k == "RUSTFLAGS" || *k == "CARGO_ENCODED_RUSTFLAGS")
            .filter_map(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()))
            .collect();
        assert_eq!(rustflags.len(), 1, "got {rustflags:?}");
        assert!(
            rustflags[0].ends_with(UNSAFE_CODE_LINT),
            "got {rustflags:?}"
        );
    }

    #[test]
    fn test_rustflags_with_unsafe_lint_without_existing_flags() {
        let expected = ("RUSTFLAGS", "--force-warn=unsafe_code".to_string());
        assert_eq!(rustflags_with_unsafe_lint(None, None), expected);
        assert_eq!(
            rustflags_with_unsafe_lint(None, Some(String::new())),
            expected
        );
    }

    #[test]
    fn test_rustflags_with_unsafe_lint_preserves_rustflags() {
        assert_eq!(
            rustflags_with_unsafe_lint(None, Some("-C opt-level=1 --cfg foo".into())),
            (
                "RUSTFLAGS",
                "-C opt-level=1 --cfg foo --force-warn=unsafe_code".to_string()
            )
        );
    }

    #[test]
    fn test_rustflags_with_unsafe_lint_appends_to_encoded_rustflags() {
        assert_eq!(
            rustflags_with_unsafe_lint(Some("--cfg\x1ffoo".into()), Some("-Dwarnings".into())),
            (
                "CARGO_ENCODED_RUSTFLAGS",
                "--cfg\x1ffoo\x1f--force-warn=unsafe_code".to_string()
            )
        );
    }

    #[test]
    fn test_rustflags_with_unsafe_lint_fills_empty_encoded_rustflags() {
        assert_eq!(
            rustflags_with_unsafe_lint(Some(String::new()), Some("-Dwarnings".into())),
            (
                "CARGO_ENCODED_RUSTFLAGS",
                "--force-warn=unsafe_code".to_string()
            )
        );
    }
}
