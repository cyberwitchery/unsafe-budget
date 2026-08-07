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
        let workspace_members = get_workspace_members(opts)?;
        let (stdout, _stderr) = run_cargo_check(opts)?;
        let occurrences = parse_diagnostics(&stdout, &workspace_members)?;
        let (units, details) = aggregate_occurrences(occurrences, &workspace_members, opts);

        Ok(ScanResult::from_parts(
            self.id(),
            self.language(),
            opts,
            units,
            details,
        ))
    }
}

/// get workspace member package names.
fn get_workspace_members(opts: &ScanOpts) -> Result<HashSet<String>> {
    let mut cmd = MetadataCommand::new();

    if let Some(ref manifest_path) = opts.manifest_path {
        cmd.manifest_path(manifest_path);
    }

    let metadata = cmd.exec()?;

    // pre-build an id -> package lookup so member resolution is linear rather
    // than O(members x packages) via a nested `.find()`.
    let package_by_id: HashMap<&PackageId, &Package> =
        metadata.packages.iter().map(|p| (&p.id, p)).collect();

    let members: HashSet<String> = metadata
        .workspace_members
        .iter()
        .filter_map(|id| package_by_id.get(id).map(|p| p.name.to_string()))
        .collect();

    Ok(members)
}

/// build the `cargo check` command used to collect unsafe_code diagnostics.
fn build_cargo_check_command(opts: &ScanOpts) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.arg("check").arg("--message-format=json");

    let existing_flags = std::env::var("RUSTFLAGS").unwrap_or_default();
    let new_flags = if existing_flags.is_empty() {
        "-Wunsafe_code".into()
    } else {
        format!("{} -Wunsafe_code", existing_flags)
    };
    cmd.env("RUSTFLAGS", new_flags);

    super::apply_cargo_flags(&mut cmd, opts);

    // always compile the whole workspace so every member emits diagnostics.
    // omitting `--workspace` would build only the current package, leaving
    // sibling members unseen and silently counted as zero. dependency exclusion
    // (for `workspace_only`) happens later in aggregation, not by narrowing the
    // compile set.
    cmd.arg("--workspace");

    cmd
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
    workspace_members: &HashSet<String>,
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

            let kind = if workspace_members.contains(&unit_name) {
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

/// extract package name from cargo's package_id representation.
/// handles formats like:
/// - "path+file:///path/to/crate#0.1.0" -> crate name from path
/// - "registry+https://...#name@version" -> name
/// - "git+https://...#name@version" / "sparse+https://...#name@version" -> name
/// - "crate_name 0.1.0 (registry+...)" -> crate_name
fn extract_package_name(package_id: &str) -> String {
    // new cargo format: "<scheme>+<url>#<name>@<version>" or "<scheme>+<url>#<version>"
    if let Some((before_hash, after_hash)) = package_id.split_once('#') {
        // "<scheme>+<url>#<name>@<version>" -> name. cargo uses this shape for any
        // remote source (registry+, sparse+, git+, alternative registries), so key
        // off the "<name>@<version>" suffix rather than the scheme prefix.
        if let Some((name, _version)) = after_hash.split_once('@') {
            return name.to_string();
        }

        // version-only suffix, e.g. "path+file:///path/to/member#0.1.0" -> "member".
        // the name is omitted when it equals the url's last path segment.
        let path = before_hash
            .strip_prefix("path+file://")
            .or_else(|| before_hash.strip_prefix("file://"))
            .unwrap_or(before_hash);
        if let Some(name) = std::path::Path::new(path).file_name() {
            return name.to_string_lossy().to_string();
        }
    }

    // old format: "crate_name version (source)"
    package_id
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_string()
}

/// aggregate occurrences into units.
fn aggregate_occurrences(
    occurrences: Vec<(Occurrence, UnitKind)>,
    workspace_members: &HashSet<String>,
    opts: &ScanOpts,
) -> (Vec<Unit>, Vec<Occurrence>) {
    let mut counts: HashMap<String, (UnitKind, u64)> = HashMap::new();
    let mut details = Vec::new();

    for (occ, kind) in occurrences {
        let entry = counts.entry(occ.unit.clone()).or_insert((kind, 0));
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
    fn test_extract_package_name_path_format() {
        // new cargo format with path+file://
        assert_eq!(
            extract_package_name("path+file:///home/user/project/my_crate#0.1.0"),
            "my_crate"
        );
        assert_eq!(
            extract_package_name("path+file:///Users/dev/workspace/foo-bar#1.2.3"),
            "foo-bar"
        );
    }

    #[test]
    fn test_extract_package_name_registry_format() {
        // registry format with name@version
        assert_eq!(
            extract_package_name(
                "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0"
            ),
            "serde"
        );
        assert_eq!(
            extract_package_name(
                "registry+https://github.com/rust-lang/crates.io-index#tokio@1.28.0"
            ),
            "tokio"
        );
    }

    #[test]
    fn test_extract_package_name_old_format() {
        // old cargo format: "name version (source)"
        assert_eq!(
            extract_package_name(
                "serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"
            ),
            "serde"
        );
        assert_eq!(extract_package_name("my_crate 0.1.0"), "my_crate");
    }

    #[test]
    fn test_extract_package_name_git_format() {
        // git source: name@version after '#', regardless of the git+ prefix or query string
        assert_eq!(
            extract_package_name("git+https://github.com/owner/repo#mycrate@0.1.0"),
            "mycrate"
        );
        // a ?rev=/?branch= query precedes the '#' and must not leak into the name
        assert_eq!(
            extract_package_name("git+https://github.com/rust-lang/log?rev=abc123#log@0.4.20"),
            "log"
        );
    }

    #[test]
    fn test_extract_package_name_sparse_format() {
        // sparse crates-io index
        assert_eq!(
            extract_package_name("sparse+https://index.crates.io/#serde@1.0.0"),
            "serde"
        );
    }

    #[test]
    fn test_extract_package_name_alternative_registry() {
        // private/alternative registry: name@version still wins over the scheme prefix
        assert_eq!(
            extract_package_name("sparse+https://registry.example.com/index/#private_crate@2.3.4"),
            "private_crate"
        );
        assert_eq!(
            extract_package_name("registry+https://my.alt.registry/index#alt_crate@0.5.0"),
            "alt_crate"
        );
    }

    #[test]
    fn test_extract_package_name_path_member_regression() {
        // version-only suffix (no '@'): must still resolve to the workspace member dir name
        assert_eq!(
            extract_package_name("path+file:///abs/workspace/sub-member#0.2.0"),
            "sub-member"
        );
    }

    #[test]
    fn test_extract_package_name_edge_cases() {
        assert_eq!(extract_package_name("unknown"), "unknown");
        assert_eq!(extract_package_name(""), "unknown");
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
}
