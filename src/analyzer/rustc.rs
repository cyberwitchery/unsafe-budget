use crate::analyzer::Analyzer;
use crate::error::{Error, Result};
use crate::model::{Occurrence, ScanOpts, ScanResult, Unit, UnitKind};
use cargo_metadata::{Message, MetadataCommand};
use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub struct RustcAnalyzer;

impl Analyzer for RustcAnalyzer {
    fn id(&self) -> &str {
        "rustc_unsafe_lint"
    }

    fn language(&self) -> &str {
        "rust"
    }

    fn run(&self, opts: &ScanOpts) -> Result<ScanResult> {
        // Get workspace metadata to identify workspace members
        let workspace_members = get_workspace_members(opts)?;

        // Run cargo check with unsafe_code warnings enabled
        let (stdout, _stderr) = run_cargo_check(opts)?;

        // Parse diagnostics
        let occurrences = parse_diagnostics(&stdout, &workspace_members)?;

        // Aggregate into units
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

/// Get workspace member package names.
fn get_workspace_members(opts: &ScanOpts) -> Result<HashSet<String>> {
    let mut cmd = MetadataCommand::new();

    if let Some(ref manifest_path) = opts.manifest_path {
        cmd.manifest_path(manifest_path);
    }

    let metadata = cmd.exec()?;

    let members: HashSet<String> = metadata
        .workspace_members
        .iter()
        .filter_map(|id| {
            metadata
                .packages
                .iter()
                .find(|p| &p.id == id)
                .map(|p| p.name.clone())
        })
        .collect();

    Ok(members)
}

/// Run cargo check and capture output.
fn run_cargo_check(opts: &ScanOpts) -> Result<(Vec<u8>, String)> {
    let mut cmd = Command::new("cargo");
    cmd.arg("check")
        .arg("--message-format=json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Set RUSTFLAGS to enable unsafe_code lint
    let existing_flags = std::env::var("RUSTFLAGS").unwrap_or_default();
    let new_flags = if existing_flags.is_empty() {
        "-Wunsafe_code".into()
    } else {
        format!("{} -Wunsafe_code", existing_flags)
    };
    cmd.env("RUSTFLAGS", new_flags);

    // Add feature flags
    if opts.all_features {
        cmd.arg("--all-features");
    }
    if opts.no_default_features {
        cmd.arg("--no-default-features");
    }
    for feature in &opts.features {
        cmd.arg("--features").arg(feature);
    }

    // Add target flags
    if opts.all_targets {
        cmd.arg("--all-targets");
    }
    for target in &opts.targets {
        cmd.arg("--target").arg(target);
    }

    // Add manifest path
    if let Some(ref path) = opts.manifest_path {
        cmd.arg("--manifest-path").arg(path);
    }

    // Add workspace flag if needed
    if !opts.workspace_only {
        cmd.arg("--workspace");
    }

    let output = cmd.output()?;

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Don't fail on non-zero exit - warnings cause this
    // Only fail if cargo itself failed catastrophically (no stdout at all and error in stderr)
    if output.stdout.is_empty() && !output.status.success() && !stderr.is_empty() {
        // Check if it's actually a cargo error vs just warnings
        if stderr.contains("error: could not compile")
            || stderr.contains("error[E")
            || stderr.contains("error: failed to")
        {
            return Err(Error::Cargo {
                message: "cargo check failed".into(),
                stderr,
            });
        }
    }

    Ok((output.stdout, stderr))
}

/// Parse cargo JSON messages and extract unsafe_code diagnostics.
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
            Err(_) => continue, // Skip non-JSON lines
        };

        if let Message::CompilerMessage(compiler_msg) = message {
            let diag = &compiler_msg.message;

            // Check if this is an unsafe_code warning
            let is_unsafe = diag.code.as_ref().is_some_and(|c| c.code == "unsafe_code");

            if !is_unsafe {
                continue;
            }

            // Get the primary span for location
            let span = diag.spans.iter().find(|s| s.is_primary);

            let (file, line, col) = if let Some(span) = span {
                (
                    PathBuf::from(&span.file_name),
                    span.line_start as u32,
                    span.column_start as u32,
                )
            } else {
                continue; // Skip if no location
            };

            // Determine the unit name from package_id
            let unit_name = extract_package_name(&compiler_msg.package_id.repr);

            // Deduplicate
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

/// Extract package name from cargo's package_id representation.
/// Handles formats like:
/// - "path+file:///path/to/crate#0.1.0" -> crate name from path
/// - "registry+https://...#name@version" -> name
/// - "crate_name 0.1.0 (registry+...)" -> crate_name
fn extract_package_name(package_id: &str) -> String {
    // New cargo format: "path+file:///path/to/crate#version" or "registry+...#name@version"
    if package_id.contains('#') {
        // registry+https://...#name@version -> extract name first (before path-based extraction)
        if package_id.starts_with("registry+") {
            if let Some(after_hash) = package_id.split('#').nth(1) {
                if let Some(name) = after_hash.split('@').next() {
                    return name.to_string();
                }
            }
        }

        // path+file:///path/to/member#0.1.0 -> extract "member" from path
        if let Some(path_part) = package_id.split('#').next() {
            // Remove scheme prefix like "path+file://"
            let path = path_part
                .strip_prefix("path+file://")
                .or_else(|| path_part.strip_prefix("file://"))
                .unwrap_or(path_part);

            // Get the last component of the path as the crate name
            if let Some(name) = std::path::Path::new(path).file_name() {
                return name.to_string_lossy().to_string();
            }
        }
    }

    // Old format: "crate_name version (source)"
    package_id
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_string()
}

/// Aggregate occurrences into units.
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

    // Ensure workspace members appear with 0 count when deps are excluded
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

    #[test]
    fn test_extract_package_name_path_format() {
        // New cargo format with path+file://
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
        // Registry format with name@version
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
        // Old cargo format: "name version (source)"
        assert_eq!(
            extract_package_name(
                "serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"
            ),
            "serde"
        );
        assert_eq!(extract_package_name("my_crate 0.1.0"), "my_crate");
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

        // Should only have workspace crate, deps filtered out
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

        // Units should be sorted alphabetically
        assert_eq!(units[0].name, "alpha");
        assert_eq!(units[1].name, "beta");
        assert_eq!(units[2].name, "zebra");
    }
}
