use crate::analyzer::Analyzer;
use crate::error::{Error, Result};
use crate::model::{Occurrence, ScanOpts, ScanResult, Scope, Totals, Unit, UnitKind};
use std::collections::HashMap;
use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub struct GoGeigerAnalyzer;

impl Analyzer for GoGeigerAnalyzer {
    fn id(&self) -> &str {
        "go_geiger"
    }

    fn language(&self) -> &str {
        "go"
    }

    fn run(&self, opts: &ScanOpts) -> Result<ScanResult> {
        let output = run_go_geiger(opts)?;
        let (units, details) = parse_geiger_output(&output, opts)?;
        let totals = compute_totals(&units);

        Ok(ScanResult {
            tool_version: env!("CARGO_PKG_VERSION").into(),
            analyzer_id: self.id().into(),
            language: self.language().into(),
            scope: Scope::from(opts),
            units,
            totals,
            details,
        })
    }
}

fn run_go_geiger(opts: &ScanOpts) -> Result<Vec<u8>> {
    let mut cmd = Command::new("go-geiger");

    // go-geiger takes package patterns as arguments
    // Default to ./... for current module
    let dir = opts
        .manifest_path
        .as_ref()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf());

    if let Some(ref d) = dir {
        cmd.current_dir(d);
    }

    cmd.arg("./...")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // go-geiger may exit non-zero if it finds unsafe, check if we got output
        if output.stdout.is_empty() {
            return Err(Error::Analyzer {
                analyzer: "go_geiger".into(),
                message: format!("go-geiger failed: {}", stderr),
            });
        }
    }

    Ok(output.stdout)
}

// go-geiger output format (line-based):
// /path/to/file.go:123:45: unsafe.Pointer
// /path/to/file.go:456:12: unsafe.Sizeof
fn parse_geiger_output(output: &[u8], opts: &ScanOpts) -> Result<(Vec<Unit>, Vec<Occurrence>)> {
    let mut counts: HashMap<String, (UnitKind, u64)> = HashMap::new();
    let mut details = Vec::new();

    for line in output.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        // Parse line: "file:line:col: message"
        let parts: Vec<&str> = line.splitn(4, ':').collect();
        if parts.len() < 3 {
            continue;
        }

        let file = PathBuf::from(parts[0]);
        let line_num: u32 = parts[1].parse().unwrap_or(0);
        let col: u32 = parts[2].trim().parse().unwrap_or(0);
        let message = parts.get(3).map(|s| s.trim().to_string());

        // Determine package name from file path
        // Try to extract module/package name from path
        let pkg_name = extract_go_package(&file);

        // Determine if this is a workspace package or dependency
        // Dependencies are typically in vendor/ or go module cache
        let is_dep = file.to_string_lossy().contains("/vendor/")
            || file.to_string_lossy().contains("/go/pkg/mod/");

        let kind = if is_dep {
            UnitKind::Dep
        } else {
            UnitKind::Workspace
        };

        // Skip based on options
        if opts.workspace_only && kind == UnitKind::Dep {
            continue;
        }
        if !opts.include_deps && kind == UnitKind::Dep {
            continue;
        }

        let entry = counts.entry(pkg_name.clone()).or_insert((kind, 0));
        entry.1 += 1;

        details.push(Occurrence {
            unit: pkg_name,
            file,
            line: line_num,
            col,
            message,
        });
    }

    let mut units: Vec<Unit> = counts
        .into_iter()
        .map(|(name, (kind, count))| Unit {
            name,
            kind,
            unsafe_count: count,
        })
        .collect();

    units.sort_by(|a, b| a.name.cmp(&b.name));
    details.sort_by(|a, b| {
        a.unit
            .cmp(&b.unit)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    Ok((units, details))
}

/// Extract Go package name from file path.
/// Tries to find the package based on common Go project layouts.
fn extract_go_package(file: &std::path::Path) -> String {
    let path_str = file.to_string_lossy();

    // Check for vendor path
    if let Some(idx) = path_str.find("/vendor/") {
        let after_vendor = &path_str[idx + 8..];
        if let Some(end) = after_vendor.rfind('/') {
            return after_vendor[..end].to_string();
        }
        return after_vendor.to_string();
    }

    // Check for go module cache path
    if let Some(idx) = path_str.find("/go/pkg/mod/") {
        let after_mod = &path_str[idx + 12..];
        // Format: module@version/path
        if let Some(at_idx) = after_mod.find('@') {
            let module = &after_mod[..at_idx];
            return module.to_string();
        }
    }

    // For workspace files, use the parent directory name or file stem
    file.parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn compute_totals(units: &[Unit]) -> Totals {
    let workspace_unsafe: u64 = units
        .iter()
        .filter(|u| u.kind == UnitKind::Workspace)
        .map(|u| u.unsafe_count)
        .sum();

    let deps_unsafe: u64 = units
        .iter()
        .filter(|u| u.kind == UnitKind::Dep)
        .map(|u| u.unsafe_count)
        .sum();

    Totals {
        workspace_unsafe,
        deps_unsafe,
        overall_unsafe: workspace_unsafe + deps_unsafe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_extract_go_package_workspace_file() {
        let path = Path::new("/home/user/myproject/pkg/utils/helper.go");
        assert_eq!(extract_go_package(path), "utils");
    }

    #[test]
    fn test_extract_go_package_vendor_path() {
        let path = Path::new("/home/user/myproject/vendor/github.com/pkg/errors/errors.go");
        assert_eq!(extract_go_package(path), "github.com/pkg/errors");
    }

    #[test]
    fn test_extract_go_package_vendor_no_subpath() {
        let path = Path::new("/home/user/myproject/vendor/errors/errors.go");
        assert_eq!(extract_go_package(path), "errors");
    }

    #[test]
    fn test_extract_go_package_module_cache() {
        let path = Path::new("/home/user/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go");
        assert_eq!(extract_go_package(path), "github.com/pkg/errors");
    }

    #[test]
    fn test_extract_go_package_fallback() {
        let path = Path::new("/some/random/path/main.go");
        assert_eq!(extract_go_package(path), "path");
    }

    #[test]
    fn test_parse_geiger_output_basic() {
        let output = b"/home/user/project/main.go:10:5: unsafe.Pointer\n\
                       /home/user/project/main.go:20:10: unsafe.Sizeof\n";

        let opts = ScanOpts::default();
        let (units, details) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "project");
        assert_eq!(units[0].unsafe_count, 2);
        assert_eq!(units[0].kind, UnitKind::Workspace);
        assert_eq!(details.len(), 2);
    }

    #[test]
    fn test_parse_geiger_output_vendor_deps() {
        let output =
            b"/home/user/project/vendor/github.com/pkg/errors/errors.go:100:5: unsafe.Pointer\n";

        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, details) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "github.com/pkg/errors");
        assert_eq!(units[0].kind, UnitKind::Dep);
        assert_eq!(details.len(), 1);
    }

    #[test]
    fn test_parse_geiger_output_filters_deps_when_workspace_only() {
        let output = b"/home/user/project/main.go:10:5: unsafe.Pointer\n\
                       /home/user/project/vendor/errors/errors.go:100:5: unsafe.Pointer\n";

        let opts = ScanOpts {
            workspace_only: true,
            ..Default::default()
        };
        let (units, details) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "project");
        assert_eq!(details.len(), 1);
    }

    #[test]
    fn test_parse_geiger_output_filters_deps_when_include_deps_false() {
        let output = b"/home/user/project/main.go:10:5: unsafe.Pointer\n\
                       /home/user/project/vendor/errors/errors.go:100:5: unsafe.Pointer\n";

        let opts = ScanOpts {
            include_deps: false,
            ..Default::default()
        };
        let (units, details) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "project");
        assert_eq!(details.len(), 1);
    }

    #[test]
    fn test_parse_geiger_output_empty() {
        let output = b"";
        let opts = ScanOpts::default();
        let (units, details) = parse_geiger_output(output, &opts).unwrap();

        assert!(units.is_empty());
        assert!(details.is_empty());
    }

    #[test]
    fn test_parse_geiger_output_empty_lines() {
        let output = b"\n\n/home/user/project/main.go:10:5: unsafe.Pointer\n\n";
        let opts = ScanOpts::default();
        let (units, details) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units.len(), 1);
        assert_eq!(details.len(), 1);
    }

    #[test]
    fn test_parse_geiger_output_malformed_lines_skipped() {
        let output = b"invalid line\n\
                       /home/user/project/main.go:10:5: unsafe.Pointer\n\
                       also invalid\n";

        let opts = ScanOpts::default();
        let (units, details) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units.len(), 1);
        assert_eq!(details.len(), 1);
    }

    #[test]
    fn test_parse_geiger_output_sorted() {
        let output = b"/home/user/project/zebra/z.go:1:1: unsafe.Pointer\n\
                       /home/user/project/alpha/a.go:1:1: unsafe.Pointer\n";

        let opts = ScanOpts::default();
        let (units, _) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units[0].name, "alpha");
        assert_eq!(units[1].name, "zebra");
    }

    #[test]
    fn test_compute_totals_empty() {
        let units: Vec<Unit> = vec![];
        let totals = compute_totals(&units);
        assert_eq!(totals.workspace_unsafe, 0);
        assert_eq!(totals.deps_unsafe, 0);
        assert_eq!(totals.overall_unsafe, 0);
    }

    #[test]
    fn test_compute_totals_mixed() {
        let units = vec![
            Unit {
                name: "myproject".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 10,
            },
            Unit {
                name: "vendor/pkg".into(),
                kind: UnitKind::Dep,
                unsafe_count: 50,
            },
        ];
        let totals = compute_totals(&units);
        assert_eq!(totals.workspace_unsafe, 10);
        assert_eq!(totals.deps_unsafe, 50);
        assert_eq!(totals.overall_unsafe, 60);
    }
}
