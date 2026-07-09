use crate::analyzer::process::{self, Run};
use crate::analyzer::Analyzer;
use crate::error::{Error, Result};
use crate::model::{Occurrence, ParseWarning, ScanOpts, ScanResult, Unit, UnitKind};
use std::collections::HashMap;
use std::io::BufRead;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

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
        let (units, details, warnings) = parse_geiger_output(&output, opts)?;

        let mut result = ScanResult::from_parts(self.id(), self.language(), opts, units, details);
        result.parse_warnings = warnings;
        Ok(result)
    }
}

fn run_go_geiger(opts: &ScanOpts) -> Result<Vec<u8>> {
    let mut cmd = Command::new("go-geiger");

    // go-geiger takes package patterns as arguments
    // default to ./... for current module
    let dir = opts
        .manifest_path
        .as_ref()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf());

    if let Some(ref d) = dir {
        cmd.current_dir(d);
    }

    cmd.arg("./...");

    let timeout_secs = opts.analyzer_timeout_secs;
    let output = match process::run_process(&mut cmd, timeout_secs.map(Duration::from_secs))? {
        Run::Completed(output) => output,
        Run::TimedOut => {
            return Err(Error::Analyzer {
                analyzer: "go_geiger".into(),
                message: format!(
                    "go-geiger timed out after {}s",
                    timeout_secs.unwrap_or_default()
                ),
            })
        }
    };

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
fn parse_geiger_output(
    output: &[u8],
    opts: &ScanOpts,
) -> Result<(Vec<Unit>, Vec<Occurrence>, Vec<ParseWarning>)> {
    let mut counts: HashMap<String, (UnitKind, u64)> = HashMap::new();
    let mut details = Vec::new();
    let mut warnings = Vec::new();

    for line in output.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        // parse line: "file:line:col: message"
        let parts: Vec<&str> = line.splitn(4, ':').collect();
        if parts.len() < 3 {
            warnings.push(ParseWarning {
                message: format!("go-geiger: skipping malformed output line: {line}"),
            });
            continue;
        }

        let file = PathBuf::from(parts[0]);
        let Ok(line_num) = parts[1].parse::<u32>() else {
            warnings.push(ParseWarning {
                message: format!("go-geiger: skipping line with unparseable line number: {line}"),
            });
            continue;
        };
        let Ok(col) = parts[2].trim().parse::<u32>() else {
            warnings.push(ParseWarning {
                message: format!("go-geiger: skipping line with unparseable column number: {line}"),
            });
            continue;
        };
        let message = parts.get(3).map(|s| s.trim().to_string());

        // determine package name from file path
        // try to extract module/package name from path
        let pkg_name = extract_go_package(&file).unwrap_or_else(|| {
            warnings.push(ParseWarning {
                message: format!(
                    "go-geiger: could not determine package for {}, attributing to \"unknown\"",
                    file.display()
                ),
            });
            "unknown".into()
        });

        // determine if this is a workspace package or dependency
        // dependencies are typically in vendor/ or go module cache
        let is_dep = file.to_string_lossy().contains("/vendor/")
            || file.to_string_lossy().contains("/go/pkg/mod/");

        let kind = if is_dep {
            UnitKind::Dep
        } else {
            UnitKind::Workspace
        };

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

    let (units, details) = super::aggregate_units(counts, details, opts);
    Ok((units, details, warnings))
}

/// extract Go package name from file path.
/// tries to find the package based on common Go project layouts.
///
/// returns `None` when no package name can be determined (e.g. bare
/// filename with no parent directory).
fn extract_go_package(file: &std::path::Path) -> Option<String> {
    let path_str = file.to_string_lossy();

    // check for vendor path
    if let Some(idx) = path_str.find("/vendor/") {
        let after_vendor = &path_str[idx + 8..];
        if let Some(end) = after_vendor.rfind('/') {
            return Some(after_vendor[..end].to_string());
        }
        return Some(after_vendor.to_string());
    }

    // check for go module cache path
    if let Some(idx) = path_str.find("/go/pkg/mod/") {
        let after_mod = &path_str[idx + 12..];
        // format: module@version/path
        if let Some(at_idx) = after_mod.find('@') {
            let module = &after_mod[..at_idx];
            return Some(module.to_string());
        }
    }

    // for workspace files, use the parent directory name or file stem
    file.parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_extract_go_package_workspace_file() {
        let path = Path::new("/home/user/myproject/pkg/utils/helper.go");
        assert_eq!(extract_go_package(path), Some("utils".into()));
    }

    #[test]
    fn test_extract_go_package_vendor_path() {
        let path = Path::new("/home/user/myproject/vendor/github.com/pkg/errors/errors.go");
        assert_eq!(
            extract_go_package(path),
            Some("github.com/pkg/errors".into())
        );
    }

    #[test]
    fn test_extract_go_package_vendor_no_subpath() {
        let path = Path::new("/home/user/myproject/vendor/errors/errors.go");
        assert_eq!(extract_go_package(path), Some("errors".into()));
    }

    #[test]
    fn test_extract_go_package_module_cache() {
        let path = Path::new("/home/user/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go");
        assert_eq!(
            extract_go_package(path),
            Some("github.com/pkg/errors".into())
        );
    }

    #[test]
    fn test_extract_go_package_fallback() {
        let path = Path::new("/some/random/path/main.go");
        assert_eq!(extract_go_package(path), Some("path".into()));
    }

    #[test]
    fn test_extract_go_package_bare_filename_returns_none() {
        let path = Path::new("main.go");
        assert_eq!(extract_go_package(path), None);
    }

    #[test]
    fn test_extract_go_package_root_file_returns_none() {
        let path = Path::new("/main.go");
        assert_eq!(extract_go_package(path), None);
    }

    #[test]
    fn test_parse_geiger_output_basic() {
        let output = b"/home/user/project/main.go:10:5: unsafe.Pointer\n\
                       /home/user/project/main.go:20:10: unsafe.Sizeof\n";

        let opts = ScanOpts::default();
        let (units, details, _) = parse_geiger_output(output, &opts).unwrap();

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
        let (units, details, _) = parse_geiger_output(output, &opts).unwrap();

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
        let (units, details, _) = parse_geiger_output(output, &opts).unwrap();

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
        let (units, details, _) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "project");
        assert_eq!(details.len(), 1);
    }

    #[test]
    fn test_parse_geiger_output_empty() {
        let output = b"";
        let opts = ScanOpts::default();
        let (units, details, _) = parse_geiger_output(output, &opts).unwrap();

        assert!(units.is_empty());
        assert!(details.is_empty());
    }

    #[test]
    fn test_parse_geiger_output_empty_lines() {
        let output = b"\n\n/home/user/project/main.go:10:5: unsafe.Pointer\n\n";
        let opts = ScanOpts::default();
        let (units, details, _) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units.len(), 1);
        assert_eq!(details.len(), 1);
    }

    #[test]
    fn test_parse_geiger_output_malformed_lines_warn() {
        let output = b"invalid line\n\
                       /home/user/project/main.go:10:5: unsafe.Pointer\n\
                       also invalid\n";

        let opts = ScanOpts::default();
        let (units, details, warnings) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units.len(), 1);
        assert_eq!(details.len(), 1);
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].message.contains("malformed output line"));
        assert!(warnings[0].message.contains("invalid line"));
        assert!(warnings[1].message.contains("malformed output line"));
        assert!(warnings[1].message.contains("also invalid"));
    }

    #[test]
    fn test_parse_geiger_output_malformed_line_col_skipped() {
        let output = b"/home/user/project/main.go:abc:5: unsafe.Pointer\n\
                       /home/user/project/main.go:10:xyz: unsafe.Sizeof\n\
                       /home/user/project/main.go:20:3: unsafe.Pointer\n";

        let opts = ScanOpts::default();
        let (units, details, warnings) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(details.len(), 1);
        assert_eq!(details[0].line, 20);
        assert_eq!(details[0].col, 3);
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].unsafe_count, 1);

        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].message.contains("unparseable line number"));
        assert!(warnings[1].message.contains("unparseable column number"));
    }

    #[test]
    fn test_parse_geiger_output_unknown_package_warns() {
        let output = b"/main.go:1:1: unsafe.Pointer\n";

        let opts = ScanOpts::default();
        let (units, details, warnings) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "unknown");
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].unit, "unknown");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("could not determine package"));
        assert!(warnings[0].message.contains("/main.go"));
    }

    #[test]
    fn test_parse_geiger_output_sorted() {
        let output = b"/home/user/project/zebra/z.go:1:1: unsafe.Pointer\n\
                       /home/user/project/alpha/a.go:1:1: unsafe.Pointer\n";

        let opts = ScanOpts::default();
        let (units, _, _) = parse_geiger_output(output, &opts).unwrap();

        assert_eq!(units[0].name, "alpha");
        assert_eq!(units[1].name, "zebra");
    }
}
