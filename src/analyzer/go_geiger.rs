use crate::analyzer::process::{self, Run};
use crate::analyzer::Analyzer;
use crate::error::{Error, Result};
use crate::model::{ParseWarning, ScanOpts, ScanResult, Unit, UnitKind};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// deeper than any import chain, so go-geiger lists every package.
const MAX_DEPTH: &str = "1000000";

/// a `go list` template printing the import path of each package in a main module.
const MAIN_MODULE_PACKAGE: &str = "{{with .Module}}{{if .Main}}{{$.ImportPath}}{{end}}{{end}}";

/// the characters go-geiger draws its import tree with.
const TREE: &[char] = &[' ', '│', '├', '└', '─'];

const LEGEND: [&str; 3] = [
    "Packages in green have no unsafe usages",
    "Packages in red contain unsafe usages",
    "Packages in white import packages with unsafe usages",
];

const PACKAGE_TALLIES: [&str; 3] = [
    "of those contain unsafe usages",
    "of those further import packages that contain unsafe usages",
    "of those do not contain any unsafe usages",
];

pub struct GoGeigerAnalyzer;

impl Analyzer for GoGeigerAnalyzer {
    fn id(&self) -> &str {
        "go_geiger"
    }

    fn language(&self) -> &str {
        "go"
    }

    fn run(&self, opts: &ScanOpts) -> Result<ScanResult> {
        let dir = scan_dir(opts);
        let workspace = workspace_packages(dir, opts)?;
        let output = run_go_geiger(dir, opts)?;
        let (units, warnings) = parse_geiger_output(&output, &workspace, opts);

        let mut result =
            ScanResult::from_parts(self.id(), self.language(), opts, units, Vec::new());
        result.parse_warnings = warnings;
        Ok(result)
    }
}

/// the directory holding the manifest, or `None` for the current directory.
fn scan_dir(opts: &ScanOpts) -> Option<&Path> {
    opts.manifest_path
        .as_deref()
        .and_then(Path::parent)
        .filter(|dir| !dir.as_os_str().is_empty())
}

/// the packages go-geiger scans that belong to the main module, or to any module of a go.work workspace.
fn workspace_packages(dir: Option<&Path>, opts: &ScanOpts) -> Result<HashSet<String>> {
    let mut cmd = Command::new("go");
    cmd.args(["list", "-e", "-deps", "-f", MAIN_MODULE_PACKAGE, "./..."]);
    let stdout = run_tool(&mut cmd, dir, "go list", opts)?;
    Ok(String::from_utf8_lossy(&stdout)
        .lines()
        .map(str::trim)
        .filter(|package| !package.is_empty())
        .map(String::from)
        .collect())
}

fn run_go_geiger(dir: Option<&Path>, opts: &ScanOpts) -> Result<Vec<u8>> {
    let mut cmd = Command::new("go-geiger");
    cmd.args(["--max-depth", MAX_DEPTH, "./..."]);
    run_tool(&mut cmd, dir, "go-geiger", opts)
}

fn run_tool(cmd: &mut Command, dir: Option<&Path>, name: &str, opts: &ScanOpts) -> Result<Vec<u8>> {
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }

    let timeout_secs = opts.analyzer_timeout_secs;
    let output = match process::run_process(cmd, timeout_secs.map(Duration::from_secs))? {
        Run::Completed(output) => output,
        Run::TimedOut => {
            return Err(Error::Analyzer {
                analyzer: "go_geiger".into(),
                message: format!(
                    "{name} timed out after {}s",
                    timeout_secs.unwrap_or_default()
                ),
            })
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Analyzer {
            analyzer: "go_geiger".into(),
            message: format!("{name} failed: {stderr}"),
        });
    }

    Ok(output.stdout)
}

/// one unit per package in go-geiger's tables, counted from its LOCAL PACKAGE column.
fn parse_geiger_output(
    output: &[u8],
    workspace: &HashSet<String>,
    opts: &ScanOpts,
) -> (Vec<Unit>, Vec<ParseWarning>) {
    let mut counts = HashMap::new();
    let mut warnings = Vec::new();

    for line in String::from_utf8_lossy(output).lines() {
        let line = strip_sgr(line);
        let line = line.trim();
        if line.is_empty() || is_table_frame(line) || is_summary(line) {
            continue;
        }

        if let Some((package, local)) = table_row(line) {
            counts
                .entry(package.to_string())
                .or_insert((package_kind(package, workspace), local));
        } else if line
            .trim_start_matches(TREE)
            .starts_with("Maximum depth reached.")
        {
            warnings.push(ParseWarning {
                message: "go-geiger: hit its maximum depth; deeper packages may be missing".into(),
            });
        } else {
            warnings.push(ParseWarning {
                message: format!("go-geiger: skipping unexpected output line: {line}"),
            });
        }
    }

    let (units, _) = super::aggregate_units(counts, Vec::new(), opts);
    (units, warnings)
}

/// `line` without SGR escape sequences.
fn strip_sgr(line: &str) -> String {
    let mut plain = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find("\x1b[") {
        plain.push_str(&rest[..start]);
        let sequence = &rest[start + 2..];
        let parameters = sequence.trim_start_matches(|c: char| c.is_ascii_digit() || c == ';');
        rest = match parameters.strip_prefix('m') {
            Some(after) => after,
            None => {
                plain.push_str("\x1b[");
                sequence
            }
        };
    }
    plain.push_str(rest);
    plain
}

/// the header of a table and the rule below it.
fn is_table_frame(line: &str) -> bool {
    line.starts_with("WITH DEPENDENCIES") || line.chars().all(|c| c == '-' || c == '+')
}

/// the summary below each table and the legend after the last.
fn is_summary(line: &str) -> bool {
    LEGEND.contains(&line)
        || line.starts_with("Couting occurances of ")
        || line.contains(" including imports effectively makes up ")
        || line.split_once(' ').is_some_and(|(packages, tally)| {
            packages.parse::<u64>().is_ok() && PACKAGE_TALLIES.contains(&tally)
        })
}

/// the package path and LOCAL PACKAGE count of a table row; a repeated package ends in `...`.
fn table_row(line: &str) -> Option<(&str, u64)> {
    let (with_dependencies, rest) = line.split_once(' ')?;
    with_dependencies.parse::<u64>().ok()?;
    let (local, rest) = rest.trim_start().split_once(' ')?;
    let local = local.parse().ok()?;
    let package = rest.trim_start_matches(TREE);
    let package = package.strip_suffix("...").unwrap_or(package);
    (!package.is_empty() && !package.contains(char::is_whitespace)).then_some((package, local))
}

/// a package `go list` places in a main module is workspace code; any other is a dependency.
fn package_kind(package: &str, workspace: &HashSet<String>) -> UnitKind {
    if workspace.contains(package) {
        UnitKind::Workspace
    } else {
        UnitKind::Dep
    }
}

/// the package directory below the innermost `vendor` directory in `path`
/// (`…/vendor/github.com/pkg/errors/errors.go` → `github.com/pkg/errors`).
pub(crate) fn vendored_package(path: &str) -> Option<String> {
    let after_vendor = match path.rfind("/vendor/") {
        Some(idx) => &path[idx + 8..],
        None => path.strip_prefix("vendor/")?,
    };
    if let Some(end) = after_vendor.rfind('/') {
        return Some(after_vendor[..end].to_string());
    }
    Some(after_vendor.to_string())
}

/// the part of `path` below its first `vendor` directory.
pub(crate) fn below_first_vendor(path: &str) -> Option<&str> {
    path.strip_prefix("vendor/")
        .or_else(|| path.split_once("/vendor/").map(|(_, below)| below))
}

/// the module a file in the go module cache belongs to, without its version
/// (`…/go/pkg/mod/github.com/!burnt!sushi/toml@v1.3.2/decode.go` → `github.com/BurntSushi/toml`).
pub(crate) fn cached_module(path: &str) -> Option<String> {
    let idx = path.find("/go/pkg/mod/")?;
    let after_mod = &path[idx + 12..];
    // format: module@version/path
    let at_idx = after_mod.find('@')?;
    let escaped = &after_mod[..at_idx];
    Some(unescape_module_path(escaped).unwrap_or_else(|| escaped.to_string()))
}

/// `unescapeString` from golang.org/x/mod/module: `!` + a lower-case letter is
/// that letter upper-cased; `None` for an invalid escaped path.
fn unescape_module_path(escaped: &str) -> Option<String> {
    let mut path = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        match c {
            '!' => path.push(
                chars
                    .next()
                    .filter(char::is_ascii_lowercase)?
                    .to_ascii_uppercase(),
            ),
            c if c.is_ascii_uppercase() || !c.is_ascii() => return None,
            c => path.push(c),
        }
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const MULTI_PACKAGE: &[u8] = include_bytes!("../../tests/fixtures/go_geiger/mp.out");
    const X_SYS_UNIX: &[u8] = include_bytes!("../../tests/fixtures/go_geiger/rw.out");
    const DEPTH_CUT: &[u8] = include_bytes!("../../tests/fixtures/go_geiger/deep_root.out");
    const MP_WORKSPACE: &[&str] = &[
        "example.com/mp",
        "example.com/mp/clean",
        "example.com/mp/inner",
    ];

    fn parse(output: &[u8], workspace: &[&str], opts: &ScanOpts) -> (Vec<Unit>, Vec<ParseWarning>) {
        let workspace = workspace.iter().copied().map(String::from).collect();
        parse_geiger_output(output, &workspace, opts)
    }

    fn with_deps() -> ScanOpts {
        ScanOpts {
            include_deps: true,
            ..Default::default()
        }
    }

    fn unit_rows(units: &[Unit]) -> Vec<(&str, UnitKind, u64)> {
        units
            .iter()
            .map(|u| (u.name.as_str(), u.kind, u.unsafe_count))
            .collect()
    }

    #[test]
    fn test_parse_geiger_output_counts_each_package_of_a_real_scan_once() {
        let (units, warnings) = parse(MULTI_PACKAGE, MP_WORKSPACE, &with_deps());
        assert_eq!(
            unit_rows(&units),
            [
                ("example.com/dep", UnitKind::Dep, 4),
                ("example.com/mp", UnitKind::Workspace, 1),
                ("example.com/mp/clean", UnitKind::Workspace, 0),
                ("example.com/mp/inner", UnitKind::Workspace, 2),
            ]
        );
        assert_eq!(warnings, []);
    }

    #[test]
    fn test_parse_geiger_output_reads_a_real_dependency() {
        let (units, warnings) = parse(X_SYS_UNIX, &["example.com/rw"], &with_deps());
        assert_eq!(
            unit_rows(&units),
            [
                ("example.com/rw", UnitKind::Workspace, 0),
                ("golang.org/x/sys/unix", UnitKind::Dep, 570),
            ]
        );
        assert_eq!(warnings, []);
    }

    #[test]
    fn test_parse_geiger_output_counts_a_repeated_package_once_and_warns_at_a_depth_cut() {
        let every_package: HashSet<_> = String::from_utf8_lossy(DEPTH_CUT)
            .lines()
            .filter_map(|line| Some(table_row(strip_sgr(line).trim())?.0.to_string()))
            .collect();
        let (units, warnings) =
            parse_geiger_output(DEPTH_CUT, &every_package, &ScanOpts::default());
        assert_eq!(units.len(), 14);
        assert!(units
            .iter()
            .all(|u| u.kind == UnitKind::Workspace && !u.name.ends_with('.')));
        let unsafe_units: Vec<_> = unit_rows(&units)
            .into_iter()
            .filter(|(_, _, count)| *count > 0)
            .collect();
        assert_eq!(
            unsafe_units,
            [("example.com/deep/shared", UnitKind::Workspace, 2)]
        );
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].message.contains("maximum depth"),
            "{warnings:?}"
        );
    }

    #[test]
    fn test_parse_geiger_output_leaves_out_dependencies_when_workspace_only_or_without_deps() {
        let workspace_only = ScanOpts {
            workspace_only: true,
            include_deps: true,
            ..Default::default()
        };
        for opts in [workspace_only, ScanOpts::default()] {
            let (units, _) = parse(MULTI_PACKAGE, MP_WORKSPACE, &opts);
            let names: Vec<_> = units.iter().map(|u| u.name.as_str()).collect();
            assert_eq!(
                names,
                [
                    "example.com/mp",
                    "example.com/mp/clean",
                    "example.com/mp/inner"
                ]
            );
        }
    }

    #[test]
    fn test_parse_geiger_output_warns_about_unexpected_lines() {
        let output = "unknown flag: --bogus\n\
                      7 1 0 0 0 1 0 example.com/mp\n\
                      found 3 example.com/x\n\
                      3 4 ├─\n\
                      some of those contain unsafe usages\n\
                      Packages in blue are new\n";
        let (units, warnings) = parse(output.as_bytes(), MP_WORKSPACE, &with_deps());
        assert!(units.is_empty(), "{units:?}");
        let messages: Vec<_> = warnings.into_iter().map(|w| w.message).collect();
        let expected: Vec<_> = output
            .lines()
            .map(|line| format!("go-geiger: skipping unexpected output line: {line}"))
            .collect();
        assert_eq!(messages, expected);
    }

    #[test]
    fn test_strip_sgr_keeps_other_escape_sequences() {
        assert_eq!(strip_sgr("\x1b[31m2\x1b[0m \x1b[1;32mok\x1b[m"), "2 ok");
        assert_eq!(strip_sgr("a\x1b[2Kb\x1b["), "a\x1b[2Kb\x1b[");
    }

    #[test]
    fn test_package_kind_is_workspace_in_a_main_module() {
        let workspace = HashSet::from(
            ["example.com/mp", "example.com/mp/inner", "example.com/dep"].map(String::from),
        );
        for (package, kind) in [
            ("example.com/mp", UnitKind::Workspace),
            ("example.com/mp/inner", UnitKind::Workspace),
            ("example.com/dep", UnitKind::Workspace),
            ("example.com/mpx", UnitKind::Dep),
            ("example.com/mp/lib", UnitKind::Dep),
            ("example.com/mp/v2", UnitKind::Dep),
            ("golang.org/x/sys/unix", UnitKind::Dep),
        ] {
            assert_eq!(package_kind(package, &workspace), kind, "{package}");
        }
    }

    #[test]
    fn test_scan_dir_of_a_bare_manifest_is_the_current_directory() {
        let scan_dir_of = |manifest: Option<&str>| {
            let opts = ScanOpts {
                manifest_path: manifest.map(PathBuf::from),
                ..Default::default()
            };
            scan_dir(&opts).map(Path::to_path_buf)
        };
        assert_eq!(scan_dir_of(Some("go.mod")), None);
        assert_eq!(
            scan_dir_of(Some("proj/go.mod")),
            Some(PathBuf::from("proj"))
        );
        assert_eq!(scan_dir_of(None), None);
    }

    #[cfg(unix)]
    #[test]
    fn test_run_tool_fails_on_a_non_zero_exit_that_printed_output() {
        let _guard = crate::analyzer::test_spawn_guard();
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo 'unknown flag: --bogus'; exit 1"]);
        let err = run_tool(&mut cmd, None, "go-geiger", &ScanOpts::default()).unwrap_err();
        assert!(err.to_string().contains("go-geiger failed"), "{err}");
    }

    #[test]
    fn test_vendored_package_is_below_the_innermost_vendor_directory() {
        for (path, package) in [
            (
                "/home/user/myproject/vendor/github.com/pkg/errors/errors.go",
                "github.com/pkg/errors",
            ),
            ("/home/user/myproject/vendor/errors/errors.go", "errors"),
            (
                "/home/user/myproject/vendor/github.com/a/tool/vendor/github.com/b/lib/lib.go",
                "github.com/b/lib",
            ),
            (
                "vendor/github.com/pkg/errors/errors.go",
                "github.com/pkg/errors",
            ),
            (
                "vendor/github.com/a/tool/vendor/github.com/b/lib/lib.go",
                "github.com/b/lib",
            ),
        ] {
            assert_eq!(vendored_package(path), Some(package.into()), "{path}");
        }
    }

    #[test]
    fn test_cached_module() {
        for (path, module) in [
            (
                "/home/user/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go",
                "github.com/pkg/errors",
            ),
            (
                "/srv/vendor/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go",
                "github.com/pkg/errors",
            ),
            (
                "/home/u/go/pkg/mod/github.com/!burnt!sushi/toml@v1.3.2/decode.go",
                "github.com/BurntSushi/toml",
            ),
        ] {
            assert_eq!(cached_module(path), Some(module.into()), "{path}");
        }
    }

    #[test]
    fn test_cached_module_keeps_an_invalid_escaped_path() {
        for module in [
            "github.com/!burnt!sushi/Toml",
            "github.com/!burnt!!sushi/toml",
            "github.com/!burnt!1sushi/toml",
            "github.com/!burnt!ésushi/toml",
            "github.com/!burnt/brûlé",
            "github.com/!burnt/toml!",
        ] {
            let path = format!("/home/u/go/pkg/mod/{module}@v1.3.2/decode.go");
            assert_eq!(cached_module(&path), Some(module.into()), "{module}");
        }
    }
}
