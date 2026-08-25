//! SARIF file analyzer.
//!
//! reads a SARIF 2.1.0 file and converts its results into the normalized
//! ScanResult format. this allows unsafe-budget to apply budget logic
//! to output from any SARIF-producing static analysis tool.

use crate::analyzer::Analyzer;
use crate::error::{Error, Result};
use crate::model::{Occurrence, ParseWarning, ScanOpts, ScanResult, Unit, UnitKind};
use crate::sarif::{
    PROP_LANGUAGE, PROP_NAMESPACE, PROP_UNITS, RULE_PARSE_WARNING, RULE_UNSAFE_CODE,
    UNIT_LOGICAL_KIND,
};
use serde_sarif::sarif::{self, Sarif};
use std::collections::HashMap;
use std::path::PathBuf;

pub struct SarifAnalyzer;

impl Analyzer for SarifAnalyzer {
    fn id(&self) -> &str {
        "sarif"
    }

    fn language(&self) -> &str {
        "unknown"
    }

    fn run(&self, opts: &ScanOpts) -> Result<ScanResult> {
        let path = opts.manifest_path.as_ref().ok_or_else(|| Error::Analyzer {
            analyzer: "sarif".into(),
            message: "sarif analyzer requires --manifest-path pointing to a .sarif file".into(),
        })?;

        let content = std::fs::read_to_string(path)?;
        let sarif: Sarif = serde_json::from_str(&content)?;

        convert_sarif(&sarif, opts)
    }
}

fn convert_sarif(sarif: &Sarif, opts: &ScanOpts) -> Result<ScanResult> {
    if sarif.runs.is_empty() {
        return Err(Error::Analyzer {
            analyzer: "sarif".into(),
            message: "SARIF file contains no runs".into(),
        });
    }

    // language is resolved per run. runs from unrecognized tools contribute no
    // signal; if the recognized runs disagree (e.g. a Rust tool and a Go tool)
    // the language is ambiguous, so report "unknown".
    let language = sarif
        .runs
        .iter()
        .map(run_language)
        .filter(|lang| lang != "unknown")
        .reduce(|acc, lang| if acc == lang { acc } else { "unknown".into() })
        .unwrap_or_else(|| "unknown".into());

    // collect occurrences from *every* run: a SARIF 2.1.0 file may legitimately
    // contain multiple runs (one per tool invocation or analysis target), so
    // processing only runs[0] would silently under-count unsafe code.
    let mut occurrences: Vec<Occurrence> = Vec::new();
    let mut parse_warnings: Vec<ParseWarning> = Vec::new();
    let mut counts: HashMap<String, (UnitKind, u64)> = HashMap::new();

    for run in &sarif.runs {
        let own_run = is_own_run(run);
        let recorded = own_run.then(|| recorded_units(run)).flatten();
        let results = run.results.as_deref().unwrap_or(&[]);
        let mut run_occurrences: Vec<Occurrence> = Vec::new();

        for result in results {
            let message = result
                .message
                .text
                .clone()
                .unwrap_or_else(|| "unknown".into());

            if own_run && result.rule_id.as_deref() != Some(RULE_UNSAFE_CODE) {
                if result.rule_id.as_deref() == Some(RULE_PARSE_WARNING) {
                    parse_warnings.push(ParseWarning { message });
                }
                continue;
            }

            let locations = result.locations.as_deref().unwrap_or(&[]);
            if locations.is_empty() {
                continue;
            }

            for location in locations {
                let phys = match &location.physical_location {
                    Some(pl) => pl,
                    None => continue,
                };

                let file = phys
                    .artifact_location
                    .as_ref()
                    .and_then(|al| al.uri.clone())
                    .unwrap_or_else(|| "unknown".into());

                let line = phys.region.as_ref().and_then(|r| r.start_line).unwrap_or(0) as u32;

                let col = phys
                    .region
                    .as_ref()
                    .and_then(|r| r.start_column)
                    .unwrap_or(0) as u32;

                let unit_name = own_run
                    .then(|| logical_unit_name(location))
                    .flatten()
                    .unwrap_or_else(|| extract_unit_name(&file));

                run_occurrences.push(Occurrence {
                    unit: unit_name,
                    file: PathBuf::from(&file),
                    line,
                    col,
                    message: Some(message.clone()),
                });
            }
        }

        match recorded {
            Some(units) => accumulate_recorded(&mut counts, units),
            None => accumulate_derived(&mut counts, &run_occurrences),
        }
        occurrences.append(&mut run_occurrences);
    }

    let (units, details) = super::aggregate_units(counts, occurrences, opts);

    let mut scan = ScanResult::from_parts("sarif", language, opts, units, details);
    scan.parse_warnings = parse_warnings;
    Ok(scan)
}

/// fold a run's recorded units into the running per-unit counts; a recorded
/// kind overrides one another run derived from a file path.
fn accumulate_recorded(counts: &mut HashMap<String, (UnitKind, u64)>, units: Vec<Unit>) {
    for unit in units {
        let entry = counts.entry(unit.name).or_insert((unit.kind, 0));
        entry.0 = unit.kind;
        entry.1 += unit.unsafe_count;
    }
}

fn accumulate_derived(counts: &mut HashMap<String, (UnitKind, u64)>, occurrences: &[Occurrence]) {
    for occ in occurrences {
        let kind = super::classify_unit_kind(&occ.file);
        let entry = counts.entry(occ.unit.clone()).or_insert((kind, 0));
        entry.1 += 1;
    }
}

/// check whether `word` appears in `haystack` at a left word boundary:
/// either at the start of the string or immediately after a non-alphanumeric
/// character. This prevents substring false positives such as "cargo" or
/// "django" matching "go".
fn has_leading_word(haystack: &str, word: &str) -> bool {
    let mut start = 0;
    while start + word.len() <= haystack.len() {
        match haystack[start..].find(word) {
            Some(pos) => {
                let abs = start + pos;
                if abs == 0 || !haystack.as_bytes()[abs - 1].is_ascii_alphanumeric() {
                    return true;
                }
                start = abs + 1;
            }
            None => break,
        }
    }
    false
}

fn property_language(run: &sarif::Run) -> Option<String> {
    run.properties
        .as_ref()?
        .additional_properties
        .get(PROP_NAMESPACE)?
        .get(PROP_LANGUAGE)?
        .as_str()
        .map(str::to_string)
}

/// the recorded language if it is meaningful, else the driver-name heuristic.
fn run_language(run: &sarif::Run) -> String {
    property_language(run)
        .filter(|lang| lang != "unknown")
        .unwrap_or_else(|| infer_language(&run.tool.driver.name))
}

/// whether a run was written by unsafe-budget.
fn is_own_run(run: &sarif::Run) -> bool {
    run.properties
        .as_ref()
        .is_some_and(|props| props.additional_properties.contains_key(PROP_NAMESPACE))
}

/// the unit list a run records, valid only for runs [`is_own_run`] accepts.
///
/// `None` when the run records none, leaving the caller to derive units from
/// its occurrences.
fn recorded_units(run: &sarif::Run) -> Option<Vec<Unit>> {
    let value = run
        .properties
        .as_ref()?
        .additional_properties
        .get(PROP_NAMESPACE)?
        .get(PROP_UNITS)?;
    serde_json::from_value(value.clone()).ok()
}

/// the unit a location names, valid only for runs [`is_own_run`] accepts.
fn logical_unit_name(location: &sarif::Location) -> Option<String> {
    location
        .logical_locations
        .as_ref()?
        .iter()
        .find(|loc| loc.kind.as_deref() == Some(UNIT_LOGICAL_KIND))
        .and_then(|loc| loc.fully_qualified_name.clone())
        .filter(|name| !name.is_empty())
}

/// infer language from the SARIF tool driver name.
fn infer_language(tool_name: &str) -> String {
    let lower = tool_name.to_lowercase();
    if lower.contains("rust") || lower.contains("cargo") || lower.contains("clippy") {
        "rust".into()
    } else if has_leading_word(&lower, "go") {
        "go".into()
    } else if lower.contains("gcc") || lower.contains("clang") {
        "c".into()
    } else {
        "unknown".into()
    }
}

/// extract a unit name from an artifact URI.
///
/// looks for a `src` path component and uses the directory immediately
/// before it as the crate/package name (`crate_name/src/lib.rs` →
/// `crate_name`). falls back to the first directory component when no
/// `src` segment is found, or `"unknown"` for bare filenames.
fn extract_unit_name(uri: &str) -> String {
    let path_str = uri.strip_prefix("file://").unwrap_or(uri);
    let path = std::path::Path::new(path_str);

    let components: Vec<_> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();

    // need at least a directory and a filename.
    if components.len() < 2 {
        return "unknown".into();
    }

    let dirs = &components[..components.len() - 1];

    // if a "src" directory appears after at least one other component,
    // the component before it is the crate/package name.
    for (i, dir) in dirs.iter().enumerate() {
        if dir == "src" && i > 0 {
            return dirs[i - 1].clone();
        }
    }

    // no "src" found, or "src" is the first component: use the first
    // directory as the unit name.
    dirs[0].clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_sarif::sarif;

    #[test]
    fn test_infer_language_rust() {
        assert_eq!(infer_language("cargo-clippy"), "rust");
        assert_eq!(infer_language("rustc"), "rust");
        assert_eq!(infer_language("Rust Analyzer"), "rust");
    }

    #[test]
    fn test_infer_language_go() {
        assert_eq!(infer_language("go-geiger"), "go");
        assert_eq!(infer_language("GoSec"), "go");
    }

    #[test]
    fn test_infer_language_c() {
        assert_eq!(infer_language("clang-tidy"), "c");
        assert_eq!(infer_language("GCC"), "c");
    }

    #[test]
    fn test_infer_language_go_not_substring() {
        // tool names containing "go" as a substring must not match.
        assert_eq!(infer_language("django"), "unknown");
        assert_eq!(infer_language("errgo"), "unknown");
        assert_eq!(infer_language("mango-lint"), "unknown");
    }

    #[test]
    fn test_infer_language_go_after_separator() {
        assert_eq!(infer_language("my-go-linter"), "go");
    }

    #[test]
    fn test_infer_language_unknown() {
        assert_eq!(infer_language("custom-tool"), "unknown");
        assert_eq!(infer_language("myanalyzer"), "unknown");
    }

    #[test]
    fn test_extract_unit_name_simple() {
        assert_eq!(extract_unit_name("src/lib.rs"), "src");
    }

    #[test]
    fn test_extract_unit_name_nested() {
        assert_eq!(extract_unit_name("my_crate/src/lib.rs"), "my_crate");
    }

    #[test]
    fn test_extract_unit_name_nested_deep() {
        assert_eq!(extract_unit_name("my_crate/src/foo/bar.rs"), "my_crate");
    }

    #[test]
    fn test_extract_unit_name_file_uri() {
        assert_eq!(
            extract_unit_name("file://project/my_crate/src/lib.rs"),
            "my_crate"
        );
    }

    #[test]
    fn test_extract_unit_name_root_file() {
        assert_eq!(extract_unit_name("lib.rs"), "unknown");
    }

    #[test]
    fn test_extract_unit_name_no_src() {
        assert_eq!(extract_unit_name("crate_a/lib.rs"), "crate_a");
    }

    fn make_sarif(results: Vec<sarif::Result>) -> Sarif {
        make_multi_run_sarif(vec![make_run("test-tool", results)])
    }

    fn make_run(driver_name: &str, results: Vec<sarif::Result>) -> sarif::Run {
        let driver = sarif::ToolComponent::builder().name(driver_name).build();
        let tool = sarif::Tool::builder().driver(driver).build();
        sarif::Run::builder().tool(tool).results(results).build()
    }

    fn make_multi_run_sarif(runs: Vec<sarif::Run>) -> Sarif {
        sarif::Sarif::builder()
            .version(serde_json::json!("2.1.0"))
            .runs(runs)
            .build()
    }

    fn make_sarif_result(file: &str, line: i64, col: i64, msg: &str) -> sarif::Result {
        sarif::Result::builder()
            .message(sarif::Message::builder().text(msg.to_string()).build())
            .locations(vec![sarif::Location::builder()
                .physical_location(
                    sarif::PhysicalLocation::builder()
                        .artifact_location(
                            sarif::ArtifactLocation::builder()
                                .uri(file.to_string())
                                .build(),
                        )
                        .region(
                            sarif::Region::builder()
                                .start_line(line)
                                .start_column(col)
                                .build(),
                        )
                        .build(),
                )
                .build()])
            .build()
    }

    #[test]
    fn test_convert_sarif_basic() {
        let sarif_log = make_sarif(vec![
            make_sarif_result("src/lib.rs", 10, 5, "unsafe pointer"),
            make_sarif_result("src/lib.rs", 20, 1, "unsafe block"),
        ]);

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();

        assert_eq!(result.analyzer_id, "sarif");
        assert_eq!(result.language, "unknown");
        assert_eq!(result.units.len(), 1);
        assert_eq!(result.units[0].name, "src");
        assert_eq!(result.units[0].unsafe_count, 2);
        assert_eq!(result.totals.workspace_unsafe, 2);
        assert_eq!(result.totals.overall_unsafe, 2);
        assert_eq!(result.details.len(), 2);
    }

    #[test]
    fn test_convert_sarif_empty_results() {
        let sarif_log = make_sarif(vec![]);
        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();

        assert!(result.units.is_empty());
        assert!(result.details.is_empty());
        assert_eq!(result.totals.overall_unsafe, 0);
    }

    #[test]
    fn test_convert_sarif_no_runs() {
        let sarif_log = sarif::Sarif::builder()
            .version(serde_json::json!("2.1.0"))
            .build();

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_sarif_missing_locations() {
        // result without locations should be skipped
        let result_no_loc = sarif::Result::builder()
            .message(
                sarif::Message::builder()
                    .text("no location".to_string())
                    .build(),
            )
            .build();

        let sarif_log = make_sarif(vec![
            result_no_loc,
            make_sarif_result("src/lib.rs", 10, 5, "has location"),
        ]);

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();

        // only the result with a location should be counted
        assert_eq!(result.details.len(), 1);
        assert_eq!(result.units[0].unsafe_count, 1);
    }

    #[test]
    fn test_convert_sarif_deterministic_order() {
        let sarif_log = make_sarif(vec![
            make_sarif_result("src/z.rs", 30, 1, "third"),
            make_sarif_result("src/a.rs", 10, 1, "first"),
            make_sarif_result("src/a.rs", 5, 1, "zeroth"),
        ]);

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();

        let files: Vec<_> = result
            .details
            .iter()
            .map(|d| d.file.to_string_lossy().to_string())
            .collect();
        let lines: Vec<_> = result.details.iter().map(|d| d.line).collect();
        assert_eq!(files, vec!["src/a.rs", "src/a.rs", "src/z.rs"]);
        assert_eq!(lines, vec![5, 10, 30]);
    }

    #[test]
    fn test_sarif_analyzer_requires_manifest_path() {
        let analyzer = SarifAnalyzer;
        let opts = ScanOpts::default(); // no manifest_path
        let result = analyzer.run(&opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_sarif_language_inference() {
        let driver = sarif::ToolComponent::builder().name("cargo-clippy").build();
        let tool = sarif::Tool::builder().driver(driver).build();
        let run = sarif::Run::builder().tool(tool).results(vec![]).build();
        let sarif_log = sarif::Sarif::builder()
            .version(serde_json::json!("2.1.0"))
            .runs(vec![run])
            .build();

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();
        assert_eq!(result.language, "rust");
    }

    #[test]
    fn test_convert_sarif_multiple_units() {
        let sarif_log = make_sarif(vec![
            make_sarif_result("crate_a/lib.rs", 10, 1, "in crate_a"),
            make_sarif_result("crate_b/main.rs", 5, 1, "in crate_b"),
            make_sarif_result("crate_a/lib.rs", 20, 1, "also in crate_a"),
        ]);

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();

        assert_eq!(result.units.len(), 2);
        // sorted alphabetically
        assert_eq!(result.units[0].name, "crate_a");
        assert_eq!(result.units[0].unsafe_count, 2);
        assert_eq!(result.units[1].name, "crate_b");
        assert_eq!(result.units[1].unsafe_count, 1);
    }

    #[test]
    fn test_convert_sarif_workspace_src_paths() {
        let sarif_log = make_sarif(vec![
            make_sarif_result("crate_a/src/lib.rs", 10, 1, "in crate_a"),
            make_sarif_result("crate_b/src/lib.rs", 5, 1, "in crate_b"),
            make_sarif_result("crate_a/src/util.rs", 20, 1, "also in crate_a"),
        ]);

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();

        assert_eq!(result.units.len(), 2);
        assert_eq!(result.units[0].name, "crate_a");
        assert_eq!(result.units[0].unsafe_count, 2);
        assert_eq!(result.units[1].name, "crate_b");
        assert_eq!(result.units[1].unsafe_count, 1);
    }

    #[test]
    fn test_convert_sarif_workspace_only_filters_deps() {
        // one workspace occurrence and one dependency-cache occurrence.
        let sarif_log = make_sarif(vec![
            make_sarif_result("crate_a/src/lib.rs", 10, 1, "workspace unsafe"),
            make_sarif_result(
                "/home/user/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go",
                5,
                1,
                "dependency unsafe",
            ),
        ]);

        let opts = ScanOpts {
            workspace_only: true,
            include_deps: true,
            ..Default::default()
        };
        let result = convert_sarif(&sarif_log, &opts).unwrap();

        // the dependency unit is filtered out; only the workspace crate remains.
        assert_eq!(result.units.len(), 1);
        assert_eq!(result.units[0].name, "crate_a");
        assert_eq!(result.units[0].kind, UnitKind::Workspace);
        assert_eq!(result.totals.deps_unsafe, 0);
        // the filtered dependency's detail occurrence is dropped too.
        assert_eq!(result.details.len(), 1);
    }

    #[test]
    fn test_convert_sarif_reports_dependency_unsafe() {
        // occurrences under a cargo registry path and a go module cache path
        // are both classified as dependencies and counted toward deps_unsafe.
        let sarif_log = make_sarif(vec![
            make_sarif_result("my_crate/src/lib.rs", 1, 1, "workspace"),
            make_sarif_result(
                "/home/user/.cargo/registry/src/index.crates.io-abc/libc-0.2.0/src/lib.rs",
                2,
                1,
                "registry dep",
            ),
            make_sarif_result(
                "/home/user/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go",
                3,
                1,
                "module cache dep",
            ),
        ]);

        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let result = convert_sarif(&sarif_log, &opts).unwrap();

        assert_eq!(result.totals.workspace_unsafe, 1);
        assert_eq!(result.totals.deps_unsafe, 2);
        assert_eq!(result.totals.overall_unsafe, 3);
        assert!(result.units.iter().any(|u| u.kind == UnitKind::Dep));
    }

    #[test]
    fn test_convert_sarif_multiple_runs() {
        // two runs, each reporting occurrences in a different crate. every run
        // must be counted, not just the first.
        let run1 = make_run(
            "test-tool",
            vec![
                make_sarif_result("crate_a/src/lib.rs", 10, 1, "in crate_a"),
                make_sarif_result("crate_a/src/util.rs", 20, 1, "also in crate_a"),
            ],
        );
        let run2 = make_run(
            "test-tool",
            vec![make_sarif_result("crate_b/src/lib.rs", 5, 1, "in crate_b")],
        );
        let sarif_log = make_multi_run_sarif(vec![run1, run2]);

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();

        assert_eq!(result.units.len(), 2);
        assert_eq!(result.units[0].name, "crate_a");
        assert_eq!(result.units[0].unsafe_count, 2);
        assert_eq!(result.units[1].name, "crate_b");
        assert_eq!(result.units[1].unsafe_count, 1);
        // all three occurrences across both runs are aggregated.
        assert_eq!(result.totals.overall_unsafe, 3);
        assert_eq!(result.details.len(), 3);
    }

    #[test]
    fn test_convert_sarif_multiple_runs_same_unit() {
        // both runs report occurrences in the same crate; the counts must sum.
        let run1 = make_run(
            "test-tool",
            vec![make_sarif_result("crate_a/src/lib.rs", 10, 1, "first")],
        );
        let run2 = make_run(
            "test-tool",
            vec![
                make_sarif_result("crate_a/src/lib.rs", 20, 1, "second"),
                make_sarif_result("crate_a/src/util.rs", 30, 1, "third"),
            ],
        );
        let sarif_log = make_multi_run_sarif(vec![run1, run2]);

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();

        assert_eq!(result.units.len(), 1);
        assert_eq!(result.units[0].name, "crate_a");
        // 1 from run1 + 2 from run2, summed into the single unit.
        assert_eq!(result.units[0].unsafe_count, 3);
        assert_eq!(result.totals.overall_unsafe, 3);
        assert_eq!(result.details.len(), 3);
    }

    #[test]
    fn test_convert_sarif_language_agreeing_runs() {
        // multiple runs from Rust tools keep the Rust language.
        let run1 = make_run(
            "cargo-clippy",
            vec![make_sarif_result("crate_a/src/lib.rs", 10, 1, "a")],
        );
        let run2 = make_run(
            "rustc",
            vec![make_sarif_result("crate_b/src/lib.rs", 5, 1, "b")],
        );
        let sarif_log = make_multi_run_sarif(vec![run1, run2]);

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();
        assert_eq!(result.language, "rust");
    }

    fn property_bag(language: &str) -> sarif::PropertyBag {
        let mut fields = serde_json::Map::new();
        fields.insert(
            PROP_LANGUAGE.to_string(),
            serde_json::Value::String(language.into()),
        );
        let mut props = std::collections::BTreeMap::new();
        props.insert(
            PROP_NAMESPACE.to_string(),
            serde_json::Value::Object(fields),
        );
        sarif::PropertyBag::builder()
            .additional_properties(props)
            .build()
    }

    #[test]
    fn test_roundtrip_preserves_unit_and_language() {
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let details = vec![
            Occurrence {
                unit: "libc".into(),
                file: PathBuf::from(
                    "/home/u/.cargo/registry/src/index.crates.io-abc/libc-0.2.0/src/lib.rs",
                ),
                line: 7,
                col: 1,
                message: Some("unsafe".into()),
            },
            Occurrence {
                unit: "my_crate".into(),
                file: PathBuf::from("/home/u/.cargo/git/checkouts/my_crate-abc/9f8e7d6/src/lib.rs"),
                line: 9,
                col: 1,
                message: Some("unsafe".into()),
            },
        ];
        let units = vec![
            Unit {
                name: "libc".into(),
                kind: UnitKind::Dep,
                unsafe_count: 1,
            },
            Unit {
                name: "my_crate".into(),
                kind: UnitKind::Dep,
                unsafe_count: 1,
            },
        ];
        let scan = ScanResult::from_parts("rustc_unsafe_lint", "rust", &opts, units, details);

        let json = serde_json::to_string(&crate::sarif::scan_to_sarif(&scan)).unwrap();
        let reparsed: Sarif = serde_json::from_str(&json).unwrap();
        let back = convert_sarif(&reparsed, &opts).unwrap();

        assert_eq!(back.language, "rust");

        let names: Vec<_> = back.units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, vec!["libc", "my_crate"]);
        assert!(!names.contains(&"registry"));
        assert!(!names.contains(&"9f8e7d6"));

        assert_eq!(back.details.len(), 2);
        assert_eq!(back.details[0].unit, "libc");
        assert_eq!(back.details[1].unit, "my_crate");
        assert!(back.units.iter().all(|u| u.kind == UnitKind::Dep));
        assert_eq!(back.totals.deps_unsafe, 2);
    }

    #[test]
    fn test_third_party_sarif_ingest_is_unchanged() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.sarif");
        let opts = ScanOpts {
            manifest_path: Some(path),
            ..Default::default()
        };
        let result = SarifAnalyzer.run(&opts).unwrap();

        assert_eq!(result.language, "rust");
        assert_eq!(result.units.len(), 1);
        assert_eq!(result.units[0].name, "src");
        assert_eq!(result.units[0].unsafe_count, 3);

        let located: Vec<_> = result
            .details
            .iter()
            .map(|d| {
                (
                    d.unit.as_str(),
                    d.file.to_string_lossy().to_string(),
                    d.line,
                )
            })
            .collect();
        assert_eq!(
            located,
            vec![
                ("src", "src/ffi.rs".to_string(), 42),
                ("src", "src/lib.rs".to_string(), 10),
                ("src", "src/lib.rs".to_string(), 25),
            ]
        );
    }

    fn own_sarif_result(file: &str, line: i64, col: i64, msg: &str) -> sarif::Result {
        let mut result = make_sarif_result(file, line, col, msg);
        result.rule_id = Some(RULE_UNSAFE_CODE.to_string());
        result
    }

    fn logical_location(kind: &str, name: &str) -> sarif::LogicalLocation {
        sarif::LogicalLocation::builder()
            .fully_qualified_name(name.to_string())
            .kind(kind.to_string())
            .build()
    }

    #[test]
    fn test_non_module_logical_location_is_ignored() {
        let mut result = make_sarif_result("crate_a/src/lib.rs", 10, 1, "unsafe");
        result.locations.as_mut().unwrap()[0].logical_locations =
            Some(vec![logical_location("function", "crate_a::foo::do_thing")]);

        let opts = ScanOpts::default();
        let converted = convert_sarif(&make_sarif(vec![result]), &opts).unwrap();

        assert_eq!(converted.units.len(), 1);
        assert_eq!(converted.units[0].name, "crate_a");
    }

    #[test]
    fn test_third_party_module_logical_location_is_ignored() {
        let mut a = make_sarif_result("mypkg/src/a.c", 10, 1, "unsafe");
        a.locations.as_mut().unwrap()[0].logical_locations = Some(vec![logical_location(
            UNIT_LOGICAL_KIND,
            "com.example.SomeModule",
        )]);
        let mut b = make_sarif_result("mypkg/src/b.c", 20, 1, "unsafe");
        b.locations.as_mut().unwrap()[0].logical_locations = Some(vec![logical_location(
            UNIT_LOGICAL_KIND,
            "com.example.OtherModule",
        )]);

        let opts = ScanOpts::default();
        let sarif_log = make_multi_run_sarif(vec![make_run("CodeQL", vec![a, b])]);
        let converted = convert_sarif(&sarif_log, &opts).unwrap();

        let names: Vec<_> = converted.units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, vec!["mypkg"]);
    }

    #[test]
    fn test_mixed_run_log_resolves_units_per_run() {
        let mut theirs = make_sarif_result("theirpkg/src/a.c", 10, 1, "unsafe");
        theirs.locations.as_mut().unwrap()[0].logical_locations = Some(vec![logical_location(
            UNIT_LOGICAL_KIND,
            "com.example.TheirModule",
        )]);
        let mut ours = own_sarif_result("ourpkg/src/b.rs", 20, 1, "unsafe");
        ours.locations.as_mut().unwrap()[0].logical_locations =
            Some(vec![logical_location(UNIT_LOGICAL_KIND, "libc")]);
        let mut own_run = make_run("unsafe-budget", vec![ours]);
        own_run.properties = Some(property_bag("rust"));

        let opts = ScanOpts::default();
        let sarif_log = make_multi_run_sarif(vec![make_run("CodeQL", vec![theirs]), own_run]);
        let converted = convert_sarif(&sarif_log, &opts).unwrap();

        let names: Vec<_> = converted.units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, vec!["libc", "theirpkg"]);
    }

    #[test]
    fn test_own_run_still_requires_the_module_kind() {
        let mut result = own_sarif_result("crate_a/src/lib.rs", 10, 1, "unsafe");
        result.locations.as_mut().unwrap()[0].logical_locations =
            Some(vec![logical_location("function", "crate_a::foo::do_thing")]);
        let mut run = make_run("unsafe-budget", vec![result]);
        run.properties = Some(property_bag("rust"));

        let opts = ScanOpts::default();
        let converted = convert_sarif(&make_multi_run_sarif(vec![run]), &opts).unwrap();

        assert_eq!(converted.units.len(), 1);
        assert_eq!(converted.units[0].name, "crate_a");
    }

    #[test]
    fn test_run_property_language_beats_unrecognized_driver() {
        let mut run = make_run("unsafe-budget", vec![]);
        run.properties = Some(property_bag("go"));

        let opts = ScanOpts::default();
        let result = convert_sarif(&make_multi_run_sarif(vec![run]), &opts).unwrap();
        assert_eq!(result.language, "go");
    }

    #[test]
    fn test_run_property_language_unknown_falls_back_to_driver() {
        let mut run = make_run("cargo-clippy", vec![]);
        run.properties = Some(property_bag("unknown"));

        let opts = ScanOpts::default();
        let result = convert_sarif(&make_multi_run_sarif(vec![run]), &opts).unwrap();
        assert_eq!(result.language, "rust");
    }

    #[test]
    fn test_convert_sarif_language_conflicting_runs() {
        // runs from tools targeting different languages are ambiguous -> unknown.
        let run1 = make_run(
            "cargo-clippy",
            vec![make_sarif_result("crate_a/src/lib.rs", 10, 1, "rusty")],
        );
        let run2 = make_run(
            "go-geiger",
            vec![make_sarif_result("pkg/main.go", 5, 1, "gopher")],
        );
        let sarif_log = make_multi_run_sarif(vec![run1, run2]);

        let opts = ScanOpts::default();
        let result = convert_sarif(&sarif_log, &opts).unwrap();
        assert_eq!(result.language, "unknown");
        // both runs' occurrences are still counted despite the language conflict.
        assert_eq!(result.totals.overall_unsafe, 2);
    }

    fn round_trip_opts() -> ScanOpts {
        ScanOpts {
            include_deps: true,
            ..Default::default()
        }
    }

    fn round_trip_fixture() -> ScanResult {
        let units = vec![
            Unit {
                name: "app".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 3,
            },
            Unit {
                name: "helper".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 0,
            },
            Unit {
                name: "libc".into(),
                kind: UnitKind::Dep,
                unsafe_count: 2,
            },
            Unit {
                name: "shared".into(),
                kind: UnitKind::Dep,
                unsafe_count: 1,
            },
        ];
        let details = vec![
            Occurrence {
                unit: "app".into(),
                file: PathBuf::from("app/src/ffi.rs"),
                line: 7,
                col: 1,
                message: Some("extern call".into()),
            },
            Occurrence {
                unit: "app".into(),
                file: PathBuf::from("app/src/lib.rs"),
                line: 10,
                col: 5,
                message: Some("unsafe block".into()),
            },
            Occurrence {
                unit: "app".into(),
                file: PathBuf::from("app/src/lib.rs"),
                line: 42,
                col: 9,
                message: None,
            },
            Occurrence {
                unit: "libc".into(),
                file: PathBuf::from(
                    "/home/u/.cargo/registry/src/index.crates.io-abc/libc-0.2.0/src/lib.rs",
                ),
                line: 3,
                col: 1,
                message: Some("raw pointer deref".into()),
            },
            Occurrence {
                unit: "libc".into(),
                file: PathBuf::from(
                    "/home/u/.cargo/registry/src/index.crates.io-abc/libc-0.2.0/src/unix.rs",
                ),
                line: 88,
                col: 2,
                message: Some("extern block".into()),
            },
            Occurrence {
                unit: "shared".into(),
                file: PathBuf::from("../shared/src/lib.rs"),
                line: 12,
                col: 3,
                message: Some("union access".into()),
            },
        ];
        let mut scan = ScanResult::from_parts(
            "rustc_unsafe_lint",
            "rust",
            &round_trip_opts(),
            units,
            details,
        );
        scan.parse_warnings = vec![
            crate::model::ParseWarning {
                message: "malformed output line 3: 'garbage'".into(),
            },
            crate::model::ParseWarning {
                message: "could not determine package for /tmp/x.go".into(),
            },
        ];
        scan
    }

    fn reread(sarif: &Sarif, opts: &ScanOpts) -> ScanResult {
        let json = serde_json::to_string(sarif).unwrap();
        let reparsed: Sarif = serde_json::from_str(&json).unwrap();
        convert_sarif(&reparsed, opts).unwrap()
    }

    /// the round-trip invariant: everything the format can carry survives.
    ///
    /// `tool_version`, `analyzer_id` and `scope` deliberately do not — they
    /// describe the invocation doing the reading. an occurrence with no message
    /// comes back carrying the writer's placeholder text, and parse warnings
    /// come back as a set, since results are sorted for deterministic output.
    #[test]
    fn test_own_sarif_round_trip_preserves_the_scan() {
        let scan = round_trip_fixture();
        let opts = round_trip_opts();
        let back = reread(&crate::sarif::scan_to_sarif(&scan), &opts);

        let mut expected = scan.clone();
        for occ in &mut expected.details {
            occ.message
                .get_or_insert_with(|| "unsafe code usage".into());
        }
        expected
            .parse_warnings
            .sort_by(|a, b| a.message.cmp(&b.message));
        let mut got = back.clone();
        got.parse_warnings.sort_by(|a, b| a.message.cmp(&b.message));

        assert_eq!(got.language, expected.language, "language");
        assert_eq!(got.units, expected.units, "units");
        assert_eq!(got.totals, expected.totals, "totals");
        assert_eq!(got.details, expected.details, "details");
        assert_eq!(
            got.parse_warnings, expected.parse_warnings,
            "parse warnings"
        );
    }

    #[test]
    fn test_own_check_sarif_round_trip_ignores_budget_results() {
        use crate::model::{CheckResult, Violation, Warning};
        let scan = round_trip_fixture();
        let check = CheckResult {
            violations: vec![Violation {
                unit: "app".into(),
                kind: UnitKind::Workspace,
                baseline: 1,
                actual: 3,
                delta: 2,
            }],
            warnings: vec![Warning {
                unit: "libc".into(),
                kind: UnitKind::Dep,
                budget: 2,
                actual: 2,
            }],
            passed: false,
            scan: scan.clone(),
        };
        let opts = round_trip_opts();
        let back = reread(&crate::sarif::check_to_sarif(&check), &opts);

        assert_eq!(back.totals, scan.totals, "totals");
        assert_eq!(back.units, scan.units, "units");
        assert_eq!(back.details.len(), scan.details.len(), "details");
        assert_eq!(
            back.parse_warnings.len(),
            scan.parse_warnings.len(),
            "parse warnings"
        );
    }

    #[test]
    fn test_round_trip_keeps_a_unit_whose_count_has_no_occurrences() {
        let opts = round_trip_opts();
        let units = vec![Unit {
            name: "geiger_pkg".into(),
            kind: UnitKind::Workspace,
            unsafe_count: 7,
        }];
        let scan = ScanResult::from_parts("cargo_geiger", "rust", &opts, units, vec![]);
        let back = reread(&crate::sarif::scan_to_sarif(&scan), &opts);

        assert_eq!(back.units, scan.units);
        assert_eq!(back.totals.workspace_unsafe, 7);

        let baseline = crate::config::Baseline {
            tool_version: "0.1.0".into(),
            analyzer_id: "sarif".into(),
            scope: back.scope.clone(),
            totals: crate::model::Totals::default(),
            units: vec![crate::config::BaselineUnit {
                name: "geiger_pkg".into(),
                kind: UnitKind::Workspace,
                unsafe_count: 1,
            }],
        };
        let checked =
            crate::budget::check(&back, Some(&baseline), &crate::config::Config::default())
                .unwrap();

        assert!(!checked.passed);
        assert_eq!(checked.violations.len(), 1);
        assert_eq!(checked.violations[0].unit, "geiger_pkg");
        assert_eq!(checked.violations[0].actual, 7);
    }

    #[test]
    fn test_round_trip_honours_workspace_only() {
        let scan = round_trip_fixture();
        let opts = ScanOpts {
            workspace_only: true,
            include_deps: true,
            ..Default::default()
        };
        let back = reread(&crate::sarif::scan_to_sarif(&scan), &opts);

        let names: Vec<_> = back.units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, vec!["app", "helper"]);
        assert_eq!(back.totals.deps_unsafe, 0);
        assert!(back.details.iter().all(|occ| occ.unit == "app"));
    }

    #[test]
    fn test_own_run_without_recorded_units_falls_back_to_paths() {
        let mut run = make_run(
            "unsafe-budget",
            vec![own_sarif_result(
                "/home/u/.cargo/registry/src/index.crates.io-abc/libc-0.2.0/src/lib.rs",
                7,
                1,
                "unsafe",
            )],
        );
        run.properties = Some(property_bag("rust"));

        let opts = round_trip_opts();
        let back = convert_sarif(&make_multi_run_sarif(vec![run]), &opts).unwrap();

        assert_eq!(back.units.len(), 1);
        assert_eq!(back.units[0].kind, UnitKind::Dep);
        assert_eq!(back.units[0].unsafe_count, 1);
    }

    #[test]
    fn test_third_party_rule_ids_are_not_filtered() {
        let mut theirs = make_sarif_result("crate_a/src/lib.rs", 10, 1, "their finding");
        theirs.rule_id = Some("budget_violation".into());

        let opts = ScanOpts::default();
        let back = convert_sarif(&make_sarif(vec![theirs]), &opts).unwrap();

        assert_eq!(back.totals.overall_unsafe, 1);
        assert!(back.parse_warnings.is_empty());
    }
}
