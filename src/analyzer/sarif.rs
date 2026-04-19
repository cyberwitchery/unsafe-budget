//! SARIF file analyzer.
//!
//! reads a SARIF 2.1.0 file and converts its results into the normalized
//! ScanResult format. this allows unsafe-budget to apply budget logic
//! to output from any SARIF-producing static analysis tool.

use crate::analyzer::Analyzer;
use crate::error::{Error, Result};
use crate::model::{Occurrence, ScanOpts, ScanResult, Unit, UnitKind};
use serde_sarif::sarif::Sarif;
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
    let run = sarif.runs.first().ok_or_else(|| Error::Analyzer {
        analyzer: "sarif".into(),
        message: "SARIF file contains no runs".into(),
    })?;

    let tool_name = &run.tool.driver.name;
    let language = infer_language(tool_name);

    let results = run.results.as_deref().unwrap_or(&[]);
    let mut occurrences: Vec<Occurrence> = Vec::new();

    for result in results {
        let message = result
            .message
            .text
            .clone()
            .unwrap_or_else(|| "unknown".into());

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

            let unit_name = extract_unit_name(&file);

            occurrences.push(Occurrence {
                unit: unit_name,
                file: PathBuf::from(&file),
                line,
                col,
                message: Some(message.clone()),
            });
        }
    }

    let (units, details) = aggregate(occurrences, opts);

    Ok(ScanResult::from_parts(
        "sarif", language, opts, units, details,
    ))
}

/// Infer language from the SARIF tool driver name.
fn infer_language(tool_name: &str) -> String {
    let lower = tool_name.to_lowercase();
    if lower.contains("rust") || lower.contains("cargo") || lower.contains("clippy") {
        "rust".into()
    } else if lower.contains("go") {
        "go".into()
    } else if lower.contains("gcc") || lower.contains("clang") {
        "c".into()
    } else {
        "unknown".into()
    }
}

/// Extract a unit name from an artifact URI.
///
/// Looks for a `src` path component and uses the directory immediately
/// before it as the crate/package name. This handles Rust workspace
/// layouts where every crate has `crate_name/src/lib.rs` — without
/// this, all such paths would collapse into unit `"src"`.
///
/// Falls back to the first directory component when no `src` segment
/// is found, or `"unknown"` for bare filenames.
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

    // Need at least a directory and a filename.
    if components.len() < 2 {
        return "unknown".into();
    }

    let dirs = &components[..components.len() - 1];

    // If a "src" directory appears after at least one other component,
    // the component before it is the crate/package name.
    for (i, dir) in dirs.iter().enumerate() {
        if dir == "src" && i > 0 {
            return dirs[i - 1].clone();
        }
    }

    // No "src" found, or "src" is the first component — use the first
    // directory as the unit name.
    dirs[0].clone()
}

fn aggregate(occurrences: Vec<Occurrence>, opts: &ScanOpts) -> (Vec<Unit>, Vec<Occurrence>) {
    let mut counts: HashMap<String, (UnitKind, u64)> = HashMap::new();

    for occ in &occurrences {
        let entry = counts
            .entry(occ.unit.clone())
            .or_insert((UnitKind::Workspace, 0));
        entry.1 += 1;
    }

    super::aggregate_units(counts, occurrences, opts)
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
        let driver = sarif::ToolComponent::builder().name("test-tool").build();
        let tool = sarif::Tool::builder().driver(driver).build();
        let run = sarif::Run::builder().tool(tool).results(results).build();
        sarif::Sarif::builder()
            .version(serde_json::json!("2.1.0"))
            .runs(vec![run])
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
        // Result without locations should be skipped
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

        // Only the result with a location should be counted
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
        // Sorted alphabetically
        assert_eq!(result.units[0].name, "crate_a");
        assert_eq!(result.units[0].unsafe_count, 2);
        assert_eq!(result.units[1].name, "crate_b");
        assert_eq!(result.units[1].unsafe_count, 1);
    }

    #[test]
    fn test_convert_sarif_workspace_src_paths() {
        // Previously all of these collapsed into unit "src".
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
}
