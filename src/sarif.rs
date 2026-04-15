//! SARIF output conversion.
//!
//! converts scan and check results into SARIF 2.1.0 format
//! for integration with github code scanning, vs code, and other tools.

use crate::model::{CheckResult, ScanResult};
use serde_sarif::sarif;

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const RULE_UNSAFE_CODE: &str = "unsafe_code";
const RULE_BUDGET_VIOLATION: &str = "budget_violation";

/// Convert a scan result into a SARIF 2.1.0 log.
///
/// Each occurrence becomes a SARIF result with level "warning".
/// If there are no details (occurrences), the results array will be empty.
pub fn scan_to_sarif(result: &ScanResult) -> sarif::Sarif {
    let rules = vec![make_unsafe_code_rule()];
    let driver = make_driver(&result.tool_version, rules);
    let tool = sarif::Tool::builder().driver(driver).build();

    let mut results = make_occurrence_results(&result.details);
    sort_results(&mut results);

    sarif::Sarif::builder()
        .version(serde_json::json!("2.1.0"))
        .schema(SARIF_SCHEMA.to_string())
        .runs(vec![sarif::Run::builder()
            .tool(tool)
            .results(results)
            .build()])
        .build()
}

/// Convert a check result into a SARIF 2.1.0 log.
///
/// Occurrences become "warning" results. Violations become "error" results.
pub fn check_to_sarif(result: &CheckResult) -> sarif::Sarif {
    let mut rules = vec![make_unsafe_code_rule()];
    if !result.violations.is_empty() {
        rules.push(make_budget_violation_rule());
    }

    let driver = make_driver(&result.scan.tool_version, rules);
    let tool = sarif::Tool::builder().driver(driver).build();

    let mut results = make_occurrence_results(&result.scan.details);

    for v in &result.violations {
        let message = format!(
            "unit '{}' exceeds budget: {} unsafe (budget: {}, delta: +{})",
            v.unit, v.actual, v.baseline, v.delta
        );
        results.push(
            sarif::Result::builder()
                .rule_id(RULE_BUDGET_VIOLATION.to_string())
                .level(sarif::ResultLevel::Error)
                .message(sarif::Message::builder().text(message).build())
                .build(),
        );
    }

    sort_results(&mut results);

    sarif::Sarif::builder()
        .version(serde_json::json!("2.1.0"))
        .schema(SARIF_SCHEMA.to_string())
        .runs(vec![sarif::Run::builder()
            .tool(tool)
            .results(results)
            .build()])
        .build()
}

fn make_driver(version: &str, rules: Vec<sarif::ReportingDescriptor>) -> sarif::ToolComponent {
    sarif::ToolComponent::builder()
        .name("unsafe-budget")
        .version(version.to_string())
        .information_uri("https://github.com/cyberwitchery/unsafe-budget".to_string())
        .rules(rules)
        .build()
}

fn make_unsafe_code_rule() -> sarif::ReportingDescriptor {
    sarif::ReportingDescriptor::builder()
        .id(RULE_UNSAFE_CODE)
        .short_description(
            sarif::MultiformatMessageString::builder()
                .text("Unsafe code usage detected")
                .build(),
        )
        .build()
}

fn make_budget_violation_rule() -> sarif::ReportingDescriptor {
    sarif::ReportingDescriptor::builder()
        .id(RULE_BUDGET_VIOLATION)
        .short_description(
            sarif::MultiformatMessageString::builder()
                .text("Unsafe code budget exceeded")
                .build(),
        )
        .build()
}

fn make_occurrence_results(details: &[crate::model::Occurrence]) -> Vec<sarif::Result> {
    details
        .iter()
        .map(|occ| {
            let message = occ.message.as_deref().unwrap_or("unsafe code usage");

            let location = sarif::Location::builder()
                .physical_location(
                    sarif::PhysicalLocation::builder()
                        .artifact_location(
                            sarif::ArtifactLocation::builder()
                                .uri(occ.file.to_string_lossy().to_string())
                                .build(),
                        )
                        .region(
                            sarif::Region::builder()
                                .start_line(occ.line as i64)
                                .start_column(occ.col as i64)
                                .build(),
                        )
                        .build(),
                )
                .build();

            sarif::Result::builder()
                .rule_id(RULE_UNSAFE_CODE.to_string())
                .level(sarif::ResultLevel::Warning)
                .message(sarif::Message::builder().text(message.to_string()).build())
                .locations(vec![location])
                .build()
        })
        .collect()
}

/// Sort results for deterministic output.
/// Violations (no locations) come first sorted by message,
/// then occurrences sorted by (file, line, col).
fn sort_results(results: &mut [sarif::Result]) {
    results.sort_by(|a, b| {
        let a_loc = a
            .locations
            .as_ref()
            .and_then(|l| l.first())
            .and_then(|l| l.physical_location.as_ref());
        let b_loc = b
            .locations
            .as_ref()
            .and_then(|l| l.first())
            .and_then(|l| l.physical_location.as_ref());

        match (a_loc, b_loc) {
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (None, None) => {
                let a_msg = a.message.text.as_deref().unwrap_or("");
                let b_msg = b.message.text.as_deref().unwrap_or("");
                a_msg.cmp(b_msg)
            }
            (Some(a_pl), Some(b_pl)) => {
                let a_uri = a_pl
                    .artifact_location
                    .as_ref()
                    .and_then(|al| al.uri.as_deref())
                    .unwrap_or("");
                let b_uri = b_pl
                    .artifact_location
                    .as_ref()
                    .and_then(|al| al.uri.as_deref())
                    .unwrap_or("");
                let a_line = a_pl.region.as_ref().and_then(|r| r.start_line).unwrap_or(0);
                let b_line = b_pl.region.as_ref().and_then(|r| r.start_line).unwrap_or(0);
                let a_col = a_pl
                    .region
                    .as_ref()
                    .and_then(|r| r.start_column)
                    .unwrap_or(0);
                let b_col = b_pl
                    .region
                    .as_ref()
                    .and_then(|r| r.start_column)
                    .unwrap_or(0);
                a_uri
                    .cmp(b_uri)
                    .then(a_line.cmp(&b_line))
                    .then(a_col.cmp(&b_col))
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CheckResult, Occurrence, ScanResult, Scope, Totals, Unit, UnitKind, Violation,
    };
    use std::path::PathBuf;

    fn make_scan_result(details: Vec<Occurrence>) -> ScanResult {
        ScanResult {
            tool_version: "0.1.0".into(),
            analyzer_id: "test".into(),
            language: "rust".into(),
            scope: Scope {
                workspace_only: false,
                include_deps: true,
                features: vec![],
                all_targets: false,
                targets: vec![],
                manifest_path: None,
            },
            units: vec![Unit {
                name: "my_crate".into(),
                kind: UnitKind::Workspace,
                unsafe_count: details.len() as u64,
            }],
            totals: Totals {
                workspace_unsafe: details.len() as u64,
                deps_unsafe: 0,
                overall_unsafe: details.len() as u64,
            },
            details,
        }
    }

    #[test]
    fn test_scan_to_sarif_basic() {
        let details = vec![
            Occurrence {
                unit: "my_crate".into(),
                file: PathBuf::from("src/lib.rs"),
                line: 10,
                col: 5,
                message: Some("unsafe block".into()),
            },
            Occurrence {
                unit: "my_crate".into(),
                file: PathBuf::from("src/lib.rs"),
                line: 20,
                col: 9,
                message: None,
            },
        ];
        let scan = make_scan_result(details);
        let sarif = scan_to_sarif(&scan);

        assert_eq!(
            sarif.schema.as_deref(),
            Some("https://json.schemastore.org/sarif-2.1.0.json")
        );
        assert_eq!(sarif.version, serde_json::json!("2.1.0"));
        assert_eq!(sarif.runs.len(), 1);

        let run = &sarif.runs[0];
        assert_eq!(run.tool.driver.name, "unsafe-budget");
        assert_eq!(run.tool.driver.version.as_deref(), Some("0.1.0"));

        let rules = run.tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "unsafe_code");

        let results = run.results.as_ref().unwrap();
        assert_eq!(results.len(), 2);

        // First result (sorted by line)
        assert_eq!(results[0].rule_id.as_deref(), Some("unsafe_code"));
        assert_eq!(results[0].level, Some(sarif::ResultLevel::Warning));
        assert_eq!(results[0].message.text.as_deref(), Some("unsafe block"));

        let loc = results[0]
            .locations
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .physical_location
            .as_ref()
            .unwrap();
        assert_eq!(
            loc.artifact_location.as_ref().unwrap().uri.as_deref(),
            Some("src/lib.rs")
        );
        assert_eq!(loc.region.as_ref().unwrap().start_line, Some(10));
        assert_eq!(loc.region.as_ref().unwrap().start_column, Some(5));

        // Second result uses default message
        assert_eq!(
            results[1].message.text.as_deref(),
            Some("unsafe code usage")
        );
    }

    #[test]
    fn test_scan_to_sarif_empty() {
        let scan = make_scan_result(vec![]);
        let sarif = scan_to_sarif(&scan);

        let results = sarif.runs[0].results.as_ref().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_to_sarif_deterministic() {
        // Feed occurrences in reverse order
        let details = vec![
            Occurrence {
                unit: "my_crate".into(),
                file: PathBuf::from("src/lib.rs"),
                line: 30,
                col: 1,
                message: Some("third".into()),
            },
            Occurrence {
                unit: "my_crate".into(),
                file: PathBuf::from("src/lib.rs"),
                line: 10,
                col: 1,
                message: Some("first".into()),
            },
            Occurrence {
                unit: "my_crate".into(),
                file: PathBuf::from("src/a.rs"),
                line: 5,
                col: 1,
                message: Some("zeroth".into()),
            },
        ];
        let scan = make_scan_result(details);
        let sarif = scan_to_sarif(&scan);

        let results = sarif.runs[0].results.as_ref().unwrap();
        let messages: Vec<_> = results
            .iter()
            .map(|r| r.message.text.as_deref().unwrap())
            .collect();
        // Sorted by file then line
        assert_eq!(messages, vec!["zeroth", "first", "third"]);
    }

    #[test]
    fn test_check_to_sarif_with_violations() {
        let scan = make_scan_result(vec![Occurrence {
            unit: "my_crate".into(),
            file: PathBuf::from("src/lib.rs"),
            line: 10,
            col: 5,
            message: Some("unsafe block".into()),
        }]);

        let check = CheckResult {
            scan,
            violations: vec![Violation {
                unit: "my_crate".into(),
                kind: UnitKind::Workspace,
                baseline: 0,
                actual: 1,
                delta: 1,
            }],
            warnings: vec![],
            passed: false,
        };

        let sarif = check_to_sarif(&check);
        let run = &sarif.runs[0];

        let rules = run.tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 2);
        let rule_ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(rule_ids.contains(&"unsafe_code"));
        assert!(rule_ids.contains(&"budget_violation"));

        let results = run.results.as_ref().unwrap();
        assert_eq!(results.len(), 2);

        // Violation (no location) comes first after sorting
        let violation_result = results
            .iter()
            .find(|r| r.rule_id.as_deref() == Some("budget_violation"))
            .unwrap();
        assert_eq!(violation_result.level, Some(sarif::ResultLevel::Error));
        assert!(violation_result
            .message
            .text
            .as_ref()
            .unwrap()
            .contains("exceeds budget"));
    }

    #[test]
    fn test_check_to_sarif_passed() {
        let scan = make_scan_result(vec![Occurrence {
            unit: "my_crate".into(),
            file: PathBuf::from("src/lib.rs"),
            line: 10,
            col: 5,
            message: Some("unsafe block".into()),
        }]);

        let check = CheckResult {
            scan,
            violations: vec![],
            warnings: vec![],
            passed: true,
        };

        let sarif = check_to_sarif(&check);
        let run = &sarif.runs[0];

        // No budget_violation rule when there are no violations
        let rules = run.tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "unsafe_code");

        let results = run.results.as_ref().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id.as_deref(), Some("unsafe_code"));
    }

    #[test]
    fn test_sarif_output_roundtrip() {
        let details = vec![Occurrence {
            unit: "my_crate".into(),
            file: PathBuf::from("src/lib.rs"),
            line: 10,
            col: 5,
            message: Some("unsafe block".into()),
        }];
        let scan = make_scan_result(details);
        let sarif_out = scan_to_sarif(&scan);

        // Serialize and parse back
        let json = serde_json::to_string_pretty(&sarif_out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(
            parsed["$schema"],
            "https://json.schemastore.org/sarif-2.1.0.json"
        );
        assert!(parsed["runs"].is_array());
        assert!(parsed["runs"][0]["results"].is_array());
    }
}
