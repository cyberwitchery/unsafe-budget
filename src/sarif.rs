//! SARIF output conversion.
//!
//! converts scan and check results into SARIF 2.1.0 format
//! for integration with github code scanning, vs code, and other tools.

use std::collections::HashMap;

use crate::model::{CheckResult, ScanResult};
use serde_sarif::sarif;

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const RULE_UNSAFE_CODE: &str = "unsafe_code";
const RULE_BUDGET_VIOLATION: &str = "budget_violation";
const RULE_BUDGET_WARNING: &str = "budget_warning";
const RULE_PARSE_WARNING: &str = "parse_warning";

/// convert a scan result into a SARIF 2.1.0 log.
///
/// each occurrence becomes a SARIF result with level "warning".
/// if there are no details (occurrences), the results array will be empty.
pub fn scan_to_sarif(result: &ScanResult) -> sarif::Sarif {
    let mut rules = vec![make_unsafe_code_rule()];
    if !result.parse_warnings.is_empty() {
        rules.push(make_parse_warning_rule());
    }
    let driver = make_driver(&result.tool_version, rules);
    let tool = sarif::Tool::builder().driver(driver).build();

    let mut results = make_occurrence_results(&result.details);
    append_parse_warning_results(&mut results, &result.parse_warnings);
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

/// convert a check result into a SARIF 2.1.0 log.
///
/// occurrences become "warning" results. Violations become "error" results.
pub fn check_to_sarif(result: &CheckResult) -> sarif::Sarif {
    let mut rules = vec![make_unsafe_code_rule()];
    if !result.violations.is_empty() {
        rules.push(make_budget_violation_rule());
    }
    if !result.warnings.is_empty() {
        rules.push(make_budget_warning_rule());
    }
    if !result.scan.parse_warnings.is_empty() {
        rules.push(make_parse_warning_rule());
    }

    let driver = make_driver(&result.scan.tool_version, rules);
    let tool = sarif::Tool::builder().driver(driver).build();

    let mut results = make_occurrence_results(&result.scan.details);
    let location_map = build_location_map(&result.scan.details);

    for v in &result.violations {
        let message = format!(
            "unit '{}' exceeds budget: {} unsafe (budget: {}, delta: +{})",
            v.unit, v.actual, v.baseline, v.delta
        );
        let locations = location_map
            .get(v.unit.as_str())
            .cloned()
            .unwrap_or_default();
        results.push(make_budget_result(
            RULE_BUDGET_VIOLATION,
            sarif::ResultLevel::Error,
            message,
            locations,
        ));
    }

    for w in &result.warnings {
        let message = format!(
            "unit '{}' is near its budget: {} unsafe (budget: {})",
            w.unit, w.actual, w.budget
        );
        let locations = location_map
            .get(w.unit.as_str())
            .cloned()
            .unwrap_or_default();
        results.push(make_budget_result(
            RULE_BUDGET_WARNING,
            sarif::ResultLevel::Note,
            message,
            locations,
        ));
    }

    append_parse_warning_results(&mut results, &result.scan.parse_warnings);
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

fn make_budget_warning_rule() -> sarif::ReportingDescriptor {
    sarif::ReportingDescriptor::builder()
        .id(RULE_BUDGET_WARNING)
        .short_description(
            sarif::MultiformatMessageString::builder()
                .text("Unsafe code near budget threshold")
                .build(),
        )
        .build()
}

fn make_parse_warning_rule() -> sarif::ReportingDescriptor {
    sarif::ReportingDescriptor::builder()
        .id(RULE_PARSE_WARNING)
        .short_description(
            sarif::MultiformatMessageString::builder()
                .text("Analyzer output contained unparseable lines")
                .build(),
        )
        .build()
}

fn append_parse_warning_results(
    results: &mut Vec<sarif::Result>,
    warnings: &[crate::model::ParseWarning],
) {
    for w in warnings {
        results.push(
            sarif::Result::builder()
                .rule_id(RULE_PARSE_WARNING.to_string())
                .level(sarif::ResultLevel::Note)
                .message(sarif::Message::builder().text(w.message.clone()).build())
                .build(),
        );
    }
}

fn make_budget_result(
    rule_id: &str,
    level: sarif::ResultLevel,
    message: String,
    locations: Vec<sarif::Location>,
) -> sarif::Result {
    let msg = sarif::Message::builder().text(message).build();
    if locations.is_empty() {
        sarif::Result::builder()
            .rule_id(rule_id.to_string())
            .level(level)
            .message(msg)
            .build()
    } else {
        sarif::Result::builder()
            .rule_id(rule_id.to_string())
            .level(level)
            .message(msg)
            .locations(locations)
            .build()
    }
}

fn make_location(occ: &crate::model::Occurrence) -> sarif::Location {
    sarif::Location::builder()
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
        .build()
}

/// pre-build a map from unit name to sorted locations.
/// avoids rescanning all details for each violation/warning.
fn build_location_map(details: &[crate::model::Occurrence]) -> HashMap<&str, Vec<sarif::Location>> {
    let mut by_unit: HashMap<&str, Vec<&crate::model::Occurrence>> = HashMap::new();
    for occ in details {
        by_unit.entry(occ.unit.as_str()).or_default().push(occ);
    }
    by_unit
        .into_iter()
        .map(|(unit, mut occs)| {
            occs.sort_by(|a, b| {
                a.file
                    .cmp(&b.file)
                    .then(a.line.cmp(&b.line))
                    .then(a.col.cmp(&b.col))
            });
            (unit, occs.iter().map(|occ| make_location(occ)).collect())
        })
        .collect()
}

fn make_occurrence_results(details: &[crate::model::Occurrence]) -> Vec<sarif::Result> {
    details
        .iter()
        .map(|occ| {
            let message = occ.message.as_deref().unwrap_or("unsafe code usage");

            sarif::Result::builder()
                .rule_id(RULE_UNSAFE_CODE.to_string())
                .level(sarif::ResultLevel::Warning)
                .message(sarif::Message::builder().text(message.to_string()).build())
                .locations(vec![make_location(occ)])
                .build()
        })
        .collect()
}

/// sort results for deterministic output.
/// results without locations come first sorted by message,
/// then results with locations sorted by (file, line, col, rule_id).
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
                let a_rule = a.rule_id.as_deref().unwrap_or("");
                let b_rule = b.rule_id.as_deref().unwrap_or("");
                a_uri
                    .cmp(b_uri)
                    .then(a_line.cmp(&b_line))
                    .then(a_col.cmp(&b_col))
                    .then(a_rule.cmp(b_rule))
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CheckResult, Occurrence, ScanResult, Scope, Totals, Unit, UnitKind, Violation, Warning,
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
                all_features: false,
                no_default_features: false,
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
            parse_warnings: vec![],
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

        // first result (sorted by line)
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

        // second result uses default message
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
        // feed occurrences in reverse order
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
        // sorted by file then line
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

        // violation includes locations from matching occurrences
        let locs = violation_result.locations.as_ref().unwrap();
        assert_eq!(locs.len(), 1);
        let pl = locs[0].physical_location.as_ref().unwrap();
        assert_eq!(
            pl.artifact_location.as_ref().unwrap().uri.as_deref(),
            Some("src/lib.rs")
        );
        assert_eq!(pl.region.as_ref().unwrap().start_line, Some(10));
        assert_eq!(pl.region.as_ref().unwrap().start_column, Some(5));
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

        // no budget_violation rule when there are no violations
        let rules = run.tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "unsafe_code");

        let results = run.results.as_ref().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id.as_deref(), Some("unsafe_code"));
    }

    #[test]
    fn test_check_to_sarif_with_warnings() {
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
            warnings: vec![Warning {
                unit: "my_crate".into(),
                kind: UnitKind::Workspace,
                budget: 5,
                actual: 4,
            }],
            passed: true,
        };

        let sarif = check_to_sarif(&check);
        let run = &sarif.runs[0];

        let rules = run.tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 2);
        let rule_ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(rule_ids.contains(&"unsafe_code"));
        assert!(rule_ids.contains(&"budget_warning"));

        let results = run.results.as_ref().unwrap();
        assert_eq!(results.len(), 2);

        let warning_result = results
            .iter()
            .find(|r| r.rule_id.as_deref() == Some("budget_warning"))
            .unwrap();
        assert_eq!(warning_result.level, Some(sarif::ResultLevel::Note));
        assert!(warning_result
            .message
            .text
            .as_ref()
            .unwrap()
            .contains("near its budget"));

        // warning includes locations from matching occurrences
        let locs = warning_result.locations.as_ref().unwrap();
        assert_eq!(locs.len(), 1);
        let pl = locs[0].physical_location.as_ref().unwrap();
        assert_eq!(
            pl.artifact_location.as_ref().unwrap().uri.as_deref(),
            Some("src/lib.rs")
        );
        assert_eq!(pl.region.as_ref().unwrap().start_line, Some(10));
    }

    #[test]
    fn test_check_to_sarif_with_violations_and_warnings() {
        let scan = make_scan_result(vec![]);

        let check = CheckResult {
            scan,
            violations: vec![Violation {
                unit: "bad_crate".into(),
                kind: UnitKind::Workspace,
                baseline: 0,
                actual: 3,
                delta: 3,
            }],
            warnings: vec![Warning {
                unit: "close_crate".into(),
                kind: UnitKind::Workspace,
                budget: 5,
                actual: 4,
            }],
            passed: false,
        };

        let sarif = check_to_sarif(&check);
        let run = &sarif.runs[0];

        let rules = run.tool.driver.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 3);
        let rule_ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(rule_ids.contains(&"unsafe_code"));
        assert!(rule_ids.contains(&"budget_violation"));
        assert!(rule_ids.contains(&"budget_warning"));

        let results = run.results.as_ref().unwrap();
        assert_eq!(results.len(), 2);

        let violation = results
            .iter()
            .find(|r| r.rule_id.as_deref() == Some("budget_violation"))
            .unwrap();
        assert_eq!(violation.level, Some(sarif::ResultLevel::Error));

        let warning = results
            .iter()
            .find(|r| r.rule_id.as_deref() == Some("budget_warning"))
            .unwrap();
        assert_eq!(warning.level, Some(sarif::ResultLevel::Note));
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

        // serialize and parse back
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

    #[test]
    fn test_check_to_sarif_violation_no_matching_occurrences() {
        // occurrences are for "my_crate" but violation is for "other_crate"
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
                unit: "other_crate".into(),
                kind: UnitKind::Dep,
                baseline: 0,
                actual: 2,
                delta: 2,
            }],
            warnings: vec![],
            passed: false,
        };

        let sarif = check_to_sarif(&check);
        let results = sarif.runs[0].results.as_ref().unwrap();

        let violation_result = results
            .iter()
            .find(|r| r.rule_id.as_deref() == Some("budget_violation"))
            .unwrap();

        // no matching occurrences => no locations
        assert!(violation_result.locations.is_none());
    }

    #[test]
    fn test_check_to_sarif_violation_multiple_occurrences() {
        let details = vec![
            Occurrence {
                unit: "my_crate".into(),
                file: PathBuf::from("src/lib.rs"),
                line: 20,
                col: 1,
                message: Some("second".into()),
            },
            Occurrence {
                unit: "other_crate".into(),
                file: PathBuf::from("other/src/lib.rs"),
                line: 1,
                col: 1,
                message: Some("unrelated".into()),
            },
            Occurrence {
                unit: "my_crate".into(),
                file: PathBuf::from("src/lib.rs"),
                line: 10,
                col: 5,
                message: Some("first".into()),
            },
        ];
        let scan = make_scan_result(details);

        let check = CheckResult {
            scan,
            violations: vec![Violation {
                unit: "my_crate".into(),
                kind: UnitKind::Workspace,
                baseline: 1,
                actual: 2,
                delta: 1,
            }],
            warnings: vec![],
            passed: false,
        };

        let sarif = check_to_sarif(&check);
        let results = sarif.runs[0].results.as_ref().unwrap();

        let violation_result = results
            .iter()
            .find(|r| r.rule_id.as_deref() == Some("budget_violation"))
            .unwrap();

        // only my_crate occurrences, sorted by file/line/col
        let locs = violation_result.locations.as_ref().unwrap();
        assert_eq!(locs.len(), 2);
        assert_eq!(
            locs[0]
                .physical_location
                .as_ref()
                .unwrap()
                .region
                .as_ref()
                .unwrap()
                .start_line,
            Some(10)
        );
        assert_eq!(
            locs[1]
                .physical_location
                .as_ref()
                .unwrap()
                .region
                .as_ref()
                .unwrap()
                .start_line,
            Some(20)
        );
    }

    #[test]
    fn test_check_to_sarif_sort_with_located_violations() {
        let details = vec![Occurrence {
            unit: "my_crate".into(),
            file: PathBuf::from("src/lib.rs"),
            line: 10,
            col: 5,
            message: Some("unsafe block".into()),
        }];
        let scan = make_scan_result(details);

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
        let results = sarif.runs[0].results.as_ref().unwrap();
        assert_eq!(results.len(), 2);

        // both at same location; budget_violation sorts before unsafe_code
        let rule_ids: Vec<_> = results
            .iter()
            .map(|r| r.rule_id.as_deref().unwrap())
            .collect();
        assert_eq!(rule_ids, vec!["budget_violation", "unsafe_code"]);
    }

    #[test]
    fn test_make_budget_result_without_locations() {
        let result = make_budget_result(
            RULE_BUDGET_VIOLATION,
            sarif::ResultLevel::Error,
            "unit 'foo' exceeds budget".into(),
            vec![],
        );

        assert_eq!(result.rule_id.as_deref(), Some(RULE_BUDGET_VIOLATION));
        assert_eq!(result.level, Some(sarif::ResultLevel::Error));
        assert_eq!(
            result.message.text.as_deref(),
            Some("unit 'foo' exceeds budget")
        );
        assert!(result.locations.is_none());
    }

    #[test]
    fn test_make_budget_result_with_locations() {
        let occ = Occurrence {
            unit: "foo".into(),
            file: PathBuf::from("src/lib.rs"),
            line: 42,
            col: 1,
            message: None,
        };
        let locations = vec![make_location(&occ)];

        let result = make_budget_result(
            RULE_BUDGET_WARNING,
            sarif::ResultLevel::Note,
            "unit 'foo' is near its budget".into(),
            locations,
        );

        assert_eq!(result.rule_id.as_deref(), Some(RULE_BUDGET_WARNING));
        assert_eq!(result.level, Some(sarif::ResultLevel::Note));
        assert_eq!(
            result.message.text.as_deref(),
            Some("unit 'foo' is near its budget")
        );
        let locs = result.locations.as_ref().unwrap();
        assert_eq!(locs.len(), 1);
        let pl = locs[0].physical_location.as_ref().unwrap();
        assert_eq!(
            pl.artifact_location.as_ref().unwrap().uri.as_deref(),
            Some("src/lib.rs")
        );
        assert_eq!(pl.region.as_ref().unwrap().start_line, Some(42));
    }

    #[test]
    fn test_scan_to_sarif_with_parse_warnings() {
        let mut scan = make_scan_result(vec![]);
        scan.parse_warnings = vec![
            crate::model::ParseWarning {
                message: "go-geiger: skipping line with unparseable line number: foo:abc:1: x"
                    .into(),
            },
            crate::model::ParseWarning {
                message: "go-geiger: skipping line with unparseable column number: foo:1:xyz: x"
                    .into(),
            },
        ];

        let sarif = scan_to_sarif(&scan);
        let run = &sarif.runs[0];

        let rules = run.tool.driver.rules.as_ref().unwrap();
        let rule_ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(rule_ids.contains(&"parse_warning"));

        let results = run.results.as_ref().unwrap();
        assert_eq!(results.len(), 2);

        for r in results {
            assert_eq!(r.rule_id.as_deref(), Some("parse_warning"));
            assert_eq!(r.level, Some(sarif::ResultLevel::Note));
            assert!(r.locations.is_none());
        }
    }

    #[test]
    fn test_scan_to_sarif_no_parse_warning_rule_when_empty() {
        let scan = make_scan_result(vec![]);
        let sarif = scan_to_sarif(&scan);
        let rules = sarif.runs[0].tool.driver.rules.as_ref().unwrap();
        let rule_ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(!rule_ids.contains(&"parse_warning"));
    }

    #[test]
    fn test_check_to_sarif_with_parse_warnings() {
        let mut scan = make_scan_result(vec![]);
        scan.parse_warnings = vec![crate::model::ParseWarning {
            message: "go-geiger: test warning".into(),
        }];

        let check = CheckResult {
            scan,
            violations: vec![],
            warnings: vec![],
            passed: true,
        };

        let sarif = check_to_sarif(&check);
        let run = &sarif.runs[0];

        let rules = run.tool.driver.rules.as_ref().unwrap();
        let rule_ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(rule_ids.contains(&"parse_warning"));

        let results = run.results.as_ref().unwrap();
        let pw = results
            .iter()
            .find(|r| r.rule_id.as_deref() == Some("parse_warning"))
            .unwrap();
        assert_eq!(pw.level, Some(sarif::ResultLevel::Note));
        assert!(pw.message.text.as_ref().unwrap().contains("test warning"));
    }
}
