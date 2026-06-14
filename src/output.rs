use crate::analyzer::AnalyzerInfo;
use crate::config::Baseline;
use crate::model::{CheckResult, Occurrence, ParseWarning, ScanResult, Unit, Violation, Warning};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};

/// output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Text,
    Json,
    Sarif,
}

impl std::str::FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            "sarif" => Ok(Format::Sarif),
            _ => Err(format!("unknown format: {}", s)),
        }
    }
}

/// print scan result.
pub fn print_scan(result: &ScanResult, format: Format) -> io::Result<()> {
    let mut out = io::stdout().lock();
    match format {
        Format::Text => print_scan_text(&mut out, result),
        Format::Json => print_json(&mut out, result),
        Format::Sarif => {
            let sarif = crate::sarif::scan_to_sarif(result);
            print_json(&mut out, &sarif)
        }
    }
}

/// print check result.
pub fn print_check(
    result: &CheckResult,
    baseline: Option<&Baseline>,
    format: Format,
) -> io::Result<()> {
    let mut out = io::stdout().lock();
    match format {
        Format::Text => print_check_text(&mut out, result, baseline),
        Format::Json => print_json(&mut out, result),
        Format::Sarif => {
            let sarif = crate::sarif::check_to_sarif(result);
            print_json(&mut out, &sarif)
        }
    }
}

/// print plugin list.
pub fn print_plugins(plugins: &[AnalyzerInfo], format: Format) -> io::Result<()> {
    let mut out = io::stdout().lock();
    match format {
        Format::Text => print_plugins_text(&mut out, plugins),
        Format::Json | Format::Sarif => {
            let list: Vec<_> = plugins
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "id": p.id,
                        "language": p.language,
                        "builtin": p.builtin,
                        "path": p.path,
                    })
                })
                .collect();
            print_json(&mut out, &list)
        }
    }
}

fn print_json<T: serde::Serialize>(out: &mut impl Write, value: &T) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, value)?;
    writeln!(out)?;
    Ok(())
}

fn print_scan_text(out: &mut impl Write, result: &ScanResult) -> io::Result<()> {
    writeln!(out, "unsafe-budget scan")?;
    writeln!(out, "==================")?;
    writeln!(out, "Analyzer: {}", result.analyzer_id)?;
    writeln!(out, "Language: {}", result.language)?;
    writeln!(out)?;
    writeln!(out, "Totals:")?;
    writeln!(
        out,
        "  Workspace: {} unsafe",
        result.totals.workspace_unsafe
    )?;
    writeln!(out, "  Dependencies: {} unsafe", result.totals.deps_unsafe)?;
    writeln!(out, "  Overall: {} unsafe", result.totals.overall_unsafe)?;
    writeln!(out)?;

    if result.units.is_empty() {
        writeln!(out, "No units found.")?;
        return Ok(());
    }

    // sort by count desc for display
    let mut units: Vec<_> = result.units.iter().collect();
    units.sort_by(|a, b| {
        b.unsafe_count
            .cmp(&a.unsafe_count)
            .then(a.name.cmp(&b.name))
    });

    writeln!(out, "Per-unit breakdown:")?;
    writeln!(out, "  {:<30} {:<12} {:>8}", "UNIT", "KIND", "UNSAFE")?;
    writeln!(out, "  {}", "-".repeat(52))?;

    for unit in units {
        writeln!(
            out,
            "  {:<30} {:<12} {:>8}",
            truncate(&unit.name, 30),
            unit.kind,
            unit.unsafe_count
        )?;
    }

    print_details_text(out, &result.details)?;
    print_parse_warnings_text(out, &result.parse_warnings)?;

    Ok(())
}

fn print_check_text(
    out: &mut impl Write,
    result: &CheckResult,
    baseline: Option<&Baseline>,
) -> io::Result<()> {
    writeln!(out, "unsafe-budget check")?;
    writeln!(out, "===================")?;
    writeln!(out, "Analyzer: {}", result.scan.analyzer_id)?;
    writeln!(out)?;

    let status = if result.passed { "PASSED" } else { "FAILED" };
    writeln!(out, "Status: {}", status)?;
    writeln!(out)?;

    writeln!(out, "Totals:")?;
    writeln!(
        out,
        "  Workspace: {} unsafe",
        result.scan.totals.workspace_unsafe
    )?;
    writeln!(
        out,
        "  Dependencies: {} unsafe",
        result.scan.totals.deps_unsafe
    )?;
    writeln!(
        out,
        "  Overall: {} unsafe",
        result.scan.totals.overall_unsafe
    )?;
    writeln!(out)?;

    // build delta map if baseline available
    let deltas: HashMap<String, i64> = baseline
        .map(|b| crate::budget::compute_deltas(&result.scan, b))
        .unwrap_or_default();

    // build violation set for quick lookup
    let violation_set: HashMap<&str, &Violation> = result
        .violations
        .iter()
        .map(|v| (v.unit.as_str(), v))
        .collect();
    let warning_set: HashMap<&str, &Warning> = result
        .warnings
        .iter()
        .map(|w| (w.unit.as_str(), w))
        .collect();

    if result.scan.units.is_empty() {
        writeln!(out, "No units found.")?;
        return Ok(());
    }

    // sort: violations first, then warnings, then others by count desc
    let mut units: Vec<&Unit> = result.scan.units.iter().collect();
    units.sort_by(|a, b| {
        let a_viol = violation_set.contains_key(a.name.as_str());
        let b_viol = violation_set.contains_key(b.name.as_str());
        let a_warn = warning_set.contains_key(a.name.as_str());
        let b_warn = warning_set.contains_key(b.name.as_str());
        match (a_viol, b_viol) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => match (a_warn, b_warn) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => b
                    .unsafe_count
                    .cmp(&a.unsafe_count)
                    .then(a.name.cmp(&b.name)),
            },
        }
    });

    writeln!(out, "Per-unit breakdown:")?;
    if baseline.is_some() {
        writeln!(
            out,
            "  {:<30} {:<10} {:>8} {:>8} {:>8}",
            "UNIT", "KIND", "UNSAFE", "DELTA", "STATUS"
        )?;
        writeln!(out, "  {}", "-".repeat(68))?;
    } else {
        writeln!(
            out,
            "  {:<30} {:<10} {:>8} {:>8}",
            "UNIT", "KIND", "UNSAFE", "STATUS"
        )?;
        writeln!(out, "  {}", "-".repeat(60))?;
    }

    for unit in units {
        let is_violation = violation_set.contains_key(unit.name.as_str());
        let is_warning = warning_set.contains_key(unit.name.as_str());
        let status = if is_violation {
            "FAIL"
        } else if is_warning {
            "WARN"
        } else {
            "ok"
        };

        if baseline.is_some() {
            let delta = deltas.get(&unit.name).copied().unwrap_or(0);
            let delta_str = format_delta(delta);
            writeln!(
                out,
                "  {:<30} {:<10} {:>8} {:>8} {:>8}",
                truncate(&unit.name, 30),
                unit.kind,
                unit.unsafe_count,
                delta_str,
                status
            )?;
        } else {
            writeln!(
                out,
                "  {:<30} {:<10} {:>8} {:>8}",
                truncate(&unit.name, 30),
                unit.kind,
                unit.unsafe_count,
                status
            )?;
        }
    }

    if !result.passed {
        writeln!(out)?;
        writeln!(out, "Violations ({}):", result.violations.len())?;
        for v in &result.violations {
            writeln!(
                out,
                "  - {}: {} unsafe (budget: {}, delta: +{})",
                v.unit, v.actual, v.baseline, v.delta
            )?;
        }
    }

    if !result.warnings.is_empty() {
        writeln!(out)?;
        writeln!(out, "Warnings ({}):", result.warnings.len())?;
        for w in &result.warnings {
            let pct = if w.budget == 0 {
                0.0
            } else {
                (w.actual as f64 / w.budget as f64) * 100.0
            };
            writeln!(
                out,
                "  - {}: {} unsafe ({:.0}% of budget {}, remaining: {})",
                w.unit,
                w.actual,
                pct,
                w.budget,
                w.budget.saturating_sub(w.actual)
            )?;
        }
    }

    print_details_text(out, &result.scan.details)?;
    print_parse_warnings_text(out, &result.scan.parse_warnings)?;

    Ok(())
}

fn print_plugins_text(out: &mut impl Write, plugins: &[AnalyzerInfo]) -> io::Result<()> {
    writeln!(out, "Available analyzers:")?;
    writeln!(out)?;

    if plugins.is_empty() {
        writeln!(out, "  (none)")?;
        return Ok(());
    }

    writeln!(out, "  {:<20} {:<12} {:<10} PATH", "ID", "LANGUAGE", "TYPE")?;
    writeln!(out, "  {}", "-".repeat(60))?;

    for p in plugins {
        let typ = if p.builtin { "builtin" } else { "plugin" };
        let path = p
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".into());
        writeln!(
            out,
            "  {:<20} {:<12} {:<10} {}",
            p.id, p.language, typ, path
        )?;
    }

    Ok(())
}

fn print_details_text(out: &mut impl Write, details: &[Occurrence]) -> io::Result<()> {
    if details.is_empty() {
        return Ok(());
    }

    // group by unit, sorted by unit name
    let mut by_unit: BTreeMap<&str, Vec<&Occurrence>> = BTreeMap::new();
    for occ in details {
        by_unit.entry(&occ.unit).or_default().push(occ);
    }

    writeln!(out)?;
    writeln!(out, "Details:")?;

    for (unit, mut occs) in by_unit {
        // sort by file, then line, then column
        occs.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.col.cmp(&b.col))
        });

        writeln!(out, "  {}:", unit)?;
        for occ in occs {
            let loc = format!("{}:{}:{}", occ.file.display(), occ.line, occ.col);
            if let Some(msg) = &occ.message {
                writeln!(out, "    {} — {}", loc, msg)?;
            } else {
                writeln!(out, "    {}", loc)?;
            }
        }
    }

    Ok(())
}

fn print_parse_warnings_text(out: &mut impl Write, warnings: &[ParseWarning]) -> io::Result<()> {
    if warnings.is_empty() {
        return Ok(());
    }

    writeln!(out)?;
    writeln!(out, "Parse warnings ({}):", warnings.len())?;
    for w in warnings {
        writeln!(out, "  - {}", w.message)?;
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let end = s
            .char_indices()
            .nth(max - 3)
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        format!("{}...", &s[..end])
    }
}

fn format_delta(delta: i64) -> String {
    match delta.cmp(&0) {
        std::cmp::Ordering::Greater => format!("+{}", delta),
        std::cmp::Ordering::Less => format!("{}", delta),
        std::cmp::Ordering::Equal => "0".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Scope, Totals, UnitKind};

    #[test]
    fn test_format_parse() {
        assert_eq!("text".parse::<Format>().unwrap(), Format::Text);
        assert_eq!("json".parse::<Format>().unwrap(), Format::Json);
        assert_eq!("sarif".parse::<Format>().unwrap(), Format::Sarif);
        assert_eq!("TEXT".parse::<Format>().unwrap(), Format::Text);
        assert_eq!("JSON".parse::<Format>().unwrap(), Format::Json);
        assert_eq!("SARIF".parse::<Format>().unwrap(), Format::Sarif);
        assert!("invalid".parse::<Format>().is_err());
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactly10!", 10), "exactly10!");
        assert_eq!(truncate("this is a long string", 10), "this is...");
    }

    #[test]
    fn test_truncate_multibyte() {
        // should not panic on multi-byte characters
        assert_eq!(truncate("日本語のパッケージ名", 8), "日本語のパ...");
        assert_eq!(truncate("café_module_long", 10), "café_mo...");
        // fits exactly
        assert_eq!(truncate("café", 10), "café");
    }

    #[test]
    fn test_format_delta() {
        assert_eq!(format_delta(5), "+5");
        assert_eq!(format_delta(-3), "-3");
        assert_eq!(format_delta(0), "0");
    }

    fn make_scan_result() -> ScanResult {
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
            units: vec![
                Unit {
                    name: "my_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 10,
                },
                Unit {
                    name: "dep_a".into(),
                    kind: UnitKind::Dep,
                    unsafe_count: 5,
                },
            ],
            totals: Totals {
                workspace_unsafe: 10,
                deps_unsafe: 5,
                overall_unsafe: 15,
            },
            details: vec![],
            parse_warnings: vec![],
        }
    }

    #[test]
    fn test_print_scan_text() {
        let result = make_scan_result();
        let mut buf = Vec::new();
        print_scan_text(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("unsafe-budget scan"));
        assert!(output.contains("Analyzer: test"));
        assert!(output.contains("Language: rust"));
        assert!(output.contains("Workspace: 10 unsafe"));
        assert!(output.contains("Dependencies: 5 unsafe"));
        assert!(output.contains("Overall: 15 unsafe"));
        assert!(output.contains("my_crate"));
        assert!(output.contains("dep_a"));
    }

    #[test]
    fn test_print_scan_text_empty() {
        let mut result = make_scan_result();
        result.units.clear();
        let mut buf = Vec::new();
        print_scan_text(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("No units found"));
    }

    #[test]
    fn test_print_scan_json() {
        let result = make_scan_result();
        let mut buf = Vec::new();
        print_json(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["analyzer_id"], "test");
        assert_eq!(parsed["totals"]["overall_unsafe"], 15);
    }

    #[test]
    fn test_print_check_text_passed() {
        let scan = make_scan_result();
        let check = CheckResult {
            scan,
            violations: vec![],
            warnings: vec![],
            passed: true,
        };

        let mut buf = Vec::new();
        print_check_text(&mut buf, &check, None).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Status: PASSED"));
        assert!(output.contains("my_crate"));
        assert!(!output.contains("Violations"));
    }

    #[test]
    fn test_print_check_text_failed() {
        let scan = make_scan_result();
        let check = CheckResult {
            scan,
            violations: vec![Violation {
                unit: "my_crate".into(),
                kind: UnitKind::Workspace,
                baseline: 5,
                actual: 10,
                delta: 5,
            }],
            warnings: vec![],
            passed: false,
        };

        let mut buf = Vec::new();
        print_check_text(&mut buf, &check, None).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Status: FAILED"));
        assert!(output.contains("Violations (1)"));
        assert!(output.contains("my_crate: 10 unsafe (budget: 5, delta: +5)"));
    }

    #[test]
    fn test_print_check_text_with_warnings() {
        let scan = make_scan_result();
        let check = CheckResult {
            scan,
            violations: vec![],
            warnings: vec![Warning {
                unit: "my_crate".into(),
                kind: UnitKind::Workspace,
                budget: 12,
                actual: 10,
            }],
            passed: true,
        };

        let mut buf = Vec::new();
        print_check_text(&mut buf, &check, None).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Status: PASSED"));
        assert!(output.contains("Warnings (1):"));
        assert!(output.contains("my_crate: 10 unsafe"));
        assert!(output.contains("WARN"));
    }

    #[test]
    fn test_print_plugins_text() {
        let plugins = vec![
            AnalyzerInfo {
                id: "rustc".into(),
                language: "rust".into(),
                builtin: true,
                path: None,
            },
            AnalyzerInfo {
                id: "custom".into(),
                language: "go".into(),
                builtin: false,
                path: Some("/usr/bin/custom".into()),
            },
        ];

        let mut buf = Vec::new();
        print_plugins_text(&mut buf, &plugins).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("rustc"));
        assert!(output.contains("builtin"));
        assert!(output.contains("custom"));
        assert!(output.contains("plugin"));
        assert!(output.contains("/usr/bin/custom"));
    }

    #[test]
    fn test_print_plugins_text_empty() {
        let plugins: Vec<AnalyzerInfo> = vec![];
        let mut buf = Vec::new();
        print_plugins_text(&mut buf, &plugins).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("(none)"));
    }

    fn make_occurrences() -> Vec<Occurrence> {
        vec![
            Occurrence {
                unit: "my_crate".into(),
                file: "src/lib.rs".into(),
                line: 10,
                col: 5,
                message: Some("unsafe block".into()),
            },
            Occurrence {
                unit: "my_crate".into(),
                file: "src/lib.rs".into(),
                line: 25,
                col: 9,
                message: Some("unsafe impl".into()),
            },
            Occurrence {
                unit: "dep_a".into(),
                file: "src/ffi.rs".into(),
                line: 3,
                col: 1,
                message: None,
            },
            Occurrence {
                unit: "my_crate".into(),
                file: "src/api.rs".into(),
                line: 42,
                col: 13,
                message: Some("unsafe function call".into()),
            },
        ]
    }

    #[test]
    fn test_print_details_text_grouped_by_unit() {
        let details = make_occurrences();
        let mut buf = Vec::new();
        print_details_text(&mut buf, &details).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Details:"));
        // units sorted alphabetically
        let dep_pos = output.find("dep_a:").unwrap();
        let crate_pos = output.find("my_crate:").unwrap();
        assert!(dep_pos < crate_pos, "dep_a should appear before my_crate");
    }

    #[test]
    fn test_print_details_text_sorted_within_unit() {
        let details = make_occurrences();
        let mut buf = Vec::new();
        print_details_text(&mut buf, &details).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // within my_crate: src/api.rs should come before src/lib.rs
        let api_pos = output.find("src/api.rs:42:13").unwrap();
        let lib10_pos = output.find("src/lib.rs:10:5").unwrap();
        let lib25_pos = output.find("src/lib.rs:25:9").unwrap();
        assert!(api_pos < lib10_pos);
        assert!(lib10_pos < lib25_pos);
    }

    #[test]
    fn test_print_details_text_with_message() {
        let details = make_occurrences();
        let mut buf = Vec::new();
        print_details_text(&mut buf, &details).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("src/lib.rs:10:5 — unsafe block"));
        assert!(output.contains("src/api.rs:42:13 — unsafe function call"));
    }

    #[test]
    fn test_print_details_text_without_message() {
        let details = make_occurrences();
        let mut buf = Vec::new();
        print_details_text(&mut buf, &details).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // dep_a occurrence has no message - just the location
        assert!(output.contains("src/ffi.rs:3:1\n"));
        assert!(!output.contains("src/ffi.rs:3:1 —"));
    }

    #[test]
    fn test_print_details_text_empty() {
        let details: Vec<Occurrence> = vec![];
        let mut buf = Vec::new();
        print_details_text(&mut buf, &details).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.is_empty(), "empty details should produce no output");
    }

    #[test]
    fn test_print_scan_text_with_details() {
        let mut result = make_scan_result();
        result.details = make_occurrences();

        let mut buf = Vec::new();
        print_scan_text(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // should still have the normal scan header
        assert!(output.contains("unsafe-budget scan"));
        assert!(output.contains("Per-unit breakdown:"));
        // and also the details section
        assert!(output.contains("Details:"));
        assert!(output.contains("my_crate:"));
        assert!(output.contains("src/lib.rs:10:5 — unsafe block"));
    }

    #[test]
    fn test_print_scan_text_without_details() {
        let result = make_scan_result();
        let mut buf = Vec::new();
        print_scan_text(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(!output.contains("Details:"));
    }

    #[test]
    fn test_print_check_text_with_details() {
        let mut scan = make_scan_result();
        scan.details = make_occurrences();

        let check = CheckResult {
            scan,
            violations: vec![Violation {
                unit: "my_crate".into(),
                kind: UnitKind::Workspace,
                baseline: 5,
                actual: 10,
                delta: 5,
            }],
            warnings: vec![],
            passed: false,
        };

        let mut buf = Vec::new();
        print_check_text(&mut buf, &check, None).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // should have violations AND details
        assert!(output.contains("Violations (1):"));
        assert!(output.contains("Details:"));
        assert!(output.contains("dep_a:"));
        assert!(output.contains("src/ffi.rs:3:1"));
    }

    #[test]
    fn test_print_check_text_without_details() {
        let scan = make_scan_result();
        let check = CheckResult {
            scan,
            violations: vec![],
            warnings: vec![],
            passed: true,
        };

        let mut buf = Vec::new();
        print_check_text(&mut buf, &check, None).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(!output.contains("Details:"));
    }

    #[test]
    fn test_print_details_text_single_occurrence() {
        let details = vec![Occurrence {
            unit: "only_crate".into(),
            file: "src/main.rs".into(),
            line: 1,
            col: 1,
            message: Some("unsafe fn".into()),
        }];

        let mut buf = Vec::new();
        print_details_text(&mut buf, &details).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Details:"));
        assert!(output.contains("  only_crate:"));
        assert!(output.contains("    src/main.rs:1:1 — unsafe fn"));
    }

    #[test]
    fn test_print_parse_warnings_text() {
        let warnings = vec![
            ParseWarning {
                message: "go-geiger: skipping line with unparseable line number: foo:abc:1: x"
                    .into(),
            },
            ParseWarning {
                message: "go-geiger: skipping line with unparseable column number: foo:1:xyz: x"
                    .into(),
            },
        ];

        let mut buf = Vec::new();
        print_parse_warnings_text(&mut buf, &warnings).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Parse warnings (2):"));
        assert!(output.contains("unparseable line number"));
        assert!(output.contains("unparseable column number"));
    }

    #[test]
    fn test_print_parse_warnings_text_empty() {
        let mut buf = Vec::new();
        print_parse_warnings_text(&mut buf, &[]).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    fn test_print_scan_text_with_parse_warnings() {
        let mut result = make_scan_result();
        result.parse_warnings = vec![ParseWarning {
            message: "go-geiger: skipping malformed line".into(),
        }];

        let mut buf = Vec::new();
        print_scan_text(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Parse warnings (1):"));
        assert!(output.contains("go-geiger: skipping malformed line"));
    }

    #[test]
    fn test_print_scan_json_includes_parse_warnings() {
        let mut result = make_scan_result();
        result.parse_warnings = vec![ParseWarning {
            message: "go-geiger: test warning".into(),
        }];

        let mut buf = Vec::new();
        print_json(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let warnings = parsed["parse_warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0]["message"], "go-geiger: test warning");
    }

    #[test]
    fn test_print_scan_json_omits_empty_parse_warnings() {
        let result = make_scan_result();

        let mut buf = Vec::new();
        print_json(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.get("parse_warnings").is_none());
    }
}
