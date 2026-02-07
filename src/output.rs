use crate::analyzer::AnalyzerInfo;
use crate::config::Baseline;
use crate::model::{CheckResult, ScanResult, Unit, Violation, Warning};
use std::collections::HashMap;
use std::io::{self, Write};

/// Output format.
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

/// Print scan result.
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

/// Print check result.
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

/// Print plugin list.
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

    // Sort by count desc for display
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

    // Build delta map if baseline available
    let deltas: HashMap<String, i64> = baseline
        .map(|b| {
            let baseline_map: HashMap<&str, u64> = b
                .units
                .iter()
                .map(|u| (u.name.as_str(), u.unsafe_count))
                .collect();
            result
                .scan
                .units
                .iter()
                .map(|u| {
                    let baseline_count = baseline_map.get(u.name.as_str()).copied().unwrap_or(0);
                    let delta = u.unsafe_count as i64 - baseline_count as i64;
                    (u.name.clone(), delta)
                })
                .collect()
        })
        .unwrap_or_default();

    // Build violation set for quick lookup
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

    // Sort: violations first, then warnings, then others by count desc
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

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
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

        // Should be valid JSON
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
}
