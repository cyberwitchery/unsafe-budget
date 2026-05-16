use crate::analyzer::AnalyzerInfo;
use crate::config::Baseline;
use crate::model::{CheckResult, Occurrence, ScanResult, Unit, Violation, Warning};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};

/// Output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Text,
    Json,
    Sarif,
    Html,
}

impl std::str::FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            "sarif" => Ok(Format::Sarif),
            "html" => Ok(Format::Html),
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
        Format::Html => print_scan_html(&mut out, result),
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
        Format::Html => print_check_html(&mut out, result, baseline),
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
        Format::Html => print_plugins_html(&mut out, plugins),
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

    print_details_text(out, &result.details)?;

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
        .map(|b| crate::budget::compute_deltas(&result.scan, b))
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

    print_details_text(out, &result.scan.details)?;

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

    // Group by unit, sorted by unit name
    let mut by_unit: BTreeMap<&str, Vec<&Occurrence>> = BTreeMap::new();
    for occ in details {
        by_unit.entry(&occ.unit).or_default().push(occ);
    }

    writeln!(out)?;
    writeln!(out, "Details:")?;

    for (unit, mut occs) in by_unit {
        // Sort by file, then line, then column
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

// --- HTML output ---

const HTML_CSS: &str = r#"
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 2rem; color: #1a1a1a; background: #fafafa; }
h1 { font-size: 1.5rem; border-bottom: 2px solid #333; padding-bottom: 0.5rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; }
.meta { color: #555; font-size: 0.9rem; margin-bottom: 1.5rem; }
.status { font-weight: bold; padding: 0.2rem 0.6rem; border-radius: 3px; }
.status-pass { background: #d4edda; color: #155724; }
.status-fail { background: #f8d7da; color: #721c24; }
.totals { display: flex; gap: 2rem; margin: 1rem 0; }
.totals div { background: #fff; border: 1px solid #ddd; border-radius: 4px; padding: 0.8rem 1.2rem; }
.totals .label { font-size: 0.8rem; color: #666; text-transform: uppercase; }
.totals .value { font-size: 1.4rem; font-weight: bold; }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.9rem; }
th { text-align: left; background: #333; color: #fff; padding: 0.5rem 0.8rem; }
td { padding: 0.5rem 0.8rem; border-bottom: 1px solid #eee; }
tr:hover td { background: #f0f0f0; }
tr.violation td { background: #fff5f5; }
tr.warning td { background: #fffbeb; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 3px; font-size: 0.8rem; font-weight: bold; }
.badge-fail { background: #f8d7da; color: #721c24; }
.badge-warn { background: #fff3cd; color: #856404; }
.badge-ok { background: #d4edda; color: #155724; }
.details { margin-top: 2rem; }
.details summary { cursor: pointer; font-weight: bold; padding: 0.5rem 0; }
.details .unit-group { margin: 0.5rem 0 1rem 1rem; }
.details .unit-name { font-weight: bold; margin-bottom: 0.3rem; }
.details .occ { font-family: monospace; font-size: 0.85rem; color: #444; padding: 0.15rem 0; }
.violations-section, .warnings-section { margin-top: 1.5rem; padding: 1rem; border-radius: 4px; }
.violations-section { background: #fff5f5; border: 1px solid #f5c6cb; }
.warnings-section { background: #fffbeb; border: 1px solid #ffeeba; }
.violations-section h2, .warnings-section h2 { margin-top: 0; }
"#;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn write_html_head(out: &mut impl Write, title: &str) -> io::Result<()> {
    writeln!(out, "<!DOCTYPE html>")?;
    writeln!(out, "<html lang=\"en\">")?;
    writeln!(out, "<head>")?;
    writeln!(out, "<meta charset=\"utf-8\">")?;
    writeln!(
        out,
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    )?;
    writeln!(out, "<title>{}</title>", html_escape(title))?;
    writeln!(out, "<style>{}</style>", HTML_CSS)?;
    writeln!(out, "</head>")?;
    writeln!(out, "<body>")?;
    Ok(())
}

fn write_html_footer(out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "</body>")?;
    writeln!(out, "</html>")?;
    Ok(())
}

fn write_totals_html(out: &mut impl Write, totals: &crate::model::Totals) -> io::Result<()> {
    writeln!(out, "<div class=\"totals\">")?;
    writeln!(
        out,
        "<div><span class=\"label\">Workspace</span><br><span class=\"value\">{}</span></div>",
        totals.workspace_unsafe
    )?;
    writeln!(
        out,
        "<div><span class=\"label\">Dependencies</span><br><span class=\"value\">{}</span></div>",
        totals.deps_unsafe
    )?;
    writeln!(
        out,
        "<div><span class=\"label\">Overall</span><br><span class=\"value\">{}</span></div>",
        totals.overall_unsafe
    )?;
    writeln!(out, "</div>")?;
    Ok(())
}

fn write_details_html(out: &mut impl Write, details: &[Occurrence]) -> io::Result<()> {
    if details.is_empty() {
        return Ok(());
    }

    let mut by_unit: BTreeMap<&str, Vec<&Occurrence>> = BTreeMap::new();
    for occ in details {
        by_unit.entry(&occ.unit).or_default().push(occ);
    }

    writeln!(out, "<div class=\"details\">")?;
    writeln!(out, "<details>")?;
    writeln!(
        out,
        "<summary>Occurrences ({} total)</summary>",
        details.len()
    )?;

    for (unit, mut occs) in by_unit {
        occs.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.col.cmp(&b.col))
        });

        writeln!(out, "<div class=\"unit-group\">")?;
        writeln!(out, "<div class=\"unit-name\">{}</div>", html_escape(unit))?;
        for occ in occs {
            let loc = format!("{}:{}:{}", occ.file.display(), occ.line, occ.col);
            if let Some(msg) = &occ.message {
                writeln!(
                    out,
                    "<div class=\"occ\">{} &mdash; {}</div>",
                    html_escape(&loc),
                    html_escape(msg)
                )?;
            } else {
                writeln!(out, "<div class=\"occ\">{}</div>", html_escape(&loc))?;
            }
        }
        writeln!(out, "</div>")?;
    }

    writeln!(out, "</details>")?;
    writeln!(out, "</div>")?;
    Ok(())
}

fn print_scan_html(out: &mut impl Write, result: &ScanResult) -> io::Result<()> {
    write_html_head(out, "unsafe-budget scan report")?;

    writeln!(out, "<h1>unsafe-budget scan</h1>")?;
    writeln!(
        out,
        "<div class=\"meta\">Analyzer: {} &middot; Language: {}</div>",
        html_escape(&result.analyzer_id),
        html_escape(&result.language)
    )?;

    write_totals_html(out, &result.totals)?;

    if result.units.is_empty() {
        writeln!(out, "<p>No units found.</p>")?;
    } else {
        let mut units: Vec<_> = result.units.iter().collect();
        units.sort_by(|a, b| {
            b.unsafe_count
                .cmp(&a.unsafe_count)
                .then(a.name.cmp(&b.name))
        });

        writeln!(out, "<h2>Per-unit breakdown</h2>")?;
        writeln!(out, "<table>")?;
        writeln!(out, "<tr><th>Unit</th><th>Kind</th><th>Unsafe</th></tr>")?;
        for unit in units {
            writeln!(
                out,
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&unit.name),
                unit.kind,
                unit.unsafe_count
            )?;
        }
        writeln!(out, "</table>")?;
    }

    write_details_html(out, &result.details)?;
    write_html_footer(out)
}

fn print_check_html(
    out: &mut impl Write,
    result: &CheckResult,
    baseline: Option<&Baseline>,
) -> io::Result<()> {
    write_html_head(out, "unsafe-budget check report")?;

    writeln!(out, "<h1>unsafe-budget check</h1>")?;
    writeln!(
        out,
        "<div class=\"meta\">Analyzer: {}</div>",
        html_escape(&result.scan.analyzer_id)
    )?;

    let (status_class, status_label) = if result.passed {
        ("status-pass", "PASSED")
    } else {
        ("status-fail", "FAILED")
    };
    writeln!(
        out,
        "<p><span class=\"status {}\">{}</span></p>",
        status_class, status_label
    )?;

    write_totals_html(out, &result.scan.totals)?;

    // Build delta map
    let deltas: HashMap<String, i64> = baseline
        .map(|b| crate::budget::compute_deltas(&result.scan, b))
        .unwrap_or_default();

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
        writeln!(out, "<p>No units found.</p>")?;
    } else {
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

        writeln!(out, "<h2>Per-unit breakdown</h2>")?;
        writeln!(out, "<table>")?;
        if baseline.is_some() {
            writeln!(
                out,
                "<tr><th>Unit</th><th>Kind</th><th>Unsafe</th><th>Delta</th><th>Status</th></tr>"
            )?;
        } else {
            writeln!(
                out,
                "<tr><th>Unit</th><th>Kind</th><th>Unsafe</th><th>Status</th></tr>"
            )?;
        }

        for unit in units {
            let is_violation = violation_set.contains_key(unit.name.as_str());
            let is_warning = warning_set.contains_key(unit.name.as_str());
            let (row_class, badge_class, badge_text) = if is_violation {
                ("violation", "badge-fail", "FAIL")
            } else if is_warning {
                ("warning", "badge-warn", "WARN")
            } else {
                ("", "badge-ok", "ok")
            };

            write!(out, "<tr class=\"{}\">", row_class)?;
            write!(out, "<td>{}</td>", html_escape(&unit.name))?;
            write!(out, "<td>{}</td>", unit.kind)?;
            write!(out, "<td>{}</td>", unit.unsafe_count)?;
            if baseline.is_some() {
                let delta = deltas.get(&unit.name).copied().unwrap_or(0);
                write!(out, "<td>{}</td>", format_delta(delta))?;
            }
            write!(
                out,
                "<td><span class=\"badge {}\">{}</span></td>",
                badge_class, badge_text
            )?;
            writeln!(out, "</tr>")?;
        }
        writeln!(out, "</table>")?;
    }

    // Violations section
    if !result.violations.is_empty() {
        writeln!(out, "<div class=\"violations-section\">")?;
        writeln!(out, "<h2>Violations ({})</h2>", result.violations.len())?;
        writeln!(out, "<ul>")?;
        for v in &result.violations {
            writeln!(
                out,
                "<li><strong>{}</strong>: {} unsafe (budget: {}, delta: +{})</li>",
                html_escape(&v.unit),
                v.actual,
                v.baseline,
                v.delta
            )?;
        }
        writeln!(out, "</ul>")?;
        writeln!(out, "</div>")?;
    }

    // Warnings section
    if !result.warnings.is_empty() {
        writeln!(out, "<div class=\"warnings-section\">")?;
        writeln!(out, "<h2>Warnings ({})</h2>", result.warnings.len())?;
        writeln!(out, "<ul>")?;
        for w in &result.warnings {
            let pct = if w.budget == 0 {
                0.0
            } else {
                (w.actual as f64 / w.budget as f64) * 100.0
            };
            writeln!(
                out,
                "<li><strong>{}</strong>: {} unsafe ({:.0}% of budget {}, remaining: {})</li>",
                html_escape(&w.unit),
                w.actual,
                pct,
                w.budget,
                w.budget.saturating_sub(w.actual)
            )?;
        }
        writeln!(out, "</ul>")?;
        writeln!(out, "</div>")?;
    }

    write_details_html(out, &result.scan.details)?;
    write_html_footer(out)
}

fn print_plugins_html(out: &mut impl Write, plugins: &[AnalyzerInfo]) -> io::Result<()> {
    write_html_head(out, "unsafe-budget — available analyzers")?;

    writeln!(out, "<h1>Available analyzers</h1>")?;

    if plugins.is_empty() {
        writeln!(out, "<p>No analyzers found.</p>")?;
    } else {
        writeln!(out, "<table>")?;
        writeln!(
            out,
            "<tr><th>ID</th><th>Language</th><th>Type</th><th>Path</th></tr>"
        )?;
        for p in plugins {
            let typ = if p.builtin { "builtin" } else { "plugin" };
            let path = p
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "—".into());
            writeln!(
                out,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&p.id),
                html_escape(&p.language),
                typ,
                html_escape(&path)
            )?;
        }
        writeln!(out, "</table>")?;
    }

    write_html_footer(out)
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
        // Should not panic on multi-byte characters
        assert_eq!(truncate("日本語のパッケージ名", 8), "日本語のパ...");
        assert_eq!(truncate("café_module_long", 10), "café_mo...");
        // Fits exactly
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
        // Units sorted alphabetically
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

        // Within my_crate: src/api.rs should come before src/lib.rs
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

        // Should still have the normal scan header
        assert!(output.contains("unsafe-budget scan"));
        assert!(output.contains("Per-unit breakdown:"));
        // And also the details section
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

        // Should have violations AND details
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
    fn test_format_parse_html() {
        assert_eq!("html".parse::<Format>().unwrap(), Format::Html);
        assert_eq!("HTML".parse::<Format>().unwrap(), Format::Html);
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"hi\""), "&quot;hi&quot;");
        assert_eq!(html_escape("plain"), "plain");
    }

    #[test]
    fn test_print_scan_html_structure() {
        let result = make_scan_result();
        let mut buf = Vec::new();
        print_scan_html(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("<!DOCTYPE html>"));
        assert!(output.contains("<title>unsafe-budget scan report</title>"));
        assert!(output.contains("<style>"));
        assert!(output.contains("unsafe-budget scan"));
        assert!(output.contains("Analyzer: test"));
        assert!(output.contains("Language: rust"));
        assert!(output.contains(">10<")); // workspace unsafe
        assert!(output.contains(">5<")); // deps unsafe
        assert!(output.contains(">15<")); // overall unsafe
        assert!(output.contains("my_crate"));
        assert!(output.contains("dep_a"));
        assert!(output.contains("</html>"));
    }

    #[test]
    fn test_print_scan_html_empty_units() {
        let mut result = make_scan_result();
        result.units.clear();
        let mut buf = Vec::new();
        print_scan_html(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("No units found"));
        assert!(!output.contains("<table>"));
    }

    #[test]
    fn test_print_scan_html_with_details() {
        let mut result = make_scan_result();
        result.details = make_occurrences();
        let mut buf = Vec::new();
        print_scan_html(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Occurrences (4 total)"));
        assert!(output.contains("src/lib.rs:10:5"));
        assert!(output.contains("unsafe block"));
        assert!(output.contains("dep_a"));
    }

    #[test]
    fn test_print_check_html_passed() {
        let scan = make_scan_result();
        let check = CheckResult {
            scan,
            violations: vec![],
            warnings: vec![],
            passed: true,
        };

        let mut buf = Vec::new();
        print_check_html(&mut buf, &check, None).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("status-pass"));
        assert!(output.contains("PASSED"));
        assert!(!output.contains("<div class=\"violations-section\">"));
    }

    #[test]
    fn test_print_check_html_failed() {
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
        print_check_html(&mut buf, &check, None).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("status-fail"));
        assert!(output.contains("FAILED"));
        assert!(output.contains("violations-section"));
        assert!(output.contains("Violations (1)"));
        assert!(output.contains("my_crate"));
        assert!(output.contains("budget: 5"));
    }

    #[test]
    fn test_print_check_html_with_warnings() {
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
        print_check_html(&mut buf, &check, None).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("warnings-section"));
        assert!(output.contains("Warnings (1)"));
        assert!(output.contains("my_crate"));
        assert!(output.contains("83%"));
        assert!(output.contains("remaining: 2"));
    }

    #[test]
    fn test_print_check_html_badges() {
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
            warnings: vec![Warning {
                unit: "dep_a".into(),
                kind: UnitKind::Dep,
                budget: 8,
                actual: 5,
            }],
            passed: false,
        };

        let mut buf = Vec::new();
        print_check_html(&mut buf, &check, None).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("badge-fail"));
        assert!(output.contains("badge-warn"));
    }

    #[test]
    fn test_print_plugins_html() {
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
        print_plugins_html(&mut buf, &plugins).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("<!DOCTYPE html>"));
        assert!(output.contains("Available analyzers"));
        assert!(output.contains("rustc"));
        assert!(output.contains("builtin"));
        assert!(output.contains("custom"));
        assert!(output.contains("plugin"));
        assert!(output.contains("/usr/bin/custom"));
    }

    #[test]
    fn test_print_plugins_html_empty() {
        let plugins: Vec<AnalyzerInfo> = vec![];
        let mut buf = Vec::new();
        print_plugins_html(&mut buf, &plugins).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("No analyzers found"));
    }

    #[test]
    fn test_html_escape_in_output() {
        let mut result = make_scan_result();
        result.units[0].name = "<script>alert('xss')</script>".into();
        let mut buf = Vec::new();
        print_scan_html(&mut buf, &result).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("&lt;script&gt;"));
        assert!(!output.contains("<script>alert"));
    }
}
