use crate::config::{Baseline, Caps, Config, IgnoreEntry, Mode};
use crate::error::{Error, Result};
use crate::model::{CheckResult, ScanResult, Totals, Unit, UnitKind, Violation, Warning};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// check a scan against the baseline (ratchet mode) or the caps (caps mode) of `config`.
///
/// `config.ignore` entries are subtracted from `scan` first, and a baseline recorded by
/// another analyzer is an error.
pub fn check(
    scan: &ScanResult,
    baseline: Option<&Baseline>,
    config: &Config,
) -> Result<CheckResult> {
    config.validate()?;
    if let Some(bl) = baseline {
        if bl.analyzer_id != scan.analyzer_id {
            return Err(Error::Baseline(format!(
                "analyzer mismatch: baseline was created with '{}' but current analyzer is '{}'\n\
                 hint: re-run `unsafe-budget update` with the current analyzer to regenerate the baseline",
                bl.analyzer_id, scan.analyzer_id
            )));
        }
    }
    let scan = apply_ignores(scan.clone(), &config.ignore);
    let unit_map = baseline.map(|b| b.unit_map());

    let violations = match config.mode {
        Mode::Ratchet => {
            let baseline_map = unit_map
                .as_ref()
                .ok_or_else(|| Error::Baseline("ratchet mode requires a baseline file".into()))?;
            check_ratchet(&scan, baseline_map, config)
        }
        Mode::Caps => {
            let caps = config.caps.as_ref().ok_or_else(|| {
                Error::Config("caps mode requires [caps] section in config".into())
            })?;
            check_caps(&scan, caps, config)
        }
    };

    let warnings = compute_warnings(&scan, unit_map.as_ref(), config, &violations);
    let deltas = baseline.map(|b| compute_deltas(&scan, b));

    let passed = violations.is_empty();
    Ok(CheckResult {
        scan,
        violations,
        warnings,
        deltas,
        passed,
    })
}

/// remove the occurrences an `[[ignore]]` entry matches (same file and line) and subtract them from
/// their unit's count and the totals. A no-op without ignores or without occurrence details.
pub(crate) fn apply_ignores(mut result: ScanResult, ignores: &[IgnoreEntry]) -> ScanResult {
    if ignores.is_empty() || result.details.is_empty() {
        return result;
    }

    let ignore_set: HashSet<(&Path, u32)> = ignores
        .iter()
        .map(|rule| (rule.file.as_path(), rule.line))
        .collect();

    let mut removed: HashMap<String, u64> = HashMap::new();
    result.details.retain(|occ| {
        if ignore_set.contains(&(occ.file.as_path(), occ.line)) {
            *removed.entry(occ.unit.clone()).or_default() += 1;
            false
        } else {
            true
        }
    });

    for unit in &mut result.units {
        if let Some(n) = removed.get(&unit.name) {
            unit.unsafe_count = unit.unsafe_count.saturating_sub(*n);
        }
    }

    result.totals = Totals::from_units(&result.units);

    result
}

fn compute_warnings(
    scan: &ScanResult,
    baseline_map: Option<&HashMap<&str, u64>>,
    config: &Config,
    violations: &[Violation],
) -> Vec<Warning> {
    let threshold = match &config.warnings {
        Some(w) => w.threshold,
        None => return Vec::new(),
    };

    let violating_units: HashSet<&str> = violations.iter().map(|v| v.unit.as_str()).collect();
    let mut warnings = Vec::new();

    for unit in &scan.units {
        if config.ignore_units.contains(&unit.name) {
            continue;
        }
        if violating_units.contains(unit.name.as_str()) {
            continue;
        }

        let Some(budget) = budget_for_unit(unit, baseline_map, config) else {
            continue;
        };
        if budget == 0 {
            continue;
        }

        let usage_ratio = unit.unsafe_count as f64 / budget as f64;
        if usage_ratio >= threshold {
            warnings.push(Warning {
                unit: unit.name.clone(),
                kind: unit.kind,
                budget,
                actual: unit.unsafe_count,
            });
        }
    }

    warnings.sort_by(|a, b| {
        let a_remaining = a.budget.saturating_sub(a.actual);
        let b_remaining = b.budget.saturating_sub(b.actual);
        a_remaining
            .cmp(&b_remaining)
            .then_with(|| b.actual.cmp(&a.actual))
            .then_with(|| a.unit.cmp(&b.unit))
    });

    warnings
}

fn budget_for_unit(
    unit: &Unit,
    baseline_map: Option<&HashMap<&str, u64>>,
    config: &Config,
) -> Option<u64> {
    match config.mode {
        Mode::Ratchet => Some(
            baseline_map
                .and_then(|m| m.get(unit.name.as_str()).copied())
                .unwrap_or(0),
        ),
        Mode::Caps => {
            let caps = config.caps.as_ref()?;
            resolve_cap(caps, unit)
        }
    }
}

/// look up the cap for a unit from the caps configuration.
fn resolve_cap(caps: &Caps, unit: &Unit) -> Option<u64> {
    match unit.kind {
        UnitKind::Workspace => caps.workspace.get(&unit.name).copied().or(caps.default),
        UnitKind::Dep => caps.deps.get(&unit.name).copied().or(caps.default),
    }
}

/// sort violations by delta (descending), then by unit name (ascending).
fn sort_violations(violations: &mut [Violation]) {
    violations.sort_by(|a, b| b.delta.cmp(&a.delta).then_with(|| a.unit.cmp(&b.unit)));
}

/// collect violations by iterating scan units, skipping ignored ones, resolving
/// a baseline value via the provided closure, and flagging any unit whose count
/// exceeds its baseline.  Returns `None` from the closure to skip a unit.
fn collect_violations(
    scan: &ScanResult,
    config: &Config,
    resolve_baseline: impl Fn(&Unit) -> Option<u64>,
) -> Vec<Violation> {
    let mut violations = Vec::new();

    for unit in &scan.units {
        if config.ignore_units.contains(&unit.name) {
            continue;
        }

        let Some(baseline) = resolve_baseline(unit) else {
            continue;
        };

        let delta = unit.unsafe_count as i64 - baseline as i64;

        if delta > 0 {
            violations.push(Violation {
                unit: unit.name.clone(),
                kind: unit.kind,
                baseline,
                actual: unit.unsafe_count,
                delta,
            });
        }
    }

    sort_violations(&mut violations);
    violations
}

/// check against ratchet baseline - fail if any unit exceeds its baseline count.
fn check_ratchet(
    scan: &ScanResult,
    baseline_map: &HashMap<&str, u64>,
    config: &Config,
) -> Vec<Violation> {
    collect_violations(scan, config, |unit| {
        Some(baseline_map.get(unit.name.as_str()).copied().unwrap_or(0))
    })
}

/// check against explicit caps.
fn check_caps(scan: &ScanResult, caps: &Caps, config: &Config) -> Vec<Violation> {
    collect_violations(scan, config, |unit| resolve_cap(caps, unit))
}

/// compute deltas between scan and baseline for reporting (non-failing).
fn compute_deltas(scan: &ScanResult, baseline: &Baseline) -> HashMap<String, i64> {
    let baseline_map = baseline.unit_map();

    scan.units
        .iter()
        .map(|u| {
            let baseline_count = baseline_map.get(u.name.as_str()).copied().unwrap_or(0);
            let delta = u.unsafe_count as i64 - baseline_count as i64;
            (u.name.clone(), delta)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Occurrence, Scope, Totals, Unit};
    use std::path::PathBuf;

    fn make_scan(units: Vec<(&str, UnitKind, u64)>) -> ScanResult {
        let units: Vec<Unit> = units
            .into_iter()
            .map(|(name, kind, count)| Unit {
                name: name.into(),
                kind,
                unsafe_count: count,
            })
            .collect();

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

        ScanResult {
            tool_version: "0.1.0".into(),
            analyzer_id: "test".into(),
            language: "rust".into(),
            scope: Scope {
                include_deps: true,
                features: vec![],
                all_features: false,
                no_default_features: false,
                all_targets: false,
                targets: vec![],
                manifest_path: None,
            },
            units,
            totals: Totals {
                workspace_unsafe,
                deps_unsafe,
                overall_unsafe: workspace_unsafe + deps_unsafe,
            },
            details: vec![],
            parse_warnings: vec![],
        }
    }

    fn make_baseline(units: Vec<(&str, UnitKind, u64)>) -> Baseline {
        use crate::config::BaselineUnit;
        Baseline {
            tool_version: "0.1.0".into(),
            analyzer_id: "test".into(),
            scope: Scope {
                include_deps: true,
                features: vec![],
                all_features: false,
                no_default_features: false,
                all_targets: false,
                targets: vec![],
                manifest_path: None,
            },
            totals: Totals::default(),
            units: units
                .into_iter()
                .map(|(name, kind, count)| BaselineUnit {
                    name: name.into(),
                    kind,
                    unsafe_count: count,
                })
                .collect(),
        }
    }

    #[test]
    fn test_ratchet_requires_baseline() {
        let scan = make_scan(vec![]);
        let config = Config::default();

        let result = check(&scan, None, &config);
        assert!(
            matches!(result, Err(Error::Baseline(ref m)) if m == "ratchet mode requires a baseline file")
        );
    }

    #[test]
    fn test_caps_requires_caps_section() {
        let scan = make_scan(vec![]);
        let config = Config {
            mode: Mode::Caps,
            caps: None,
            ..Config::default()
        };

        let result = check(&scan, None, &config);
        assert!(
            matches!(result, Err(Error::Config(ref m)) if m == "caps mode requires [caps] section in config")
        );
    }

    #[test]
    fn test_threshold_warning_invalid_threshold_fails() {
        let scan = make_scan(vec![("my_crate", UnitKind::Workspace, 8)]);
        let config = Config {
            mode: Mode::Caps,
            caps: Some(Caps {
                default: None,
                workspace: [("my_crate".into(), 10)].into_iter().collect(),
                deps: HashMap::new(),
            }),
            warnings: Some(crate::config::Warnings { threshold: 1.1 }),
            ..Config::default()
        };

        let result = check(&scan, None, &config);
        assert!(
            matches!(result, Err(Error::Config(ref m)) if m.contains("between 0.0 and 1.0, got 1.1"))
        );
    }

    fn make_caps(default: Option<u64>, workspace: &[(&str, u64)], deps: &[(&str, u64)]) -> Caps {
        Caps {
            default,
            workspace: workspace.iter().map(|(n, c)| ((*n).into(), *c)).collect(),
            deps: deps.iter().map(|(n, c)| ((*n).into(), *c)).collect(),
        }
    }

    type Units<'a> = Vec<(&'a str, UnitKind, u64)>;
    type Violations<'a> = Vec<(&'a str, u64, u64, i64)>;

    fn violation_rows(result: &CheckResult) -> Violations<'_> {
        result
            .violations
            .iter()
            .map(|v| (v.unit.as_str(), v.baseline, v.actual, v.delta))
            .collect()
    }

    #[test]
    fn test_ratchet() {
        let ws = UnitKind::Workspace;
        let dep = UnitKind::Dep;
        let baseline = vec![("my_crate", ws, 10), ("libc", dep, 20)];
        // name, scan, baseline, ignore_units -> violations
        type Case<'a> = (&'a str, Units<'a>, Units<'a>, Vec<&'a str>, Violations<'a>);
        let cases: Vec<Case> = vec![
            (
                "same",
                vec![("my_crate", ws, 10), ("libc", dep, 20)],
                baseline.clone(),
                vec![],
                vec![],
            ),
            (
                "decreased",
                vec![("my_crate", ws, 5), ("libc", dep, 15)],
                baseline.clone(),
                vec![],
                vec![],
            ),
            (
                "increased",
                vec![("my_crate", ws, 15), ("libc", dep, 20)],
                baseline.clone(),
                vec![],
                vec![("my_crate", 10, 15, 5)],
            ),
            (
                "new unit counts against zero",
                vec![("my_crate", ws, 10), ("new_dep", dep, 5)],
                vec![("my_crate", ws, 10)],
                vec![],
                vec![("new_dep", 0, 5, 5)],
            ),
            (
                "ignored unit",
                vec![("my_crate", ws, 100), ("libc", dep, 20)],
                baseline.clone(),
                vec!["my_crate"],
                vec![],
            ),
        ];
        for (name, scan, base, ignore, expected) in cases {
            let config = Config {
                ignore_units: ignore.into_iter().map(String::from).collect(),
                ..Config::default()
            };
            let result = check(&make_scan(scan), Some(&make_baseline(base)), &config).unwrap();
            assert_eq!(violation_rows(&result), expected, "{name}");
            assert_eq!(result.passed, expected.is_empty(), "{name}");
            assert!(result.warnings.is_empty(), "{name}");
        }
    }

    #[test]
    fn test_caps() {
        let ws = UnitKind::Workspace;
        let dep = UnitKind::Dep;
        type Case<'a> = (&'a str, Units<'a>, Caps, Violations<'a>);
        let cases: Vec<Case> = vec![
            (
                "under explicit and default caps",
                vec![("my_crate", ws, 5), ("libc", dep, 100)],
                make_caps(Some(200), &[("my_crate", 10)], &[]),
                vec![],
            ),
            (
                "over explicit workspace cap",
                vec![("my_crate", ws, 15)],
                make_caps(None, &[("my_crate", 10)], &[]),
                vec![("my_crate", 10, 15, 5)],
            ),
            (
                "dep over default",
                vec![("some_dep", dep, 50)],
                make_caps(Some(20), &[], &[]),
                vec![("some_dep", 20, 50, 30)],
            ),
            (
                "dep-specific cap overrides default",
                vec![("libc", dep, 100), ("other", dep, 50)],
                make_caps(Some(20), &[], &[("libc", 200)]),
                vec![("other", 20, 50, 30)],
            ),
            (
                "workspace over default",
                vec![("unlisted_crate", ws, 150)],
                make_caps(Some(100), &[], &[]),
                vec![("unlisted_crate", 100, 150, 50)],
            ),
            (
                "explicit workspace cap overrides default",
                vec![("my_crate", ws, 15)],
                make_caps(Some(100), &[("my_crate", 10)], &[]),
                vec![("my_crate", 10, 15, 5)],
            ),
            (
                "workspace mixed explicit and default",
                vec![
                    ("explicit_crate", ws, 8),
                    ("default_crate", ws, 50),
                    ("over_default", ws, 200),
                ],
                make_caps(Some(100), &[("explicit_crate", 10)], &[]),
                vec![("over_default", 100, 200, 100)],
            ),
            (
                "no default and no explicit cap is unchecked",
                vec![("unlisted_crate", ws, 9999)],
                make_caps(None, &[], &[]),
                vec![],
            ),
            (
                "default applies to workspace and deps",
                vec![("ws_crate", ws, 150), ("some_dep", dep, 150)],
                make_caps(Some(100), &[], &[]),
                vec![("some_dep", 100, 150, 50), ("ws_crate", 100, 150, 50)],
            ),
        ];
        for (name, scan, caps, expected) in cases {
            let config = Config {
                mode: Mode::Caps,
                caps: Some(caps),
                ..Config::default()
            };
            let result = check(&make_scan(scan), None, &config).unwrap();
            assert_eq!(violation_rows(&result), expected, "{name}");
            assert_eq!(result.passed, expected.is_empty(), "{name}");
            assert!(result.warnings.is_empty(), "{name}");
        }
    }

    #[test]
    fn test_caps_threshold_warnings() {
        // unit, count, caps -> violating units, warnings (unit, budget, actual)
        type Case<'a> = (&'a str, u64, Caps, Vec<&'a str>, Vec<(&'a str, u64, u64)>);
        let cases: Vec<Case> = vec![
            (
                "my_crate",
                8,
                make_caps(None, &[("my_crate", 10)], &[]),
                vec![],
                vec![("my_crate", 10, 8)],
            ),
            (
                "my_crate",
                7,
                make_caps(None, &[("my_crate", 10)], &[]),
                vec![],
                vec![],
            ),
            (
                "my_crate",
                11,
                make_caps(None, &[("my_crate", 10)], &[]),
                vec!["my_crate"],
                vec![],
            ),
            (
                "unlisted_crate",
                85,
                make_caps(Some(100), &[], &[]),
                vec![],
                vec![("unlisted_crate", 100, 85)],
            ),
        ];
        for (unit, count, caps, violations, warnings) in cases {
            let config = Config {
                mode: Mode::Caps,
                caps: Some(caps),
                warnings: Some(crate::config::Warnings { threshold: 0.8 }),
                ..Config::default()
            };
            let scan = make_scan(vec![(unit, UnitKind::Workspace, count)]);
            let result = check(&scan, None, &config).unwrap();
            let got: Vec<&str> = result.violations.iter().map(|v| v.unit.as_str()).collect();
            assert_eq!(got, violations, "{unit} {count}");
            let got: Vec<(&str, u64, u64)> = result
                .warnings
                .iter()
                .map(|w| (w.unit.as_str(), w.budget, w.actual))
                .collect();
            assert_eq!(got, warnings, "{unit} {count}");
        }
    }

    fn make_scope() -> Scope {
        Scope {
            include_deps: true,
            features: vec![],
            all_features: false,
            no_default_features: false,
            all_targets: false,
            targets: vec![],
            manifest_path: None,
        }
    }

    fn make_result_with_details() -> ScanResult {
        ScanResult {
            tool_version: "0.1.0".into(),
            analyzer_id: "rustc_unsafe_lint".into(),
            language: "rust".into(),
            scope: make_scope(),
            units: vec![
                Unit {
                    name: "my_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 3,
                },
                Unit {
                    name: "other_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 1,
                },
            ],
            totals: Totals {
                workspace_unsafe: 4,
                deps_unsafe: 0,
                overall_unsafe: 4,
            },
            details: vec![
                Occurrence {
                    unit: "my_crate".into(),
                    file: PathBuf::from("src/lib.rs"),
                    line: 10,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "my_crate".into(),
                    file: PathBuf::from("src/lib.rs"),
                    line: 20,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "my_crate".into(),
                    file: PathBuf::from("src/ffi.rs"),
                    line: 42,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "other_crate".into(),
                    file: PathBuf::from("other/src/lib.rs"),
                    line: 5,
                    col: 1,
                    message: None,
                },
            ],
            parse_warnings: vec![],
        }
    }

    fn make_result_without_details() -> ScanResult {
        ScanResult {
            tool_version: "0.1.0".into(),
            analyzer_id: "cargo_geiger".into(),
            language: "rust".into(),
            scope: make_scope(),
            units: vec![
                Unit {
                    name: "my_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 10,
                },
                Unit {
                    name: "libc".into(),
                    kind: UnitKind::Dep,
                    unsafe_count: 200,
                },
            ],
            totals: Totals {
                workspace_unsafe: 10,
                deps_unsafe: 200,
                overall_unsafe: 210,
            },
            details: vec![],
            parse_warnings: vec![],
        }
    }

    /// a plugin's self-reported counts alongside an incomplete occurrence list.
    fn make_result_with_partial_details() -> ScanResult {
        ScanResult {
            tool_version: "0.1.0".into(),
            analyzer_id: "my_plugin".into(),
            language: "rust".into(),
            scope: make_scope(),
            units: vec![
                Unit {
                    name: "plugin_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 12,
                },
                Unit {
                    name: "other_crate".into(),
                    kind: UnitKind::Workspace,
                    unsafe_count: 1,
                },
            ],
            totals: Totals {
                workspace_unsafe: 13,
                deps_unsafe: 0,
                overall_unsafe: 13,
            },
            details: vec![
                Occurrence {
                    unit: "plugin_crate".into(),
                    file: PathBuf::from("src/a.rs"),
                    line: 1,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "plugin_crate".into(),
                    file: PathBuf::from("src/a.rs"),
                    line: 2,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "plugin_crate".into(),
                    file: PathBuf::from("src/b.rs"),
                    line: 3,
                    col: 1,
                    message: None,
                },
                Occurrence {
                    unit: "other_crate".into(),
                    file: PathBuf::from("other/src/lib.rs"),
                    line: 5,
                    col: 1,
                    message: None,
                },
            ],
            parse_warnings: vec![],
        }
    }

    #[test]
    fn ignore_filter_no_details_preserves_counts() {
        // aggregate counts with no details (cargo_geiger's output shape)
        let ignore = |file: &str, line| IgnoreEntry {
            file: PathBuf::from(file),
            line,
            reason: None,
        };
        let cases = [
            vec![ignore("src/lib.rs", 10)],
            vec![
                ignore("src/lib.rs", 10),
                ignore("src/ffi.rs", 42),
                ignore("vendor/libc/src/lib.rs", 1),
            ],
        ];
        for ignores in cases {
            let filtered = apply_ignores(make_result_without_details(), &ignores);

            // counts must not be zeroed
            assert_eq!(filtered.units[0].unsafe_count, 10);
            assert_eq!(filtered.units[1].unsafe_count, 200);
            assert_eq!(filtered.totals.workspace_unsafe, 10);
            assert_eq!(filtered.totals.deps_unsafe, 200);
            assert_eq!(filtered.totals.overall_unsafe, 210);
        }
    }

    #[test]
    fn ignore_filter_keeps_count_of_unit_with_partial_details() {
        let result = make_result_with_partial_details();
        let ignores = vec![IgnoreEntry {
            file: PathBuf::from("other/src/lib.rs"),
            line: 5,
            reason: None,
        }];
        let filtered = apply_ignores(result, &ignores);

        assert_eq!(filtered.units[0].unsafe_count, 12); // untouched by the ignore
        assert_eq!(filtered.units[1].unsafe_count, 0); // its only occurrence removed
        assert_eq!(filtered.totals.overall_unsafe, 12);
    }

    #[test]
    fn ignore_filter_subtracts_from_unit_with_partial_details() {
        let result = make_result_with_partial_details();
        let ignores = vec![IgnoreEntry {
            file: PathBuf::from("src/a.rs"),
            line: 2,
            reason: None,
        }];
        let filtered = apply_ignores(result, &ignores);

        assert_eq!(filtered.details.len(), 3);
        assert_eq!(filtered.units[0].unsafe_count, 11); // 12 - 1
        assert_eq!(filtered.units[1].unsafe_count, 1);
        assert_eq!(filtered.totals.overall_unsafe, 12);
    }

    #[test]
    fn ignore_filter_saturates_when_occurrences_exceed_count() {
        let mut result = make_result_with_partial_details();
        result.units[0].unsafe_count = 2;
        let ignores = vec![
            IgnoreEntry {
                file: PathBuf::from("src/a.rs"),
                line: 1,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("src/a.rs"),
                line: 2,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("src/b.rs"),
                line: 3,
                reason: None,
            },
        ];
        let filtered = apply_ignores(result, &ignores);

        assert_eq!(filtered.units[0].unsafe_count, 0);
        assert_eq!(filtered.totals.overall_unsafe, 1);
    }

    #[test]
    fn ignore_filter_subtraction_equals_recompute_when_details_complete() {
        let result = make_result_with_details();
        let ignores = vec![
            IgnoreEntry {
                file: PathBuf::from("src/lib.rs"),
                line: 20,
                reason: None,
            },
            IgnoreEntry {
                file: PathBuf::from("other/src/lib.rs"),
                line: 5,
                reason: None,
            },
        ];
        let filtered = apply_ignores(result, &ignores);

        let mut surviving: HashMap<&str, u64> = HashMap::new();
        for occ in &filtered.details {
            *surviving.entry(occ.unit.as_str()).or_default() += 1;
        }
        for unit in &filtered.units {
            assert_eq!(
                unit.unsafe_count,
                surviving.get(unit.name.as_str()).copied().unwrap_or(0),
                "unit {}",
                unit.name
            );
        }
        assert_eq!(filtered.totals.overall_unsafe, 2);
    }

    #[test]
    fn ignore_filter_recomputes_dep_totals() {
        let mut result = make_result_with_details();
        // add a dep unit with a detail occurrence.
        result.units.push(Unit {
            name: "dep_crate".into(),
            kind: UnitKind::Dep,
            unsafe_count: 1,
        });
        result.details.push(Occurrence {
            unit: "dep_crate".into(),
            file: PathBuf::from("dep/src/lib.rs"),
            line: 3,
            col: 1,
            message: None,
        });
        result.totals = Totals::from_units(&result.units);

        let ignores = vec![IgnoreEntry {
            file: PathBuf::from("dep/src/lib.rs"),
            line: 3,
            reason: None,
        }];
        let filtered = apply_ignores(result, &ignores);

        assert_eq!(filtered.units[2].unsafe_count, 0); // dep_crate filtered
        assert_eq!(filtered.totals.deps_unsafe, 0);
        assert_eq!(filtered.totals.workspace_unsafe, 4); // unchanged
        assert_eq!(filtered.totals.overall_unsafe, 4);
    }

    #[test]
    fn check_gives_the_cli_verdict() {
        let mut baseline = make_baseline(vec![
            ("my_crate", UnitKind::Workspace, 2),
            ("other_crate", UnitKind::Workspace, 1),
        ]);
        let ffi = IgnoreEntry {
            file: PathBuf::from("src/ffi.rs"),
            line: 42,
            reason: None,
        };
        // name, baseline analyzer, ignores -> (passed, my_crate count, my_crate delta) or error
        type Case<'a> = (
            &'a str,
            &'a str,
            Vec<IgnoreEntry>,
            std::result::Result<(bool, u64, i64), &'a str>,
        );
        let cases: Vec<Case> = vec![
            (
                "ignored",
                "rustc_unsafe_lint",
                vec![ffi.clone()],
                Ok((true, 2, 0)),
            ),
            (
                "not ignored",
                "rustc_unsafe_lint",
                vec![],
                Ok((false, 3, 1)),
            ),
            (
                "other analyzer",
                "cargo_geiger",
                vec![ffi],
                Err("analyzer mismatch"),
            ),
        ];
        for (name, analyzer, ignore, expected) in cases {
            baseline.analyzer_id = analyzer.into();
            let config = Config {
                ignore,
                ..Config::default()
            };
            let got = match check(&make_result_with_details(), Some(&baseline), &config) {
                Ok(r) => Ok((
                    r.passed,
                    r.scan.units[0].unsafe_count,
                    r.deltas.unwrap()["my_crate"],
                )),
                Err(Error::Baseline(m)) => Err(m),
                Err(e) => panic!("{name}: {e}"),
            };
            match (got, expected) {
                (Err(m), Err(want)) => assert!(m.starts_with(want), "{name}: {m}"),
                (got, want) => assert_eq!(got, want.map_err(String::from), "{name}"),
            }
        }
    }

    #[test]
    fn ignore_filter_matches_file_and_line() {
        let ignore = |file: &str, line| IgnoreEntry {
            file: PathBuf::from(file),
            line,
            reason: None,
        };
        // name, ignores -> details left, per-unit counts, (workspace, deps, overall)
        type Case<'a> = (&'a str, Vec<IgnoreEntry>, usize, [u64; 2], (u64, u64, u64));
        let cases: Vec<Case> = vec![
            ("no ignores", vec![], 4, [3, 1], (4, 0, 4)),
            (
                "one match",
                vec![IgnoreEntry {
                    file: PathBuf::from("src/ffi.rs"),
                    line: 42,
                    reason: Some("reviewed".into()),
                }],
                3,
                [2, 1],
                (3, 0, 3),
            ),
            (
                "two matches",
                vec![ignore("src/lib.rs", 10), ignore("src/ffi.rs", 42)],
                2,
                [1, 1],
                (2, 0, 2),
            ),
            (
                "wrong file and line",
                vec![ignore("src/nonexistent.rs", 999)],
                4,
                [3, 1],
                (4, 0, 4),
            ),
            (
                "right file, wrong line",
                vec![ignore("src/ffi.rs", 99)],
                4,
                [3, 1],
                (4, 0, 4),
            ),
            (
                "every occurrence",
                vec![
                    ignore("src/lib.rs", 10),
                    ignore("src/lib.rs", 20),
                    ignore("src/ffi.rs", 42),
                    ignore("other/src/lib.rs", 5),
                ],
                0,
                [0, 0],
                (0, 0, 0),
            ),
        ];
        for (name, ignores, details, counts, totals) in cases {
            let filtered = apply_ignores(make_result_with_details(), &ignores);
            assert_eq!(filtered.details.len(), details, "{name}");
            assert_eq!(
                [
                    filtered.units[0].unsafe_count,
                    filtered.units[1].unsafe_count
                ],
                counts,
                "{name}"
            );
            assert_eq!(
                (
                    filtered.totals.workspace_unsafe,
                    filtered.totals.deps_unsafe,
                    filtered.totals.overall_unsafe
                ),
                totals,
                "{name}"
            );
        }
    }
}
