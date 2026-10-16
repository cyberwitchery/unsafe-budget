use crate::config::{Baseline, Caps, Config, Mode};
use crate::error::{Error, Result};
use crate::model::{CheckResult, ScanResult, Unit, UnitKind, Violation, Warning};
use std::collections::{HashMap, HashSet};

/// check scan results against baseline/caps based on config mode.
pub fn check(
    scan: &ScanResult,
    baseline: Option<&Baseline>,
    config: &Config,
) -> Result<CheckResult> {
    let unit_map = baseline.map(|b| b.unit_map());

    let violations = match config.mode {
        Mode::Ratchet => {
            let baseline_map = unit_map
                .as_ref()
                .ok_or_else(|| Error::Baseline("ratchet mode requires a baseline file".into()))?;
            check_ratchet(scan, baseline_map, config)
        }
        Mode::Caps => {
            let caps = config.caps.as_ref().ok_or_else(|| {
                Error::Config("caps mode requires [caps] section in config".into())
            })?;
            check_caps(scan, caps, config)
        }
    };

    let warnings = compute_warnings(scan, unit_map.as_ref(), config, &violations)?;

    let passed = violations.is_empty();
    Ok(CheckResult {
        scan: scan.clone(),
        violations,
        warnings,
        passed,
    })
}

fn compute_warnings(
    scan: &ScanResult,
    baseline_map: Option<&HashMap<&str, u64>>,
    config: &Config,
    violations: &[Violation],
) -> Result<Vec<Warning>> {
    let threshold = match &config.warnings {
        Some(w) => w.threshold,
        None => return Ok(Vec::new()),
    };

    if !(0.0..=1.0).contains(&threshold) {
        return Err(Error::Config(format!(
            "warnings.threshold must be between 0.0 and 1.0, got {}",
            threshold
        )));
    }

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

    Ok(warnings)
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
pub fn compute_deltas(scan: &ScanResult, baseline: &Baseline) -> HashMap<String, i64> {
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
    use crate::model::{Scope, Totals, Unit};

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
                workspace_only: false,
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
                workspace_only: false,
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
}
