use crate::config::{Baseline, Caps, Config, Mode};
use crate::error::{Error, Result};
use crate::model::{CheckResult, ScanResult, UnitKind, Violation};
use std::collections::HashMap;

/// Check scan results against baseline/caps based on config mode.
pub fn check(
    scan: &ScanResult,
    baseline: Option<&Baseline>,
    config: &Config,
) -> Result<CheckResult> {
    let violations = match config.mode {
        Mode::Ratchet => {
            let baseline = baseline
                .ok_or_else(|| Error::Baseline("ratchet mode requires a baseline file".into()))?;
            check_ratchet(scan, baseline, config)
        }
        Mode::Caps => {
            let caps = config.caps.as_ref().ok_or_else(|| {
                Error::Config("caps mode requires [caps] section in config".into())
            })?;
            check_caps(scan, caps, config)
        }
    };

    let passed = violations.is_empty();
    Ok(CheckResult {
        scan: scan.clone(),
        violations,
        passed,
    })
}

/// Check against ratchet baseline - fail if any unit exceeds its baseline count.
fn check_ratchet(scan: &ScanResult, baseline: &Baseline, config: &Config) -> Vec<Violation> {
    let baseline_map: HashMap<&str, u64> = baseline
        .units
        .iter()
        .map(|u| (u.name.as_str(), u.unsafe_count))
        .collect();

    let mut violations = Vec::new();

    for unit in &scan.units {
        if config.ignore_units.contains(&unit.name) {
            continue;
        }

        let baseline_count = baseline_map.get(unit.name.as_str()).copied().unwrap_or(0);
        let delta = unit.unsafe_count as i64 - baseline_count as i64;

        if delta > 0 {
            violations.push(Violation {
                unit: unit.name.clone(),
                kind: unit.kind,
                baseline: baseline_count,
                actual: unit.unsafe_count,
                delta,
            });
        }
    }

    violations.sort_by(|a, b| b.delta.cmp(&a.delta).then_with(|| a.unit.cmp(&b.unit)));
    violations
}

/// Check against explicit caps.
fn check_caps(scan: &ScanResult, caps: &Caps, config: &Config) -> Vec<Violation> {
    let mut violations = Vec::new();

    for unit in &scan.units {
        if config.ignore_units.contains(&unit.name) {
            continue;
        }

        let cap = match unit.kind {
            UnitKind::Workspace => caps.workspace.get(&unit.name).copied(),
            UnitKind::Dep => caps.deps.get(&unit.name).copied().or(caps.default),
        };

        if let Some(cap) = cap {
            if unit.unsafe_count > cap {
                violations.push(Violation {
                    unit: unit.name.clone(),
                    kind: unit.kind,
                    baseline: cap,
                    actual: unit.unsafe_count,
                    delta: unit.unsafe_count as i64 - cap as i64,
                });
            }
        }
    }

    violations.sort_by(|a, b| b.delta.cmp(&a.delta).then_with(|| a.unit.cmp(&b.unit)));
    violations
}

/// Compute deltas between scan and baseline for reporting (non-failing).
pub fn compute_deltas(scan: &ScanResult, baseline: &Baseline) -> HashMap<String, i64> {
    let baseline_map: HashMap<&str, u64> = baseline
        .units
        .iter()
        .map(|u| (u.name.as_str(), u.unsafe_count))
        .collect();

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
    fn test_ratchet_pass_same() {
        let scan = make_scan(vec![
            ("my_crate", UnitKind::Workspace, 10),
            ("libc", UnitKind::Dep, 20),
        ]);
        let baseline = make_baseline(vec![
            ("my_crate", UnitKind::Workspace, 10),
            ("libc", UnitKind::Dep, 20),
        ]);
        let config = Config::default();

        let result = check(&scan, Some(&baseline), &config).unwrap();
        assert!(result.passed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_ratchet_pass_decreased() {
        let scan = make_scan(vec![
            ("my_crate", UnitKind::Workspace, 5),
            ("libc", UnitKind::Dep, 15),
        ]);
        let baseline = make_baseline(vec![
            ("my_crate", UnitKind::Workspace, 10),
            ("libc", UnitKind::Dep, 20),
        ]);
        let config = Config::default();

        let result = check(&scan, Some(&baseline), &config).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_ratchet_fail_increased() {
        let scan = make_scan(vec![
            ("my_crate", UnitKind::Workspace, 15),
            ("libc", UnitKind::Dep, 20),
        ]);
        let baseline = make_baseline(vec![
            ("my_crate", UnitKind::Workspace, 10),
            ("libc", UnitKind::Dep, 20),
        ]);
        let config = Config::default();

        let result = check(&scan, Some(&baseline), &config).unwrap();
        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].unit, "my_crate");
        assert_eq!(result.violations[0].delta, 5);
    }

    #[test]
    fn test_ratchet_fail_new_unit() {
        let scan = make_scan(vec![
            ("my_crate", UnitKind::Workspace, 10),
            ("new_dep", UnitKind::Dep, 5),
        ]);
        let baseline = make_baseline(vec![("my_crate", UnitKind::Workspace, 10)]);
        let config = Config::default();

        let result = check(&scan, Some(&baseline), &config).unwrap();
        assert!(!result.passed);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].unit, "new_dep");
    }

    #[test]
    fn test_ratchet_ignore_units() {
        let scan = make_scan(vec![
            ("my_crate", UnitKind::Workspace, 100),
            ("libc", UnitKind::Dep, 20),
        ]);
        let baseline = make_baseline(vec![
            ("my_crate", UnitKind::Workspace, 10),
            ("libc", UnitKind::Dep, 20),
        ]);
        let config = Config {
            ignore_units: vec!["my_crate".into()],
            ..Config::default()
        };

        let result = check(&scan, Some(&baseline), &config).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_caps_pass() {
        let scan = make_scan(vec![
            ("my_crate", UnitKind::Workspace, 5),
            ("libc", UnitKind::Dep, 100),
        ]);
        let config = Config {
            mode: Mode::Caps,
            caps: Some(Caps {
                default: Some(200),
                workspace: [("my_crate".into(), 10)].into_iter().collect(),
                deps: HashMap::new(),
            }),
            ..Config::default()
        };

        let result = check(&scan, None, &config).unwrap();
        assert!(result.passed);
    }

    #[test]
    fn test_caps_fail_workspace() {
        let scan = make_scan(vec![("my_crate", UnitKind::Workspace, 15)]);
        let config = Config {
            mode: Mode::Caps,
            caps: Some(Caps {
                default: None,
                workspace: [("my_crate".into(), 10)].into_iter().collect(),
                deps: HashMap::new(),
            }),
            ..Config::default()
        };

        let result = check(&scan, None, &config).unwrap();
        assert!(!result.passed);
        assert_eq!(result.violations[0].delta, 5);
    }

    #[test]
    fn test_caps_fail_dep_default() {
        let scan = make_scan(vec![("some_dep", UnitKind::Dep, 50)]);
        let config = Config {
            mode: Mode::Caps,
            caps: Some(Caps {
                default: Some(20),
                workspace: HashMap::new(),
                deps: HashMap::new(),
            }),
            ..Config::default()
        };

        let result = check(&scan, None, &config).unwrap();
        assert!(!result.passed);
        assert_eq!(result.violations[0].unit, "some_dep");
    }

    #[test]
    fn test_caps_dep_specific_override() {
        let scan = make_scan(vec![
            ("libc", UnitKind::Dep, 100),
            ("other", UnitKind::Dep, 50),
        ]);
        let config = Config {
            mode: Mode::Caps,
            caps: Some(Caps {
                default: Some(20),
                workspace: HashMap::new(),
                deps: [("libc".into(), 200)].into_iter().collect(),
            }),
            ..Config::default()
        };

        let result = check(&scan, None, &config).unwrap();
        assert!(!result.passed);
        // libc passes (100 < 200), other fails (50 > 20)
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].unit, "other");
    }

    #[test]
    fn test_ratchet_requires_baseline() {
        let scan = make_scan(vec![]);
        let config = Config::default();

        let result = check(&scan, None, &config);
        assert!(result.is_err());
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
        assert!(result.is_err());
    }
}
