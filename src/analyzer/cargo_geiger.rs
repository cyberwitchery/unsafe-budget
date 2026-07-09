use crate::analyzer::process::{self, Run};
use crate::analyzer::Analyzer;
use crate::error::{Error, Result};
use crate::model::{Occurrence, ScanOpts, ScanResult, Unit, UnitKind};
use serde::Deserialize;
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

pub struct CargoGeigerAnalyzer;

impl Analyzer for CargoGeigerAnalyzer {
    fn id(&self) -> &str {
        "cargo_geiger"
    }

    fn language(&self) -> &str {
        "rust"
    }

    fn run(&self, opts: &ScanOpts) -> Result<ScanResult> {
        let output = run_cargo_geiger(opts)?;
        let report = parse_geiger_output(&output)?;
        let (units, details) = convert_report(&report, opts);

        Ok(ScanResult::from_parts(
            self.id(),
            self.language(),
            opts,
            units,
            details,
        ))
    }
}

fn run_cargo_geiger(opts: &ScanOpts) -> Result<Vec<u8>> {
    let mut cmd = Command::new("cargo");
    cmd.arg("geiger").arg("--output-format").arg("json");

    super::apply_cargo_flags(&mut cmd, opts);

    let timeout_secs = opts.analyzer_timeout_secs;
    let output = match process::run_process(&mut cmd, timeout_secs.map(Duration::from_secs))? {
        Run::Completed(output) => output,
        Run::TimedOut => {
            return Err(Error::Analyzer {
                analyzer: "cargo_geiger".into(),
                message: format!(
                    "cargo geiger timed out after {}s",
                    timeout_secs.unwrap_or_default()
                ),
            })
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Analyzer {
            analyzer: "cargo_geiger".into(),
            message: format!("cargo geiger failed: {}", stderr),
        });
    }

    Ok(output.stdout)
}

// cargo-geiger JSON output structures
#[derive(Debug, Deserialize)]
struct GeigerReport {
    packages: Vec<GeigerPackage>,
}

#[derive(Debug, Deserialize)]
struct GeigerPackage {
    package: PackageId,
    unsafety: Unsafety,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PackageId {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Unsafety {
    used: UnsafeCount,
    unused: UnsafeCount,
}

#[derive(Debug, Deserialize)]
struct UnsafeCount {
    functions: CountPair,
    exprs: CountPair,
    item_impls: CountPair,
    item_traits: CountPair,
    methods: CountPair,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CountPair {
    safe: u64,
    #[serde(rename = "unsafe")]
    unsafe_: u64,
}

impl UnsafeCount {
    fn total_unsafe(&self) -> u64 {
        self.functions.unsafe_
            + self.exprs.unsafe_
            + self.item_impls.unsafe_
            + self.item_traits.unsafe_
            + self.methods.unsafe_
    }
}

fn parse_geiger_output(output: &[u8]) -> Result<GeigerReport> {
    serde_json::from_slice(output).map_err(|e| Error::Analyzer {
        analyzer: "cargo_geiger".into(),
        message: format!("failed to parse cargo-geiger output: {}", e),
    })
}

fn convert_report(report: &GeigerReport, opts: &ScanOpts) -> (Vec<Unit>, Vec<Occurrence>) {
    let mut counts: HashMap<String, (UnitKind, u64)> = HashMap::new();

    for pkg in &report.packages {
        // determine if workspace or dep based on source
        // workspace packages have no source (path dependencies from workspace)
        let is_workspace = pkg.package.source.is_none();
        let kind = if is_workspace {
            UnitKind::Workspace
        } else {
            UnitKind::Dep
        };

        let unsafe_count = pkg.unsafety.used.total_unsafe() + pkg.unsafety.unused.total_unsafe();

        let entry = counts.entry(pkg.package.name.clone()).or_insert((kind, 0));
        entry.1 += unsafe_count;
    }

    // cargo-geiger doesn't provide line-level details in JSON output
    super::aggregate_units(counts, vec![], opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_count_pair(safe: u64, unsafe_: u64) -> CountPair {
        CountPair { safe, unsafe_ }
    }

    fn make_unsafe_count(
        funcs: u64,
        exprs: u64,
        impls: u64,
        traits: u64,
        methods: u64,
    ) -> UnsafeCount {
        UnsafeCount {
            functions: make_count_pair(0, funcs),
            exprs: make_count_pair(0, exprs),
            item_impls: make_count_pair(0, impls),
            item_traits: make_count_pair(0, traits),
            methods: make_count_pair(0, methods),
        }
    }

    #[test]
    fn test_unsafe_count_total() {
        let count = make_unsafe_count(1, 2, 3, 4, 5);
        assert_eq!(count.total_unsafe(), 15);
    }

    #[test]
    fn test_unsafe_count_total_zeros() {
        let count = make_unsafe_count(0, 0, 0, 0, 0);
        assert_eq!(count.total_unsafe(), 0);
    }

    #[test]
    fn test_parse_geiger_output_valid() {
        let json = r#"{
            "packages": [
                {
                    "package": {"name": "my_crate", "version": "0.1.0"},
                    "unsafety": {
                        "used": {
                            "functions": {"safe": 10, "unsafe": 2},
                            "exprs": {"safe": 100, "unsafe": 5},
                            "item_impls": {"safe": 5, "unsafe": 0},
                            "item_traits": {"safe": 0, "unsafe": 0},
                            "methods": {"safe": 20, "unsafe": 1}
                        },
                        "unused": {
                            "functions": {"safe": 0, "unsafe": 0},
                            "exprs": {"safe": 0, "unsafe": 0},
                            "item_impls": {"safe": 0, "unsafe": 0},
                            "item_traits": {"safe": 0, "unsafe": 0},
                            "methods": {"safe": 0, "unsafe": 0}
                        }
                    }
                }
            ]
        }"#;

        let report = parse_geiger_output(json.as_bytes()).unwrap();
        assert_eq!(report.packages.len(), 1);
        assert_eq!(report.packages[0].package.name, "my_crate");
        assert_eq!(report.packages[0].unsafety.used.total_unsafe(), 8);
    }

    #[test]
    fn test_parse_geiger_output_invalid() {
        let json = r#"{"invalid": true}"#;
        let result = parse_geiger_output(json.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_report_workspace_package() {
        let report = GeigerReport {
            packages: vec![GeigerPackage {
                package: PackageId {
                    name: "my_crate".into(),
                    version: "0.1.0".into(),
                    source: None, // No source = workspace
                },
                unsafety: Unsafety {
                    used: make_unsafe_count(1, 2, 0, 0, 0),
                    unused: make_unsafe_count(0, 0, 0, 0, 0),
                },
            }],
        };

        let opts = ScanOpts::default();
        let (units, details) = convert_report(&report, &opts);

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "my_crate");
        assert_eq!(units[0].kind, UnitKind::Workspace);
        assert_eq!(units[0].unsafe_count, 3);
        assert!(details.is_empty()); // cargo-geiger doesn't provide details
    }

    #[test]
    fn test_convert_report_dependency_package() {
        let report = GeigerReport {
            packages: vec![GeigerPackage {
                package: PackageId {
                    name: "libc".into(),
                    version: "0.2.0".into(),
                    source: Some("registry+https://github.com/rust-lang/crates.io-index".into()),
                },
                unsafety: Unsafety {
                    used: make_unsafe_count(10, 20, 5, 0, 0),
                    unused: make_unsafe_count(0, 0, 0, 0, 0),
                },
            }],
        };

        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, _) = convert_report(&report, &opts);

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "libc");
        assert_eq!(units[0].kind, UnitKind::Dep);
        assert_eq!(units[0].unsafe_count, 35);
    }

    #[test]
    fn test_convert_report_filters_deps_when_workspace_only() {
        let report = GeigerReport {
            packages: vec![
                GeigerPackage {
                    package: PackageId {
                        name: "my_crate".into(),
                        version: "0.1.0".into(),
                        source: None,
                    },
                    unsafety: Unsafety {
                        used: make_unsafe_count(1, 0, 0, 0, 0),
                        unused: make_unsafe_count(0, 0, 0, 0, 0),
                    },
                },
                GeigerPackage {
                    package: PackageId {
                        name: "libc".into(),
                        version: "0.2.0".into(),
                        source: Some("registry".into()),
                    },
                    unsafety: Unsafety {
                        used: make_unsafe_count(100, 0, 0, 0, 0),
                        unused: make_unsafe_count(0, 0, 0, 0, 0),
                    },
                },
            ],
        };

        let opts = ScanOpts {
            workspace_only: true,
            ..Default::default()
        };
        let (units, _) = convert_report(&report, &opts);

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "my_crate");
    }

    #[test]
    fn test_convert_report_filters_deps_when_include_deps_false() {
        let report = GeigerReport {
            packages: vec![
                GeigerPackage {
                    package: PackageId {
                        name: "my_crate".into(),
                        version: "0.1.0".into(),
                        source: None,
                    },
                    unsafety: Unsafety {
                        used: make_unsafe_count(1, 0, 0, 0, 0),
                        unused: make_unsafe_count(0, 0, 0, 0, 0),
                    },
                },
                GeigerPackage {
                    package: PackageId {
                        name: "libc".into(),
                        version: "0.2.0".into(),
                        source: Some("registry".into()),
                    },
                    unsafety: Unsafety {
                        used: make_unsafe_count(100, 0, 0, 0, 0),
                        unused: make_unsafe_count(0, 0, 0, 0, 0),
                    },
                },
            ],
        };

        let opts = ScanOpts {
            include_deps: false,
            ..Default::default()
        };
        let (units, _) = convert_report(&report, &opts);

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "my_crate");
    }

    #[test]
    fn test_convert_report_sorted_output() {
        let report = GeigerReport {
            packages: vec![
                GeigerPackage {
                    package: PackageId {
                        name: "zebra".into(),
                        version: "0.1.0".into(),
                        source: None,
                    },
                    unsafety: Unsafety {
                        used: make_unsafe_count(1, 0, 0, 0, 0),
                        unused: make_unsafe_count(0, 0, 0, 0, 0),
                    },
                },
                GeigerPackage {
                    package: PackageId {
                        name: "alpha".into(),
                        version: "0.1.0".into(),
                        source: None,
                    },
                    unsafety: Unsafety {
                        used: make_unsafe_count(1, 0, 0, 0, 0),
                        unused: make_unsafe_count(0, 0, 0, 0, 0),
                    },
                },
            ],
        };

        let opts = ScanOpts::default();
        let (units, _) = convert_report(&report, &opts);

        assert_eq!(units[0].name, "alpha");
        assert_eq!(units[1].name, "zebra");
    }
}
