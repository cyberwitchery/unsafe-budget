use crate::analyzer::process::{self, Run};
use crate::analyzer::Analyzer;
use crate::error::{Error, Result};
use crate::model::{ParseWarning, ScanOpts, ScanResult, Unit, UnitKind};
use cargo_metadata::{MetadataCommand, Package};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
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
        let members = get_workspace_members(opts)?;
        let mut reports = Vec::with_capacity(members.len());
        for member in &members {
            let mut cmd = build_cargo_geiger_command(opts, member)?;
            let output = run_cargo_geiger(&mut cmd, opts)?;
            reports.push(parse_geiger_output(&output)?);
        }
        let (units, warnings) = convert_reports(&reports, &members, opts);

        // cargo-geiger doesn't provide line-level details in JSON output
        let mut result =
            ScanResult::from_parts(self.id(), self.language(), opts, units, Vec::new());
        result.parse_warnings = warnings;
        Ok(result)
    }
}

struct Member {
    name: String,
    version: String,
    manifest_path: PathBuf,
    features: Vec<String>,
}

/// get the workspace member packages, each with the requested features that apply to it.
fn get_workspace_members(opts: &ScanOpts) -> Result<Vec<Member>> {
    let mut cmd = MetadataCommand::new();
    cmd.no_deps();

    if let Some(ref manifest_path) = opts.manifest_path {
        cmd.manifest_path(manifest_path);
    }

    let metadata = cmd.exec()?;

    let members: Vec<Member> = metadata
        .workspace_packages()
        .into_iter()
        .map(|p| Member {
            name: p.name.to_string(),
            version: p.version.to_string(),
            manifest_path: p.manifest_path.clone().into(),
            features: opts
                .features
                .iter()
                .filter(|f| feature_applies(f, p))
                .cloned()
                .collect(),
        })
        .collect();

    if let Some(feature) = opts
        .features
        .iter()
        .find(|f| !members.iter().any(|m| m.features.contains(f)))
    {
        return Err(Error::Analyzer {
            analyzer: "cargo_geiger".into(),
            message: format!("no workspace member has the feature `{feature}`"),
        });
    }

    Ok(members)
}

/// whether a `cargo --workspace --features` build would apply `feature` to `package`.
fn feature_applies(feature: &str, package: &Package) -> bool {
    match feature.split_once('/') {
        Some((dep, _)) => {
            let dep = dep.strip_suffix('?').unwrap_or(dep);
            package.name.as_str() == dep
                || package
                    .dependencies
                    .iter()
                    .any(|d| d.rename.as_deref().unwrap_or(&d.name) == dep)
        }
        None => package.features.contains_key(feature),
    }
}

/// build the `cargo geiger` command that scans `member`.
fn build_cargo_geiger_command(opts: &ScanOpts, member: &Member) -> Result<Command> {
    let mut cmd = Command::new("cargo");
    cmd.arg("geiger").arg("--output-format").arg("Json");

    if opts.all_features {
        cmd.arg("--all-features");
    }
    if opts.no_default_features {
        cmd.arg("--no-default-features");
    }
    // cargo-geiger reads only the first `--features` and the first `--target`.
    if !member.features.is_empty() {
        cmd.arg("--features").arg(member.features.join(" "));
    }

    if opts.all_targets {
        cmd.arg("--all-targets");
    }
    match opts.targets.as_slice() {
        [] => {}
        [target] => {
            cmd.arg("--target").arg(target);
        }
        targets => {
            return Err(Error::Analyzer {
                analyzer: "cargo_geiger".into(),
                message: format!(
                    "cargo geiger scans one target at a time, got {}",
                    targets.join(", ")
                ),
            })
        }
    }

    cmd.arg("--manifest-path").arg(&member.manifest_path);
    Ok(cmd)
}

fn run_cargo_geiger(cmd: &mut Command, opts: &ScanOpts) -> Result<Vec<u8>> {
    let timeout_secs = opts.analyzer_timeout_secs;
    let output = match process::run_process(cmd, timeout_secs.map(Duration::from_secs))? {
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

// cargo-geiger JSON output structures (cargo-geiger-serde's `SafetyReport`)
#[derive(Debug, Deserialize)]
struct GeigerReport {
    packages: Vec<GeigerPackage>,
    packages_without_metrics: Vec<PackageId>,
}

#[derive(Debug, Deserialize)]
struct GeigerPackage {
    package: PackageInfo,
    unsafety: Unsafety,
}

#[derive(Debug, Deserialize)]
struct PackageInfo {
    id: PackageId,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct PackageId {
    name: String,
    version: String,
    source: Source,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Source {
    Git { url: String, rev: String },
    Registry { name: String, url: String },
    Path(String),
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
struct CountPair {
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

/// merge the per-member reports, counting each package once.
fn convert_reports(
    reports: &[GeigerReport],
    members: &[Member],
    opts: &ScanOpts,
) -> (Vec<Unit>, Vec<ParseWarning>) {
    let exclude_deps = opts.workspace_only || !opts.include_deps;
    let member_ids: HashSet<(&str, &str)> = members
        .iter()
        .map(|m| (m.name.as_str(), m.version.as_str()))
        .collect();
    // cargo-geiger 0.11 garbles path source urls.
    let kind_of = |id: &PackageId| {
        if matches!(id.source, Source::Path(_))
            && member_ids.contains(&(id.name.as_str(), id.version.as_str()))
        {
            UnitKind::Workspace
        } else {
            UnitKind::Dep
        }
    };

    let mut counts: HashMap<String, (UnitKind, u64)> = HashMap::new();
    let mut scanned: HashSet<&PackageId> = HashSet::new();

    for pkg in reports.iter().flat_map(|r| &r.packages) {
        let id = &pkg.package.id;
        if !scanned.insert(id) {
            continue;
        }
        let kind = kind_of(id);
        if exclude_deps && kind == UnitKind::Dep {
            continue;
        }

        let unsafe_count = pkg.unsafety.used.total_unsafe() + pkg.unsafety.unused.total_unsafe();

        let entry = counts.entry(id.name.clone()).or_insert((kind, 0));
        if kind == UnitKind::Workspace {
            entry.0 = kind;
        }
        entry.1 += unsafe_count;
    }

    let unscanned: BTreeSet<&PackageId> = reports
        .iter()
        .flat_map(|r| &r.packages_without_metrics)
        .filter(|id| !scanned.contains(id))
        .filter(|id| !exclude_deps || kind_of(id) == UnitKind::Workspace)
        .collect();
    let warnings = unscanned
        .into_iter()
        .map(|id| ParseWarning {
            message: format!(
                "cargo-geiger: no metrics for {} {}, its unsafe code is not counted",
                id.name, id.version
            ),
        })
        .collect();

    let (units, _) = super::aggregate_units(counts, vec![], opts);
    (units, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHA_REPORT: &str = include_str!("../../tests/fixtures/cargo_geiger/alpha.json");
    const BETA_REPORT: &str = include_str!("../../tests/fixtures/cargo_geiger/beta.json");

    fn member(name: &str, version: &str) -> Member {
        Member {
            name: name.into(),
            version: version.into(),
            manifest_path: PathBuf::from(format!("/ws/{name}/Cargo.toml")),
            features: vec![],
        }
    }

    fn fixture_members() -> Vec<Member> {
        vec![member("alpha", "0.1.0"), member("beta", "0.2.0")]
    }

    fn report(json: &str) -> GeigerReport {
        parse_geiger_output(json.as_bytes()).unwrap()
    }

    /// `json` with the package named `name` moved to `packages_without_metrics`.
    fn without_metrics(json: &str, name: &str) -> GeigerReport {
        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        let packages = value["packages"].as_array_mut().unwrap();
        let at = packages
            .iter()
            .position(|p| p["package"]["id"]["name"] == name)
            .unwrap();
        let id = packages.remove(at)["package"]["id"].clone();
        value["packages_without_metrics"]
            .as_array_mut()
            .unwrap()
            .push(id);
        serde_json::from_value(value).unwrap()
    }

    fn unit_rows(units: &[Unit]) -> Vec<(&str, UnitKind, u64)> {
        units
            .iter()
            .map(|u| (u.name.as_str(), u.kind, u.unsafe_count))
            .collect()
    }

    fn args(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn test_unsafe_count_total() {
        let pair = |unsafe_| CountPair { unsafe_ };
        let count = UnsafeCount {
            functions: pair(1),
            exprs: pair(2),
            item_impls: pair(3),
            item_traits: pair(4),
            methods: pair(5),
        };
        assert_eq!(count.total_unsafe(), 15);
    }

    #[test]
    fn test_parse_geiger_output_reads_a_real_report() {
        let report = report(BETA_REPORT);

        let ids: Vec<(&str, &str, &Source)> = report
            .packages
            .iter()
            .map(|p| {
                let id = &p.package.id;
                (id.name.as_str(), id.version.as_str(), &id.source)
            })
            .collect();
        assert_eq!(
            ids,
            [
                (
                    "alpha",
                    "0.1.0",
                    &Source::Path("file:///work/ws/alpha%230.1.".into())
                ),
                (
                    "beta",
                    "0.2.0",
                    &Source::Path("file:///work/ws/beta%230.2.".into())
                ),
                (
                    "itoa",
                    "1.0.18",
                    &Source::Registry {
                        name: "crates.io".into(),
                        url: "https://github.com/rust-lang/crates.io-index".into(),
                    }
                ),
            ]
        );
        assert_eq!(report.packages[0].unsafety.used.total_unsafe(), 8);
        assert_eq!(report.packages[2].unsafety.used.total_unsafe(), 0);
        assert_eq!(report.packages[2].unsafety.unused.total_unsafe(), 146);
        assert!(report.packages_without_metrics.is_empty());
    }

    #[test]
    fn test_parse_geiger_output_reads_a_git_source() {
        let source: Source = serde_json::from_str(
            r#"{"Git": {"url": "https://example.com/dep.git", "rev": "abc"}}"#,
        )
        .unwrap();
        assert_eq!(
            source,
            Source::Git {
                url: "https://example.com/dep.git".into(),
                rev: "abc".into(),
            }
        );
    }

    #[test]
    fn test_parse_geiger_output_invalid() {
        let json = r#"{"invalid": true}"#;
        let result = parse_geiger_output(json.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_reports_counts_a_shared_dependency_once() {
        let reports = [report(ALPHA_REPORT), report(BETA_REPORT)];
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, warnings) = convert_reports(&reports, &fixture_members(), &opts);

        assert_eq!(
            unit_rows(&units),
            [
                ("alpha", UnitKind::Workspace, 8),
                ("beta", UnitKind::Workspace, 4),
                ("itoa", UnitKind::Dep, 146),
            ]
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_convert_reports_keeps_only_members_when_workspace_only() {
        let reports = [report(ALPHA_REPORT), report(BETA_REPORT)];
        for opts in [
            ScanOpts {
                workspace_only: true,
                include_deps: true,
                ..Default::default()
            },
            ScanOpts {
                include_deps: false,
                ..Default::default()
            },
        ] {
            let (units, _) = convert_reports(&reports, &fixture_members(), &opts);
            assert_eq!(
                unit_rows(&units),
                [
                    ("alpha", UnitKind::Workspace, 8),
                    ("beta", UnitKind::Workspace, 4),
                ]
            );
        }
    }

    #[test]
    fn test_convert_reports_takes_a_path_package_outside_the_workspace_as_a_dependency() {
        let reports = [report(BETA_REPORT)];
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, _) = convert_reports(&reports, &[member("beta", "0.2.0")], &opts);

        assert_eq!(units[0].name, "alpha");
        assert_eq!(units[0].kind, UnitKind::Dep);
    }

    #[test]
    fn test_convert_reports_takes_a_registry_package_named_like_a_member_as_a_dependency() {
        let reports = [report(BETA_REPORT)];
        let mut members = fixture_members();
        members.push(member("itoa", "1.0.18"));
        let opts = ScanOpts {
            workspace_only: true,
            ..Default::default()
        };
        let (units, _) = convert_reports(&reports, &members, &opts);

        assert!(units.iter().all(|u| u.name != "itoa"));
    }

    #[test]
    fn test_convert_reports_makes_a_unit_shared_by_a_dependency_and_a_member_workspace() {
        let mut value: serde_json::Value = serde_json::from_str(BETA_REPORT).unwrap();
        let packages = value["packages"].as_array_mut().unwrap();
        let mut renamed_beta = packages[1].clone();
        renamed_beta["package"]["id"]["name"] = "itoa".into();
        packages.push(renamed_beta);
        let reports = [serde_json::from_value(value).unwrap()];
        let mut members = fixture_members();
        members.push(member("itoa", "0.2.0"));
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, _) = convert_reports(&reports, &members, &opts);

        assert_eq!(unit_rows(&units)[2], ("itoa", UnitKind::Workspace, 150));
    }

    #[test]
    fn test_convert_reports_warns_about_packages_without_metrics() {
        let reports = [without_metrics(BETA_REPORT, "itoa")];
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, warnings) = convert_reports(&reports, &fixture_members(), &opts);

        assert!(units.iter().all(|u| u.name != "itoa"));
        assert_eq!(
            warnings,
            [ParseWarning {
                message: "cargo-geiger: no metrics for itoa 1.0.18, its unsafe code is not counted"
                    .into(),
            }]
        );

        let workspace_only = ScanOpts {
            workspace_only: true,
            ..Default::default()
        };
        let (_, warnings) = convert_reports(&reports, &fixture_members(), &workspace_only);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_convert_reports_does_not_warn_about_a_package_another_report_scanned() {
        let reports = [report(ALPHA_REPORT), without_metrics(BETA_REPORT, "itoa")];
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, warnings) = convert_reports(&reports, &fixture_members(), &opts);

        assert!(units
            .iter()
            .any(|u| u.name == "itoa" && u.unsafe_count == 146));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_command_scans_one_package_as_json() {
        let cmd = build_cargo_geiger_command(&ScanOpts::default(), &member("m", "0.1.0")).unwrap();

        assert_eq!(cmd.get_program(), "cargo");
        assert_eq!(
            args(&cmd),
            [
                "geiger",
                "--output-format",
                "Json",
                "--manifest-path",
                "/ws/m/Cargo.toml"
            ]
        );
    }

    #[test]
    fn test_command_passes_features_and_target_once() {
        let opts = ScanOpts {
            all_features: true,
            no_default_features: true,
            features: vec!["a".into(), "b".into(), "c".into()],
            all_targets: true,
            targets: vec!["x86_64-unknown-linux-gnu".into()],
            manifest_path: Some(PathBuf::from("Cargo.toml")),
            ..Default::default()
        };
        let member = Member {
            features: vec!["a".into(), "b".into()],
            ..member("m", "0.1.0")
        };
        let cmd = build_cargo_geiger_command(&opts, &member).unwrap();

        assert_eq!(
            args(&cmd),
            [
                "geiger",
                "--output-format",
                "Json",
                "--all-features",
                "--no-default-features",
                "--features",
                "a b",
                "--all-targets",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--manifest-path",
                "/ws/m/Cargo.toml"
            ]
        );
    }

    #[test]
    fn test_command_rejects_more_than_one_target() {
        let opts = ScanOpts {
            targets: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        let err = build_cargo_geiger_command(&opts, &member("m", "0.1.0")).unwrap_err();
        assert!(err.to_string().contains("one target"), "{err}");
    }
}
