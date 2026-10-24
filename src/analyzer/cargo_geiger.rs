use crate::analyzer::process::{self, Run};
use crate::analyzer::Analyzer;
use crate::error::{Error, Result};
use crate::model::{ParseWarning, ScanOpts, ScanResult, Unit, UnitKind};
use cargo_metadata::{CargoOpt, Metadata, MetadataCommand, Package};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
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
        let metadata = get_metadata(opts)?;
        let members = get_workspace_members(&metadata, opts)?;
        let mut reports = Vec::with_capacity(members.len());
        for member in &members {
            let mut cmd = build_cargo_geiger_command(opts, member)?;
            let output = run_cargo_geiger(&mut cmd, opts)?;
            reports.push(parse_geiger_output(&output)?);
        }
        let (units, mut warnings) =
            convert_reports(&reports, &members, &package_dirs(&metadata), opts);
        warnings.extend(target_dir_warnings(
            metadata.target_directory.as_std_path(),
            &members,
        ));

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

/// `cargo metadata` for the workspace and every dependency any feature enables.
fn get_metadata(opts: &ScanOpts) -> Result<Metadata> {
    let mut cmd = MetadataCommand::new();
    cmd.features(CargoOpt::AllFeatures);

    if let Some(ref manifest_path) = opts.manifest_path {
        cmd.manifest_path(manifest_path);
    }

    Ok(cmd.exec()?)
}

/// get the workspace member packages, each with the requested features that apply to it.
fn get_workspace_members(metadata: &Metadata, opts: &ScanOpts) -> Result<Vec<Member>> {
    // cargo reads a `--features` value as a space- or comma-separated list
    let requested: Vec<&str> = opts
        .features
        .iter()
        .flat_map(|f| f.split_whitespace())
        .collect();

    let members: Vec<Member> = metadata
        .workspace_packages()
        .into_iter()
        .map(|p| Member {
            name: p.name.to_string(),
            version: p.version.to_string(),
            manifest_path: p.manifest_path.clone().into(),
            features: requested
                .iter()
                .filter(|f| feature_applies(f, p))
                .map(|f| f.to_string())
                .collect(),
        })
        .collect();

    if let Some(feature) = requested
        .iter()
        .find(|f| !members.iter().any(|m| m.features.iter().any(|x| x == *f)))
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

/// package directories, keyed by name, version and whether the source is a path.
type PackageDirs = HashMap<(String, String, bool), PathBuf>;

fn package_dirs(metadata: &Metadata) -> PackageDirs {
    metadata
        .packages
        .iter()
        .filter_map(|p| {
            let dir = p.manifest_path.parent()?.as_std_path();
            let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
            Some((
                (
                    p.name.to_string(),
                    p.version.to_string(),
                    p.source.is_none(),
                ),
                dir,
            ))
        })
        .collect()
}

/// a warning for each member whose directory holds `target_dir`, if a build script generated unsafe code there.
fn target_dir_warnings(target_dir: &Path, members: &[Member]) -> Vec<ParseWarning> {
    let holders: Vec<(&Member, &Path)> = members
        .iter()
        .filter_map(|m| Some((m, m.manifest_path.parent()?)))
        .filter(|(_, dir)| target_dir.starts_with(dir))
        .collect();
    if holders.is_empty() {
        return Vec::new();
    }
    let Some(file) = generated_unsafe_code(target_dir) else {
        return Vec::new();
    };
    holders
        .into_iter()
        .map(|(m, dir)| ParseWarning {
            message: format!(
                "cargo-geiger: {} may be credited with the unsafe code a build script generated in {}; set CARGO_TARGET_DIR outside {} to leave it out",
                m.name,
                file.display(),
                dir.display()
            ),
        })
        .collect()
}

/// a `.rs` file a build script wrote to its `OUT_DIR` under `target_dir` whose unsafe code cargo-geiger may count.
fn generated_unsafe_code(target_dir: &Path) -> Option<PathBuf> {
    // <target>/<profile>/build/<pkg>/out and <target>/<triple>/<profile>/build/<pkg>/out
    let profiles = subdirs(target_dir).into_iter().flat_map(|d| {
        let mut dirs = subdirs(&d);
        dirs.push(d);
        dirs
    });
    profiles
        .flat_map(|p| subdirs(&p.join("build")))
        .find_map(|b| unsafe_rs_in(&b.join("out")))
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect()
}

fn unsafe_rs_in(dir: &Path) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .find_map(|e| {
            let path = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => unsafe_rs_in(&path),
                Ok(t)
                    if t.is_file()
                        && path.extension().is_some_and(|x| x == "rs")
                        && std::fs::read_to_string(&path).is_ok_and(|s| may_count_unsafe(&s)) =>
                {
                    Some(path)
                }
                _ => None,
            }
        })
}

/// whether `src` uses `unsafe` other than for an `extern` block or a fn pointer type.
fn may_count_unsafe(src: &str) -> bool {
    fn ident(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }
    fn keyword<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
        s.strip_prefix(kw).filter(|r| !r.starts_with(ident))
    }
    src.match_indices("unsafe").any(|(i, kw)| {
        if src[..i].ends_with(ident) {
            return false;
        }
        let Some(rest) = keyword(&src[i..], kw) else {
            return false;
        };
        let rest = rest.trim_start();
        let (rest, is_extern) = match keyword(rest, "extern") {
            Some(abi) => {
                let abi = abi.trim_start();
                let rest = abi
                    .strip_prefix('"')
                    .and_then(|s| s.split_once('"'))
                    .map_or(abi, |(_, r)| r);
                (rest.trim_start(), true)
            }
            None => (rest, false),
        };
        match keyword(rest, "fn") {
            Some(sig) => !sig.trim_start().starts_with('('),
            None => !(is_extern && rest.starts_with('{')),
        }
    })
}

/// build the `cargo geiger` command that scans `member`.
fn build_cargo_geiger_command(opts: &ScanOpts, member: &Member) -> Result<Command> {
    let mut cmd = Command::new("cargo");
    cmd.arg("geiger")
        .arg("--output-format")
        .arg("Json")
        .arg("--build-dependencies");

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

fn dir_key(id: &PackageId) -> (String, String, bool) {
    (
        id.name.clone(),
        id.version.clone(),
        matches!(id.source, Source::Path(_)),
    )
}

/// each package's count in `report`, less the `used` count of every package nested directly in its directory.
fn own_counts(report: &GeigerReport, dirs: &PackageDirs) -> Vec<u64> {
    let pkg_dirs: Vec<Option<&PathBuf>> = report
        .packages
        .iter()
        .map(|p| dirs.get(&dir_key(&p.package.id)))
        .collect();
    let mut counts: Vec<u64> = report
        .packages
        .iter()
        .map(|p| match p.package.id.source {
            Source::Path(_) => p.unsafety.used.total_unsafe(),
            // cargo-geiger 0.11 files registry code under `unused`
            _ => p.unsafety.used.total_unsafe() + p.unsafety.unused.total_unsafe(),
        })
        .collect();

    for (pkg, dir) in report.packages.iter().zip(&pkg_dirs) {
        let Some(dir) = dir else { continue };
        let container = pkg_dirs
            .iter()
            .enumerate()
            .filter_map(|(i, d)| Some((i, (*d)?)))
            .filter(|(_, d)| d != dir && dir.starts_with(d))
            .max_by_key(|(_, d)| d.components().count());
        if let Some((i, _)) = container {
            counts[i] = counts[i].saturating_sub(pkg.unsafety.used.total_unsafe());
        }
    }
    counts
}

/// merge the per-member reports: a member counts from its own report, any other package from the first that lists it.
fn convert_reports(
    reports: &[GeigerReport],
    members: &[Member],
    dirs: &PackageDirs,
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

    for (report, member) in reports.iter().zip(members) {
        for (pkg, unsafe_count) in report.packages.iter().zip(own_counts(report, dirs)) {
            let id = &pkg.package.id;
            let first = scanned.insert(id);
            let kind = kind_of(id);
            let counted = match kind {
                UnitKind::Workspace => {
                    (id.name.as_str(), id.version.as_str())
                        == (member.name.as_str(), member.version.as_str())
                }
                UnitKind::Dep => first && !exclude_deps,
            };
            if !counted {
                continue;
            }

            super::add_unit_count(&mut counts, id.name.clone(), kind, unsafe_count);
        }
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
    const MULTI_MEMBER_ROOT: &str =
        include_str!("../../tests/fixtures/cargo_geiger/multi_member_root.json");
    const MULTI_MEMBER_SIBLING: &str =
        include_str!("../../tests/fixtures/cargo_geiger/multi_member_sibling.json");
    const MULTI_MEMBER_ROOT_ON_SIBLING: &str =
        include_str!("../../tests/fixtures/cargo_geiger/multi_member_root_on_sibling.json");
    const VENDORED_REPORT: &str = include_str!("../../tests/fixtures/cargo_geiger/vendored.json");
    const BIN_MEMBER_ALPHA: &str =
        include_str!("../../tests/fixtures/cargo_geiger/bin_member_alpha.json");
    const BIN_MEMBER_ZETA: &str =
        include_str!("../../tests/fixtures/cargo_geiger/bin_member_zeta.json");
    const BUILD_DEPENDENCY_ROOT: &str =
        include_str!("../../tests/fixtures/cargo_geiger/build_dependency_root.json");
    const BUILD_DEPENDENCY_CODEGEN: &str =
        include_str!("../../tests/fixtures/cargo_geiger/build_dependency_codegen.json");

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

    fn multi_member_members() -> Vec<Member> {
        ["rootpkg", "sibling"]
            .into_iter()
            .zip(["", "sibling/"])
            .map(|(name, dir)| Member {
                manifest_path: PathBuf::from(format!(
                    "/work/multi_member_workspace/{dir}Cargo.toml"
                )),
                ..member(name, "0.1.0")
            })
            .collect()
    }

    fn multi_member_dirs() -> PackageDirs {
        PackageDirs::from([
            (
                dir_key_of("rootpkg", "0.1.0", true),
                PathBuf::from("/work/multi_member_workspace"),
            ),
            (
                dir_key_of("sibling", "0.1.0", true),
                PathBuf::from("/work/multi_member_workspace/sibling"),
            ),
        ])
    }

    fn dir_key_of(name: &str, version: &str, path: bool) -> (String, String, bool) {
        (name.into(), version.into(), path)
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
        match parse_geiger_output(json.as_bytes()) {
            Err(Error::Analyzer { analyzer, message }) => {
                assert_eq!(analyzer, "cargo_geiger");
                assert!(
                    message.starts_with("failed to parse cargo-geiger output"),
                    "{message}"
                );
            }
            Err(e) => panic!("unexpected error: {e}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn test_convert_reports_counts_a_shared_dependency_once() {
        let reports = [report(ALPHA_REPORT), report(BETA_REPORT)];
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, warnings) =
            convert_reports(&reports, &fixture_members(), &PackageDirs::new(), &opts);

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
            let (units, _) =
                convert_reports(&reports, &fixture_members(), &PackageDirs::new(), &opts);
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
        let (units, _) = convert_reports(
            &reports,
            &[member("beta", "0.2.0")],
            &PackageDirs::new(),
            &opts,
        );

        assert_eq!(units[0].name, "alpha");
        assert_eq!(units[0].kind, UnitKind::Dep);
    }

    #[test]
    fn test_convert_reports_takes_a_registry_package_named_like_a_member_as_a_dependency() {
        let reports = [report(BETA_REPORT)];
        let members = [member("beta", "0.2.0"), member("itoa", "1.0.18")];
        let opts = ScanOpts {
            workspace_only: true,
            ..Default::default()
        };
        let (units, _) = convert_reports(&reports, &members, &PackageDirs::new(), &opts);

        assert_eq!(unit_rows(&units), [("beta", UnitKind::Workspace, 4)]);
    }

    #[test]
    fn test_convert_reports_makes_a_unit_shared_by_a_dependency_and_a_member_workspace() {
        let mut value: serde_json::Value = serde_json::from_str(BETA_REPORT).unwrap();
        value["packages"][1]["package"]["id"]["name"] = "itoa".into();
        let reports = [serde_json::from_value(value).unwrap()];
        let members = [member("itoa", "0.2.0")];
        let include_deps = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, _) = convert_reports(&reports, &members, &PackageDirs::new(), &include_deps);
        assert_eq!(unit_rows(&units)[1], ("itoa", UnitKind::Workspace, 150));

        let workspace_only = ScanOpts {
            workspace_only: true,
            ..Default::default()
        };
        let (units, _) = convert_reports(&reports, &members, &PackageDirs::new(), &workspace_only);
        assert_eq!(unit_rows(&units), [("itoa", UnitKind::Workspace, 4)]);
    }

    #[test]
    fn test_convert_reports_counts_only_used_code_of_a_root_package() {
        let reports = [report(MULTI_MEMBER_ROOT), report(MULTI_MEMBER_SIBLING)];
        let members = multi_member_members();
        let (units, _) = convert_reports(
            &reports,
            &members,
            &multi_member_dirs(),
            &ScanOpts::default(),
        );

        assert_eq!(
            unit_rows(&units),
            [
                ("rootpkg", UnitKind::Workspace, 0),
                ("sibling", UnitKind::Workspace, 5),
            ]
        );
    }

    #[test]
    fn test_convert_reports_subtracts_a_member_nested_in_another() {
        let reports = [
            report(MULTI_MEMBER_ROOT_ON_SIBLING),
            report(MULTI_MEMBER_SIBLING),
        ];
        let members = multi_member_members();
        let (units, _) = convert_reports(
            &reports,
            &members,
            &multi_member_dirs(),
            &ScanOpts::default(),
        );

        assert_eq!(
            unit_rows(&units),
            [
                ("rootpkg", UnitKind::Workspace, 0),
                ("sibling", UnitKind::Workspace, 5),
            ]
        );
    }

    #[test]
    fn test_convert_reports_subtracts_vendored_dependencies() {
        let reports = [report(VENDORED_REPORT)];
        let dirs = PackageDirs::from([
            (
                dir_key_of("vend", "0.1.0", true),
                PathBuf::from("/work/vend"),
            ),
            (
                dir_key_of("itoa", "1.0.18", false),
                PathBuf::from("/work/vend/vendor/itoa"),
            ),
        ]);
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, _) = convert_reports(&reports, &[member("vend", "0.1.0")], &dirs, &opts);

        assert_eq!(
            unit_rows(&units),
            [
                ("itoa", UnitKind::Dep, 146),
                ("vend", UnitKind::Workspace, 0),
            ]
        );
    }

    #[test]
    fn test_convert_reports_subtracts_a_nested_build_dependency() {
        let reports = [
            report(BUILD_DEPENDENCY_ROOT),
            report(BUILD_DEPENDENCY_CODEGEN),
        ];
        let members = [member("r", "0.1.0"), member("codegen", "0.1.0")];
        let dirs = PackageDirs::from([
            (
                dir_key_of("r", "0.1.0", true),
                PathBuf::from("/work/builddep"),
            ),
            (
                dir_key_of("codegen", "0.1.0", true),
                PathBuf::from("/work/builddep/codegen"),
            ),
        ]);
        let opts = ScanOpts {
            workspace_only: true,
            ..Default::default()
        };
        let (units, _) = convert_reports(&reports, &members, &dirs, &opts);

        assert_eq!(
            unit_rows(&units),
            [
                ("codegen", UnitKind::Workspace, 6),
                ("r", UnitKind::Workspace, 2),
            ]
        );
    }

    #[test]
    fn test_own_counts_subtracts_a_nested_package_from_its_nearest_container_only() {
        let mut value: serde_json::Value =
            serde_json::from_str(MULTI_MEMBER_ROOT_ON_SIBLING).unwrap();
        let packages = value["packages"].as_array_mut().unwrap();
        let mut nested = packages[1].clone();
        nested["package"]["id"]["name"] = "nested".into();
        packages.push(nested);
        for (package, used) in packages.iter_mut().zip([12, 10, 5]) {
            let counts = package["unsafety"]["used"].as_object_mut().unwrap();
            for count in counts.values_mut() {
                count["unsafe_"] = 0.into();
            }
            counts["functions"]["unsafe_"] = used.into();
        }
        let report: GeigerReport = serde_json::from_value(value).unwrap();
        let mut dirs = multi_member_dirs();
        dirs.insert(
            dir_key_of("nested", "0.1.0", true),
            PathBuf::from("/work/multi_member_workspace/sibling/nested"),
        );

        assert_eq!(own_counts(&report, &dirs), [2, 5, 5]);
    }

    #[test]
    fn test_convert_reports_takes_a_member_from_its_own_report() {
        let reports = [report(BIN_MEMBER_ALPHA), report(BIN_MEMBER_ZETA)];
        let members = [member("alpha", "0.1.0"), member("zeta", "0.1.0")];
        let (units, _) = convert_reports(
            &reports,
            &members,
            &PackageDirs::new(),
            &ScanOpts::default(),
        );

        assert_eq!(
            unit_rows(&units),
            [
                ("alpha", UnitKind::Workspace, 0),
                ("zeta", UnitKind::Workspace, 4),
            ]
        );
    }

    #[test]
    fn test_package_dirs_include_an_optional_path_dependency_outside_the_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        for (dir, manifest) in [
            (
                root.clone(),
                "[package]\nname = \"vend\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ngamma = { path = \"vendor/gamma\", optional = true }\n",
            ),
            (
                root.join("vendor/gamma"),
                "[package]\nname = \"gamma\"\nversion = \"0.3.0\"\nedition = \"2021\"\n",
            ),
        ] {
            std::fs::create_dir_all(dir.join("src")).unwrap();
            std::fs::write(dir.join("Cargo.toml"), manifest).unwrap();
            std::fs::write(dir.join("src/lib.rs"), "").unwrap();
        }
        let opts = ScanOpts {
            manifest_path: Some(root.join("Cargo.toml")),
            ..Default::default()
        };
        let metadata = get_metadata(&opts).unwrap();

        assert_eq!(get_workspace_members(&metadata, &opts).unwrap().len(), 1);
        assert_eq!(
            package_dirs(&metadata).get(&dir_key_of("gamma", "0.3.0", true)),
            Some(&root.join("vendor/gamma"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_package_dirs_resolve_a_symlinked_path_dependency() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        for (dir, manifest) in [
            (
                root.join("r"),
                "[package]\nname = \"r\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nq = { path = \"link\" }\n",
            ),
            (
                root.join("qreal"),
                "[package]\nname = \"q\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
        ] {
            std::fs::create_dir_all(dir.join("src")).unwrap();
            std::fs::write(dir.join("Cargo.toml"), manifest).unwrap();
            std::fs::write(dir.join("src/lib.rs"), "").unwrap();
        }
        std::os::unix::fs::symlink("../qreal", root.join("r/link")).unwrap();
        let opts = ScanOpts {
            manifest_path: Some(root.join("r/Cargo.toml")),
            ..Default::default()
        };

        assert_eq!(
            package_dirs(&get_metadata(&opts).unwrap()).get(&dir_key_of("q", "0.1.0", true)),
            Some(&root.join("qreal"))
        );
    }

    #[test]
    fn test_target_dir_warnings_need_generated_unsafe_code() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        let members = [
            Member {
                manifest_path: ws.join("Cargo.toml"),
                ..member("rootpkg", "0.1.0")
            },
            Member {
                manifest_path: ws.join("sibling/Cargo.toml"),
                ..member("sibling", "0.1.0")
            },
        ];
        let no_build = ws.join("no-build");
        std::fs::create_dir_all(no_build.join("debug/deps")).unwrap();
        assert!(target_dir_warnings(&no_build, &members).is_empty());

        for (target, profile) in [
            ("target", "debug"),
            ("tgt", "x86_64-unknown-linux-gnu/release"),
        ] {
            let target = ws.join(target);
            let build = target.join(profile).join("build");
            std::fs::create_dir_all(build.join("gen-89ab")).unwrap();
            std::fs::write(build.join("gen-89ab/build-script-build"), "").unwrap();
            std::fs::create_dir_all(target.join("debug/deps")).unwrap();
            std::fs::write(target.join("debug/deps/lib.rs"), "unsafe fn f() {}\n").unwrap();
            let outs = [
                build.join("gen-0123/out"),
                build.join("gen-4567/out/nested"),
            ];
            for out in &outs {
                std::fs::create_dir_all(out).unwrap();
                std::fs::write(out.join("private.rs"), "pub use crate::de::*;\n").unwrap();
                std::fs::write(out.join("gen.txt"), "unsafe {}\n").unwrap();
                std::fs::write(
                    out.join("bindings.rs"),
                    "pub type Cb = Option<unsafe extern \"C\" fn(i32) -> i32>;\nunsafe extern \"C\" { pub fn abs(x: i32) -> i32; }\n",
                )
                .unwrap();
            }
            assert!(target_dir_warnings(&target, &members).is_empty());

            for out in &outs {
                let generated = out.join("gen.rs");
                std::fs::write(&generated, "pub unsafe fn f() {}\n").unwrap();
                let warnings = target_dir_warnings(&target, &members);
                assert_eq!(warnings.len(), 1, "{}", generated.display());
                assert!(
                    warnings[0].message.starts_with(&format!(
                        "cargo-geiger: rootpkg may be credited with the unsafe code a build script generated in {};",
                        generated.display()
                    )),
                    "{}",
                    warnings[0].message
                );
                assert!(target_dir_warnings(&target, &members[1..]).is_empty());
                std::fs::remove_file(&generated).unwrap();
            }
        }
    }

    #[test]
    fn test_may_count_unsafe_skips_extern_blocks_and_fn_pointer_types() {
        for src in [
            "fn f(p: *const u8) -> u8 { unsafe { *p } }",
            "pub unsafe fn f() {}",
            "unsafe impl Send for S {}",
            "pub unsafe trait T {}",
            "pub unsafe extern \"C\" fn cb(x: i32) -> i32 { x }",
            "unsafe extern fn cb() {}",
            "type F = unsafe fn();\nunsafe impl Sync for S {}",
        ] {
            assert!(may_count_unsafe(src), "{src}");
        }
        for src in [
            "pub type Cb = Option<unsafe extern \"C\" fn(arg: i32) -> i32>;",
            "pub type Cb = Option<unsafe extern \"C-unwind\" fn (i32)>;",
            "unsafe extern \"C\" {\n    pub fn abs(x: i32) -> i32;\n}",
            "unsafe extern {}",
            "type F = unsafe fn();",
            "#![allow(unsafe_code)]\nfn is_unsafe() {}",
        ] {
            assert!(!may_count_unsafe(src), "{src}");
        }
    }

    #[test]
    fn test_convert_reports_warns_about_packages_without_metrics() {
        let reports = [without_metrics(BETA_REPORT, "itoa")];
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, warnings) =
            convert_reports(&reports, &fixture_members(), &PackageDirs::new(), &opts);

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
        let (_, warnings) = convert_reports(
            &reports,
            &fixture_members(),
            &PackageDirs::new(),
            &workspace_only,
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_convert_reports_does_not_warn_about_a_package_another_report_scanned() {
        let reports = [report(ALPHA_REPORT), without_metrics(BETA_REPORT, "itoa")];
        let opts = ScanOpts {
            include_deps: true,
            ..Default::default()
        };
        let (units, warnings) =
            convert_reports(&reports, &fixture_members(), &PackageDirs::new(), &opts);

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
                "--build-dependencies",
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
                "--build-dependencies",
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
