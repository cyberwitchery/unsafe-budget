//! the `scan`, `check` and `update` commands as library calls.
//!
//! each runs the analyzer through [`analyzer::scan`] and applies the config's `[[ignore]]`
//! entries, so a caller gets the same result and verdict as the CLI for the same inputs.

use std::path::Path;

use crate::analyzer::{self, Analyzer};
use crate::budget;
use crate::config::{Baseline, Config, Mode};
use crate::error::Result;
use crate::model::{CheckResult, ScanOpts, ScanResult, Scope};

/// what [`check`] found.
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    /// the verdict.
    pub result: CheckResult,
    /// how this scan's scope differs from the baseline's, one [`Scope::diff_fields`] line each.
    pub scope_differences: Vec<String>,
}

/// run `analyzer` and subtract the `[[ignore]]` entries of `config`.
pub fn scan(analyzer: &dyn Analyzer, opts: &ScanOpts, config: &Config) -> Result<ScanResult> {
    Ok(budget::apply_ignores(
        analyzer::scan(analyzer, opts)?,
        &config.ignore,
    ))
}

/// run `analyzer` and check the result against `config`: in ratchet mode against the
/// `unsafe-budget.lock` in `project_dir`, which is read after the scan.
pub fn check(
    analyzer: &dyn Analyzer,
    opts: &ScanOpts,
    config: &Config,
    project_dir: &Path,
) -> Result<CheckOutcome> {
    let scan = analyzer::scan(analyzer, opts)?;
    let baseline = match config.mode {
        Mode::Ratchet => Some(Baseline::load_from_dir(project_dir)?),
        Mode::Caps => None,
    };
    let result = budget::check(&scan, baseline.as_ref(), config)?;
    let scope_differences = baseline
        .map(|bl| bl.scope.diff_fields(&Scope::from(opts)))
        .unwrap_or_default();
    Ok(CheckOutcome {
        result,
        scope_differences,
    })
}

/// [`scan`], then write the result's lock ([`Baseline::from_scan`]) to `project_dir`.
pub fn update(
    analyzer: &dyn Analyzer,
    opts: &ScanOpts,
    config: &Config,
    project_dir: &Path,
) -> Result<ScanResult> {
    let result = scan(analyzer, opts, config)?;
    Baseline::from_scan(&result).save_to_dir(project_dir)?;
    Ok(result)
}
