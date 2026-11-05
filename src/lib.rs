//! # unsafe-budget
//!
//! an unsafe code budget gate for ci pipelines.
//!
//! tracks unsafe code usage in rust and go projects, compares it against
//! baselines, and enforces budgets.
//!
//! the `unsafe-budget` and `cargo-unsafe-budget` binaries are thin wrappers
//! around [`pipeline`]: parse the arguments, run the pipeline, render the result
//! with [`output`] and map the verdict to an exit code.
//!
//! ## quick example
//!
//! ```no_run
//! use std::path::Path;
//! use unsafe_budget::analyzer::detect_analyzer;
//! use unsafe_budget::config::Config;
//! use unsafe_budget::model::ScanOpts;
//! use unsafe_budget::output::{self, Format};
//! use unsafe_budget::pipeline;
//!
//! let dir = Path::new(".");
//! let config = Config::load_from_dir(dir).unwrap();
//! let opts = ScanOpts {
//!     include_deps: config.include_deps,
//!     ..ScanOpts::default()
//! };
//! let analyzer = detect_analyzer(&opts).unwrap();
//!
//! // the same verdict as `unsafe-budget check`
//! let outcome = pipeline::check(analyzer.as_ref(), &opts, &config, dir).unwrap();
//! for difference in &outcome.scope_differences {
//!     eprintln!("scope differs from baseline: {difference}");
//! }
//! output::write_check(&mut std::io::stdout(), &outcome.result, Format::Text).unwrap();
//! assert!(outcome.result.passed);
//! ```
//!
//! ## modules
//!
//! - [`pipeline`] - the `scan`, `check` and `update` commands
//! - [`analyzer`] - analyzer trait and built-in implementations
//! - [`budget`] - budget comparison engine (ratchet and caps modes)
//! - [`config`] - configuration and baseline file handling
//! - [`model`] - core data types (ScanResult, Unit, etc.)
//! - [`output`] - text, json and sarif renderers
//! - [`sarif`] - SARIF 2.1.0 conversion
//! - [`error`] - the error type

pub mod analyzer;
pub mod budget;
pub mod config;
pub mod error;
pub mod model;
pub mod output;
pub mod pipeline;
pub mod sarif;
