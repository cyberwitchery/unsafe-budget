//! # unsafe-budget
//!
//! an unsafe code budget gate for ci pipelines.
//!
//! tracks unsafe code usage in rust and go projects, compares it against
//! baselines, and enforces budgets.
//!
//! ## quick example
//!
//! ```no_run
//! use unsafe_budget::analyzer::detect_analyzer;
//! use unsafe_budget::model::ScanOpts;
//!
//! let opts = ScanOpts::default();
//! let analyzer = detect_analyzer(&opts).unwrap();
//! let result = analyzer.run(&opts).unwrap();
//!
//! println!("total unsafe: {}", result.totals.overall_unsafe);
//! for unit in &result.units {
//!     println!("  {}: {}", unit.name, unit.unsafe_count);
//! }
//! ```
//!
//! ## modules
//!
//! - [`analyzer`] - analyzer trait and built-in implementations
//! - [`budget`] - budget comparison engine (ratchet and caps modes)
//! - [`config`] - configuration and baseline file handling
//! - [`model`] - core data types (ScanResult, Unit, etc.)
//! - [`output`] - text and json formatters
//! - [`sarif`] - SARIF 2.1.0 conversion

pub mod analyzer;
pub mod app;
pub mod budget;
pub mod cli;
pub mod config;
pub mod error;
pub mod model;
pub mod output;
pub mod sarif;
