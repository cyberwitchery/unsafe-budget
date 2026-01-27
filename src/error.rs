use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("config file error: {0}")]
    Config(String),

    #[error("baseline file not found: {path}")]
    BaselineNotFound { path: PathBuf },

    #[error("baseline file error: {0}")]
    Baseline(String),

    #[error("analyzer '{analyzer}' failed: {message}")]
    Analyzer { analyzer: String, message: String },

    #[error("cargo execution failed: {message}\nstderr: {stderr}")]
    Cargo { message: String, stderr: String },

    #[error("plugin error: {0}")]
    Plugin(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("toml serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("cargo metadata error: {0}")]
    CargoMetadata(#[from] cargo_metadata::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
