use std::fmt::Display;
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

    #[error("io error: {context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },

    #[error("json error: {context}: {source}")]
    Json {
        context: String,
        source: serde_json::Error,
    },

    #[error("toml parse error: {context}: {source}")]
    TomlParse {
        context: String,
        source: toml::de::Error,
    },

    #[error("toml serialize error: {context}: {source}")]
    TomlSerialize {
        context: String,
        source: toml::ser::Error,
    },

    #[error("cargo metadata error: {context}: {source}")]
    CargoMetadata {
        context: String,
        source: cargo_metadata::Error,
    },
}

/// constructors whose `context` names the file or command the error concerns.
impl Error {
    /// an [`Error::Analyzer`] of the analyzer with the id `analyzer`.
    pub fn analyzer(analyzer: &str, message: impl Into<String>) -> Self {
        Self::Analyzer {
            analyzer: analyzer.into(),
            message: message.into(),
        }
    }

    pub fn io(context: impl Display, source: std::io::Error) -> Self {
        Self::Io {
            context: context.to_string(),
            source,
        }
    }

    pub fn json(context: impl Display, source: serde_json::Error) -> Self {
        Self::Json {
            context: context.to_string(),
            source,
        }
    }

    pub fn toml_parse(context: impl Display, source: toml::de::Error) -> Self {
        Self::TomlParse {
            context: context.to_string(),
            source,
        }
    }

    pub fn toml_serialize(context: impl Display, source: toml::ser::Error) -> Self {
        Self::TomlSerialize {
            context: context.to_string(),
            source,
        }
    }

    pub fn cargo_metadata(context: impl Display, source: cargo_metadata::Error) -> Self {
        Self::CargoMetadata {
            context: context.to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
