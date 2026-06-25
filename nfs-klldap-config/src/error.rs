//! Error type for nfs-klldap-config (manual, no thiserror,
//! for small binary size).

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse { path: String, msg: String },
    Validation(String),
    Generation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "IO error: {}", e),
            ConfigError::Parse { path, msg } => write!(f, "TOML parse error for {}: {}", path, msg),
            ConfigError::Validation(s) => write!(f, "Validation error: {}", s),
            ConfigError::Generation(s) => write!(f, "Generation error: {}", s),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}
