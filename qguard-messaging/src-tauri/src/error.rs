use thiserror::Error;

#[derive(Error, Debug)]
pub enum QGuardError {
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("replay detected: {0}")]
    Replay(String),
    #[error("trust error: {0}")]
    Trust(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl serde::Serialize for QGuardError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, QGuardError>;

impl From<anyhow::Error> for QGuardError {
    fn from(value: anyhow::Error) -> Self {
        Self::Storage(value.to_string())
    }
}
