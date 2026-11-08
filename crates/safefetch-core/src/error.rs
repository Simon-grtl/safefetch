use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors are rendered to the user, so messages never contain secrets,
/// query strings or full URLs.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid settings: {0}")]
    InvalidSettings(String),
    #[error("Invalid link: {0}")]
    InvalidUrl(String),
    #[error("Refused: {0}")]
    Policy(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Server answered HTTP {0}")]
    HttpStatus(u16),
    #[error("Size mismatch: {0}")]
    SizeMismatch(String),
    #[error("Not enough disk space: {0}")]
    DiskSpace(String),
    #[error("File too large: {0}")]
    TooLarge(String),
    #[error("Cancelled")]
    Cancelled,
    #[error("Download incomplete ({0} bytes received); it can be resumed")]
    Incomplete(u64),
    #[error("File system error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Secret storage error: {0}")]
    Secret(String),
    #[error("Not found")]
    NotFound,
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Errors worth retrying (with resume).
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Network(_) | Error::Incomplete(_) => true,
            Error::HttpStatus(s) => matches!(s, 408 | 425 | 429 | 500 | 502 | 503 | 504),
            _ => false,
        }
    }
}

impl serde::Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

/// Reduce a reqwest error to a message without the URL (it may carry tokens).
pub fn net_err(e: reqwest::Error) -> Error {
    let e = e.without_url();
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    Error::Network(msg)
}
