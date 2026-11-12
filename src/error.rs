use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Malformed input (encoding, JSON shape, missing member).
    Malformed(String),
    /// Algorithm not supported, or not permitted by the caller's allow-list.
    Algorithm(String),
    /// Key is unusable for the operation (wrong type, too short, mismatched curve).
    Key(String),
    /// Signature or MAC did not verify.
    BadSignature,
    /// A claim failed validation (exp, nbf, aud, iss, ...).
    Claim(String),
    /// Backend or entropy failure.
    Crypto(String),
    /// The selected crypto backend does not implement this operation.
    Unsupported(String),
    /// Authenticated decryption failed. Deliberately carries no detail.
    Decrypt,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(m) => write!(f, "malformed: {m}"),
            Error::Algorithm(m) => write!(f, "algorithm: {m}"),
            Error::Key(m) => write!(f, "key: {m}"),
            Error::BadSignature => write!(f, "signature verification failed"),
            Error::Claim(m) => write!(f, "claim: {m}"),
            Error::Crypto(m) => write!(f, "crypto: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported by backend: {m}"),
            Error::Decrypt => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Malformed(format!("json: {e}"))
    }
}
