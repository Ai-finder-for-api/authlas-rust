//! base64url without padding (RFC 7515 section 2). Decoding is strict:
//! padding, whitespace and non-canonical trailing bits are rejected.
use crate::error::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

pub fn encode(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::Malformed(format!("base64url: {e}")))
}
