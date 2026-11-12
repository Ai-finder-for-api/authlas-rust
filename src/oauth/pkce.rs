//! Proof Key for Code Exchange (RFC 7636).
use crate::{b64, crypto, error::{Error, Result}, jwa::Hash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method { S256, Plain }

impl Method {
    pub fn as_str(self) -> &'static str { match self { Method::S256 => "S256", Method::Plain => "plain" } }

    /// `code_challenge_method` as sent. RFC 7636 4.3 says an absent method means `plain`; that is only
    /// honoured if `allow_plain` (RFC 9700 2.1.1: servers should refuse plain).
    pub fn parse(s: Option<&str>, allow_plain: bool) -> Result<Method> {
        match s {
            Some("S256") => Ok(Method::S256),
            Some("plain") | None if allow_plain => Ok(Method::Plain),
            Some("plain") | None => Err(Error::Malformed("code_challenge_method S256 is required".into())),
            Some(_) => Err(Error::Malformed("unsupported code_challenge_method".into())),
        }
    }
}

fn unreserved(b: u8) -> bool { b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') }

/// 43..=128 characters from the unreserved set (RFC 7636 4.1).
pub fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len()) && v.bytes().all(unreserved)
}

/// A new verifier: 32 random bytes, base64url, 43 characters (256 bits of entropy).
pub fn generate_verifier() -> Result<String> {
    let mut b = [0u8; 32];
    crypto::random(&mut b)?;
    Ok(b64::encode(b))
}

/// `BASE64URL(SHA256(ASCII(verifier)))`
pub fn s256_challenge(verifier: &str) -> Result<String> {
    if !valid_verifier(verifier) { return Err(Error::Malformed("invalid code_verifier".into())); }
    Ok(b64::encode(crypto::digest(Hash::Sha256, verifier.as_bytes())?))
}

pub fn challenge(verifier: &str, method: Method) -> Result<String> {
    match method {
        Method::S256 => s256_challenge(verifier),
        Method::Plain => {
            if valid_verifier(verifier) { Ok(verifier.to_string()) }
            else { Err(Error::Malformed("invalid code_verifier".into())) }
        }
    }
}

/// Server side, at request time: is this `code_challenge` well formed for the method?
pub fn check_challenge_syntax(challenge: &str, method: Method) -> Result<()> {
    let ok = match method {
        // 32 bytes of hash -> exactly 43 base64url characters.
        Method::S256 => challenge.len() == 43 && b64::decode(challenge).map(|b| b.len() == 32).unwrap_or(false),
        Method::Plain => valid_verifier(challenge),
    };
    if ok { Ok(()) } else { Err(Error::Malformed("invalid code_challenge".into())) }
}

/// Server side, at token time. Constant time on the comparison; one error for every failure.
pub fn verify(stored_challenge: &str, method: Method, verifier: &str) -> Result<()> {
    let computed = challenge(verifier, method).map_err(|_| Error::Claim("code_verifier does not match".into()))?;
    if crypto::ct_eq(computed.as_bytes(), stored_challenge.as_bytes()) { Ok(()) }
    else { Err(Error::Claim("code_verifier does not match".into())) }
}
