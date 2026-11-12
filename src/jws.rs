//! JSON Web Signature, compact serialization (RFC 7515).
use crate::{b64, crypto, error::{Error, Result}, json, jwa::{Algorithm, Family}, jwk::Jwk};
use serde_json::{Map, Value};

/// Parsed protected header.
#[derive(Debug, Clone)]
pub struct Header {
    pub alg: Algorithm,
    pub kid: Option<String>,
    pub typ: Option<String>,
    pub raw: Map<String, Value>,
}

impl Header {
    fn parse(bytes: &[u8]) -> Result<Header> {
        let raw = json::parse_object(bytes)?;
        let alg = match raw.get("alg") {
            Some(Value::String(s)) => s.parse::<Algorithm>()?,
            Some(_) => return Err(Error::Malformed("alg must be a string".into())),
            None => return Err(Error::Malformed("missing alg".into())),
        };
        let s = |k: &str| match raw.get(k) {
            Some(Value::String(v)) => Ok(Some(v.clone())),
            Some(_) => Err(Error::Malformed(format!("{k} must be a string"))),
            None => Ok(None),
        };
        let (kid, typ) = (s("kid")?, s("typ")?);
        Ok(Header { alg, kid, typ, raw })
    }
}

/// Verification policy. There is deliberately no `Default` that allows every algorithm.
#[derive(Debug, Clone)]
pub struct Policy<'a> {
    /// Algorithms the caller accepts. The token's `alg` must be in this list.
    pub allowed: &'a [Algorithm],
    /// `crit` extension names the caller implements (RFC 7515 section 4.1.11).
    pub understood_crit: &'a [&'a str],
    /// Required `typ` (compared case-insensitively, with optional `application/` prefix per RFC 7515 4.1.9).
    pub typ: Option<&'a str>,
}

impl<'a> Policy<'a> {
    pub fn new(allowed: &'a [Algorithm]) -> Self {
        Policy { allowed, understood_crit: &[], typ: None }
    }
}

fn norm_typ(t: &str) -> String {
    let l = t.to_ascii_lowercase();
    l.strip_prefix("application/").unwrap_or(&l).to_string()
}

/// Checks that a key may be used with `alg` for the given operation (`sign` or `verify`).
pub(crate) fn check_key_use(alg: Algorithm, key: &Jwk, op: &str) -> Result<()> {
    if let Some(ka) = &key.alg {
        if ka != alg.as_str() {
            return Err(Error::Key(format!("key is restricted to alg {ka}, token uses {}", alg.as_str())));
        }
    }
    if let Some(u) = &key.use_ {
        if u != "sig" {
            return Err(Error::Key(format!("key use is {u:?}, not \"sig\"")));
        }
    }
    if let Some(ops) = &key.key_ops {
        if !ops.iter().any(|o| o == op) {
            return Err(Error::Key(format!("key_ops does not permit {op:?}")));
        }
    }
    match (alg.family(), key.kty.as_str()) {
        (Family::Hmac, "oct") | (Family::RsaPkcs1 | Family::RsaPss, "RSA") | (Family::Ecdsa, "EC") | (Family::EdDsa, "OKP") => Ok(()),
        #[cfg(feature = "test-mode")]
        (Family::Unsecured, _) => Ok(()),
        _ => Err(Error::Key(format!("key type {} cannot be used with {}", key.kty, alg.as_str()))),
    }
}

fn hmac_key(alg: Algorithm, key: &Jwk) -> Result<Vec<u8>> {
    let k = key.req("k")?;
    // RFC 7518 section 3.2: key length MUST be at least the hash output size.
    let need = alg.hash().expect("hmac has hash").output_len();
    if k.len() < need {
        return Err(Error::Key(format!("HMAC key must be at least {need} bytes for {}", alg.as_str())));
    }
    Ok(k)
}

/// Signs `payload` and returns the compact JWS. `extra` members are merged into the protected header;
/// `alg` always comes from the `alg` argument.
pub fn sign(alg: Algorithm, key: &Jwk, extra: &Map<String, Value>, payload: &[u8]) -> Result<String> {
    check_key_use(alg, key, "sign")?;
    let mut h = extra.clone();
    h.insert("alg".into(), Value::String(alg.as_str().into()));
    if let Some(kid) = &key.kid {
        h.entry("kid").or_insert_with(|| Value::String(kid.clone()));
    }
    let head = b64::encode(serde_json::to_vec(&h)?);
    let input = format!("{head}.{}", b64::encode(payload));
    let sig = match alg.family() {
        Family::Hmac => crypto::hmac(alg.hash().unwrap(), &hmac_key(alg, key)?, input.as_bytes())?,
        #[cfg(feature = "test-mode")]
        Family::Unsecured => Vec::new(),
        _ => crypto::sign(alg, key, input.as_bytes())?,
    };
    Ok(format!("{input}.{}", b64::encode(sig)))
}

/// Splits a compact JWS into (header_b64, payload_b64, sig_b64) and enforces three segments.
fn split(token: &str) -> Result<(&str, &str, &str)> {
    let mut it = token.split('.');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) => Ok((h, p, s)),
        _ => Err(Error::Malformed("compact JWS must have exactly three segments".into())),
    }
}

/// Decodes the header without verifying anything. Use it to pick a key (by `kid`), never to trust the token.
pub fn peek_header(token: &str) -> Result<Header> {
    let (h, _, _) = split(token)?;
    Header::parse(&b64::decode(h)?)
}

/// Verifies a compact JWS and returns its header and payload.
pub fn verify(token: &str, key: &Jwk, policy: &Policy<'_>) -> Result<(Header, Vec<u8>)> {
    let (h64, p64, s64) = split(token)?;
    let header = Header::parse(&b64::decode(h64)?)?;

    if !policy.allowed.contains(&header.alg) {
        return Err(Error::Algorithm(format!("alg {} is not allowed by policy", header.alg.as_str())));
    }
    if let Some(crit) = header.raw.get("crit") {
        let list = crit.as_array().filter(|a| !a.is_empty())
            .ok_or_else(|| Error::Malformed("crit must be a non-empty array".into()))?;
        for c in list {
            let name = c.as_str().ok_or_else(|| Error::Malformed("crit entries must be strings".into()))?;
            if !policy.understood_crit.contains(&name) {
                return Err(Error::Malformed(format!("unsupported critical header {name:?}")));
            }
            if !header.raw.contains_key(name) {
                return Err(Error::Malformed(format!("critical header {name:?} is missing")));
            }
        }
    }
    if let Some(want) = policy.typ {
        match &header.typ {
            Some(t) if norm_typ(t) == norm_typ(want) => {}
            _ => return Err(Error::Malformed(format!("typ must be {want:?}"))),
        }
    }
    check_key_use(header.alg, key, "verify")?;

    let sig = b64::decode(s64)?;
    let input = format!("{h64}.{p64}");
    match header.alg.family() {
        Family::Hmac => {
            let mac = crypto::hmac(header.alg.hash().unwrap(), &hmac_key(header.alg, key)?, input.as_bytes())?;
            if !crypto::ct_eq(&mac, &sig) {
                return Err(Error::BadSignature);
            }
        }
        #[cfg(feature = "test-mode")]
        Family::Unsecured => {
            if !sig.is_empty() {
                return Err(Error::BadSignature);
            }
        }
        _ => crypto::verify(header.alg, key, input.as_bytes(), &sig)?,
    }
    Ok((header, b64::decode(p64)?))
}

