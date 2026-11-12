//! JSON Web Token (RFC 7519), validated per RFC 8725 (JWT best current practice),
//! with proof-of-possession claims (RFC 7800) and nested JWTs (sign then encrypt).
//!
//! Defaults that follow the BCP and cannot be switched off by omission:
//! * the caller names the algorithms, the issuer and the audience; there is no constructor without them;
//! * `exp` is required;
//! * `jwk`, `jku`, `x5u` and `x5c` headers are never used to pick a key. Key selection is the caller's job
//!   (`jws::peek_header` gives the `kid`).
use crate::{b64, error::{Error, Result}, json, jwa::{Algorithm, Hash}, jwe, jws, jwk::Jwk};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Largest NumericDate accepted (2^53, the largest integer a double holds exactly).
const MAX_DATE: f64 = 9_007_199_254_740_992.0;

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A JWT claims set. Registered claims have typed accessors; everything else stays in `map`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Claims {
    pub map: Map<String, Value>,
}

impl Claims {
    pub fn new() -> Self { Claims::default() }

    pub fn parse(bytes: &[u8]) -> Result<Claims> {
        Ok(Claims { map: json::parse_object(bytes)? })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.map).expect("a JSON map always serializes")
    }

    pub fn set(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.map.insert(name.to_string(), value.into());
        self
    }
    pub fn issuer(self, v: &str) -> Self { self.set("iss", v) }
    pub fn subject(self, v: &str) -> Self { self.set("sub", v) }
    /// One audience is written as a string, several as an array (RFC 7519 4.1.3).
    pub fn audience(self, v: &[&str]) -> Self {
        match v {
            [one] => self.set("aud", *one),
            many => self.set("aud", Value::Array(many.iter().map(|s| Value::String((*s).into())).collect())),
        }
    }
    pub fn expires_at(self, t: u64) -> Self { self.set("exp", t) }
    pub fn not_before(self, t: u64) -> Self { self.set("nbf", t) }
    pub fn issued_at(self, t: u64) -> Self { self.set("iat", t) }
    pub fn jti(self, v: &str) -> Self { self.set("jti", v) }

    /// RFC 7800 `cnf` with the RFC 7638 thumbprint (`jkt`, as used by RFC 9449 DPoP-bound tokens).
    pub fn confirm_jkt(self, key: &Jwk) -> Result<Self> {
        let t = key.thumbprint(Hash::Sha256)?;
        Ok(self.set("cnf", serde_json::json!({ "jkt": t })))
    }
    /// RFC 8705 certificate-bound token: `cnf` with `x5t#S256`.
    pub fn confirm_x5t_s256(self, thumbprint: &str) -> Self {
        self.set("cnf", serde_json::json!({ "x5t#S256": thumbprint }))
    }
    /// RFC 7800 `cnf` carrying a public JWK. A private key here is refused.
    pub fn confirm_jwk(self, key: &Jwk) -> Result<Self> {
        if key.is_private() { return Err(Error::Key("cnf.jwk must be a public key".into())); }
        let v: Value = serde_json::from_str(&key.to_json())?;
        Ok(self.set("cnf", serde_json::json!({ "jwk": v })))
    }

    pub fn str_claim(&self, name: &str) -> Result<Option<&str>> {
        match self.map.get(name) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(Error::Claim(format!("{name} must be a string"))),
        }
    }

    /// `aud` as a list: a string becomes a one-element list. Anything else is an error.
    pub fn aud_list(&self) -> Result<Option<Vec<&str>>> {
        match self.map.get("aud") {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(vec![s.as_str()])),
            Some(Value::Array(a)) => a.iter()
                .map(|v| v.as_str().ok_or_else(|| Error::Claim("aud entries must be strings".into())))
                .collect::<Result<Vec<_>>>().map(Some),
            Some(_) => Err(Error::Claim("aud must be a string or an array of strings".into())),
        }
    }

    /// A NumericDate (RFC 7519 2). Fractions are floored. Negative, non-finite or absurd values are errors.
    pub fn date(&self, name: &str) -> Result<Option<u64>> {
        match self.map.get(name) {
            None => Ok(None),
            Some(Value::Number(n)) => {
                let f = n.as_f64().ok_or_else(|| Error::Claim(format!("{name} is not a number")))?;
                if !f.is_finite() || !(0.0..=MAX_DATE).contains(&f) {
                    return Err(Error::Claim(format!("{name} is out of range")));
                }
                Ok(Some(f.floor() as u64))
            }
            Some(_) => Err(Error::Claim(format!("{name} must be a number"))),
        }
    }

    /// The `cnf` claim (RFC 7800), if present.
    pub fn cnf(&self) -> Result<Option<Confirmation>> {
        let Some(v) = self.map.get("cnf") else { return Ok(None) };
        let o = v.as_object().ok_or_else(|| Error::Claim("cnf must be an object".into()))?;
        if o.is_empty() { return Err(Error::Claim("cnf must not be empty".into())); }
        let s = |k: &str| match o.get(k) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(Error::Claim(format!("cnf.{k} must be a string"))),
        };
        let jwk = match o.get("jwk") {
            None => None,
            Some(j @ Value::Object(_)) => {
                let k = Jwk::parse(&j.to_string()).map_err(|_| Error::Claim("cnf.jwk is not a valid JWK".into()))?;
                if k.is_private() { return Err(Error::Claim("cnf.jwk carries private key material".into())); }
                Some(k)
            }
            Some(_) => return Err(Error::Claim("cnf.jwk must be an object".into())),
        };
        Ok(Some(Confirmation { jwk, kid: s("kid")?, jkt: s("jkt")?, x5t_s256: s("x5t#S256")?, jwe: s("jwe")?, jku: s("jku")? }))
    }
}

/// RFC 7800 confirmation methods.
#[derive(Debug, Clone, PartialEq)]
pub struct Confirmation {
    pub jwk: Option<Jwk>,
    pub kid: Option<String>,
    /// RFC 7638 thumbprint, SHA-256, base64url (RFC 9449 section 6).
    pub jkt: Option<String>,
    /// RFC 8705 certificate thumbprint, SHA-256, base64url.
    pub x5t_s256: Option<String>,
    pub jwe: Option<String>,
    pub jku: Option<String>,
}

impl Confirmation {
    /// True if the presented key is the one the token is bound to (by `jkt` or `jwk`). Constant time on the thumbprint.
    pub fn matches_key(&self, presented: &Jwk) -> Result<bool> {
        if let Some(j) = &self.jkt {
            let t = presented.thumbprint(Hash::Sha256)?;
            return Ok(crate::crypto::ct_eq(t.as_bytes(), j.as_bytes()));
        }
        if let Some(k) = &self.jwk {
            let a = k.thumbprint(Hash::Sha256)?;
            let b = presented.thumbprint(Hash::Sha256)?;
            return Ok(crate::crypto::ct_eq(a.as_bytes(), b.as_bytes()));
        }
        Err(Error::Claim("cnf has no jkt or jwk to compare with".into()))
    }
    pub fn matches_x5t_s256(&self, cert_thumbprint: &str) -> bool {
        self.x5t_s256.as_deref().map_or(false, |t| crate::crypto::ct_eq(t.as_bytes(), cert_thumbprint.as_bytes()))
    }
}

/// Remembers `jti` values so a token can be accepted once.
pub trait ReplayCache {
    /// Returns true if `key` has not been seen. Entries may be dropped after `exp`.
    fn first_use(&self, key: &str, exp: u64, now: u64) -> bool;
}

/// Process-local replay cache. Use a shared store when several instances validate the same tokens.
#[derive(Default)]
pub struct MemoryReplayCache {
    seen: Mutex<HashMap<String, u64>>,
}

impl MemoryReplayCache {
    pub fn new() -> Self { Self::default() }
    pub fn len(&self) -> usize { self.seen.lock().map(|m| m.len()).unwrap_or(0) }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

impl ReplayCache for MemoryReplayCache {
    fn first_use(&self, key: &str, exp: u64, now: u64) -> bool {
        let Ok(mut m) = self.seen.lock() else { return false }; // poisoned: fail closed
        m.retain(|_, e| *e > now);
        if m.contains_key(key) { return false; }
        m.insert(key.to_string(), exp);
        true
    }
}

/// What a token must satisfy. Construct with [`Validation::new`]; the rest are tightening or documented relaxations.
pub struct Validation<'a> {
    pub algs: &'a [Algorithm],
    /// Required `iss`, compared exactly.
    pub issuer: &'a str,
    /// This recipient's identifier. It must appear in `aud`.
    pub audience: &'a str,
    /// Clock skew allowance in seconds. Capped at [`Validation::MAX_LEEWAY`].
    pub leeway: u64,
    /// Override the clock (tests, replaying a log). `None` uses the system clock.
    pub now: Option<u64>,
    /// Require `typ`, e.g. `at+jwt` (RFC 9068) or `JWT`. RFC 8725 3.11 recommends this to stop cross-JWT confusion.
    pub typ: Option<&'a str>,
    /// Further claims that must be present.
    pub require: &'a [&'a str],
    /// Reject tokens older than this many seconds since `iat` (needs `iat`).
    pub max_age: Option<u64>,
    /// Reject a repeated `jti` (needs `jti`).
    pub replay: Option<&'a dyn ReplayCache>,
    pub understood_crit: &'a [&'a str],
    /// `exp` must be present. On by default; only profiles that define tokens without expiry (RFC 9701) turn it off.
    pub require_exp: bool,
}

impl<'a> Validation<'a> {
    pub const MAX_LEEWAY: u64 = 300;

    pub fn new(algs: &'a [Algorithm], issuer: &'a str, audience: &'a str) -> Self {
        Validation { algs, issuer, audience, leeway: 30, now: None, typ: None, require: &[], max_age: None, replay: None, understood_crit: &[], require_exp: true }
    }

    fn jws_policy(&self) -> jws::Policy<'a> {
        let mut p = jws::Policy::new(self.algs);
        p.typ = self.typ;
        p.understood_crit = self.understood_crit;
        p
    }

    /// Checks the claims alone. [`verify`] calls this after the signature.
    pub fn check(&self, c: &Claims) -> Result<()> {
        let now = self.now.unwrap_or_else(unix_now);
        let leeway = self.leeway.min(Self::MAX_LEEWAY);

        match c.str_claim("iss")? {
            Some(i) if crate::crypto::ct_eq(i.as_bytes(), self.issuer.as_bytes()) => {}
            Some(_) => return Err(Error::Claim("iss does not match".into())),
            None => return Err(Error::Claim("iss is missing".into())),
        }
        match c.aud_list()? {
            Some(a) if a.iter().any(|x| *x == self.audience) => {}
            Some(_) => return Err(Error::Claim("aud does not include this recipient".into())),
            None => return Err(Error::Claim("aud is missing".into())),
        }
        // RFC 7519 4.1.4: the token must not be accepted on or after exp.
        let exp = c.date("exp")?;
        if exp.is_none() && self.require_exp { return Err(Error::Claim("exp is missing".into())); }
        if let Some(exp) = exp {
            if now >= exp.saturating_add(leeway) {
                return Err(Error::Claim("token has expired".into()));
            }
        }
        if let Some(nbf) = c.date("nbf")? {
            if now.saturating_add(leeway) < nbf {
                return Err(Error::Claim("token is not valid yet".into()));
            }
        }
        let iat = c.date("iat")?;
        if let Some(iat) = iat {
            if iat > now.saturating_add(leeway) {
                return Err(Error::Claim("iat is in the future".into()));
            }
        }
        if let Some(max) = self.max_age {
            let iat = iat.ok_or_else(|| Error::Claim("iat is required when max_age is set".into()))?;
            if now.saturating_sub(iat) > max.saturating_add(leeway) {
                return Err(Error::Claim("token is older than max_age".into()));
            }
        }
        c.str_claim("sub")?;
        for name in self.require {
            if !c.map.contains_key(*name) {
                return Err(Error::Claim(format!("{name} is missing")));
            }
        }
        if let Some(r) = self.replay {
            let jti = c.str_claim("jti")?.ok_or_else(|| Error::Claim("jti is required for replay protection".into()))?;
            let key = format!("{}\n{}", self.issuer, jti);
            if !r.first_use(&key, exp.unwrap_or(now + 3600).saturating_add(leeway), now) {
                return Err(Error::Claim("token was already used".into()));
            }
        }
        Ok(())
    }
}

/// Signs `claims` as a compact JWT. `typ` defaults to `JWT`; pass e.g. `at+jwt` to override.
pub fn sign(alg: Algorithm, key: &Jwk, claims: &Claims, typ: Option<&str>) -> Result<String> {
    let mut h = Map::new();
    h.insert("typ".into(), Value::String(typ.unwrap_or("JWT").into()));
    if let Some(kid) = &key.kid { h.insert("kid".into(), Value::String(kid.clone())); }
    jws::sign(alg, key, &h, &claims.to_bytes())
}

/// Verifies the signature, then the claims.
pub fn verify(token: &str, key: &Jwk, v: &Validation<'_>) -> Result<(jws::Header, Claims)> {
    let (header, payload) = jws::verify(token, key, &v.jws_policy())?;
    let claims = Claims::parse(&payload).map_err(|_| Error::Claim("payload is not a JSON object".into()))?;
    v.check(&claims)?;
    Ok((header, claims))
}

/// Sign, then encrypt (RFC 7519 section 5.2, RFC 8725 3.11): the outer JWE carries `cty: JWT`.
pub fn encrypt_nested(inner_jws: &str, alg: jwe::KeyAlg, enc: jwe::Enc, recipient: &Jwk) -> Result<String> {
    let mut h = Map::new();
    h.insert("cty".into(), Value::String("JWT".into()));
    jwe::encrypt(alg, enc, recipient, &h, inner_jws.as_bytes())
}

/// Decrypts a nested JWT and validates the inner token. Requires `cty: JWT` so a JWE holding something else is not misread.
pub fn decrypt_nested(token: &str, decryption_key: &Jwk, jwe_policy: &jwe::Policy<'_>, verification_key: &Jwk, v: &Validation<'_>) -> Result<(jws::Header, Claims)> {
    let (outer, inner) = jwe::decrypt(token, decryption_key, jwe_policy)?;
    match outer.raw.get("cty").and_then(Value::as_str) {
        Some(c) if c.eq_ignore_ascii_case("jwt") || c.eq_ignore_ascii_case("application/jwt") => {}
        _ => return Err(Error::Malformed("nested JWT needs cty \"JWT\" in the JWE header".into())),
    }
    let inner = String::from_utf8(inner).map_err(|_| Error::Malformed("inner token is not UTF-8".into()))?;
    verify(&inner, verification_key, v)
}

/// Reads claims without checking anything. For logging and routing only; never for decisions.
pub fn peek_claims_unverified(token: &str) -> Result<Claims> {
    let mut it = token.split('.');
    let (_, Some(p), Some(_), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(Error::Malformed("compact JWS must have exactly three segments".into()));
    };
    Claims::parse(&b64::decode(p)?)
}
