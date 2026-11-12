//! Client authentication at the token endpoint (RFC 6749 2.3, RFC 7521/7523, RFC 8705).
//!
//! A request may use exactly one method (RFC 6749 2.3: "MUST NOT use more than one authentication method").
//! Secrets are compared in constant time. Failures all return the same `invalid_client`.
use super::error::{ErrorCode, OAuthError, OResult};
use super::form::Params;
use crate::{b64, crypto, jwa::Algorithm, jwk::Jwk, jwt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method { SecretBasic, SecretPost, None, PrivateKeyJwt, ClientSecretJwt }

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::SecretBasic => "client_secret_basic", Method::SecretPost => "client_secret_post",
            Method::None => "none", Method::PrivateKeyJwt => "private_key_jwt", Method::ClientSecretJwt => "client_secret_jwt",
        }
    }
    pub fn parse(s: &str) -> Option<Method> {
        [Method::SecretBasic, Method::SecretPost, Method::None, Method::PrivateKeyJwt, Method::ClientSecretJwt]
            .into_iter().find(|m| m.as_str() == s)
    }
}

pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// What the client presented, before it is checked against the registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presented {
    Basic { client_id: String, secret: String },
    Post { client_id: String, secret: String },
    Assertion { client_id: Option<String>, assertion: String },
    /// Public client: only `client_id`.
    None { client_id: String },
}

impl Presented {
    pub fn method(&self) -> Method {
        match self {
            Presented::Basic { .. } => Method::SecretBasic, Presented::Post { .. } => Method::SecretPost,
            Presented::Assertion { .. } => Method::PrivateKeyJwt, Presented::None { .. } => Method::None,
        }
    }
}

fn form_decode(s: &str) -> Option<String> {
    // RFC 6749 2.3.1: id and secret are form-urlencoded before Basic encoding.
    let body = format!("x={s}");
    let pairs: Vec<_> = url::form_urlencoded::parse(body.as_bytes()).collect();
    match pairs.as_slice() { [(_, v)] => Some(v.to_string()), _ => None }
}

fn std_b64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(s).ok()
}

/// Extracts client credentials from the Authorization header and body. At most one method may be used.
pub fn extract(authorization: Option<&str>, body: &Params) -> OResult<Presented> {
    let bad = || OAuthError::invalid_client("client authentication failed");
    let mut found: Vec<Presented> = Vec::new();

    if let Some(h) = authorization {
        let (scheme, rest) = h.split_once(' ').ok_or_else(bad)?;
        if scheme.eq_ignore_ascii_case("basic") {
            let raw = std_b64_decode(rest.trim_matches(' ')).ok_or_else(bad)?;
            let s = String::from_utf8(raw).map_err(|_| bad())?;
            let (id, secret) = s.split_once(':').ok_or_else(bad)?;
            found.push(Presented::Basic { client_id: form_decode(id).ok_or_else(bad)?, secret: form_decode(secret).ok_or_else(bad)? });
        }
        // Other schemes (Bearer, DPoP) are not client authentication here.
    }
    let body_id = body.get("client_id").map_err(|_| bad())?;
    if body.contains("client_secret") {
        let secret = body.require("client_secret").map_err(|_| bad())?;
        found.push(Presented::Post { client_id: body_id.ok_or_else(bad)?.to_string(), secret: secret.to_string() });
    }
    if body.contains("client_assertion") || body.contains("client_assertion_type") {
        if body.get("client_assertion_type").map_err(|_| bad())? != Some(ASSERTION_TYPE) { return Err(bad()); }
        let a = body.require("client_assertion").map_err(|_| bad())?;
        found.push(Presented::Assertion { client_id: body_id.map(str::to_string), assertion: a.to_string() });
    }
    match found.len() {
        0 => match body_id {
            Some(id) => Ok(Presented::None { client_id: id.to_string() }),
            None => Err(bad()),
        },
        1 => {
            let p = found.remove(0);
            // If client_id is also in the body next to Basic, it must agree (RFC 6749 3.2.1 / 2.3.1).
            if let (Presented::Basic { client_id, .. }, Some(b)) = (&p, body_id) {
                if client_id != b { return Err(bad()); }
            }
            Ok(p)
        }
        _ => Err(OAuthError::invalid_request("more than one client authentication method used")),
    }
}

/// What the server registered for a client.
#[derive(Debug, Clone)]
pub struct Registered {
    pub client_id: String,
    pub method: Method,
    /// For `client_secret_*`: the secret, or better its SHA-256 (set `secret_is_hash`).
    pub secret: Option<Vec<u8>>,
    pub secret_is_hash: bool,
    /// For `private_key_jwt`: the client's public key.
    pub jwk: Option<Jwk>,
    pub assertion_algs: Vec<Algorithm>,
}

/// Verifies what was presented. Returns the authenticated `client_id`.
/// `token_endpoint` is the audience a JWT assertion must name; `issuer` is also accepted (RFC 7523 3, RFC 9700 4.?).
pub fn authenticate(p: &Presented, reg: &Registered, token_endpoint: &str, issuer: Option<&str>, now: Option<u64>, replay: Option<&dyn jwt::ReplayCache>) -> OResult<String> {
    let bad = || OAuthError::invalid_client("client authentication failed");
    if p.method() != reg.method && !(matches!(p, Presented::Assertion { .. }) && reg.method == Method::ClientSecretJwt) {
        return Err(bad());
    }
    let secret_ok = |presented: &str| -> bool {
        let Some(stored) = &reg.secret else { return false };
        if reg.secret_is_hash {
            crypto::digest(crate::jwa::Hash::Sha256, presented.as_bytes()).map(|d| crypto::ct_eq(&d, stored)).unwrap_or(false)
        } else {
            crypto::ct_eq(presented.as_bytes(), stored)
        }
    };
    match p {
        Presented::Basic { client_id, secret } | Presented::Post { client_id, secret } => {
            // Run the comparison even if the id is wrong so timing does not reveal which part failed.
            let ok = secret_ok(secret);
            if ok && client_id == &reg.client_id { Ok(client_id.clone()) } else { Err(bad()) }
        }
        Presented::None { client_id } => {
            if reg.method == Method::None && client_id == &reg.client_id { Ok(client_id.clone()) } else { Err(bad()) }
        }
        Presented::Assertion { client_id, assertion } => {
            let key = match reg.method {
                Method::PrivateKeyJwt => reg.jwk.clone().ok_or_else(bad)?,
                Method::ClientSecretJwt => {
                    let s = reg.secret.as_ref().filter(|_| !reg.secret_is_hash).ok_or_else(bad)?;
                    Jwk::parse(&serde_json::json!({"kty": "oct", "k": b64::encode(s)}).to_string()).map_err(|_| bad())?
                }
                _ => return Err(bad()),
            };
            let algs: &[Algorithm] = &reg.assertion_algs;
            if algs.is_empty() { return Err(bad()); }
            // RFC 7523 3: iss = sub = client_id; aud = token endpoint (or issuer); exp required; jti for replay.
            let mut v = jwt::Validation::new(algs, &reg.client_id, token_endpoint);
            v.now = now;
            v.leeway = 30;
            v.require = &["sub", "jti"];
            v.replay = replay;
            v.max_age = None;
            let mut result = jwt::verify(assertion, &key, &v);
            if result.is_err() {
                if let Some(i) = issuer {
                    // Second chance with the issuer identifier as audience. Replay cache entry is only written on success.
                    let mut v2 = jwt::Validation::new(algs, &reg.client_id, i);
                    v2.now = now; v2.require = &["sub", "jti"]; v2.replay = replay;
                    result = jwt::verify(assertion, &key, &v2);
                }
            }
            let (_, c) = result.map_err(|_| bad())?;
            if c.str_claim("sub").ok().flatten() != Some(reg.client_id.as_str()) { return Err(bad()); }
            if let Some(id) = client_id { if id != &reg.client_id { return Err(bad()); } }
            Ok(reg.client_id.clone())
        }
    }
}

/// Builds the `private_key_jwt` / `client_secret_jwt` assertion a client sends (RFC 7523 2.2).
pub fn build_assertion(alg: Algorithm, key: &Jwk, client_id: &str, audience: &str, lifetime_secs: u64) -> crate::Result<String> {
    let now = jwt::unix_now();
    let mut jti = [0u8; 16];
    crypto::random(&mut jti)?;
    let c = jwt::Claims::new().issuer(client_id).subject(client_id).audience(&[audience])
        .issued_at(now).expires_at(now + lifetime_secs.min(300)).jti(&b64::encode(jti));
    jwt::sign(alg, key, &c, Some("JWT"))
}

/// `Authorization: Basic ...` header value for a client (RFC 6749 2.3.1).
pub fn basic_header(client_id: &str, secret: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    format!("Basic {}", STANDARD.encode(format!("{}:{}", enc(client_id), enc(secret))))
}

pub fn invalid_client_for_basic() -> OAuthError {
    // RFC 6749 5.2: 401 plus WWW-Authenticate when the client tried the Authorization header.
    OAuthError::new(ErrorCode::InvalidClient)
}
