//! JWT profile for OAuth 2.0 access tokens (RFC 9068).
//!
//! Resource-server side is the part that matters: a JWT with the right signature is still not an access token
//! unless `typ` is `at+jwt`, the issuer is the expected one, `aud` names this resource, and the required claims exist.
use super::error::{ErrorCode, OAuthError, OResult};
use super::scope::Scope;
use crate::{b64, crypto, jwa::Algorithm, jwk::Jwk, jwt::{self, Claims, Validation}, Result};

pub const TYP: &str = "at+jwt";

/// Authorization server: issue an access token.
pub struct Issue<'a> {
    pub alg: Algorithm,
    pub key: &'a Jwk,
    pub issuer: &'a str,
    pub audience: &'a [&'a str],
    pub subject: &'a str,
    pub client_id: &'a str,
    pub scope: &'a Scope,
    pub lifetime: u64,
    pub now: Option<u64>,
    /// Extra claims (roles, auth_time, acr ...). Registered claims set by this module cannot be overridden.
    pub extra: &'a [(&'a str, serde_json::Value)],
    pub cnf: Option<serde_json::Value>,
}

impl Issue<'_> {
    pub fn sign(&self) -> Result<String> {
        let now = self.now.unwrap_or_else(jwt::unix_now);
        let mut jti = [0u8; 16];
        crypto::random(&mut jti)?;
        let mut c = Claims::new().issuer(self.issuer).subject(self.subject).audience(self.audience)
            .expires_at(now + self.lifetime).issued_at(now).jti(&b64::encode(jti)).set("client_id", self.client_id);
        if !self.scope.is_empty() { c = c.set("scope", self.scope.to_string()); }
        if let Some(cnf) = &self.cnf { c = c.set("cnf", cnf.clone()); }
        for (k, v) in self.extra {
            if !c.map.contains_key(*k) { c.map.insert((*k).to_string(), v.clone()); }
        }
        jwt::sign(self.alg, self.key, &c, Some(TYP))
    }
}

/// Resource server: how to validate.
pub struct Verify<'a> {
    pub algs: &'a [Algorithm],
    pub issuer: &'a str,
    /// This resource server's identifier (RFC 8707 resource indicator).
    pub audience: &'a str,
    pub now: Option<u64>,
    pub leeway: u64,
    pub replay: Option<&'a dyn jwt::ReplayCache>,
}

/// Verified access token.
#[derive(Debug, Clone)]
pub struct AccessToken {
    pub claims: Claims,
    pub subject: String,
    pub client_id: String,
    pub scope: Scope,
    pub jti: String,
    pub exp: u64,
}

impl AccessToken {
    /// RFC 6750 3.1 / RFC 9068: 403 `insufficient_scope` when a needed scope is missing.
    pub fn require_scope(&self, needed: &str) -> OResult<()> {
        if self.scope.contains(needed) { Ok(()) }
        else { Err(OAuthError::with(ErrorCode::InsufficientScope, "the access token lacks a required scope")) }
    }
}

pub fn verify(token: &str, key: &Jwk, v: &Verify<'_>) -> OResult<AccessToken> {
    let bad = |m: &str| OAuthError::with(ErrorCode::InvalidToken, m);
    let mut val = Validation::new(v.algs, v.issuer, v.audience);
    val.typ = Some(TYP);
    val.now = v.now;
    val.leeway = v.leeway;
    val.require = &["sub", "client_id", "jti", "iat"];
    val.replay = v.replay;
    let (_, c) = jwt::verify(token, key, &val).map_err(|e| bad(match e {
        crate::Error::BadSignature => "signature",
        crate::Error::Claim(_) => "claims",
        _ => "format",
    }))?;
    let scope = match c.str_claim("scope").map_err(|_| bad("claims"))? {
        Some(s) if !s.is_empty() => Scope::parse(s).map_err(|_| bad("claims"))?,
        _ => Scope::default(),
    };
    let s = |n: &str| c.str_claim(n).ok().flatten().map(String::from).ok_or_else(|| bad("claims"));
    Ok(AccessToken { subject: s("sub")?, client_id: s("client_id")?, jti: s("jti")?, exp: c.date("exp").ok().flatten().ok_or_else(|| bad("claims"))?, scope, claims: c })
}
