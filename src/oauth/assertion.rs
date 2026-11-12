//! Assertion framework (RFC 7521) and the JWT bearer authorization grant (RFC 7523 section 2.1, 3).
//!
//! A trusted party signs a JWT that says "this subject may get an access token". The authorization server checks it against a
//! registry of trusted issuers. Rules enforced here:
//! * the issuer must be in the registry, and the key comes from the registry, never from the token (RFC 8725 3.5);
//! * `iss`, `sub`, `aud` and `exp` are required; `aud` must name this server's token endpoint or issuer identifier;
//! * the lifetime (`exp` minus `iat`, or minus now when `iat` is absent) is capped by the issuer's registry entry;
//! * when the issuer requires it, `jti` is mandatory and a repeat is refused (RFC 7523 3 item 7);
//! * the granted scope can only narrow what the issuer is allowed to grant;
//! * client authentication is optional for this grant (RFC 7521 4.1) but an unauthenticated assertion for a confidential client
//!   would be a bypass, so the caller must pass the authentication result (see [`Request::client_id`]).
//!
//! SAML 2.0 bearer assertions (RFC 7522) share the request shape. XML signature verification is the most attacked part of SAML
//! (signature wrapping). Authlas does not ship an XML-DSig verifier, so SAML goes through the [`AssertionVerifier`] trait: you
//! plug in a SAML library, and this module still enforces the request shape, scope narrowing and replay rules.
use super::error::{ErrorCode, OAuthError, OResult};
use super::form::Params;
use super::scope::Scope;
use crate::{jwa::Algorithm, jwk::Jwk, jws, jwt::{self, Claims, ReplayCache, Validation}};

pub const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const GRANT_SAML2_BEARER: &str = "urn:ietf:params:oauth:grant-type:saml2-bearer";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind { Jwt, Saml2 }

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub kind: Kind,
    pub assertion: String,
    pub scope: Option<Scope>,
    /// Set by the caller after client authentication succeeded (RFC 7521 4.1). `None` means the client was not authenticated.
    pub client_id: Option<String>,
}

pub const MAX_ASSERTION_LEN: usize = 16 * 1024;

pub fn parse_request(body: &Params) -> OResult<Request> {
    let bad = |m: &str| OAuthError::invalid_request(m);
    let kind = match body.get("grant_type").map_err(|_| bad("grant_type repeated"))? {
        Some(GRANT_JWT_BEARER) => Kind::Jwt,
        Some(GRANT_SAML2_BEARER) => Kind::Saml2,
        _ => return Err(OAuthError::new(ErrorCode::UnsupportedGrantType)),
    };
    let assertion = body.get("assertion").map_err(|_| bad("assertion must not repeat"))?.ok_or_else(|| bad("assertion is required"))?;
    if assertion.is_empty() || assertion.len() > MAX_ASSERTION_LEN { return Err(OAuthError::invalid_grant("assertion has an invalid size")); }
    let scope = body.get("scope").map_err(|_| bad("scope must not repeat"))?
        .map(|s| Scope::parse(s).map_err(|_| OAuthError::with(ErrorCode::InvalidScope, "malformed scope"))).transpose()?;
    Ok(Request { kind, assertion: assertion.to_string(), scope, client_id: None })
}

/// Builds the form body a client sends.
pub fn request_body(kind: Kind, assertion: &str, scope: Option<&Scope>) -> String {
    let gt = match kind { Kind::Jwt => GRANT_JWT_BEARER, Kind::Saml2 => GRANT_SAML2_BEARER };
    let s = scope.map(|s| s.to_string());
    let mut pairs = vec![("grant_type", gt), ("assertion", assertion)];
    if let Some(s) = &s { pairs.push(("scope", s)); }
    super::form::encode(pairs)
}

/// One trusted assertion issuer.
#[derive(Debug, Clone)]
pub struct TrustedIssuer {
    pub issuer: String,
    pub keys: Vec<Jwk>,
    pub algs: Vec<Algorithm>,
    /// Longest accepted validity, in seconds.
    pub max_lifetime: u64,
    pub require_jti: bool,
    /// The most this issuer can grant. A request outside it is `invalid_scope`.
    pub allowed_scopes: Scope,
    /// When non-empty, only these subjects may be asserted (for issuers that serve one tenant).
    pub allowed_subjects: Vec<String>,
}

impl TrustedIssuer {
    pub fn new(issuer: &str, keys: Vec<Jwk>, algs: Vec<Algorithm>, allowed_scopes: Scope) -> Self {
        TrustedIssuer { issuer: issuer.into(), keys, algs, max_lifetime: 300, require_jti: true, allowed_scopes, allowed_subjects: vec![] }
    }
}

pub struct Context<'a> {
    pub trusted: &'a [TrustedIssuer],
    pub token_endpoint: &'a str,
    pub issuer: &'a str,
    pub now: Option<u64>,
    pub leeway: u64,
    pub replay: Option<&'a dyn ReplayCache>,
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub assertion_issuer: String,
    pub subject: String,
    pub scope: Scope,
    pub claims: Claims,
}

/// Plug-in point for formats this crate does not verify itself (SAML 2.0).
pub trait AssertionVerifier {
    /// Returns the verified `(issuer, subject, not_on_or_after, assertion_id)` or an error. Must itself check audience,
    /// recipient, `NotBefore`/`NotOnOrAfter` and the XML signature.
    fn verify(&self, assertion: &str) -> Result<VerifiedAssertion, String>;
}

#[derive(Debug, Clone)]
pub struct VerifiedAssertion { pub issuer: String, pub subject: String, pub expires_at: u64, pub id: String }

fn denied(m: &str) -> OAuthError { OAuthError::invalid_grant(m) }

/// Verifies a JWT bearer assertion for the authorization server.
pub fn verify_jwt(req: &Request, ctx: &Context<'_>) -> OResult<Grant> {
    if req.kind != Kind::Jwt { return Err(OAuthError::new(ErrorCode::UnsupportedGrantType)); }
    let claims = jwt::peek_claims_unverified(&req.assertion).map_err(|_| denied("assertion is not a valid JWT"))?;
    let iss = claims.str_claim("iss").ok().flatten().ok_or_else(|| denied("assertion has no issuer"))?;
    // Same answer for an unknown issuer and for a bad signature, so the registry cannot be enumerated.
    let uniform = || denied("assertion was not accepted");
    let ti = ctx.trusted.iter().find(|t| t.issuer == iss).ok_or_else(uniform)?;
    let header = jws::peek_header(&req.assertion).map_err(|_| uniform())?;
    let candidates: Vec<&Jwk> = match (&header.kid, ti.keys.as_slice()) {
        (Some(k), keys) => keys.iter().filter(|x| x.kid.as_deref() == Some(k.as_str())).collect(),
        (None, [only]) => vec![only],
        _ => vec![],
    };
    if candidates.is_empty() { return Err(uniform()); }
    let now = ctx.now.unwrap_or_else(jwt::unix_now);
    let mut verified = None;
    for key in candidates {
        // Try both accepted audiences. The replay cache is written only on the attempt that succeeds.
        for aud in [ctx.token_endpoint, ctx.issuer] {
            let mut v = Validation::new(&ti.algs, &ti.issuer, aud);
            v.now = Some(now); v.leeway = ctx.leeway;
            v.require = if ti.require_jti { &["sub", "jti"] } else { &["sub"] };
            // Replay is recorded below, after every other check, so a request that fails on scope does not burn a good assertion.
            if let Ok(ok) = jwt::verify(&req.assertion, key, &v) { verified = Some(ok); break; }
        }
        if verified.is_some() { break; }
    }
    let (_, c) = verified.ok_or_else(uniform)?;
    // Lifetime cap: RFC 7523 3 leaves it to the server; a bearer assertion that lives for a year is a standing credential.
    let exp = c.date("exp").ok().flatten().ok_or_else(uniform)?;
    let start = c.date("iat").ok().flatten().unwrap_or(now).min(now);
    if exp.saturating_sub(start) > ti.max_lifetime { return Err(denied("assertion lifetime is longer than this issuer may grant")); }
    let sub = c.str_claim("sub").ok().flatten().filter(|s| !s.is_empty()).ok_or_else(uniform)?.to_string();
    if !ti.allowed_subjects.is_empty() && !ti.allowed_subjects.iter().any(|s| s == &sub) { return Err(uniform()); }
    let scope = narrow(req.scope.as_ref(), &ti.allowed_scopes)?;
    if let (true, Some(r)) = (ti.require_jti, ctx.replay) {
        let jti = c.str_claim("jti").ok().flatten().ok_or_else(uniform)?;
        // Same key shape as jwt::Validation uses, so one cache serves both.
        if !r.first_use(&format!("{}
{}", ti.issuer, jti), exp.saturating_add(ctx.leeway.min(jwt::Validation::MAX_LEEWAY)), now) {
            return Err(denied("assertion was already used"));
        }
    }
    Ok(Grant { assertion_issuer: ti.issuer.clone(), subject: sub, scope, claims: c })
}

/// Verifies a non-JWT assertion through a plug-in verifier (RFC 7522). The server rules (lifetime, replay, scope) still apply.
pub fn verify_with(req: &Request, verifier: &dyn AssertionVerifier, trusted: &[TrustedIssuer], ctx: &Context<'_>) -> OResult<Grant> {
    if req.kind != Kind::Saml2 { return Err(OAuthError::new(ErrorCode::UnsupportedGrantType)); }
    let v = verifier.verify(&req.assertion).map_err(|_| denied("assertion was not accepted"))?;
    let ti = trusted.iter().find(|t| t.issuer == v.issuer).ok_or_else(|| denied("assertion was not accepted"))?;
    let now = ctx.now.unwrap_or_else(jwt::unix_now);
    if now >= v.expires_at.saturating_add(ctx.leeway.min(300)) { return Err(denied("assertion has expired")); }
    if v.expires_at.saturating_sub(now) > ti.max_lifetime + ctx.leeway.min(300) { return Err(denied("assertion lifetime is longer than this issuer may grant")); }
    if v.subject.is_empty() { return Err(denied("assertion has no subject")); }
    if !ti.allowed_subjects.is_empty() && !ti.allowed_subjects.iter().any(|s| s == &v.subject) { return Err(denied("assertion was not accepted")); }
    if let Some(r) = ctx.replay {
        if !r.first_use(&format!("{}\n{}", v.issuer, v.id), v.expires_at, now) { return Err(denied("assertion was already used")); }
    }
    let scope = narrow(req.scope.as_ref(), &ti.allowed_scopes)?;
    Ok(Grant { assertion_issuer: v.issuer, subject: v.subject, scope, claims: Claims::new() })
}

fn narrow(requested: Option<&Scope>, allowed: &Scope) -> OResult<Scope> {
    match requested {
        None => Ok(allowed.clone()),
        Some(r) if r.is_subset_of(allowed) => Ok(r.clone()),
        Some(_) => Err(OAuthError::with(ErrorCode::InvalidScope, "requested scope exceeds what the assertion issuer may grant")),
    }
}

// ---------- building (the trusted party / client side) ----------

/// Builds a JWT bearer assertion (RFC 7523 2.1).
pub fn build_jwt(alg: Algorithm, key: &Jwk, issuer: &str, subject: &str, audience: &str, lifetime: u64) -> crate::Result<String> {
    let now = jwt::unix_now();
    let mut j = [0u8; 16];
    crate::crypto::random(&mut j)?;
    let c = Claims::new().issuer(issuer).subject(subject).audience(&[audience]).issued_at(now).expires_at(now + lifetime).jti(&crate::b64::encode(j));
    jwt::sign(alg, key, &c, Some("JWT"))
}
