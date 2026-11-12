//! ID Tokens: issuing (OP) and validating (RP), per OpenID Connect Core 3.1.3.6 and 3.1.3.7.
//!
//! Validation rules that are easy to skip, and are not skipped here:
//! * `iss` equals the issuer the RP discovered; `aud` contains the RP's `client_id` and nothing the RP does not trust;
//! * more than one audience requires `azp`, and `azp` (when present) must be the RP's `client_id`;
//! * `nonce` that was sent must come back, compared in constant time;
//! * `max_age` that was sent requires `auth_time`, and the authentication must be recent enough;
//! * `at_hash` and `c_hash` are checked when present, and required when the caller says the flow requires them;
//! * `iat` and `sub` must exist, `exp` must be in the future, and a token with `typ: at+jwt` is not an ID token.
use crate::jwa::{Algorithm, Family, Hash};
use crate::jwk::Jwk;
use crate::jwt::{self, Claims, ReplayCache, Validation};
use crate::{b64, crypto, jws, Error, Result};
use serde_json::Value;

/// Longest ID token lifetime the issuer will sign. ID tokens prove an authentication event; they are not sessions.
pub const MAX_LIFETIME: u64 = 3600;

/// Left half of the hash of `value` (OIDC Core 3.1.3.6), base64url. The hash is the one the signing algorithm uses; for EdDSA
/// it is SHA-512 (Ed25519).
pub fn half_hash(alg: Algorithm, value: &str) -> Result<String> {
    let h = match alg.family() {
        Family::EdDsa => Hash::Sha512,
        _ => alg.hash().ok_or_else(|| Error::Algorithm("no hash for this algorithm".into()))?,
    };
    let d = crypto::digest(h, value.as_bytes())?;
    Ok(b64::encode(&d[..d.len() / 2]))
}

/// What the OP puts in an ID token.
pub struct IdTokenIssue<'a> {
    pub alg: Algorithm,
    pub key: &'a Jwk,
    pub issuer: &'a str,
    pub client_id: &'a str,
    /// The `sub` for this client (use [`super::claims::PairwiseSubjects`] for pairwise clients).
    pub subject: &'a str,
    pub lifetime: u64,
    pub now: Option<u64>,
    /// The request's `nonce`. Copied verbatim.
    pub nonce: Option<&'a str>,
    pub auth_time: Option<u64>,
    /// Set when the request carried `max_age` or an essential `auth_time` claim: signing then fails without `auth_time`.
    pub require_auth_time: bool,
    pub acr: Option<&'a str>,
    pub amr: &'a [&'a str],
    /// When given, `at_hash` is added.
    pub access_token: Option<&'a str>,
    /// When given, `c_hash` is added (hybrid flows only).
    pub code: Option<&'a str>,
    /// Session id for logout (`sid`).
    pub sid: Option<&'a str>,
    /// Further audiences. When used, `azp` is set to `client_id`.
    pub extra_audiences: &'a [&'a str],
    /// Extra claims (from the `claims` request, or scopes in the ID token). Registered claims set here cannot be overridden.
    pub extra: &'a [(&'a str, Value)],
}

impl<'a> IdTokenIssue<'a> {
    pub fn new(alg: Algorithm, key: &'a Jwk, issuer: &'a str, client_id: &'a str, subject: &'a str) -> Self {
        IdTokenIssue { alg, key, issuer, client_id, subject, lifetime: 300, now: None, nonce: None, auth_time: None, require_auth_time: false, acr: None,
            amr: &[], access_token: None, code: None, sid: None, extra_audiences: &[], extra: &[] }
    }

    pub fn sign(&self) -> Result<String> {
        if self.lifetime == 0 || self.lifetime > MAX_LIFETIME { return Err(Error::Claim(format!("ID token lifetime must be 1..={MAX_LIFETIME} seconds"))); }
        if self.require_auth_time && self.auth_time.is_none() { return Err(Error::Claim("auth_time is required by the request (max_age or claims) but was not provided".into())); }
        if matches!(self.alg.family(), Family::Hmac) { return Err(Error::Algorithm("ID tokens are signed with asymmetric keys by this issuer".into())); }
        let now = self.now.unwrap_or_else(jwt::unix_now);
        if let Some(t) = self.auth_time { if t > now + 5 { return Err(Error::Claim("auth_time is in the future".into())); } }
        let mut aud = vec![self.client_id];
        aud.extend_from_slice(self.extra_audiences);
        let mut c = Claims::new().issuer(self.issuer).subject(self.subject).audience(&aud).expires_at(now + self.lifetime).issued_at(now);
        if !self.extra_audiences.is_empty() { c = c.set("azp", self.client_id); }
        if let Some(n) = self.nonce { c = c.set("nonce", n); }
        if let Some(t) = self.auth_time { c = c.set("auth_time", t); }
        if let Some(a) = self.acr { c = c.set("acr", a); }
        if !self.amr.is_empty() { c = c.set("amr", Value::Array(self.amr.iter().map(|s| Value::String((*s).into())).collect())); }
        if let Some(t) = self.access_token { c = c.set("at_hash", half_hash(self.alg, t)?); }
        if let Some(t) = self.code { c = c.set("c_hash", half_hash(self.alg, t)?); }
        if let Some(s) = self.sid { c = c.set("sid", s); }
        for (k, v) in self.extra { if !c.map.contains_key(*k) { c.map.insert((*k).to_string(), v.clone()); } }
        jwt::sign(self.alg, self.key, &c, None)
    }
}

/// How an RP validates an ID token.
pub struct Validate<'a> {
    pub algs: &'a [Algorithm],
    /// The issuer identifier from discovery.
    pub issuer: &'a str,
    pub client_id: &'a str,
    /// The nonce sent in the authentication request. `Some`: the token must carry exactly this nonce.
    pub nonce: Option<&'a str>,
    /// The `max_age` sent in the request. `Some`: `auth_time` is required and must be within it (plus leeway).
    pub max_age: Option<u64>,
    /// The access token from the same token response: `at_hash` is checked against it.
    pub access_token: Option<&'a str>,
    pub code: Option<&'a str>,
    /// Refuse a token without `at_hash` (required when the ID token comes from the authorization endpoint in a flow that returns a token).
    pub require_at_hash: bool,
    pub require_c_hash: bool,
    /// Acceptable `acr` values. Non-empty: the token must carry one of them.
    pub acr_values: &'a [&'a str],
    /// Audiences besides `client_id` that the RP accepts. Any other audience is refused (Core 3.1.3.7 step 3).
    pub trusted_audiences: &'a [&'a str],
    pub now: Option<u64>,
    pub leeway: u64,
    /// Reject ID tokens whose `iat` is older than this (bounds how long nonces must be remembered).
    pub max_iat_age: Option<u64>,
    pub replay: Option<&'a dyn ReplayCache>,
}

impl<'a> Validate<'a> {
    pub fn new(algs: &'a [Algorithm], issuer: &'a str, client_id: &'a str) -> Self {
        Validate { algs, issuer, client_id, nonce: None, max_age: None, access_token: None, code: None, require_at_hash: false, require_c_hash: false,
            acr_values: &[], trusted_audiences: &[], now: None, leeway: 30, max_iat_age: None, replay: None }
    }
}

/// A validated ID token.
#[derive(Debug, Clone)]
pub struct IdToken {
    pub header: jws::Header,
    pub claims: Claims,
    pub subject: String,
    pub auth_time: Option<u64>,
    pub nonce: Option<String>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub sid: Option<String>,
}

fn str_list(c: &Claims, name: &str) -> Result<Vec<String>> {
    match c.map.get(name) {
        None => Ok(vec![]),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| Error::Claim(format!("{name} must hold strings")))).collect(),
        Some(_) => Err(Error::Claim(format!("{name} must be an array"))),
    }
}

/// Validates `token` with the OP's key for it. Choose the key from the OP's JWK Set with [`crate::jwk::JwkSet::select`].
/// Symmetric algorithms are only possible when the caller lists them in `algs` and passes the client secret as the key.
pub fn validate(token: &str, key: &Jwk, v: &Validate<'_>) -> Result<IdToken> {
    let h = jws::peek_header(token)?;
    if h.typ.as_deref().map_or(false, |t| t.eq_ignore_ascii_case("at+jwt") || t.eq_ignore_ascii_case("application/at+jwt")) {
        return Err(Error::Claim("an access token is not an ID token".into()));
    }
    let mut val = Validation::new(v.algs, v.issuer, v.client_id);
    val.leeway = v.leeway;
    val.now = v.now;
    val.require = &["sub", "iat"];
    val.replay = v.replay;
    let (header, claims) = jwt::verify(token, key, &val)?;
    let now = v.now.unwrap_or_else(jwt::unix_now);
    let leeway = v.leeway.min(Validation::MAX_LEEWAY);

    // Audience (Core 3.1.3.7 steps 3, 4, 5).
    let aud = claims.aud_list()?.ok_or_else(|| Error::Claim("aud is missing".into()))?;
    if let Some(extra) = aud.iter().find(|a| **a != v.client_id && !v.trusted_audiences.contains(a)) {
        return Err(Error::Claim(format!("aud lists an audience this client does not trust: {extra}")));
    }
    let azp = claims.str_claim("azp")?;
    if aud.len() > 1 && azp.is_none() { return Err(Error::Claim("several audiences but no azp".into())); }
    if let Some(a) = azp { if a != v.client_id { return Err(Error::Claim("azp is not this client".into())); } }

    // Nonce (step 11).
    let nonce = claims.str_claim("nonce")?.map(String::from);
    if let Some(sent) = v.nonce {
        match &nonce { Some(got) if crypto::ct_eq(got.as_bytes(), sent.as_bytes()) => {}, Some(_) => return Err(Error::Claim("nonce does not match".into())), None => return Err(Error::Claim("nonce is missing".into())) }
    }

    // auth_time / max_age (steps 12, 13).
    let auth_time = claims.date("auth_time")?;
    if let Some(t) = auth_time { if t > now.saturating_add(leeway) { return Err(Error::Claim("auth_time is in the future".into())); } }
    if let Some(max) = v.max_age {
        let t = auth_time.ok_or_else(|| Error::Claim("auth_time is required when max_age was requested".into()))?;
        if now.saturating_sub(t) > max.saturating_add(leeway) { return Err(Error::Claim("authentication is older than max_age".into())); }
    }
    if let Some(max) = v.max_iat_age {
        let iat = claims.date("iat")?.ok_or_else(|| Error::Claim("iat is missing".into()))?;
        if now.saturating_sub(iat) > max.saturating_add(leeway) { return Err(Error::Claim("ID token is too old".into())); }
    }

    // acr (step 14).
    let acr = claims.str_claim("acr")?.map(String::from);
    if !v.acr_values.is_empty() {
        match acr.as_deref() { Some(a) if v.acr_values.contains(&a) => {}, _ => return Err(Error::Claim("acr is not one of the acceptable values".into())) }
    }

    // at_hash / c_hash (3.1.3.6, 3.3.2.11).
    for (name, value, required) in [("at_hash", v.access_token, v.require_at_hash), ("c_hash", v.code, v.require_c_hash)] {
        match (claims.str_claim(name)?, value) {
            (Some(h), Some(val)) => { if !crypto::ct_eq(h.as_bytes(), half_hash(header.alg, val)?.as_bytes()) { return Err(Error::Claim(format!("{name} does not match"))); } }
            (None, _) if required => return Err(Error::Claim(format!("{name} is required"))),
            (Some(_), None) if required => return Err(Error::Claim(format!("{name} is present but there is nothing to check it against"))),
            _ => {}
        }
    }

    let subject = claims.str_claim("sub")?.filter(|s| !s.is_empty() && s.len() <= 255).ok_or_else(|| Error::Claim("sub is missing or longer than 255 characters".into()))?.to_string();
    Ok(IdToken { header, subject, auth_time, nonce, acr, amr: str_list(&claims, "amr")?, sid: claims.str_claim("sid")?.map(String::from), claims })
}

/// OP side: an `id_token_hint` (Core 3.1.2.1). The signature, issuer and audience are checked, but expiry is not: a hint is
/// usually an old token and the spec says the OP should accept expired ones. The result is a *hint*: it must never log a user in.
pub fn verify_hint(token: &str, key: &Jwk, algs: &[Algorithm], issuer: &str, client_id: Option<&str>) -> Result<Claims> {
    let (_, payload) = jws::verify(token, key, &jws::Policy::new(algs))?;
    let c = Claims::parse(&payload).map_err(|_| Error::Claim("payload is not a JSON object".into()))?;
    match c.str_claim("iss")? { Some(i) if i == issuer => {}, _ => return Err(Error::Claim("hint was not issued by this OP".into())) }
    if let Some(cid) = client_id {
        match c.aud_list()? { Some(a) if a.contains(&cid) => {}, _ => return Err(Error::Claim("hint was not issued to this client".into())) }
    }
    c.str_claim("sub")?.ok_or_else(|| Error::Claim("hint has no sub".into()))?;
    Ok(c)
}

/// Builds the ID token for a redeemed authorization code (OP side, token endpoint). Reads `nonce`, `auth_time`, `acr`, `sid`, `amr`,
/// `max_age` and `claims` back from the [`crate::oauth::token::CodeRecord`] that [`crate::oauth::token::issue_code_with`] stored.
/// Returns `None` when the grant has no `openid` scope (a plain OAuth grant gets no ID token).
///
/// `profile` is everything the OP knows about the user; only claims the request asked for in `claims.id_token` are copied in.
/// Standard scope claims (`profile`, `email`, ...) are NOT put in the ID token: they belong to UserInfo (Core 5.4), which keeps
/// ID tokens small and keeps PII out of tokens that pass through browsers.
pub fn for_code(rec: &crate::oauth::token::CodeRecord, key: &Jwk, alg: Algorithm, issuer: &str, subject: &str, access_token: &str,
    lifetime: u64, profile: &serde_json::Map<String, Value>, now: Option<u64>) -> Result<Option<String>> {
    if !rec.scope.contains("openid") { return Ok(None); }
    let get = |n: &str| rec.extra.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    let claims = match get("claims") { Some(c) => super::request::ClaimsRequest::parse(c)?, None => super::request::ClaimsRequest::default() };
    let max_age = get("max_age").and_then(|s| s.parse::<u64>().ok());
    let auth_time = get("auth_time").and_then(|s| s.parse::<u64>().ok());
    let amr: Vec<&str> = get("amr").map(|s| s.split(' ').filter(|x| !x.is_empty()).collect()).unwrap_or_default();
    let (picked, missing) = super::request::pick_claims(&claims.id_token, profile);
    let _ = missing; // essential-but-unavailable claims are simply omitted: the spec lets the OP leave them out
    let picked: Vec<(String, Value)> = picked.into_iter().filter(|(k, _)| !matches!(k.as_str(), "auth_time" | "acr" | "nonce" | "sub" | "iss" | "aud" | "exp" | "iat")).collect();
    let extra: Vec<(&str, Value)> = picked.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    let mut i = IdTokenIssue::new(alg, key, issuer, &rec.client_id, subject);
    i.lifetime = lifetime; i.now = now; i.nonce = rec.nonce.as_deref(); i.auth_time = auth_time; i.acr = get("acr"); i.amr = &amr;
    i.sid = get("sid"); i.access_token = Some(access_token); i.extra = &extra;
    i.require_auth_time = max_age.is_some() || claims.requires_auth_time();
    i.sign().map(Some)
}
