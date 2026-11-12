//! Token endpoint: request parsing, response building, authorization-code redemption and refresh-token rotation.
//!
//! Storage is behind traits so a database can back it. Codes and refresh tokens are stored as SHA-256 hashes,
//! so a leaked store does not yield usable credentials. Both are high-entropy random values, which is why a
//! plain hash (not a password hash) is the right tool.
//!
//! Rules enforced here:
//! * authorization codes are single use, short lived, bound to client, redirect URI and PKCE challenge
//!   (RFC 6749 4.1.2, 4.1.3, RFC 7636, RFC 9700 2.1.1);
//! * a second use of a code revokes every token issued from it (RFC 6749 4.1.2);
//! * refresh tokens rotate on every use, and presenting an old one revokes the whole family (RFC 9700 4.14);
//! * the resource-owner password grant does not exist (RFC 9700 2.4, OAuth 2.1).
use super::error::{ErrorCode, OAuthError, OResult};
use super::form::Params;
use super::pkce::{self, Method};
use super::scope::Scope;
use crate::{b64, crypto, jwa::Hash, jwt::unix_now};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

pub const GRANT_AUTH_CODE: &str = "authorization_code";
pub const GRANT_REFRESH: &str = "refresh_token";
pub const GRANT_CLIENT_CREDENTIALS: &str = "client_credentials";

// ---------- request ----------

#[derive(Debug, Clone, PartialEq)]
pub enum TokenRequest {
    AuthorizationCode { code: String, redirect_uri: Option<String>, code_verifier: Option<String>, resources: Vec<String> },
    RefreshToken { refresh_token: String, scope: Option<Scope>, resources: Vec<String> },
    ClientCredentials { scope: Option<Scope>, resources: Vec<String> },
}

/// Parses the form body. Client authentication parameters are handled by `client_auth::extract`.
pub fn parse_request(body: &Params) -> OResult<TokenRequest> {
    let bad = |m: &str| OAuthError::invalid_request(m);
    let one = |n: &str| body.get(n).map_err(|_| bad(&format!("{n} must not repeat")));
    let scope = |n: &str| -> OResult<Option<Scope>> {
        one(n)?.map(|s| Scope::parse(s).map_err(|_| OAuthError::with(ErrorCode::InvalidScope, "malformed scope"))).transpose()
    };
    let resources: Vec<String> = body.get_all("resource").to_vec();
    match one("grant_type")?.ok_or_else(|| bad("grant_type is required"))? {
        GRANT_AUTH_CODE => Ok(TokenRequest::AuthorizationCode {
            code: one("code")?.ok_or_else(|| bad("code is required"))?.to_string(),
            redirect_uri: one("redirect_uri")?.map(str::to_string),
            code_verifier: one("code_verifier")?.map(str::to_string),
            resources,
        }),
        GRANT_REFRESH => Ok(TokenRequest::RefreshToken {
            refresh_token: one("refresh_token")?.ok_or_else(|| bad("refresh_token is required"))?.to_string(),
            scope: scope("scope")?, resources,
        }),
        GRANT_CLIENT_CREDENTIALS => Ok(TokenRequest::ClientCredentials { scope: scope("scope")?, resources }),
        // The password grant is refused outright, whatever the client is.
        _ => Err(OAuthError::new(ErrorCode::UnsupportedGrantType)),
    }
}

// ---------- response ----------

#[derive(Debug, Clone, PartialEq)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<Scope>,
    pub extra: Vec<(String, Value)>,
}

impl TokenResponse {
    pub fn bearer(access_token: &str, expires_in: u64) -> Self {
        TokenResponse { access_token: access_token.into(), token_type: "Bearer".into(), expires_in: Some(expires_in), refresh_token: None, scope: None, extra: vec![] }
    }
    pub fn to_json(&self) -> String {
        let mut v = json!({ "access_token": self.access_token, "token_type": self.token_type });
        if let Some(e) = self.expires_in { v["expires_in"] = json!(e); }
        if let Some(r) = &self.refresh_token { v["refresh_token"] = json!(r); }
        if let Some(s) = &self.scope { v["scope"] = json!(s.to_string()); }
        for (k, x) in &self.extra {
            // Extensions cannot overwrite the core members.
            if v.get(k).is_none() { v[k] = x.clone(); }
        }
        v.to_string()
    }
    /// Client side. `token_type` is compared case-insensitively (RFC 6749 7.1). `access_token` must be present.
    pub fn parse(body: &str) -> OResult<TokenResponse> {
        let bad = || OAuthError::with(ErrorCode::ServerError, "malformed token response");
        let v: Value = serde_json::from_str(body).map_err(|_| bad())?;
        let o = v.as_object().ok_or_else(bad)?;
        let s = |k: &str| match o.get(k) { None => Ok(None), Some(Value::String(s)) => Ok(Some(s.clone())), Some(_) => Err(bad()) };
        let access_token = s("access_token")?.filter(|t| !t.is_empty()).ok_or_else(bad)?;
        let token_type = s("token_type")?.ok_or_else(bad)?;
        let expires_in = match o.get("expires_in") {
            None => None,
            // Some servers send a string; accept digits only.
            Some(Value::Number(n)) => Some(n.as_u64().ok_or_else(bad)?),
            Some(Value::String(t)) if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) => Some(t.parse().map_err(|_| bad())?),
            Some(_) => return Err(bad()),
        };
        let scope = s("scope")?.map(|x| Scope::parse(&x)).transpose().map_err(|_| bad())?;
        let extra = o.iter().filter(|(k, _)| !["access_token", "token_type", "expires_in", "refresh_token", "scope"].contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
        Ok(TokenResponse { access_token, token_type, expires_in, refresh_token: s("refresh_token")?, scope, extra })
    }
}

/// A fresh 256-bit random credential, base64url.
pub fn random_token() -> crate::Result<String> {
    let mut b = [0u8; 32];
    crypto::random(&mut b)?;
    Ok(b64::encode(b))
}

fn fingerprint(secret: &str) -> String {
    b64::encode(crypto::digest(Hash::Sha256, secret.as_bytes()).unwrap_or_default())
}

// ---------- authorization codes ----------

/// What the server remembers about an issued code.
#[derive(Debug, Clone)]
pub struct CodeRecord {
    pub client_id: String,
    pub subject: String,
    pub redirect_uri: String,
    pub scope: Scope,
    pub resources: Vec<String>,
    pub challenge: Option<String>,
    pub method: Option<Method>,
    pub expires_at: u64,
    /// Identifier tying together everything issued from this code, so it can be revoked as a unit.
    pub grant_id: String,
    pub nonce: Option<String>,
    pub extra: Vec<(String, String)>,
    /// Whether the `redirect_uri` parameter was in the authorization request (RFC 6749 4.1.3).
    pub redirect_uri_was_sent: bool,
}

pub enum CodeTake {
    Valid(CodeRecord),
    /// The code was already used. `grant_id` identifies what to revoke.
    Reused { grant_id: String },
    Unknown,
}

pub trait CodeStore {
    fn put(&self, code_fingerprint: String, rec: CodeRecord);
    /// Atomically removes and returns the record. A second call for the same code must report `Reused`.
    fn take(&self, code_fingerprint: &str) -> CodeTake;
}

pub trait RevocationSink {
    /// Called when reuse of a code or refresh token is detected.
    fn revoke_grant(&self, grant_id: &str);
}

#[derive(Default)]
pub struct MemoryCodeStore {
    live: Mutex<HashMap<String, CodeRecord>>,
    used: Mutex<HashMap<String, (String, u64)>>,
}
impl MemoryCodeStore { pub fn new() -> Self { Self::default() } }

impl CodeStore for MemoryCodeStore {
    fn put(&self, fp: String, rec: CodeRecord) {
        if let Ok(mut m) = self.live.lock() { m.insert(fp, rec); }
    }
    fn take(&self, fp: &str) -> CodeTake {
        let (Ok(mut live), Ok(mut used)) = (self.live.lock(), self.used.lock()) else { return CodeTake::Unknown };
        let now = unix_now();
        used.retain(|_, (_, until)| *until > now);
        if let Some(rec) = live.remove(fp) {
            // Remember the code for an hour after use so replay is distinguishable from "never existed".
            used.insert(fp.to_string(), (rec.grant_id.clone(), rec.expires_at.max(now) + 3600));
            return CodeTake::Valid(rec);
        }
        match used.get(fp) { Some((g, _)) => CodeTake::Reused { grant_id: g.clone() }, None => CodeTake::Unknown }
    }
}

/// Lifetime of an authorization code. RFC 6749 4.1.2: "A maximum authorization code lifetime of 10 minutes is RECOMMENDED."
pub const CODE_LIFETIME: u64 = 60;

/// Issues a code. Returns (code to send to the client, grant_id).
pub fn issue_code(store: &dyn CodeStore, req: &super::request::AuthRequest, subject: &str, granted: Scope, now: Option<u64>) -> crate::Result<(String, String)> {
    issue_code_with(store, req, subject, granted, now, &[])
}

/// Same, and also stores `session` pairs on the record (for OpenID Connect: `auth_time`, `acr`, `sid`, `amr`). The request's OIDC
/// parameters (`max_age`, `claims`, ...) are stored too, so the token endpoint can build the ID token without the browser's help.
/// Pairs in `session` replace request extensions of the same name: a client cannot supply its own `auth_time`.
pub fn issue_code_with(store: &dyn CodeStore, req: &super::request::AuthRequest, subject: &str, granted: Scope, now: Option<u64>, session: &[(&str, &str)]) -> crate::Result<(String, String)> {
    let code = random_token()?;
    let grant_id = random_token()?;
    let rec = CodeRecord {
        client_id: req.client_id.clone(), subject: subject.into(), redirect_uri: req.redirect_uri.clone(),
        scope: granted, resources: req.resources.clone(), challenge: req.code_challenge.clone(), method: req.code_challenge_method,
        expires_at: now.unwrap_or_else(unix_now) + CODE_LIFETIME, grant_id: grant_id.clone(), nonce: req.nonce.clone(),
        extra: req.extra.iter().chain(req.oidc.iter()).filter(|(k, _)| !session.iter().any(|(n, _)| n == k)).cloned()
            .chain(session.iter().map(|(k, v)| (k.to_string(), v.to_string()))).collect(),
        redirect_uri_was_sent: true,
    };
    store.put(fingerprint(&code), rec);
    Ok((code, grant_id))
}

/// Redeems a code. Every check failure returns the same `invalid_grant` so an attacker learns nothing.
pub fn redeem_code(
    store: &dyn CodeStore, revoker: &dyn RevocationSink, client_id: &str, code: &str,
    redirect_uri: Option<&str>, code_verifier: Option<&str>, now: Option<u64>,
) -> OResult<CodeRecord> {
    let denied = || OAuthError::invalid_grant("authorization code is invalid, expired or already used");
    let rec = match store.take(&fingerprint(code)) {
        CodeTake::Valid(r) => r,
        CodeTake::Reused { grant_id } => { revoker.revoke_grant(&grant_id); return Err(denied()); }
        CodeTake::Unknown => return Err(denied()),
    };
    if now.unwrap_or_else(unix_now) >= rec.expires_at { return Err(denied()); }
    if rec.client_id != client_id { return Err(denied()); }
    // RFC 6749 4.1.3: redirect_uri is required if it was in the authorization request, and must be identical.
    if rec.redirect_uri_was_sent && redirect_uri != Some(rec.redirect_uri.as_str()) { return Err(denied()); }
    match (&rec.challenge, rec.method) {
        (Some(ch), Some(m)) => {
            let v = code_verifier.ok_or_else(denied)?;
            pkce::verify(ch, m, v).map_err(|_| denied())?;
        }
        // No challenge stored: a verifier now is a downgrade-attack signal (RFC 9700 4.8.2): refuse.
        (None, _) => if code_verifier.is_some() { return Err(denied()); },
        (Some(_), None) => return Err(denied()),
    }
    Ok(rec)
}

// ---------- refresh tokens ----------

#[derive(Debug, Clone)]
pub struct RefreshRecord {
    pub client_id: String,
    pub subject: String,
    pub scope: Scope,
    pub resources: Vec<String>,
    pub grant_id: String,
    pub expires_at: u64,
    /// Absolute end of the whole family; rotation never extends past it.
    pub family_expires_at: u64,
}

pub enum RefreshTake {
    Valid(RefreshRecord),
    Reused { grant_id: String },
    Unknown,
}

pub trait RefreshStore {
    fn put(&self, fp: String, rec: RefreshRecord);
    fn take(&self, fp: &str) -> RefreshTake;
    fn revoke_grant(&self, grant_id: &str);
    /// Reads a live record without consuming it, for profiles that do not rotate refresh tokens (FAPI 2.0 5.3.2.1).
    /// The default returns `None`, so a store that does not implement it fails closed.
    fn peek(&self, _fp: &str) -> Option<RefreshRecord> { None }
}

#[derive(Default)]
pub struct MemoryRefreshStore {
    live: Mutex<HashMap<String, RefreshRecord>>,
    spent: Mutex<HashMap<String, String>>,
    dead_grants: Mutex<HashSet<String>>,
}
impl MemoryRefreshStore { pub fn new() -> Self { Self::default() } }

impl RefreshStore for MemoryRefreshStore {
    fn put(&self, fp: String, rec: RefreshRecord) {
        if let (Ok(mut m), Ok(d)) = (self.live.lock(), self.dead_grants.lock()) {
            if !d.contains(&rec.grant_id) { m.insert(fp, rec); }
        }
    }
    fn take(&self, fp: &str) -> RefreshTake {
        let (Ok(mut live), Ok(mut spent), Ok(dead)) = (self.live.lock(), self.spent.lock(), self.dead_grants.lock()) else { return RefreshTake::Unknown };
        if let Some(r) = live.remove(fp) {
            if dead.contains(&r.grant_id) { return RefreshTake::Unknown; }
            spent.insert(fp.to_string(), r.grant_id.clone());
            return RefreshTake::Valid(r);
        }
        match spent.get(fp) { Some(g) => RefreshTake::Reused { grant_id: g.clone() }, None => RefreshTake::Unknown }
    }
    fn revoke_grant(&self, grant_id: &str) {
        if let (Ok(mut m), Ok(mut d)) = (self.live.lock(), self.dead_grants.lock()) {
            d.insert(grant_id.to_string());
            m.retain(|_, r| r.grant_id != grant_id);
        }
    }
    fn peek(&self, fp: &str) -> Option<RefreshRecord> {
        let (live, dead) = (self.live.lock().ok()?, self.dead_grants.lock().ok()?);
        live.get(fp).filter(|r| !dead.contains(&r.grant_id)).cloned()
    }
}

impl RevocationSink for MemoryRefreshStore {
    fn revoke_grant(&self, grant_id: &str) { RefreshStore::revoke_grant(self, grant_id) }
}

pub const REFRESH_LIFETIME: u64 = 30 * 24 * 3600;
pub const REFRESH_FAMILY_LIFETIME: u64 = 180 * 24 * 3600;

/// Issues the first refresh token of a grant.
pub fn issue_refresh(store: &dyn RefreshStore, rec_from: &CodeRecord, now: Option<u64>) -> crate::Result<String> {
    let t = random_token()?;
    let now = now.unwrap_or_else(unix_now);
    store.put(fingerprint(&t), RefreshRecord {
        client_id: rec_from.client_id.clone(), subject: rec_from.subject.clone(), scope: rec_from.scope.clone(),
        resources: rec_from.resources.clone(), grant_id: rec_from.grant_id.clone(),
        expires_at: now + REFRESH_LIFETIME, family_expires_at: now + REFRESH_FAMILY_LIFETIME,
    });
    Ok(t)
}

/// Uses a refresh token. Returns the new refresh token and the record (with the possibly narrowed scope).
/// Scope may be narrowed, never widened (RFC 6749 6).
pub fn rotate_refresh(store: &dyn RefreshStore, client_id: &str, token: &str, requested: Option<&Scope>, now: Option<u64>) -> OResult<(String, RefreshRecord)> {
    let denied = || OAuthError::invalid_grant("refresh token is invalid, expired or already used");
    let now = now.unwrap_or_else(unix_now);
    let rec = match store.take(&fingerprint(token)) {
        RefreshTake::Valid(r) => r,
        RefreshTake::Reused { grant_id } => { store.revoke_grant(&grant_id); return Err(denied()); }
        RefreshTake::Unknown => return Err(denied()),
    };
    if rec.client_id != client_id || now >= rec.expires_at || now >= rec.family_expires_at {
        // A token presented by the wrong client is a theft signal: kill the family.
        if rec.client_id != client_id { store.revoke_grant(&rec.grant_id); }
        return Err(denied());
    }
    let scope = match requested {
        None => rec.scope.clone(),
        Some(s) if s.is_subset_of(&rec.scope) => s.clone(),
        Some(_) => return Err(OAuthError::with(ErrorCode::InvalidScope, "requested scope exceeds the original grant")),
    };
    let next = random_token().map_err(|_| OAuthError::new(ErrorCode::ServerError))?;
    let new_rec = RefreshRecord { scope, expires_at: (now + REFRESH_LIFETIME).min(rec.family_expires_at), ..rec };
    store.put(fingerprint(&next), new_rec.clone());
    Ok((next, new_rec))
}

/// Uses a refresh token without rotating it: the same token stays valid until it expires or the grant is revoked.
/// This is the FAPI 2.0 default for confidential, sender-constrained clients (5.3.2.1, note 1). It never extends the lifetime
/// and may only narrow the scope. The caller is responsible for the sender constraint on the token request.
pub fn use_refresh_static(store: &dyn RefreshStore, client_id: &str, token: &str, requested: Option<&Scope>, now: Option<u64>) -> OResult<RefreshRecord> {
    let denied = || OAuthError::invalid_grant("refresh token is invalid, expired or revoked");
    let now = now.unwrap_or_else(unix_now);
    let rec = store.peek(&fingerprint(token)).ok_or_else(denied)?;
    if rec.client_id != client_id {
        store.revoke_grant(&rec.grant_id);
        return Err(denied());
    }
    if now >= rec.expires_at || now >= rec.family_expires_at { return Err(denied()); }
    let scope = match requested {
        None => rec.scope.clone(),
        Some(s) if s.is_subset_of(&rec.scope) => s.clone(),
        Some(_) => return Err(OAuthError::with(ErrorCode::InvalidScope, "requested scope exceeds the original grant")),
    };
    Ok(RefreshRecord { scope, ..rec })
}
