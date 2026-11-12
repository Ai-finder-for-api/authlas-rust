//! Pushed Authorization Requests (RFC 9126) and JWT-Secured Authorization Requests (RFC 9101).
//!
//! PAR: the client authenticates at the PAR endpoint and receives a one-time `request_uri`; the browser only carries
//! `client_id` and that reference, so the parameters cannot be read or altered on the way.
//! JAR: the request parameters are a signed JWT. The signed values win over anything in the query string
//! (RFC 9101 6.3), and `iss`/`aud`/`exp` are mandatory so a request object cannot be replayed at another server.
use super::error::{ErrorCode, OAuthError, OResult};
use super::form::Params;
use crate::{b64, crypto, jwa::{Algorithm, Hash}, jwk::Jwk, jwt::{self, unix_now, Validation}};
use std::collections::HashMap;
use std::sync::Mutex;

pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
/// RFC 9126 7.1: lifetimes should be short because the client uses the reference immediately.
pub const PAR_LIFETIME: u64 = 60;

// ---------- PAR ----------

#[derive(Debug, Clone)]
pub struct Pushed {
    pub client_id: String,
    /// The original form body, re-parsed through the normal authorization-request validator.
    pub query: String,
    pub expires_at: u64,
}

#[derive(Default)]
pub struct ParStore { items: Mutex<HashMap<String, Pushed>> }

impl ParStore {
    pub fn new() -> Self { Self::default() }

    /// `body` is the already client-authenticated POST body. Returns the JSON response (RFC 9126 2.2).
    pub fn push(&self, authenticated_client: &str, body: &Params, raw_body: &str, now: Option<u64>) -> OResult<(String, u64)> {
        // RFC 9126 2.1: request_uri must not appear in a pushed request.
        if body.contains("request_uri") { return Err(OAuthError::invalid_request("request_uri is not allowed in a pushed request")); }
        // client_id in the body, when present, must be the authenticated client (RFC 6749 3.2.1).
        if let Some(c) = body.get("client_id").map_err(|_| OAuthError::invalid_request("client_id repeated"))? {
            if c != authenticated_client { return Err(OAuthError::invalid_client("client_id does not match the authenticated client")); }
        }
        // Client authentication parameters are not part of the stored request.
        let kept: Vec<(String, String)> = url::form_urlencoded::parse(raw_body.as_bytes())
            .filter(|(k, _)| !matches!(k.as_ref(), "client_secret" | "client_assertion" | "client_assertion_type"))
            .map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in &kept { ser.append_pair(k, v); }
        if !body.contains("client_id") { ser.append_pair("client_id", authenticated_client); }
        let mut raw = [0u8; 32];
        crypto::random(&mut raw).map_err(|_| OAuthError::new(ErrorCode::ServerError))?;
        let uri = format!("{REQUEST_URI_PREFIX}{}", b64::encode(raw));
        let now = now.unwrap_or_else(unix_now);
        self.items.lock().map_err(|_| OAuthError::new(ErrorCode::ServerError))?.insert(uri.clone(), Pushed {
            client_id: authenticated_client.into(), query: ser.finish(), expires_at: now + PAR_LIFETIME });
        Ok((uri, PAR_LIFETIME))
    }

    /// Authorization endpoint: redeem a `request_uri`. One use only, and only by the client that pushed it (RFC 9126 4).
    /// Returns the stored query string to validate like any other authorization request.
    pub fn redeem(&self, client_id: &str, request_uri: &str, now: Option<u64>) -> OResult<String> {
        let bad = || OAuthError::with(ErrorCode::InvalidRequestUri, "request_uri is unknown, expired or already used");
        if !request_uri.starts_with(REQUEST_URI_PREFIX) { return Err(bad()); }
        let p = self.items.lock().map_err(|_| OAuthError::new(ErrorCode::ServerError))?.remove(request_uri).ok_or_else(bad)?;
        if p.client_id != client_id || now.unwrap_or_else(unix_now) >= p.expires_at { return Err(bad()); }
        Ok(p.query)
    }
}

pub fn par_response_json(request_uri: &str, expires_in: u64) -> String {
    serde_json::json!({ "request_uri": request_uri, "expires_in": expires_in }).to_string()
}

/// Client side: reads the PAR response.
pub fn parse_par_response(body: &str) -> OResult<(String, u64)> {
    let bad = || OAuthError::with(ErrorCode::ServerError, "malformed PAR response");
    let v: serde_json::Value = serde_json::from_str(body).map_err(|_| bad())?;
    let uri = v.get("request_uri").and_then(|x| x.as_str()).filter(|u| u.starts_with(REQUEST_URI_PREFIX) || !u.is_empty()).ok_or_else(bad)?;
    let exp = v.get("expires_in").and_then(|x| x.as_u64()).ok_or_else(bad)?;
    Ok((uri.to_string(), exp))
}

/// Authorization request that references a pushed request: only `client_id` and `request_uri` travel in the browser.
pub fn reference_query(client_id: &str, request_uri: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new()).append_pair("client_id", client_id).append_pair("request_uri", request_uri).finish()
}

// ---------- JAR ----------

pub const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

pub struct RequestObjectRules<'a> {
    pub algs: &'a [Algorithm],
    pub client_id: &'a str,
    /// The authorization server's issuer identifier (the required `aud`).
    pub issuer: &'a str,
    pub now: Option<u64>,
    pub max_lifetime: u64,
    /// If true, `typ` must be `oauth-authz-req+jwt` (RFC 9101 10.8 recommends it).
    pub require_typ: bool,
}

/// Verifies a request object and returns the parameters it carries as a query string. Parameters outside the
/// object are discarded except `client_id` (which must match), so an attacker cannot add or override signed values.
pub fn verify_request_object(object: &str, key: &Jwk, r: &RequestObjectRules<'_>) -> OResult<String> {
    let bad = |m: &str| OAuthError::with(ErrorCode::InvalidRequestObject, m);
    let mut v = Validation::new(r.algs, r.client_id, r.issuer);
    v.now = r.now;
    v.leeway = 30;
    if r.require_typ { v.typ = Some(REQUEST_OBJECT_TYP); }
    let (_, c) = jwt::verify(object, key, &v).map_err(|_| bad("request object rejected"))?;
    let now = r.now.unwrap_or_else(unix_now);
    let exp = c.date("exp").ok().flatten().ok_or_else(|| bad("exp is required"))?;
    // RFC 9101 10.2: bound the lifetime so a leaked object is not usable forever.
    let iat_or_nbf = c.date("nbf").ok().flatten().or(c.date("iat").ok().flatten()).unwrap_or(now);
    if exp.saturating_sub(iat_or_nbf) > r.max_lifetime { return Err(bad("request object lifetime is too long")); }
    if c.map.contains_key("request") || c.map.contains_key("request_uri") { return Err(bad("request objects must not nest request or request_uri")); }
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, val) in &c.map {
        if matches!(k.as_str(), "iss" | "aud" | "exp" | "nbf" | "iat" | "jti") { continue; }
        let text = match val {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            // authorization_details and claims are JSON values carried as JSON text (RFC 9396 7, OIDC 5.5).
            other => other.to_string(),
        };
        ser.append_pair(k, &text);
    }
    match c.str_claim("client_id").ok().flatten() {
        Some(id) if id == r.client_id => {}
        None => { ser.append_pair("client_id", r.client_id); }
        Some(_) => return Err(bad("client_id in the request object does not match")),
    }
    Ok(ser.finish())
}

/// Client side: signs a request object.
pub fn build_request_object(alg: Algorithm, key: &Jwk, client_id: &str, issuer: &str, params: &[(&str, serde_json::Value)], lifetime: u64) -> crate::Result<String> {
    let now = unix_now();
    let mut jti = [0u8; 16];
    crypto::random(&mut jti)?;
    let mut c = jwt::Claims::new().issuer(client_id).audience(&[issuer]).issued_at(now).not_before(now).expires_at(now + lifetime.min(600)).jti(&b64::encode(jti)).set("client_id", client_id);
    for (k, v) in params { if !c.map.contains_key(*k) { c.map.insert((*k).to_string(), v.clone()); } }
    jwt::sign(alg, key, &c, Some(REQUEST_OBJECT_TYP))
}

/// Fingerprint helper for `request_uri` logging without storing the reference itself.
pub fn request_uri_fingerprint(uri: &str) -> String {
    b64::encode(crypto::digest(Hash::Sha256, uri.as_bytes()).unwrap_or_default()).chars().take(12).collect()
}
