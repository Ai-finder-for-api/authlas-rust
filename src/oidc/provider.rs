//! OpenID Provider metadata (Discovery 1.0), RP-Initiated Logout 1.0, and Back-Channel Logout 1.0.
use crate::jwa::{Algorithm, Family};
use crate::jwk::Jwk;
use crate::jwt::{self, Claims, ReplayCache, Validation};
use crate::oauth::form::Params;
use crate::oauth::metadata::AsMetadata;
use crate::oauth::redirect;
use crate::{crypto, jws, Error, Result};
use serde_json::{json, Map, Value};
use url::Url;

pub const BACKCHANNEL_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
pub const LOGOUT_TYP: &str = "logout+jwt";

// ---------------------------------------------------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------------------------------------------------

/// OP metadata. Built on [`AsMetadata`] (same issuer rules, same endpoint checks); the OIDC members are typed here.
#[derive(Debug, Clone)]
pub struct ProviderMetadata {
    pub base: AsMetadata,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub acr_values_supported: Vec<String>,
    pub claims_parameter_supported: bool,
    pub backchannel_logout_supported: bool,
    pub backchannel_logout_session_supported: bool,
    pub end_session_endpoint: Option<String>,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
}

fn list(o: &Map<String, Value>, k: &str) -> Result<Vec<String>> {
    match o.get(k) {
        None => Ok(vec![]),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| Error::Malformed(format!("{k} must hold strings")))).collect(),
        Some(_) => Err(Error::Malformed(format!("{k} must be an array"))),
    }
}
fn flag(o: &Map<String, Value>, k: &str, default: bool) -> Result<bool> {
    match o.get(k) { None => Ok(default), Some(Value::Bool(b)) => Ok(*b), Some(_) => Err(Error::Malformed(format!("{k} must be a boolean"))) }
}

impl ProviderMetadata {
    /// Parses a fetched `/.well-known/openid-configuration` document for `expected_issuer`. The `issuer` member must equal
    /// `expected_issuer` exactly (Discovery 4.3): a document that names another issuer is a mix-up and is refused.
    pub fn parse(body: &str, expected_issuer: &str) -> Result<ProviderMetadata> {
        let base = AsMetadata::parse(body, expected_issuer)?;
        let o = crate::json::parse_object(body.as_bytes())?;
        let end_session_endpoint = match o.get("end_session_endpoint") {
            None => None,
            Some(Value::String(s)) => { let u = Url::parse(s).map_err(|_| Error::Malformed("end_session_endpoint is not a URL".into()))?; if u.scheme() != "https" { return Err(Error::Malformed("end_session_endpoint must use https".into())); } Some(s.clone()) }
            Some(_) => return Err(Error::Malformed("end_session_endpoint must be a string".into())),
        };
        Ok(ProviderMetadata {
            subject_types_supported: list(&o, "subject_types_supported")?,
            id_token_signing_alg_values_supported: list(&o, "id_token_signing_alg_values_supported")?,
            claims_supported: list(&o, "claims_supported")?,
            acr_values_supported: list(&o, "acr_values_supported")?,
            claims_parameter_supported: flag(&o, "claims_parameter_supported", false)?,
            backchannel_logout_supported: flag(&o, "backchannel_logout_supported", false)?,
            backchannel_logout_session_supported: flag(&o, "backchannel_logout_session_supported", false)?,
            request_parameter_supported: flag(&o, "request_parameter_supported", false)?,
            request_uri_parameter_supported: flag(&o, "request_uri_parameter_supported", true)?,
            end_session_endpoint, base,
        })
    }

    /// What is wrong for an RP that wants the code flow (Discovery 3 required members, plus the MCP/OAuth 2.1 PKCE condition).
    pub fn problems_for_rp(&self) -> Vec<&'static str> {
        let mut p = self.base.problems_for_code_flow();
        if self.base.jwks_uri.is_none() { p.push("no jwks_uri"); }
        if self.subject_types_supported.is_empty() { p.push("no subject_types_supported"); }
        if self.id_token_signing_alg_values_supported.is_empty() { p.push("no id_token_signing_alg_values_supported"); }
        if self.id_token_signing_alg_values_supported.iter().any(|a| a == "none") { p.push("OP offers unsigned ID tokens (alg none)"); }
        if !self.base.scopes_supported.is_empty() && !self.base.scopes_supported.iter().any(|s| s == "openid") { p.push("scopes_supported lacks openid"); }
        p
    }

    /// Algorithms the RP can use for this OP: the intersection of what the OP signs with and what the RP accepts (asymmetric only).
    pub fn usable_algs(&self, rp_accepts: &[Algorithm]) -> Vec<Algorithm> {
        rp_accepts.iter().copied().filter(|a| !matches!(a.family(), Family::Hmac) && self.id_token_signing_alg_values_supported.iter().any(|s| s == a.as_str())).collect()
    }

    /// A conservative document for an OP built from this library.
    pub fn secure_defaults(issuer: &str, base_url: &str, algs: &[Algorithm]) -> ProviderMetadata {
        let mut b = AsMetadata::secure_defaults(issuer, base_url);
        let root = base_url.trim_end_matches('/');
        b.userinfo_endpoint = Some(format!("{root}/userinfo"));
        b.scopes_supported = vec!["openid".into(), "profile".into(), "email".into(), "address".into(), "phone".into(), "offline_access".into()];
        ProviderMetadata {
            base: b, subject_types_supported: vec!["public".into(), "pairwise".into()],
            id_token_signing_alg_values_supported: algs.iter().map(|a| a.as_str().to_string()).collect(),
            claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "sid", "at_hash", "name", "given_name", "family_name", "email", "email_verified"].iter().map(|s| s.to_string()).collect(),
            acr_values_supported: vec![], claims_parameter_supported: true, backchannel_logout_supported: false, backchannel_logout_session_supported: false,
            end_session_endpoint: Some(format!("{root}/logout")), request_parameter_supported: false, request_uri_parameter_supported: false,
        }
    }

    pub fn to_json(&self) -> String {
        let mut m: Map<String, Value> = serde_json::from_str(&self.base.to_json()).unwrap_or_default();
        let l = |m: &mut Map<String, Value>, k: &str, v: &Vec<String>| if !v.is_empty() { m.insert(k.into(), json!(v)); };
        l(&mut m, "subject_types_supported", &self.subject_types_supported);
        l(&mut m, "id_token_signing_alg_values_supported", &self.id_token_signing_alg_values_supported);
        l(&mut m, "claims_supported", &self.claims_supported);
        l(&mut m, "acr_values_supported", &self.acr_values_supported);
        m.insert("claims_parameter_supported".into(), json!(self.claims_parameter_supported));
        m.insert("request_parameter_supported".into(), json!(self.request_parameter_supported));
        m.insert("request_uri_parameter_supported".into(), json!(self.request_uri_parameter_supported));
        if self.backchannel_logout_supported {
            m.insert("backchannel_logout_supported".into(), json!(true));
            m.insert("backchannel_logout_session_supported".into(), json!(self.backchannel_logout_session_supported));
        }
        if let Some(e) = &self.end_session_endpoint { m.insert("end_session_endpoint".into(), json!(e)); }
        Value::Object(m).to_string()
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// RP-Initiated Logout (OP side)
// ---------------------------------------------------------------------------------------------------------------------

/// What the OP knows about the RP named in the request.
#[derive(Debug, Clone, Default)]
pub struct LogoutClient {
    pub client_id: String,
    pub post_logout_redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogoutRequest {
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub ui_locales: Vec<String>,
    pub logout_hint: Option<String>,
    /// Claims of a verified `id_token_hint` (see [`super::id_token::verify_hint`]). Filled in by [`LogoutRequest::parse`] only through `hint`.
    pub hint: Option<Claims>,
}

/// The OP's plan for a logout request.
#[derive(Debug, Clone, PartialEq)]
pub struct LogoutPlan {
    pub client_id: Option<String>,
    /// The user's `sub` and `sid` from the hint, to find the session to end.
    pub subject: Option<String>,
    pub sid: Option<String>,
    /// Where to send the browser afterwards, with `state` appended. `None`: show the OP's own "you are signed out" page.
    pub redirect: Option<String>,
    /// True when no valid `id_token_hint` proves who asked. The OP must then ask the user to confirm before ending the session
    /// (Logout 2: otherwise any web page can sign users out by embedding the logout URL).
    pub needs_confirmation: bool,
}

impl LogoutRequest {
    /// Parses the query or form. `hint` is the verified `id_token_hint`, if one was sent and verified.
    pub fn parse(params: &str, hint: Option<Claims>) -> Result<LogoutRequest> {
        let p = Params::parse(params).map_err(|_| Error::Malformed("malformed logout request".into()))?;
        let one = |n: &str, max: usize| -> Result<Option<String>> {
            match p.get(n).map_err(|_| Error::Malformed(format!("{n} must not repeat")))? {
                None => Ok(None),
                Some(s) if s.len() <= max && !s.chars().any(char::is_control) => Ok(Some(s.to_string())),
                Some(_) => Err(Error::Malformed(format!("invalid {n}"))),
            }
        };
        Ok(LogoutRequest {
            client_id: one("client_id", 512)?, post_logout_redirect_uri: one("post_logout_redirect_uri", redirect::MAX_LEN)?, state: one("state", 512)?,
            logout_hint: one("logout_hint", 512)?, ui_locales: p.get("ui_locales").ok().flatten().map(|s| s.split(' ').filter(|x| !x.is_empty()).map(String::from).collect()).unwrap_or_default(), hint,
        })
    }

    /// Decides what to do. `lookup` finds the RP by `client_id`.
    ///
    /// * A `post_logout_redirect_uri` is honoured only when the RP is known and the URI equals a registered one exactly (no port
    ///   flexibility, no prefix match). Anything else is dropped, never redirected to: the logout still happens, the user stays on the OP.
    /// * `client_id` and the hint's `aud` must agree when both are present.
    /// * Without a verified `id_token_hint` the user must confirm.
    pub fn plan(&self, lookup: &dyn Fn(&str) -> Option<LogoutClient>) -> Result<LogoutPlan> {
        let hint_aud: Vec<String> = match &self.hint { Some(h) => h.aud_list()?.unwrap_or_default().iter().map(|s| s.to_string()).collect(), None => vec![] };
        let client_id = match (&self.client_id, hint_aud.as_slice()) {
            (Some(c), []) => Some(c.clone()),
            (Some(c), aud) => { if !aud.iter().any(|a| a == c) { return Err(Error::Claim("client_id is not an audience of the id_token_hint".into())); } Some(c.clone()) }
            (None, [one]) => Some(one.clone()),
            (None, _) => None,
        };
        let client = client_id.as_deref().and_then(lookup);
        let redirect = match (&self.post_logout_redirect_uri, &client) {
            (Some(uri), Some(c)) if c.post_logout_redirect_uris.iter().any(|r| r == uri) => {
                let mut u = Url::parse(uri).map_err(|_| Error::Malformed("post_logout_redirect_uri".into()))?;
                if let Some(s) = &self.state { u.query_pairs_mut().append_pair("state", s); }
                Some(u.to_string())
            }
            _ => None,
        };
        let (subject, sid) = match &self.hint {
            Some(h) => (h.str_claim("sub")?.map(String::from), h.str_claim("sid")?.map(String::from)),
            None => (None, None),
        };
        Ok(LogoutPlan { client_id, subject, sid, redirect, needs_confirmation: self.hint.is_none() })
    }
}

/// RP side: builds the logout URL (Logout 2). `id_token_hint` makes the OP skip its confirmation page. The `post_logout_redirect_uri`
/// must be one the RP registered; a random `state` is returned for the caller to keep and compare.
pub fn build_logout_url(end_session_endpoint: &str, id_token_hint: Option<&str>, client_id: &str, post_logout_redirect_uri: Option<&str>) -> Result<(String, Option<String>)> {
    let u = Url::parse(end_session_endpoint).map_err(|_| Error::Malformed("end_session_endpoint".into()))?;
    if u.scheme() != "https" { return Err(Error::Malformed("end_session_endpoint must use https".into())); }
    let state = if post_logout_redirect_uri.is_some() { Some(crate::oauth::pkce::generate_verifier()?) } else { None };
    let mut pairs: Vec<(&str, &str)> = vec![("client_id", client_id)];
    if let Some(h) = id_token_hint { pairs.push(("id_token_hint", h)); }
    if let Some(r) = post_logout_redirect_uri { pairs.push(("post_logout_redirect_uri", r)); }
    if let Some(s) = &state { pairs.push(("state", s)); }
    let sep = if end_session_endpoint.contains('?') { '&' } else { '?' };
    Ok((format!("{end_session_endpoint}{sep}{}", crate::oauth::form::encode(pairs)), state))
}

// ---------------------------------------------------------------------------------------------------------------------
// Back-Channel Logout
// ---------------------------------------------------------------------------------------------------------------------

/// OP: signs a Logout Token (Back-Channel Logout 2.4). Needs `sub` or `sid`. Never carries a `nonce`.
pub struct LogoutTokenIssue<'a> {
    pub alg: Algorithm,
    pub key: &'a Jwk,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub subject: Option<&'a str>,
    pub sid: Option<&'a str>,
    pub lifetime: u64,
    pub now: Option<u64>,
}

impl LogoutTokenIssue<'_> {
    pub fn sign(&self) -> Result<String> {
        if self.subject.is_none() && self.sid.is_none() { return Err(Error::Claim("a logout token needs sub or sid".into())); }
        if self.lifetime == 0 || self.lifetime > 120 { return Err(Error::Claim("logout token lifetime must be 1..=120 seconds".into())); }
        let now = self.now.unwrap_or_else(jwt::unix_now);
        let mut jti = [0u8; 16];
        crypto::random(&mut jti)?;
        let mut c = Claims::new().issuer(self.issuer).audience(&[self.client_id]).issued_at(now).expires_at(now + self.lifetime)
            .jti(&crate::b64::encode(jti)).set("events", json!({ BACKCHANNEL_EVENT: {} }));
        if let Some(s) = self.subject { c = c.subject(s); }
        if let Some(s) = self.sid { c = c.set("sid", s); }
        jwt::sign(self.alg, self.key, &c, Some(LOGOUT_TYP))
    }
}

/// RP: how to validate a Logout Token.
pub struct LogoutValidate<'a> {
    pub algs: &'a [Algorithm],
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub now: Option<u64>,
    pub leeway: u64,
    /// Require `typ: logout+jwt`. On by default through [`LogoutValidate::new`]; turn it off only for OPs that predate the recommendation.
    pub require_typ: bool,
    /// The OP said `backchannel_logout_session_required`: a `sid` must be present.
    pub require_sid: bool,
    pub replay: Option<&'a dyn ReplayCache>,
}

impl<'a> LogoutValidate<'a> {
    pub fn new(algs: &'a [Algorithm], issuer: &'a str, client_id: &'a str) -> Self {
        LogoutValidate { algs, issuer, client_id, now: None, leeway: 30, require_typ: true, require_sid: false, replay: None }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogoutToken { pub issuer: String, pub subject: Option<String>, pub sid: Option<String>, pub jti: String }

/// Validates the `logout_token` parameter of a back-channel request (Back-Channel Logout 2.6). Any error means HTTP 400.
/// An ID token presented as a logout token fails on `events` and on `nonce`; that is the cross-JWT confusion defence.
pub fn validate_logout_token(token: &str, key: &Jwk, v: &LogoutValidate<'_>) -> Result<LogoutToken> {
    let mut val = Validation::new(v.algs, v.issuer, v.client_id);
    val.now = v.now;
    val.leeway = v.leeway;
    val.require = &["iat", "exp", "jti", "events"];
    val.typ = if v.require_typ { Some(LOGOUT_TYP) } else { None };
    val.replay = v.replay;
    let (_, c) = jwt::verify(token, key, &val)?;
    match c.map.get("events") {
        Some(Value::Object(e)) if matches!(e.get(BACKCHANNEL_EVENT), Some(Value::Object(_))) => {}
        _ => return Err(Error::Claim("events does not declare a back-channel logout".into())),
    }
    if c.map.contains_key("nonce") { return Err(Error::Claim("a logout token must not contain a nonce".into())); }
    let subject = c.str_claim("sub")?.map(String::from);
    let sid = c.str_claim("sid")?.map(String::from);
    if subject.is_none() && sid.is_none() { return Err(Error::Claim("a logout token needs sub or sid".into())); }
    if v.require_sid && sid.is_none() { return Err(Error::Claim("sid is required by this OP's configuration".into())); }
    let _ = jws::peek_header(token)?;
    Ok(LogoutToken { issuer: v.issuer.to_string(), subject, sid, jti: c.str_claim("jti")?.ok_or_else(|| Error::Claim("jti is missing".into()))?.to_string() })
}

/// Pulls the `logout_token` out of the POST body. Exactly one is accepted.
pub fn logout_token_from_body(body: &str) -> Result<String> {
    let p = Params::parse(body).map_err(|_| Error::Malformed("malformed body".into()))?;
    p.get("logout_token").map_err(|_| Error::Malformed("logout_token must not repeat".into()))?.map(String::from).ok_or_else(|| Error::Malformed("logout_token is required".into()))
}
