//! OAuth 2.0 Token Exchange (RFC 8693).
//!
//! Exchange is where privilege escalation hides, so the policy is explicit and default-deny:
//! * the caller names which (client, subject token type, requested type) combinations are allowed;
//! * the issued scope can only narrow the subject token's scope;
//! * delegation records the chain in `act` (RFC 8693 4.1) and `may_act` on the subject token must permit the actor.
use super::error::{ErrorCode, OAuthError, OResult};
use super::form::Params;
use super::scope::Scope;
use crate::jwt::Claims;
use serde_json::{json, Value};

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
pub const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
pub const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const SAML1: &str = "urn:ietf:params:oauth:token-type:saml1";
pub const SAML2: &str = "urn:ietf:params:oauth:token-type:saml2";

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub subject_token: String,
    pub subject_token_type: String,
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    pub requested_token_type: Option<String>,
    pub audiences: Vec<String>,
    pub resources: Vec<String>,
    pub scope: Option<Scope>,
}

fn known_type(t: &str) -> bool { [ACCESS_TOKEN, REFRESH_TOKEN, ID_TOKEN, JWT, SAML1, SAML2].contains(&t) }

pub fn parse_request(body: &Params) -> OResult<Request> {
    let bad = |m: &str| OAuthError::invalid_request(m);
    let one = |n: &str| body.get(n).map_err(|_| bad(&format!("{n} must not repeat")));
    let subject_token = one("subject_token")?.ok_or_else(|| bad("subject_token is required"))?.to_string();
    let subject_token_type = one("subject_token_type")?.ok_or_else(|| bad("subject_token_type is required"))?.to_string();
    let actor_token = one("actor_token")?.map(String::from);
    let actor_token_type = one("actor_token_type")?.map(String::from);
    // RFC 8693 2.1: actor_token_type is required exactly when actor_token is present.
    if actor_token.is_some() != actor_token_type.is_some() { return Err(bad("actor_token and actor_token_type go together")); }
    let requested = one("requested_token_type")?.map(String::from);
    for t in [Some(&subject_token_type), actor_token_type.as_ref(), requested.as_ref()].into_iter().flatten() {
        if !known_type(t) { return Err(OAuthError::with(ErrorCode::InvalidRequest, "unsupported token type identifier")); }
    }
    let scope = one("scope")?.map(|s| Scope::parse(s).map_err(|_| OAuthError::new(ErrorCode::InvalidScope))).transpose()?;
    Ok(Request { subject_token, subject_token_type, actor_token, actor_token_type, requested_token_type: requested,
        audiences: body.get_all("audience").to_vec(), resources: body.get_all("resource").to_vec(), scope })
}

/// One allowed exchange.
#[derive(Debug, Clone)]
pub struct Rule {
    pub client_id: String,
    pub subject_token_types: Vec<String>,
    pub requested_token_types: Vec<String>,
    /// Audiences / resources the client may obtain tokens for. Empty means none (default deny).
    pub allowed_targets: Vec<String>,
    pub allow_delegation: bool,
}

/// The validated subject token (and actor token, if any), as the caller verified them.
pub struct Subject<'a> { pub claims: &'a Claims, pub scope: &'a Scope }

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub scope: Scope,
    pub targets: Vec<String>,
    pub token_type: String,
    /// `act` claim for the new token when delegation applies, nested over any existing chain.
    pub act: Option<Value>,
    pub subject: String,
}

pub fn authorize(rules: &[Rule], client_id: &str, req: &Request, subject: &Subject<'_>, actor: Option<&Claims>) -> OResult<Decision> {
    let denied = |m: &str| OAuthError::with(ErrorCode::InvalidGrant, m);
    let rule = rules.iter().find(|r| r.client_id == client_id).ok_or_else(|| OAuthError::new(ErrorCode::UnauthorizedClient))?;
    if !rule.subject_token_types.contains(&req.subject_token_type) { return Err(denied("subject token type is not allowed")); }
    let requested = req.requested_token_type.clone().unwrap_or_else(|| ACCESS_TOKEN.to_string());
    if !rule.requested_token_types.contains(&requested) { return Err(OAuthError::with(ErrorCode::InvalidRequest, "requested token type is not allowed")); }

    let targets: Vec<String> = req.audiences.iter().chain(req.resources.iter()).cloned().collect();
    for t in &targets {
        if !rule.allowed_targets.iter().any(|a| a == t) { return Err(OAuthError::with(ErrorCode::InvalidTarget, "target is not allowed for this client")); }
    }

    // Scope can only get smaller.
    let scope = match &req.scope {
        None => subject.scope.clone(),
        Some(s) if s.is_subset_of(subject.scope) => s.clone(),
        Some(_) => return Err(OAuthError::with(ErrorCode::InvalidScope, "requested scope exceeds the subject token")),
    };

    let sub = subject.claims.str_claim("sub").ok().flatten().ok_or_else(|| denied("subject token has no sub"))?.to_string();
    let act = match (&req.actor_token, actor) {
        (None, _) => None,
        (Some(_), None) => return Err(denied("actor token could not be validated")),
        (Some(_), Some(a)) => {
            if !rule.allow_delegation { return Err(denied("delegation is not allowed for this client")); }
            let actor_sub = a.str_claim("sub").ok().flatten().ok_or_else(|| denied("actor token has no sub"))?;
            let actor_iss = a.str_claim("iss").ok().flatten();
            // may_act (RFC 8693 4.4) restricts who may act for the subject; if present it must match.
            if let Some(m) = subject.claims.map.get("may_act") {
                let o = m.as_object().ok_or_else(|| denied("may_act is malformed"))?;
                let sub_ok = o.get("sub").and_then(Value::as_str) == Some(actor_sub);
                let iss_ok = o.get("iss").and_then(Value::as_str).map_or(true, |i| Some(i) == actor_iss);
                if !(sub_ok && iss_ok) { return Err(denied("actor is not permitted by may_act")); }
            }
            let mut act = json!({ "sub": actor_sub });
            if let Some(i) = actor_iss { act["iss"] = json!(i); }
            // Keep earlier delegation as history inside the new act claim (RFC 8693 4.1 nested act).
            if let Some(prev) = subject.claims.map.get("act") { act["act"] = prev.clone(); }
            Some(act)
        }
    };
    Ok(Decision { scope, targets, token_type: requested, act, subject: sub })
}

/// Response body (RFC 8693 2.2.1). `issued_token_type` is required.
pub fn response_json(access_token: &str, issued_token_type: &str, token_type: &str, expires_in: Option<u64>, scope: Option<&Scope>) -> String {
    let mut v = json!({ "access_token": access_token, "issued_token_type": issued_token_type, "token_type": token_type });
    if let Some(e) = expires_in { v["expires_in"] = json!(e); }
    if let Some(s) = scope { v["scope"] = json!(s.to_string()); }
    v.to_string()
}
