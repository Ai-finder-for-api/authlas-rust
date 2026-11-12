//! Rich Authorization Requests (RFC 9396) and step-up authentication (RFC 9470).
use super::error::{ErrorCode, OAuthError, OResult};
use crate::jwt::{unix_now, Claims};
use serde_json::{json, Map, Value};

// ---------- RAR ----------

/// One entry of `authorization_details`. `type` is required; the rest is type-specific.
#[derive(Debug, Clone, PartialEq)]
pub struct Detail {
    pub kind: String,
    pub locations: Vec<String>,
    pub actions: Vec<String>,
    pub datatypes: Vec<String>,
    pub identifier: Option<String>,
    pub privileges: Vec<String>,
    /// Members beyond the common ones, kept for the type's own validator.
    pub extra: Map<String, Value>,
}

const COMMON: &[&str] = &["type", "locations", "actions", "datatypes", "identifier", "privileges"];

fn strings(o: &Map<String, Value>, k: &str) -> OResult<Vec<String>> {
    let bad = || OAuthError::with(ErrorCode::InvalidAuthorizationDetails, &format!("{k} must be an array of strings"));
    match o.get(k) {
        None => Ok(vec![]),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(bad)).collect(),
        Some(_) => Err(bad()),
    }
}

/// Parses the JSON text of the `authorization_details` parameter.
/// `allowed_types` is the server's list (`authorization_details_types_supported`); anything else is refused.
pub fn parse(text: &str, allowed_types: &[&str]) -> OResult<Vec<Detail>> {
    let bad = |m: &str| OAuthError::with(ErrorCode::InvalidAuthorizationDetails, m);
    if text.len() > 32 * 1024 { return Err(bad("authorization_details too large")); }
    let v: Value = serde_json::from_str(text).map_err(|_| bad("not valid JSON"))?;
    let arr = v.as_array().filter(|a| !a.is_empty() && a.len() <= 32).ok_or_else(|| bad("must be a non-empty array of at most 32 objects"))?;
    arr.iter().map(|item| {
        let o = item.as_object().ok_or_else(|| bad("entries must be objects"))?;
        let kind = o.get("type").and_then(Value::as_str).filter(|t| !t.is_empty()).ok_or_else(|| bad("type is required"))?.to_string();
        if !allowed_types.contains(&kind.as_str()) { return Err(bad("unsupported authorization details type")); }
        for l in strings(o, "locations")? {
            let ok = url::Url::parse(&l).map(|u| u.fragment().is_none()).unwrap_or(false);
            if !ok { return Err(bad("locations must be absolute URIs")); }
        }
        Ok(Detail {
            locations: strings(o, "locations")?, actions: strings(o, "actions")?, datatypes: strings(o, "datatypes")?,
            privileges: strings(o, "privileges")?,
            identifier: match o.get("identifier") { None => None, Some(Value::String(s)) => Some(s.clone()), Some(_) => return Err(bad("identifier must be a string")) },
            extra: o.iter().filter(|(k, _)| !COMMON.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect(),
            kind,
        })
    }).collect()
}

impl Detail {
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("type".into(), json!(self.kind));
        for (k, v) in [("locations", &self.locations), ("actions", &self.actions), ("datatypes", &self.datatypes), ("privileges", &self.privileges)] {
            if !v.is_empty() { m.insert(k.into(), json!(v)); }
        }
        if let Some(i) = &self.identifier { m.insert("identifier".into(), json!(i)); }
        for (k, v) in &self.extra { m.entry(k.clone()).or_insert_with(|| v.clone()); }
        Value::Object(m)
    }

    /// Does this granted entry cover what the resource server needs? Every list member of `needed` must appear in `self`.
    /// An empty list in `needed` means "no constraint". An empty list in `self` grants nothing for that field.
    pub fn covers(&self, needed: &Detail) -> bool {
        let sub = |have: &Vec<String>, want: &Vec<String>| want.iter().all(|w| have.contains(w));
        self.kind == needed.kind && sub(&self.locations, &needed.locations) && sub(&self.actions, &needed.actions)
            && sub(&self.datatypes, &needed.datatypes) && sub(&self.privileges, &needed.privileges)
            && needed.identifier.as_ref().map_or(true, |i| self.identifier.as_ref() == Some(i))
    }
}

pub fn to_json(details: &[Detail]) -> String { Value::Array(details.iter().map(Detail::to_value).collect()).to_string() }

/// The granted set may only be a reduction of the requested one (RFC 9396 7): every granted entry must be covered by a requested one.
pub fn is_reduction(requested: &[Detail], granted: &[Detail]) -> bool {
    granted.iter().all(|g| requested.iter().any(|r| r.covers(g)))
}

/// Resource server: does the token's `authorization_details` claim authorise this operation?
pub fn token_permits(claims: &Claims, needed: &Detail) -> OResult<()> {
    let denied = || OAuthError::with(ErrorCode::InsufficientScope, "authorization_details do not cover this operation");
    let text = claims.map.get("authorization_details").ok_or_else(denied)?.to_string();
    let types = [needed.kind.as_str()];
    // Only the needed type matters here; other types in the token are ignored, not errors.
    let all: Vec<Detail> = match serde_json::from_str::<Vec<Value>>(&text) {
        Ok(v) => v.iter().filter(|e| e.get("type").and_then(Value::as_str) == Some(&needed.kind))
            .map(|e| parse(&Value::Array(vec![e.clone()]).to_string(), &types)).collect::<OResult<Vec<_>>>()?.into_iter().flatten().collect(),
        Err(_) => return Err(denied()),
    };
    if all.iter().any(|g| g.covers(needed)) { Ok(()) } else { Err(denied()) }
}

// ---------- step-up (RFC 9470) ----------

/// What a resource requires of the authentication event behind a token.
#[derive(Debug, Clone, Default)]
pub struct AuthRequirement {
    /// Acceptable `acr` values, best first. Empty means any.
    pub acr_values: Vec<String>,
    /// Maximum age of the authentication event in seconds.
    pub max_age: Option<u64>,
}

/// Returns `Ok` if the token's authentication context meets the requirement.
/// A missing `acr`/`auth_time` fails the check; it is never assumed to be fine.
pub fn check_authentication(claims: &Claims, need: &AuthRequirement, now: Option<u64>) -> Result<(), OAuthError> {
    let fail = || OAuthError::with(ErrorCode::InsufficientUserAuthentication, "a different authentication level is required");
    if !need.acr_values.is_empty() {
        let acr = claims.str_claim("acr").map_err(|_| fail())?.ok_or_else(fail)?;
        if !need.acr_values.iter().any(|a| a == acr) { return Err(fail()); }
    }
    if let Some(max) = need.max_age {
        let at = claims.date("auth_time").map_err(|_| fail())?.ok_or_else(fail)?;
        let now = now.unwrap_or_else(unix_now);
        if at > now + 30 || now.saturating_sub(at) > max { return Err(fail()); }
    }
    Ok(())
}

/// `WWW-Authenticate` value for the failure (RFC 9470 3).
pub fn challenge(scheme: &str, need: &AuthRequirement, realm: Option<&str>) -> String {
    let mut parts = vec![];
    if let Some(r) = realm { parts.push(format!("realm=\"{}\"", r.replace(['"', '\\'], ""))); }
    parts.push("error=\"insufficient_user_authentication\"".to_string());
    parts.push("error_description=\"A different authentication level is required\"".to_string());
    if !need.acr_values.is_empty() { parts.push(format!("acr_values=\"{}\"", need.acr_values.iter().map(|a| a.replace(['"', '\\', ' '], "")).collect::<Vec<_>>().join(" "))); }
    if let Some(m) = need.max_age { parts.push(format!("max_age={m}")); }
    format!("{scheme} {}", parts.join(", "))
}

/// Client side: parse the challenge into the parameters for a new authorization request.
pub fn parse_challenge(www_authenticate: &str) -> Option<AuthRequirement> {
    if !www_authenticate.contains("insufficient_user_authentication") { return None; }
    let get = |name: &str| -> Option<String> {
        let key = format!("{name}=");
        let i = www_authenticate.find(&key)? + key.len();
        let rest = &www_authenticate[i..];
        if let Some(q) = rest.strip_prefix('"') { q.split_once('"').map(|(v, _)| v.to_string()) }
        else { Some(rest.split([',', ' ']).next()?.to_string()) }
    };
    Some(AuthRequirement {
        acr_values: get("acr_values").map(|v| v.split(' ').filter(|s| !s.is_empty()).map(String::from).collect()).unwrap_or_default(),
        max_age: get("max_age").and_then(|v| v.parse().ok()),
    })
}
