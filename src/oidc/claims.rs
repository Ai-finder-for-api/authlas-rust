//! Standard claims (Core 5.1), the UserInfo endpoint (5.3), and pairwise subject identifiers (8).
use crate::jwa::Hash;
use crate::oauth::error::{ErrorCode, OAuthError, OResult};
use crate::oauth::scope::Scope;
use crate::{b64, crypto, Error, Result};
use serde_json::{json, Map, Value};
use url::{Host, Url};

use super::request::{scope_claims, ClaimsRequest};

/// Longest `sub` the spec allows (Core 2).
pub const MAX_SUB: usize = 255;

/// Checks the types of the standard claims in a profile (Core 5.1). Unknown names pass through. Returns the first problem.
pub fn check_standard_claims(profile: &Map<String, Value>) -> Result<()> {
    let bad = |n: &str, why: &str| Err(Error::Malformed(format!("claim {n}: {why}")));
    for (k, v) in profile {
        match k.as_str() {
            "sub" => match v.as_str() { Some(s) if !s.is_empty() && s.len() <= MAX_SUB => {}, _ => return bad(k, "must be a non-empty string of at most 255 characters") },
            "name" | "given_name" | "family_name" | "middle_name" | "nickname" | "preferred_username" | "gender" | "zoneinfo" | "locale" | "phone_number" =>
                if !v.is_string() { return bad(k, "must be a string") },
            "profile" | "picture" | "website" => match v.as_str() {
                Some(s) => if !matches!(Url::parse(s).map(|u| u.scheme().to_string()).as_deref(), Ok("https") | Ok("http")) { return bad(k, "must be an http(s) URL") },
                None => return bad(k, "must be a string"),
            },
            "email" => match v.as_str() { Some(s) if s.contains('@') && !s.contains(char::is_whitespace) => {}, _ => return bad(k, "must look like an email address") },
            "email_verified" | "phone_number_verified" => if !v.is_boolean() { return bad(k, "must be a JSON boolean, not a string") },
            "birthdate" => match v.as_str() {
                Some(s) if valid_birthdate(s) => {},
                _ => return bad(k, "must be YYYY-MM-DD, 0000-MM-DD or YYYY"),
            },
            "updated_at" => if !(v.is_u64() || v.as_f64().map_or(false, |f| f >= 0.0)) { return bad(k, "must be a number of seconds") },
            "address" => match v.as_object() {
                Some(a) => for (ak, av) in a {
                    if matches!(ak.as_str(), "formatted" | "street_address" | "locality" | "region" | "postal_code" | "country") && !av.is_string() { return bad("address", "members must be strings"); }
                },
                None => return bad(k, "must be an object"),
            },
            _ => {}
        }
    }
    Ok(())
}

fn valid_birthdate(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: &[u8]| !r.is_empty() && r.iter().all(u8::is_ascii_digit);
    match b.len() {
        4 => digits(b),
        10 => digits(&b[0..4]) && b[4] == b'-' && digits(&b[5..7]) && b[7] == b'-' && digits(&b[8..10])
            && (1..=12).contains(&s[5..7].parse::<u32>().unwrap_or(0)) && (1..=31).contains(&s[8..10].parse::<u32>().unwrap_or(0)),
        _ => false,
    }
}

/// What the UserInfo endpoint returns: `sub` plus the claims the access token's scopes entitle the client to, plus the
/// `claims.userinfo` request. A claim the user does not have is left out. Nothing outside the entitlement leaves, whatever `profile` holds.
pub fn userinfo_response(profile: &Map<String, Value>, subject: &str, scope: &Scope, claims: &ClaimsRequest) -> Result<Map<String, Value>> {
    if subject.is_empty() || subject.len() > MAX_SUB { return Err(Error::Malformed("sub must be 1 to 255 characters".into())); }
    let mut out = Map::new();
    out.insert("sub".into(), json!(subject));
    let mut allowed: Vec<&str> = vec![];
    for s in scope.tokens() { allowed.extend_from_slice(scope_claims(s)); }
    allowed.extend(claims.userinfo_names());
    for name in allowed {
        if name == "sub" { continue; }
        if let Some(v) = profile.get(name) { out.insert(name.into(), v.clone()); }
    }
    check_standard_claims(&out)?;
    Ok(out)
}

/// UserInfo is only for access tokens that carry `openid` (Core 5.3.1). Returns the OAuth error to send otherwise.
pub fn userinfo_authorize(scope: &Scope) -> OResult<()> {
    if scope.contains("openid") { Ok(()) } else { Err(OAuthError::with(ErrorCode::InsufficientScope, "the openid scope is required")) }
}

/// RP side: a UserInfo response is only believed if its `sub` equals the ID token's `sub` (Core 5.3.4). Without this check,
/// a mixed-up token can make the RP attach someone else's profile to the session.
pub fn validate_userinfo(body: &str, id_token_sub: &str) -> Result<Map<String, Value>> {
    let o = crate::json::parse_object(body.as_bytes())?;
    match o.get("sub").and_then(Value::as_str) {
        Some(s) if crypto::ct_eq(s.as_bytes(), id_token_sub.as_bytes()) => {}
        Some(_) => return Err(Error::Claim("UserInfo sub does not match the ID token sub".into())),
        None => return Err(Error::Claim("UserInfo response has no sub".into())),
    }
    check_standard_claims(&o)?;
    Ok(o)
}

// ---------------------------------------------------------------------------------------------------------------------
// Pairwise subject identifiers
// ---------------------------------------------------------------------------------------------------------------------

/// The sector identifier for a client (Core 8.1): the host of `sector_identifier_uri` when given, else the one host that every
/// redirect URI shares. Several hosts without a `sector_identifier_uri` is an error.
pub fn sector_identifier(redirect_uris: &[String], sector_identifier_uri: Option<&str>) -> Result<String> {
    if let Some(u) = sector_identifier_uri {
        let url = crate::ssrf::ssrf_check(u)?;
        return url.host_str().map(str::to_ascii_lowercase).ok_or_else(|| Error::Malformed("sector_identifier_uri has no host".into()));
    }
    let mut hosts: Vec<String> = vec![];
    for r in redirect_uris {
        let u = Url::parse(r).map_err(|_| Error::Malformed("redirect_uri is not a URL".into()))?;
        let h = match u.host() { Some(Host::Domain(d)) => d.to_ascii_lowercase(), Some(Host::Ipv4(a)) => a.to_string(), Some(Host::Ipv6(a)) => a.to_string(), None => return Err(Error::Malformed("redirect_uri has no host".into())) };
        if !hosts.contains(&h) { hosts.push(h); }
    }
    match hosts.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(Error::Malformed("no redirect_uris".into())),
        _ => Err(Error::Claim("redirect_uris span several hosts: a sector_identifier_uri is required".into())),
    }
}

/// Checks the document fetched from `sector_identifier_uri` (Core 8.1): a JSON array of strings that contains every registered
/// redirect URI. The caller fetches it (after [`crate::ssrf::ssrf_check`]).
pub fn validate_sector_document(body: &str, redirect_uris: &[String]) -> Result<()> {
    if body.len() > 64 * 1024 { return Err(Error::Malformed("sector identifier document is too large".into())); }
    let v: Value = serde_json::from_str(body).map_err(|_| Error::Malformed("sector identifier document is not JSON".into()))?;
    let arr = v.as_array().ok_or_else(|| Error::Malformed("sector identifier document must be a JSON array".into()))?;
    let listed: Vec<&str> = arr.iter().map(|x| x.as_str().ok_or_else(|| Error::Malformed("entries must be strings".into()))).collect::<Result<_>>()?;
    for r in redirect_uris {
        if !listed.contains(&r.as_str()) { return Err(Error::Claim(format!("redirect_uri {r} is not listed in the sector identifier document"))); }
    }
    Ok(())
}

/// Derives pairwise `sub` values: `base64url(HMAC-SHA-256(secret, len(sector) || sector || len(account) || account))`.
/// Deterministic, one-way without the secret, different per sector, and the length prefixes keep `("ab","c")` and `("a","bc")` apart.
/// Keep `secret` in a vault: changing it changes every user's identifier at every client.
pub struct PairwiseSubjects { secret: zeroize::Zeroizing<Vec<u8>> }

impl PairwiseSubjects {
    pub fn new(secret: &[u8]) -> Result<Self> {
        if secret.len() < 32 { return Err(Error::Key("pairwise secret must be at least 32 bytes".into())); }
        Ok(PairwiseSubjects { secret: zeroize::Zeroizing::new(secret.to_vec()) })
    }
    pub fn subject(&self, sector: &str, local_account_id: &str) -> Result<String> {
        if sector.is_empty() || local_account_id.is_empty() { return Err(Error::Malformed("sector and account id must not be empty".into())); }
        let mut m = Vec::with_capacity(sector.len() + local_account_id.len() + 16);
        m.extend_from_slice(&(sector.len() as u64).to_be_bytes()); m.extend_from_slice(sector.as_bytes());
        m.extend_from_slice(&(local_account_id.len() as u64).to_be_bytes()); m.extend_from_slice(local_account_id.as_bytes());
        Ok(b64::encode(crypto::hmac(Hash::Sha256, &self.secret, &m)?))
    }
}
