//! Bearer tokens at a resource server (RFC 6750) and the WWW-Authenticate challenge.
//!
//! Tokens in the URI query (RFC 6750 2.3) leak into logs and Referer headers; RFC 9700 2.4 and OAuth 2.1 forbid them.
//! They are not accepted here. Form-body tokens (2.2) are not accepted either: the header is the only way in.
use super::error::{ErrorCode, OAuthError, OResult};

/// Scheme of an access token presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme { Bearer, DPoP }

/// `b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="` (RFC 6750 2.1).
fn is_b64token(t: &str) -> bool {
    let body = t.trim_end_matches('=');
    !body.is_empty() && t.len() <= 8192 &&
        body.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/'))
}

/// Extracts the token from one Authorization header value. The scheme is case-insensitive (RFC 9110 11.1).
/// Exactly one space separates scheme and token.
pub fn parse_authorization(header: &str) -> OResult<(Scheme, &str)> {
    let (scheme, tok) = header.split_once(' ').ok_or_else(|| OAuthError::new(ErrorCode::InvalidToken))?;
    let s = if scheme.eq_ignore_ascii_case("bearer") { Scheme::Bearer }
        else if scheme.eq_ignore_ascii_case("dpop") { Scheme::DPoP }
        else { return Err(OAuthError::new(ErrorCode::InvalidToken)); };
    if !is_b64token(tok) { return Err(OAuthError::with(ErrorCode::InvalidToken, "malformed token")); }
    Ok((s, tok))
}

/// Several Authorization headers (or none) are an error rather than "take the first".
pub fn from_headers<'a>(values: &[&'a str]) -> OResult<(Scheme, &'a str)> {
    match values {
        [one] => parse_authorization(one),
        [] => Err(OAuthError::new(ErrorCode::InvalidRequest)),
        _ => Err(OAuthError::invalid_request("more than one Authorization header")),
    }
}

fn quote(s: &str) -> String {
    // quoted-string: escape backslash and quote; drop control characters.
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c { '"' | '\\' => { o.push('\\'); o.push(c); } c if (c as u32) < 0x20 || c as u32 == 0x7f => o.push(' '), c => o.push(c) }
    }
    o
}

/// Builds a `WWW-Authenticate` value. With no `error`, only the realm is sent (RFC 6750 3.1: no error
/// code when the request lacked credentials).
pub fn challenge(scheme: Scheme, realm: &str, error: Option<ErrorCode>, description: Option<&str>, scope: Option<&str>, resource_metadata: Option<&str>) -> String {
    let name = match scheme { Scheme::Bearer => "Bearer", Scheme::DPoP => "DPoP" };
    let mut parts = vec![format!("realm=\"{}\"", quote(realm))];
    if let Some(s) = scope { parts.push(format!("scope=\"{}\"", quote(s))); }
    if let Some(e) = error { parts.push(format!("error=\"{}\"", e.as_str())); }
    if let Some(d) = description { parts.push(format!("error_description=\"{}\"", quote(&super::error::sanitize_description(d)))); }
    // RFC 9728 5.1
    if let Some(r) = resource_metadata { parts.push(format!("resource_metadata=\"{}\"", quote(r))); }
    format!("{name} {}", parts.join(", "))
}

/// Same challenge for an `OAuthError`: `invalid_token` -> 401, `insufficient_scope` -> 403 with the needed scope.
pub fn challenge_for(scheme: Scheme, realm: &str, e: &OAuthError, scope: Option<&str>, resource_metadata: Option<&str>) -> (u16, String) {
    let code = if e.code == ErrorCode::InvalidRequest && e.description.is_none() { None } else { Some(e.code) };
    (e.status(), challenge(scheme, realm, code, e.description.as_deref(), scope, resource_metadata))
}
