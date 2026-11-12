//! Redirect URIs: registration checks, exact matching, and building the response URI.
//!
//! RFC 9700 2.1: the authorization server compares redirect URIs by simple string comparison.
//! The one exception is RFC 8252 7.3: for native apps on a loopback IP literal, the port is ignored.
//! RFC 6749 3.1.2: no fragment. RFC 8252 7.1: private-use schemes must be reverse domain names.
use crate::error::{Error, Result};
use url::{Host, Url};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    /// Web or server application: https only (or loopback http for development).
    Web,
    /// Native application: also loopback http and reverse-domain private-use schemes.
    Native,
}

pub const MAX_LEN: usize = 2048;

fn is_loopback_ip(u: &Url) -> bool {
    match u.host() {
        Some(Host::Ipv4(a)) => a.is_loopback(),
        Some(Host::Ipv6(a)) => a.is_loopback(),
        _ => false,
    }
}

/// Reverse domain name with at least one dot, as in `com.example.app` (RFC 8252 7.1).
fn is_private_use_scheme(s: &str) -> bool {
    s.contains('.') && s.split('.').all(|l| !l.is_empty()) &&
        s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// Validates a URI at client registration time. Returns the parsed URL.
pub fn validate_registered(uri: &str, kind: ClientKind) -> Result<Url> {
    if uri.len() > MAX_LEN { return Err(Error::Malformed("redirect_uri too long".into())); }
    if uri.bytes().any(|b| b < 0x21 || b == 0x7f) {
        return Err(Error::Malformed("redirect_uri contains whitespace or control characters".into()));
    }
    // The WHATWG parser silently repairs input ("https:///h" becomes "https://h/", a backslash becomes a slash). A registered string
    // that browsers and a strict string compare read differently is a redirect-attack gap, so refuse them.
    if uri.contains('\\') {
        return Err(Error::Malformed("redirect_uri must not contain backslashes".into()));
    }
    let u = Url::parse(uri).map_err(|_| Error::Malformed("redirect_uri is not an absolute URI".into()))?;
    if matches!(u.scheme(), "http" | "https") {
        let after = uri.split_once("://").map(|(_, r)| r).unwrap_or("");
        if after.is_empty() || after.starts_with(['/', '?']) {
            return Err(Error::Malformed("redirect_uri has an empty authority".into()));
        }
    }
    if u.fragment().is_some() || uri.contains('#') {
        return Err(Error::Malformed("redirect_uri must not contain a fragment".into()));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(Error::Malformed("redirect_uri must not contain credentials".into()));
    }
    match u.scheme() {
        "https" => {
            if u.host().is_none() { return Err(Error::Malformed("redirect_uri needs a host".into())); }
        }
        "http" => {
            // RFC 8252 7.3 and RFC 9700: plain http only for loopback IP literals. "localhost" is refused:
            // it can be remapped by the resolver or hosts file (RFC 8252 8.3).
            if !is_loopback_ip(&u) {
                return Err(Error::Malformed("http redirect_uri is only allowed on 127.0.0.1 or [::1]".into()));
            }
            if kind == ClientKind::Web && u.port().is_none() {
                return Err(Error::Malformed("loopback redirect_uri needs an explicit port for web clients".into()));
            }
        }
        s if kind == ClientKind::Native && is_private_use_scheme(s) => {
            // RFC 8252 7.1: the form is scheme:/path, a host part is discouraged but allowed.
        }
        "javascript" | "data" | "vbscript" | "file" | "blob" | "about" => {
            return Err(Error::Malformed("redirect_uri scheme is forbidden".into()));
        }
        _ => return Err(Error::Malformed("redirect_uri scheme is not allowed for this client".into())),
    }
    Ok(u)
}

/// Does the presented URI equal a registered one?
pub fn matches(registered: &str, presented: &str) -> bool {
    if registered == presented { return true; }
    // Loopback exception: same everything but the port, only when the registered URI is an http loopback IP.
    let (Ok(r), Ok(p)) = (Url::parse(registered), Url::parse(presented)) else { return false };
    if r.scheme() != "http" || p.scheme() != "http" || !is_loopback_ip(&r) || !is_loopback_ip(&p) { return false; }
    if r.host() != p.host() || r.path() != p.path() || r.query() != p.query() { return false; }
    // The registration must not pin a port (a pinned port is compared exactly above).
    r.port().is_none() && p.fragment().is_none() && p.username().is_empty() && p.password().is_none()
}

/// Picks the redirect URI for a request (RFC 6749 3.1.2.3).
/// * presented: must match a registered URI exactly.
/// * absent: allowed only when exactly one URI is registered.
pub fn resolve<'a>(registered: &'a [String], presented: Option<&'a str>) -> Result<&'a str> {
    match presented {
        Some(p) => {
            if p.len() > MAX_LEN { return Err(Error::Malformed("redirect_uri too long".into())); }
            if registered.iter().any(|r| matches(r, p)) { Ok(p) }
            else { Err(Error::Malformed("redirect_uri is not registered".into())) }
        }
        None => match registered {
            [one] => Ok(one),
            [] => Err(Error::Malformed("client has no registered redirect_uri".into())),
            _ => Err(Error::Malformed("redirect_uri is required".into())),
        },
    }
}

/// Where response parameters go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode { Query, Fragment, FormPost }

impl ResponseMode {
    pub fn parse(s: &str) -> Option<ResponseMode> {
        match s { "query" => Some(Self::Query), "fragment" => Some(Self::Fragment), "form_post" => Some(Self::FormPost), _ => None }
    }
}

/// Builds the redirect target. Existing query members of the registered URI are kept (RFC 6749 3.1.2).
/// For `FormPost` use [`form_post_html`] instead.
pub fn build_response_uri(base: &str, mode: ResponseMode, params: &[(String, String)]) -> Result<String> {
    let mut u = Url::parse(base).map_err(|_| Error::Malformed("bad redirect_uri".into()))?;
    match mode {
        ResponseMode::Query => {
            let mut q = u.query_pairs_mut();
            for (k, v) in params { q.append_pair(k, v); }
        }
        ResponseMode::Fragment => {
            let f = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(params).finish();
            u.set_fragment(Some(&f));
        }
        ResponseMode::FormPost => return Err(Error::Malformed("use form_post_html for form_post".into())),
    }
    Ok(u.to_string())
}

fn html_escape(s: &str) -> String {
    s.chars().flat_map(|c| match c {
        '&' => "&amp;".chars().collect::<Vec<_>>(),
        '<' => "&lt;".chars().collect(), '>' => "&gt;".chars().collect(),
        '"' => "&quot;".chars().collect(), '\'' => "&#39;".chars().collect(),
        c => vec![c],
    }).collect()
}

/// Auto-submitting form for `response_mode=form_post`. Serve with `Cache-Control: no-store`.
/// Everything is escaped; the page carries no script from outside and no inline handlers other than the submit.
pub fn form_post_html(action: &str, params: &[(String, String)]) -> String {
    let mut s = String::from("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Redirecting</title></head><body onload=\"document.forms[0].submit()\"><form method=\"post\" action=\"");
    s.push_str(&html_escape(action));
    s.push_str("\">");
    for (k, v) in params {
        s.push_str(&format!("<input type=\"hidden\" name=\"{}\" value=\"{}\"/>", html_escape(k), html_escape(v)));
    }
    s.push_str("<noscript><button type=\"submit\">Continue</button></noscript></form></body></html>");
    s
}
