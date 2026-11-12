//! Authorization endpoint: building requests (client side) and validating them (server side).
//!
//! The server side separates two kinds of failure, as RFC 6749 4.1.2.1 requires:
//! * [`Failure::Direct`]: `client_id` or `redirect_uri` is wrong. Show an error page. Never redirect.
//! * [`Failure::Redirect`]: the redirect target is trusted; send the error there.
//!
//! Defaults (RFC 9700, OAuth 2.1): `response_type=code` only, PKCE S256 required for every client,
//! no `plain`, exact redirect matching, repeated parameters refused.
use super::error::{ErrorCode, OAuthError};
use super::form::{self, Params};
use super::pkce::{self, Method};
use super::redirect::{self, ClientKind, ResponseMode};
use super::scope::Scope;
use crate::error::Result;

/// OpenID Connect authentication request parameters (Core 3.1.2.1). They are kept on [`AuthRequest::oidc`] verbatim; the
/// `oidc` module parses and enforces them.
pub const OIDC_PARAMS: &[&str] = &["prompt", "max_age", "login_hint", "id_token_hint", "acr_values", "claims", "ui_locales", "display"];

pub const KNOWN: &[&str] = &[
    "response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method",
    "resource", "response_mode", "nonce", "request", "request_uri", "authorization_details", "prompt", "max_age",
    "login_hint", "id_token_hint", "acr_values", "claims", "ui_locales", "display", "dpop_jkt",
];

/// What the server knows about a registered client.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub kind: ClientKind,
    /// Scopes this client may ever ask for.
    pub allowed_scopes: Scope,
    pub response_types: Vec<String>,
}

/// Server-wide rules.
#[derive(Debug, Clone)]
pub struct ServerPolicy {
    /// Accept `code_challenge_method=plain`. Off by default (RFC 9700 2.1.1).
    pub allow_plain_pkce: bool,
    /// Require PKCE on every authorization request. On by default (RFC 9700 2.1.1, OAuth 2.1).
    pub require_pkce: bool,
    /// Require `state`. Not needed when PKCE is used (OAuth 2.1), so off by default.
    pub require_state: bool,
    /// Longest accepted `state`.
    pub max_state_len: usize,
    /// Require the client's `resource` indicators (RFC 8707) to be in this list when non-empty.
    pub allowed_resources: Vec<String>,
    /// Include `iss` in every response (RFC 9207).
    pub issuer: Option<String>,
    /// Leave scope out of requests and give the client its default set instead of failing.
    pub default_scope: Option<Scope>,
}

impl Default for ServerPolicy {
    fn default() -> Self {
        ServerPolicy { allow_plain_pkce: false, require_pkce: true, require_state: false, max_state_len: 512,
            allowed_resources: Vec::new(), issuer: None, default_scope: None }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Scope,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<Method>,
    pub resources: Vec<String>,
    pub response_mode: ResponseMode,
    pub nonce: Option<String>,
    /// OpenID Connect parameters as sent ([`OIDC_PARAMS`]). Not interpreted here; see `oidc::request::AuthenticationRequest`.
    pub oidc: Vec<(String, String)>,
    /// Extension parameters the library did not interpret (RAR, DPoP binding, vendor parameters, ...).
    pub extra: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Failure {
    Direct(OAuthError),
    Redirect { redirect_uri: String, mode: ResponseMode, error: OAuthError },
}

impl Failure {
    /// Pairs to send to the client for `Redirect`, with `state` and `iss` already added.
    pub fn redirect_target(&self, iss: Option<&str>) -> Option<Result<String>> {
        match self {
            Failure::Direct(_) => None,
            Failure::Redirect { redirect_uri, mode, error } => Some(redirect::build_response_uri(redirect_uri, *mode, &error.to_params(iss))),
        }
    }
    pub fn error(&self) -> &OAuthError {
        match self { Failure::Direct(e) => e, Failure::Redirect { error, .. } => error }
    }
}

fn valid_state(s: &str, max: usize) -> bool {
    // RFC 6749 appendix A.5: 1*VSCHAR (%x20-7E).
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Server side: validate an authorization request from its query string (or form body for POST).
pub fn validate(query: &str, client: &ClientInfo, policy: &ServerPolicy) -> std::result::Result<AuthRequest, Failure> {
    let direct = |m: &str| Failure::Direct(OAuthError::invalid_request(m));
    let p = Params::parse(query).map_err(|_| direct("malformed or repeated parameters"))?;

    // 1. Client and redirect URI. Until both check out, nothing is redirected.
    let client_id = p.get("client_id").map_err(|_| direct("client_id repeated"))?.ok_or_else(|| direct("client_id is required"))?;
    if client_id != client.client_id { return Err(direct("unknown client_id")); }
    let ru = p.get("redirect_uri").map_err(|_| direct("redirect_uri repeated"))?;
    let redirect_uri = redirect::resolve(&client.redirect_uris, ru).map_err(|_| direct("redirect_uri is missing or not registered"))?.to_string();

    // From here on errors go back to the client.
    let mode = match p.get("response_mode").ok().flatten() {
        None => ResponseMode::Query,
        Some(m) => match ResponseMode::parse(m) {
            Some(m) => m,
            None => return Err(Failure::Redirect { redirect_uri, mode: ResponseMode::Query, error: OAuthError::invalid_request("unsupported response_mode") }),
        },
    };
    let state = p.get("state").ok().flatten().map(str::to_string);
    let bad_state = state.as_deref().map_or(false, |s| !valid_state(s, policy.max_state_len));
    // Do not echo a state we consider malformed.
    let echo = if bad_state { None } else { state.clone() };
    let fail = |code: ErrorCode, d: &str| Failure::Redirect {
        redirect_uri: redirect_uri.clone(), mode, error: OAuthError::with(code, d).state(echo.as_deref()),
    };

    if bad_state { return Err(fail(ErrorCode::InvalidRequest, "invalid state")); }
    if policy.require_state && state.is_none() { return Err(fail(ErrorCode::InvalidRequest, "state is required")); }
    // Parameters that must not repeat were already rejected by Params::parse (only resource may repeat).

    let response_type = p.get("response_type").ok().flatten().ok_or_else(|| fail(ErrorCode::InvalidRequest, "response_type is required"))?;
    if !client.response_types.iter().any(|t| t == response_type) {
        return Err(fail(ErrorCode::UnsupportedResponseType, "response_type is not supported"));
    }

    // PKCE
    let challenge = p.get("code_challenge").ok().flatten().map(str::to_string);
    let method_raw = p.get("code_challenge_method").ok().flatten();
    let method = match (&challenge, method_raw) {
        (None, None) => None,
        (None, Some(_)) => return Err(fail(ErrorCode::InvalidRequest, "code_challenge_method without code_challenge")),
        (Some(c), m) => {
            let m = Method::parse(m, policy.allow_plain_pkce).map_err(|_| fail(ErrorCode::InvalidRequest, "code_challenge_method must be S256"))?;
            pkce::check_challenge_syntax(c, m).map_err(|_| fail(ErrorCode::InvalidRequest, "invalid code_challenge"))?;
            Some(m)
        }
    };
    if challenge.is_none() && policy.require_pkce {
        return Err(fail(ErrorCode::InvalidRequest, "code_challenge is required"));
    }

    // Scope
    let scope = match p.get("scope").ok().flatten() {
        Some(s) => Scope::parse(s).map_err(|_| fail(ErrorCode::InvalidScope, "malformed scope"))?,
        None => match &policy.default_scope {
            Some(d) => d.clone(),
            None => return Err(fail(ErrorCode::InvalidScope, "scope is required")),
        },
    };
    let excess = scope.excess(&client.allowed_scopes);
    if !excess.is_empty() { return Err(fail(ErrorCode::InvalidScope, "scope is not permitted for this client")); }

    // Resource indicators (RFC 8707 2): absolute URI, no fragment.
    let resources: Vec<String> = p.get_all("resource").to_vec();
    for r in &resources {
        let ok = url::Url::parse(r).map(|u| u.fragment().is_none() && !u.cannot_be_a_base()).unwrap_or(false) && !r.contains('#');
        if !ok { return Err(fail(ErrorCode::InvalidTarget, "resource must be an absolute URI without a fragment")); }
        if !policy.allowed_resources.is_empty() && !policy.allowed_resources.iter().any(|a| a == r) {
            return Err(fail(ErrorCode::InvalidTarget, "resource is not known to this server"));
        }
    }

    let extra = p.unknown(KNOWN).filter_map(|n| p.get(n).ok().flatten().map(|v| (n.to_string(), v.to_string()))).collect();
    Ok(AuthRequest {
        client_id: client_id.to_string(), redirect_uri, response_type: response_type.to_string(), scope, state,
        code_challenge: challenge, code_challenge_method: method, resources, response_mode: mode,
        nonce: p.get("nonce").ok().flatten().map(str::to_string), extra,
        oidc: OIDC_PARAMS.iter().filter_map(|n| p.get(n).ok().flatten().map(|v| (n.to_string(), v.to_string()))).collect(),
    })
}

/// Pairs for a successful `code` response, with `state` echoed and `iss` added (RFC 9207).
pub fn success_params(req: &AuthRequest, code: &str, iss: Option<&str>) -> Vec<(String, String)> {
    let mut v = vec![("code".to_string(), code.to_string())];
    if let Some(s) = &req.state { v.push(("state".into(), s.clone())); }
    if let Some(i) = iss { v.push(("iss".into(), i.to_string())); }
    v
}

/// Client side: what to send. Returns the URL to open and the verifier to keep until the token request.
pub struct Outgoing {
    pub url: String,
    pub state: String,
    pub code_verifier: String,
    pub nonce: Option<String>,
}

pub struct Builder<'a> {
    pub authorization_endpoint: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: Option<&'a Scope>,
    pub resources: &'a [&'a str],
    pub extra: &'a [(&'a str, &'a str)],
    /// OpenID Connect: add a nonce.
    pub with_nonce: bool,
}

impl<'a> Builder<'a> {
    pub fn new(authorization_endpoint: &'a str, client_id: &'a str, redirect_uri: &'a str) -> Self {
        Builder { authorization_endpoint, client_id, redirect_uri, scope: None, resources: &[], extra: &[], with_nonce: false }
    }

    /// Always S256 PKCE, and a fresh 256-bit `state` (CSRF defence, RFC 9700 4.7).
    pub fn build(&self) -> Result<Outgoing> {
        let verifier = pkce::generate_verifier()?;
        let challenge = pkce::s256_challenge(&verifier)?;
        let state = pkce::generate_verifier()?;
        let nonce = if self.with_nonce { Some(pkce::generate_verifier()?) } else { None };
        let mut pairs: Vec<(&str, &str)> = vec![
            ("response_type", "code"), ("client_id", self.client_id), ("redirect_uri", self.redirect_uri),
            ("state", &state), ("code_challenge", &challenge), ("code_challenge_method", "S256"),
        ];
        let scope_s = self.scope.map(|s| s.to_string());
        if let Some(s) = &scope_s { pairs.push(("scope", s)); }
        for r in self.resources { pairs.push(("resource", r)); }
        if let Some(n) = &nonce { pairs.push(("nonce", n)); }
        pairs.extend_from_slice(self.extra);
        let sep = if self.authorization_endpoint.contains('?') { '&' } else { '?' };
        Ok(Outgoing { url: format!("{}{}{}", self.authorization_endpoint, sep, form::encode(pairs)), state, code_verifier: verifier, nonce })
    }
}

/// Client side: check the redirect that came back (RFC 6749 4.1.2, RFC 9207). Returns the code.
/// `expected_iss` is the issuer from metadata; when given, a missing or different `iss` is an error (mix-up defence).
pub fn parse_response(query: &str, expected_state: &str, expected_iss: Option<&str>) -> std::result::Result<String, OAuthError> {
    let p = Params::parse(query).map_err(|_| OAuthError::invalid_request("malformed response"))?;
    let state = p.get("state").map_err(|_| OAuthError::invalid_request("state repeated"))?;
    // State is checked before anything else is believed, errors included.
    match state {
        Some(s) if crate::crypto::ct_eq(s.as_bytes(), expected_state.as_bytes()) => {}
        _ => return Err(OAuthError::invalid_request("state mismatch")),
    }
    if let Some(want) = expected_iss {
        match p.get("iss").map_err(|_| OAuthError::invalid_request("iss repeated"))? {
            Some(got) if got == want => {}
            _ => return Err(OAuthError::invalid_request("iss missing or does not match the expected issuer")),
        }
    }
    if let Some(e) = p.get("error").ok().flatten() {
        let code = ErrorCode::parse(e).unwrap_or(ErrorCode::ServerError);
        let d = p.get("error_description").ok().flatten().unwrap_or("");
        return Err(OAuthError::with(code, d));
    }
    p.get("code").ok().flatten().map(str::to_string).ok_or_else(|| OAuthError::invalid_request("no code in response"))
}
