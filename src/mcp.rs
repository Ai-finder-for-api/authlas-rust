//! MCP authorization (Model Context Protocol, spec revision 2025-11-25), on top of OAuth 2.1.
//!
//! Three roles, all in this module:
//!
//! * **MCP client**: find the authorization server from a 401 (RFC 9728), try the three metadata URLs in the order the spec fixes,
//!   refuse a server that does not advertise PKCE S256, pick scopes, send `resource` in the authorization AND token request,
//!   and step up on `insufficient_scope` with a retry limit.
//! * **MCP server (resource server)**: publish protected resource metadata, challenge with `resource_metadata` and `scope`,
//!   accept only tokens issued for this exact resource, and answer 403 `insufficient_scope` with the scopes the call needs.
//! * **Authorization server**: validate a Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document-00), with the
//!   SSRF checks the draft asks for, and turn it into a client the authorization endpoint can use.
//!
//! This module does no I/O. The caller fetches URLs and hands in the bodies, so the HTTP stack, proxy and DNS policy stay theirs.
//! The helpers that decide *whether a fetch is allowed* ([`ssrf_check`], [`is_public_ip`]) are here because getting them wrong is
//! the usual way these features get exploited.
//!
//! Token passthrough is forbidden by the spec and no function here makes it easy: [`Principal`] carries identity and scope, not
//! the raw token. If your server calls an upstream API, obtain a separate token from that API's own authorization server.
use crate::jwa::Algorithm;
use crate::jwk::Jwk;
use crate::jwt::{self, ReplayCache};
use crate::oauth::bearer::{self, Scheme};
use crate::oauth::error::{ErrorCode, OAuthError, OResult};
use crate::oauth::form;
use crate::oauth::introspection::Introspection;
use crate::oauth::metadata::{self, AsMetadata, ResourceMetadata};
use crate::oauth::redirect::{self, ClientKind};
use crate::oauth::request::{self, Builder, ClientInfo, Outgoing};
use crate::oauth::scope::Scope;
use crate::oauth::at_jwt;
use crate::{Error, Result};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use url::{Host, Url};

pub const SPEC_REVISION: &str = "2025-11-25";

// ---------------------------------------------------------------------------------------------------------------------
// Canonical resource identifiers
// ---------------------------------------------------------------------------------------------------------------------

/// The canonical URI of an MCP server (RFC 8707 2): lowercase scheme and host, no default port, no trailing slash, no query,
/// no fragment, no credentials. `https` only, except that loopback hosts may use `http` for local development.
pub fn canonical_resource(input: &str) -> Result<String> {
    let bad = |m: &str| Error::Malformed(format!("resource: {m}"));
    if input.is_empty() || input.len() > 2048 { return Err(bad("empty or too long")); }
    if input.bytes().any(|b| b <= 0x20 || b == 0x7f) || input.contains('\\') { return Err(bad("whitespace, control or backslash")); }
    if input.contains('#') || input.contains('?') { return Err(bad("must not have a query or fragment")); }
    let after = input.split_once("://").map(|(_, r)| r).unwrap_or("");
    // The URL parser repairs "https:///h" into "https://h/". A string that two readers parse differently is not an identifier.
    if after.is_empty() || after.starts_with('/') { return Err(bad("empty authority")); }
    let path = after.find('/').map(|i| &after[i..]).unwrap_or("");
    if path.split('/').any(|s| s == "." || s == "..") { return Err(bad("dot segments")); }
    let u = Url::parse(input).map_err(|_| bad("not an absolute URL"))?;
    if !u.username().is_empty() || u.password().is_some() { return Err(bad("must not carry credentials")); }
    let loopback = match u.host() {
        Some(Host::Ipv4(a)) => a.is_loopback(), Some(Host::Ipv6(a)) => a.is_loopback(),
        Some(Host::Domain(d)) => d == "localhost", None => false,
    };
    match u.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(bad("must be https (http only for loopback)")),
    }
    if u.host().is_none() { return Err(bad("needs a host")); }
    let mut s = u.as_str().to_string();
    while s.ends_with('/') { s.pop(); }
    Ok(s)
}

/// Are these the same resource? Compares canonical forms, so case of scheme/host and a trailing slash do not matter.
pub fn resources_equal(a: &str, b: &str) -> bool {
    match (canonical_resource(a), canonical_resource(b)) { (Ok(x), Ok(y)) => x == y, _ => false }
}

fn well_known(u: &Url, suffix: &str) -> String {
    format!("{}/.well-known/{}{}", u.origin().ascii_serialization(), suffix, u.path().trim_end_matches('/'))
}

// ---------------------------------------------------------------------------------------------------------------------
// Discovery (client side)
// ---------------------------------------------------------------------------------------------------------------------

/// Where to look for protected resource metadata when the 401 carried no `resource_metadata` parameter, in the order the spec gives:
/// first the path-specific URL, then the root.
pub fn resource_metadata_urls(mcp_url: &str) -> Result<Vec<String>> {
    let c = canonical_resource(mcp_url)?;
    let u = Url::parse(&c).map_err(|_| Error::Malformed("resource".into()))?;
    let specific = well_known(&u, "oauth-protected-resource");
    let root = format!("{}/.well-known/oauth-protected-resource", u.origin().ascii_serialization());
    Ok(if specific == root { vec![specific] } else { vec![specific, root] })
}

/// Authorization server metadata URLs, in the priority order the MCP spec requires (RFC 8414 plus OpenID Connect Discovery).
/// With a path in the issuer: OAuth path-insertion, OIDC path-insertion, OIDC path-appending. Without: OAuth, then OIDC.
pub fn as_discovery_urls(issuer: &str) -> Result<Vec<String>> {
    let u = Url::parse(issuer).map_err(|_| Error::Malformed("issuer is not a URL".into()))?;
    let has_path = !u.path().trim_end_matches('/').is_empty();
    let mut v = vec![metadata::well_known_url(issuer, "oauth-authorization-server")?, metadata::well_known_url(issuer, "openid-configuration")?];
    if has_path { v.push(metadata::oidc_metadata_url(issuer)?); }
    Ok(v)
}

/// Parses a fetched protected resource metadata document for the MCP server at `mcp_url`.
/// The document's `resource` must name that server (RFC 9728 3.3). The comparison ignores case of scheme/host and a trailing slash.
/// It must list at least one authorization server (MCP requires it).
pub fn parse_resource_metadata(body: &str, mcp_url: &str) -> Result<ResourceMetadata> {
    let o = crate::json::parse_object(body.as_bytes())?;
    let claimed = o.get("resource").and_then(Value::as_str).ok_or_else(|| Error::Malformed("resource is missing".into()))?;
    if !resources_equal(claimed, mcp_url) { return Err(Error::Claim("resource in metadata does not name the server that was called".into())); }
    let md = ResourceMetadata::parse(body, claimed)?;
    if md.authorization_servers.is_empty() { return Err(Error::Malformed("authorization_servers is empty".into())); }
    Ok(md)
}

/// Picks an authorization server from the resource's list. `trusted` is the client's own allow-list (empty: take the first,
/// which is only reasonable for tools that talk to servers the user typed in). RFC 9728 7.6 puts this choice on the client.
pub fn select_authorization_server<'a>(md: &'a ResourceMetadata, trusted: &[&str]) -> Result<&'a str> {
    if trusted.is_empty() { return md.authorization_servers.first().map(String::as_str).ok_or_else(|| Error::Malformed("no authorization server".into())); }
    md.authorization_servers.iter().map(String::as_str).find(|a| trusted.contains(a)).ok_or_else(|| Error::Claim("none of the advertised authorization servers is trusted".into()))
}

/// MCP clients MUST refuse to continue when the server does not advertise PKCE. Absent `code_challenge_methods_supported` means
/// "no PKCE", and so does a list without S256. Returns the reasons the flow cannot go on.
pub fn require_pkce(md: &AsMetadata) -> Result<()> {
    if md.code_challenge_methods_supported.is_empty() { return Err(Error::Claim("authorization server does not advertise code_challenge_methods_supported: refusing to continue without PKCE".into())); }
    if !md.code_challenge_methods_supported.iter().any(|m| m == "S256") { return Err(Error::Claim("authorization server does not support PKCE S256".into())); }
    Ok(())
}

/// Does the server accept Client ID Metadata Documents?
pub fn supports_client_id_metadata(md: &AsMetadata) -> bool {
    md.extra.get("client_id_metadata_document_supported").and_then(Value::as_bool).unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration { Preregistered, ClientIdMetadataDocument, Dynamic, Manual }

/// The spec's priority order: pre-registered credentials, then a Client ID Metadata Document, then Dynamic Client Registration,
/// then ask the user.
pub fn choose_registration(have_preregistered: bool, md: &AsMetadata, client_metadata_url: Option<&str>) -> Registration {
    if have_preregistered { Registration::Preregistered }
    else if client_metadata_url.is_some() && supports_client_id_metadata(md) { Registration::ClientIdMetadataDocument }
    else if md.registration_endpoint.is_some() { Registration::Dynamic }
    else { Registration::Manual }
}

// ---------------------------------------------------------------------------------------------------------------------
// WWW-Authenticate parsing
// ---------------------------------------------------------------------------------------------------------------------

/// One challenge from a `WWW-Authenticate` header (RFC 9110 11.6.1). Parameter names are lowercased.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Challenge {
    pub scheme: String,
    pub params: Vec<(String, String)>,
}

impl Challenge {
    pub fn param(&self, name: &str) -> Option<&str> { self.params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()) }
    pub fn resource_metadata(&self) -> Option<&str> { self.param("resource_metadata") }
    pub fn scope(&self) -> Option<&str> { self.param("scope") }
    pub fn error(&self) -> Option<&str> { self.param("error") }
    pub fn error_description(&self) -> Option<&str> { self.param("error_description") }
    pub fn is_bearer(&self) -> bool { self.scheme.eq_ignore_ascii_case("bearer") }
}

const MAX_HEADER: usize = 8192;
const MAX_PARAMS: usize = 32;

fn is_tchar(c: char) -> bool { c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c) }

/// Parses one header value into challenges. A repeated parameter inside one challenge is an error: "first one wins" would let an
/// attacker-controlled intermediary choose the `resource_metadata` URL. A token68 credential is not supported and is an error.
pub fn parse_challenges(header: &str) -> Result<Vec<Challenge>> {
    let bad = |m: &str| Error::Malformed(format!("WWW-Authenticate: {m}"));
    if header.len() > MAX_HEADER { return Err(bad("too long")); }
    let chars: Vec<char> = header.chars().collect();
    let mut i = 0;
    let mut out: Vec<Challenge> = vec![];
    let skip = |i: &mut usize, set: &str| while *i < chars.len() && (chars[*i] == ' ' || chars[*i] == '\t' || set.contains(chars[*i])) { *i += 1; };
    loop {
        skip(&mut i, ",");
        if i >= chars.len() { break; }
        let start = i;
        while i < chars.len() && is_tchar(chars[i]) { i += 1; }
        if i == start { return Err(bad("unexpected character")); }
        let word: String = chars[start..i].iter().collect();
        let mut j = i;
        while j < chars.len() && (chars[j] == ' ' || chars[j] == '\t') { j += 1; }
        if j < chars.len() && chars[j] == '=' && !out.is_empty() {
            // auth-param of the current challenge
            if chars.get(j + 1) == Some(&'=') || chars.get(j + 1).is_none() { return Err(bad("token68 credentials are not supported")); }
            j += 1;
            while j < chars.len() && (chars[j] == ' ' || chars[j] == '\t') { j += 1; }
            let value = if chars.get(j) == Some(&'"') {
                j += 1;
                let mut s = String::new();
                loop {
                    match chars.get(j) {
                        None => return Err(bad("unterminated quoted string")),
                        Some('"') => { j += 1; break; }
                        Some('\\') => { j += 1; match chars.get(j) { Some(c) => { s.push(*c); j += 1; } None => return Err(bad("dangling escape")) } }
                        Some(c) if (*c as u32) < 0x20 || *c as u32 == 0x7f => return Err(bad("control character")),
                        Some(c) => { s.push(*c); j += 1; }
                    }
                }
                s
            } else {
                let s0 = j;
                while j < chars.len() && is_tchar(chars[j]) { j += 1; }
                if j == s0 { return Err(bad("empty parameter value")); }
                chars[s0..j].iter().collect()
            };
            let name = word.to_ascii_lowercase();
            let ch = out.last_mut().expect("checked non-empty");
            if ch.params.iter().any(|(k, _)| *k == name) { return Err(bad("repeated parameter")); }
            if ch.params.len() >= MAX_PARAMS { return Err(bad("too many parameters")); }
            ch.params.push((name, value));
            i = j;
        } else {
            out.push(Challenge { scheme: word, params: vec![] });
            i = j;
        }
        if out.len() > 8 { return Err(bad("too many challenges")); }
    }
    Ok(out)
}

/// Challenges from several header fields (a response may carry more than one `WWW-Authenticate`).
pub fn parse_all(headers: &[&str]) -> Result<Vec<Challenge>> {
    let mut v = vec![];
    for h in headers { v.extend(parse_challenges(h)?); }
    Ok(v)
}

/// The Bearer challenge, if any.
pub fn bearer_challenge(challenges: &[Challenge]) -> Option<&Challenge> { challenges.iter().find(|c| c.is_bearer()) }

/// Scope to request first (spec "Scope Selection Strategy"): the 401's `scope` parameter if it has one, else everything in the
/// resource's `scopes_supported`, else none (omit the parameter). A challenged scope is authoritative; no relation to
/// `scopes_supported` is assumed.
pub fn select_scope(challenge: Option<&Challenge>, resource: Option<&ResourceMetadata>) -> Option<Scope> {
    if let Some(s) = challenge.and_then(Challenge::scope).and_then(|s| Scope::parse(s).ok()) { return Some(s); }
    resource.filter(|r| !r.scopes_supported.is_empty()).and_then(|r| Scope::from_tokens(r.scopes_supported.iter().map(String::as_str)).ok())
}

// ---------------------------------------------------------------------------------------------------------------------
// Client flow
// ---------------------------------------------------------------------------------------------------------------------

/// One authorization attempt against one MCP server. Everything it builds carries `resource`.
#[derive(Debug, Clone)]
pub struct Flow<'a> {
    pub as_metadata: &'a AsMetadata,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    /// Canonical URI of the MCP server (from [`canonical_resource`]).
    pub resource: String,
}

impl<'a> Flow<'a> {
    pub fn new(as_metadata: &'a AsMetadata, client_id: &'a str, redirect_uri: &'a str, mcp_url: &str) -> Result<Flow<'a>> {
        require_pkce(as_metadata)?;
        if as_metadata.authorization_endpoint.is_none() || as_metadata.token_endpoint.is_none() { return Err(Error::Malformed("authorization server has no authorization or token endpoint".into())); }
        Ok(Flow { as_metadata, client_id, redirect_uri, resource: canonical_resource(mcp_url)? })
    }

    /// Authorization URL with S256 PKCE, a fresh `state`, and `resource`. Keep the returned verifier and state.
    pub fn start(&self, scope: Option<&Scope>) -> Result<Outgoing> {
        let endpoint = self.as_metadata.authorization_endpoint.as_deref().ok_or_else(|| Error::Malformed("no authorization_endpoint".into()))?;
        let mut b = Builder::new(endpoint, self.client_id, self.redirect_uri);
        b.scope = scope;
        let r = [self.resource.as_str()];
        b.resources = &r;
        b.build()
    }

    /// Checks the redirect and returns the code. When the server says it sends `iss` (RFC 9207), a missing or wrong one is refused.
    pub fn parse_redirect(&self, query: &str, expected_state: &str) -> std::result::Result<String, OAuthError> {
        let iss = if self.as_metadata.authorization_response_iss_parameter_supported { Some(self.as_metadata.issuer.as_str()) } else { None };
        request::parse_response(query, expected_state, iss)
    }

    /// Form body for the token endpoint. The spec requires `resource` here too.
    pub fn token_request(&self, code: &str, code_verifier: &str) -> String {
        form::encode([("grant_type", "authorization_code"), ("code", code), ("redirect_uri", self.redirect_uri), ("client_id", self.client_id),
            ("code_verifier", code_verifier), ("resource", self.resource.as_str())])
    }

    pub fn refresh_request(&self, refresh_token: &str, scope: Option<&Scope>) -> String {
        let s = scope.map(|s| s.to_string());
        let mut p = vec![("grant_type", "refresh_token"), ("refresh_token", refresh_token), ("client_id", self.client_id), ("resource", self.resource.as_str())];
        if let Some(s) = &s { p.push(("scope", s)); }
        form::encode(p)
    }
}

/// Tracks scope upgrade attempts so a client cannot loop forever on `insufficient_scope`.
#[derive(Debug)]
pub struct StepUpTracker {
    pub max_attempts: u32,
    attempts: HashMap<String, u32>,
}

impl StepUpTracker {
    pub fn new(max_attempts: u32) -> Self { StepUpTracker { max_attempts, attempts: HashMap::new() } }

    /// Call with the challenge from a 403. `key` identifies resource plus operation (for example `"<resource> tools/call write_file"`).
    /// Returns the scope to authorize with: what was already granted plus what the server now asks for. Errors when the challenge is
    /// not `insufficient_scope`, when it asks for nothing new, or when the limit for `key` is reached.
    pub fn next_scope(&mut self, key: &str, granted: &Scope, challenge: &Challenge) -> Result<Scope> {
        if challenge.error() != Some("insufficient_scope") { return Err(Error::Claim("not an insufficient_scope challenge".into())); }
        let wanted = Scope::parse(challenge.scope().ok_or_else(|| Error::Claim("insufficient_scope challenge names no scope".into()))?)?;
        let n = self.attempts.entry(key.to_string()).or_insert(0);
        if *n >= self.max_attempts { return Err(Error::Claim("scope upgrade limit reached: treat as a permanent authorization failure".into())); }
        *n += 1;
        let mut all: Vec<&str> = granted.tokens().collect();
        for t in wanted.tokens() { if !all.contains(&t) { all.push(t); } }
        let next = Scope::from_tokens(all)?;
        if next == *granted { return Err(Error::Claim("the server asks for scopes that are already granted".into())); }
        Ok(next)
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Resource server
// ---------------------------------------------------------------------------------------------------------------------

/// A denied request: status code, `WWW-Authenticate` value and the OAuth error. Send all three.
#[derive(Debug, Clone)]
pub struct Denied {
    pub status: u16,
    pub www_authenticate: String,
    pub error: OAuthError,
}

impl Denied {
    pub fn body(&self) -> String { self.error.to_json() }
}

/// Who the token says is calling. Deliberately has no field for the raw token (see the module docs on passthrough).
#[derive(Debug, Clone, PartialEq)]
pub struct Principal {
    pub subject: Option<String>,
    pub client_id: Option<String>,
    pub scope: Scope,
    pub expires_at: Option<u64>,
    pub jti: Option<String>,
    pub cnf: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct ResourceServer {
    /// Canonical URI of this MCP server. Tokens must name it in `aud`.
    pub resource: String,
    /// Issuer identifiers of the authorization servers whose tokens are accepted.
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    /// Signature algorithms accepted on JWT access tokens.
    pub algs: Vec<Algorithm>,
    pub realm: String,
    pub leeway: u64,
    pub resource_name: Option<String>,
    /// Scope to name in 401 challenges (what a client needs to use this server at all).
    pub challenge_scope: Option<Scope>,
    /// Put the scopes the token already has into the 403 challenge as well, so clients do not lose them (recommended).
    pub include_granted_in_challenge: bool,
    metadata_url: String,
}

fn denied(scheme_realm: &str, e: OAuthError, scope: Option<&Scope>, rm: &str) -> Denied {
    let sc = scope.map(|s| s.to_string());
    let code = if e.code == ErrorCode::InvalidRequest && e.description.is_none() { None } else { Some(e.code) };
    let www = bearer::challenge(Scheme::Bearer, scheme_realm, code, e.description.as_deref(), sc.as_deref(), Some(rm));
    Denied { status: e.status(), www_authenticate: www, error: e }
}

impl ResourceServer {
    pub fn new(resource: &str, authorization_servers: &[&str], algs: &[Algorithm]) -> Result<ResourceServer> {
        let resource = canonical_resource(resource)?;
        if authorization_servers.is_empty() { return Err(Error::Malformed("an MCP server must name at least one authorization server".into())); }
        if algs.is_empty() { return Err(Error::Algorithm("list the token signature algorithms you accept".into())); }
        for a in authorization_servers {
            let u = Url::parse(a).map_err(|_| Error::Malformed("authorization server is not a URL".into()))?;
            if u.scheme() != "https" || u.query().is_some() || u.fragment().is_some() { return Err(Error::Malformed("authorization server must be an https issuer identifier".into())); }
        }
        let u = Url::parse(&resource).map_err(|_| Error::Malformed("resource".into()))?;
        let metadata_url = well_known(&u, "oauth-protected-resource");
        Ok(ResourceServer {
            resource, authorization_servers: authorization_servers.iter().map(|s| s.to_string()).collect(), scopes_supported: vec![],
            algs: algs.to_vec(), realm: "mcp".into(), leeway: 30, resource_name: None, challenge_scope: None, include_granted_in_challenge: true, metadata_url,
        })
    }

    /// URL to serve [`ResourceServer::metadata_json`] at, and the value of `resource_metadata` in challenges.
    pub fn metadata_url(&self) -> &str { &self.metadata_url }

    pub fn metadata(&self) -> ResourceMetadata {
        ResourceMetadata {
            resource: self.resource.clone(), authorization_servers: self.authorization_servers.clone(), scopes_supported: self.scopes_supported.clone(),
            bearer_methods_supported: vec!["header".into()], resource_signing_alg_values_supported: vec![], resource_name: self.resource_name.clone(),
            ..Default::default()
        }
    }
    pub fn metadata_json(&self) -> String { self.metadata().to_json() }

    /// 401 for a request without credentials. No `error` code, as RFC 6750 3.1 says, but `resource_metadata` and `scope`.
    pub fn unauthenticated(&self) -> Denied {
        let e = OAuthError::new(ErrorCode::InvalidRequest);
        let mut d = denied(&self.realm, e, self.challenge_scope.as_ref(), &self.metadata_url);
        d.status = 401;
        d
    }

    fn invalid_token(&self, why: &str) -> Denied { denied(&self.realm, OAuthError::with(ErrorCode::InvalidToken, why), self.challenge_scope.as_ref(), &self.metadata_url) }

    fn header_token<'a>(&self, authorization: &[&'a str]) -> std::result::Result<&'a str, Denied> {
        if authorization.is_empty() { return Err(self.unauthenticated()); }
        match bearer::from_headers(authorization) {
            Ok((Scheme::Bearer, t)) => Ok(t),
            Ok((Scheme::DPoP, _)) => Err(self.invalid_token("DPoP-bound tokens are not accepted here")),
            Err(e) if e.code == ErrorCode::InvalidRequest => Err(denied(&self.realm, e, None, &self.metadata_url)),
            Err(_) => Err(self.invalid_token("malformed Authorization header")),
        }
    }

    /// Validates a JWT access token (RFC 9068) for this server. `authorization` is every `Authorization` header value of the request.
    /// `keys(issuer, kid)` returns the verification key for a *trusted* issuer; it is never called for an issuer outside
    /// `authorization_servers`. The token must name this server's canonical URI in `aud` (RFC 8707); tokens meant for anything else are
    /// refused, which is what blocks the confused-deputy attack.
    pub fn authenticate_jwt(&self, authorization: &[&str], keys: &dyn Fn(&str, Option<&str>) -> Option<Jwk>, replay: Option<&dyn ReplayCache>, now: Option<u64>) -> std::result::Result<Principal, Denied> {
        let token = self.header_token(authorization)?;
        let iss = jwt::peek_claims_unverified(token).ok().and_then(|c| c.str_claim("iss").ok().flatten().map(String::from))
            .ok_or_else(|| self.invalid_token("no issuer"))?;
        let trusted = self.authorization_servers.iter().find(|a| crate::crypto::ct_eq(a.as_bytes(), iss.as_bytes())).ok_or_else(|| self.invalid_token("untrusted issuer"))?;
        let kid = crate::jws::peek_header(token).ok().and_then(|h| h.kid);
        let key = keys(trusted, kid.as_deref()).ok_or_else(|| self.invalid_token("no verification key"))?;
        let t = at_jwt::verify(token, &key, &at_jwt::Verify { algs: &self.algs, issuer: trusted, audience: &self.resource, now, leeway: self.leeway, replay })
            .map_err(|e| denied(&self.realm, e, self.challenge_scope.as_ref(), &self.metadata_url))?;
        Ok(Principal { subject: Some(t.subject), client_id: Some(t.client_id), scope: t.scope, expires_at: Some(t.exp), jti: Some(t.jti), cnf: t.claims.map.get("cnf").cloned() })
    }

    /// Same for opaque tokens, through RFC 7662 introspection. `introspect` performs the call to your authorization server.
    /// `active`, expiry, the issuer (when reported) and the audience are all checked here; a response with no `aud` is refused.
    pub fn authenticate_introspection(&self, authorization: &[&str], introspect: &dyn Fn(&str) -> OResult<Introspection>, now: Option<u64>) -> std::result::Result<Principal, Denied> {
        let token = self.header_token(authorization)?;
        let r = introspect(token).map_err(|e| if e.code == ErrorCode::ServerError || e.code == ErrorCode::TemporarilyUnavailable { denied(&self.realm, e, None, &self.metadata_url) } else { self.invalid_token("token rejected") })?;
        let now = now.unwrap_or_else(jwt::unix_now);
        if !r.is_usable(now, self.leeway) { return Err(self.invalid_token("token is not active")); }
        if !r.is_for_audience(&self.resource) { return Err(self.invalid_token("token was not issued for this server")); }
        if let Some(i) = &r.iss { if !self.authorization_servers.iter().any(|a| a == i) { return Err(self.invalid_token("untrusted issuer")); } }
        Ok(Principal { subject: r.sub, client_id: r.client_id, scope: r.scope.unwrap_or_default(), expires_at: r.exp, jti: r.jti, cnf: r.cnf })
    }

    /// 403 `insufficient_scope` unless the token carries every scope in `needed`. The challenge names the scopes the client should
    /// ask for next: the ones the token has plus the missing ones (or only the missing ones with `include_granted_in_challenge = false`).
    pub fn authorize(&self, p: &Principal, needed: &[&str]) -> std::result::Result<(), Denied> {
        let missing: Vec<&str> = needed.iter().copied().filter(|n| !p.scope.contains(n)).collect();
        if missing.is_empty() { return Ok(()); }
        let mut ask: Vec<&str> = if self.include_granted_in_challenge { p.scope.tokens().collect() } else { vec![] };
        for m in missing { if !ask.contains(&m) { ask.push(m); } }
        let scope = Scope::from_tokens(ask).ok();
        let e = OAuthError::with(ErrorCode::InsufficientScope, "the access token lacks a required scope");
        Err(denied(&self.realm, e, scope.as_ref(), &self.metadata_url))
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// SSRF guard for fetching client-supplied URLs (shared module, re-exported here)
// ---------------------------------------------------------------------------------------------------------------------

pub use crate::ssrf::{is_public_ip, ssrf_check};

/// How long to keep a fetched Client ID Metadata Document, in seconds (0: do not store). Errors and `no-store`/`no-cache` are never
/// cached; `max-age` is honoured within [`CACHE_MIN`, `CACHE_MAX`]; with no directive the default is [`CACHE_DEFAULT`].
pub fn cache_lifetime(status: u16, cache_control: Option<&str>) -> u64 {
    if status != 200 { return 0; }
    let mut max_age = None;
    for d in cache_control.unwrap_or("").split(',') {
        let d = d.trim().to_ascii_lowercase();
        if d == "no-store" || d == "no-cache" { return 0; }
        if let Some(v) = d.strip_prefix("max-age=") { max_age = v.trim_matches('"').parse::<u64>().ok(); }
    }
    match max_age { Some(0) => 0, Some(n) => n.clamp(CACHE_MIN, CACHE_MAX), None => CACHE_DEFAULT }
}
pub const CACHE_MIN: u64 = 60;
pub const CACHE_MAX: u64 = 86_400;
pub const CACHE_DEFAULT: u64 = 300;

// ---------------------------------------------------------------------------------------------------------------------
// Client ID Metadata Documents
// ---------------------------------------------------------------------------------------------------------------------

/// Recommended maximum size of the document (draft section 6.6).
pub const CIMD_MAX_BYTES: usize = 5 * 1024;

/// Local policy for accepting a Client ID Metadata Document.
#[derive(Debug, Clone, Default)]
pub struct CimdPolicy {
    /// Accept `http://localhost[:port]/path` redirect URIs (many MCP clients register one). They match exactly, port included.
    /// Loopback IP literals (`127.0.0.1`, `[::1]`) are the safer choice. Registered with a port they match exactly; registered
    /// without one (`http://127.0.0.1/callback`) they get the RFC 8252 7.3 flexible port, which suits clients that bind an ephemeral port.
    pub allow_localhost: bool,
    /// If set, every `https` redirect URI must share the origin of the `client_id`. Native loopback and private-use URIs are exempt.
    pub require_same_origin_redirects: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientIdDocument {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub jwks: Option<Vec<Jwk>>,
    pub jwks_uri: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub scope: Option<Scope>,
    /// Host of the `client_id`. Show it on the consent screen next to the name: it is the one thing the client cannot fake.
    pub display_host: String,
    /// Every redirect URI is on the local machine. Such a client can be impersonated by any local program that copies the
    /// document, so show an extra warning (the spec requires showing the redirect URI host).
    pub localhost_only: bool,
}

/// Validity of a `client_id` URL (draft section 3): https, a path, no dot segments, no fragment, no credentials.
pub fn check_client_id_url(client_id: &str) -> Result<Url> {
    let bad = |m: &str| Error::Malformed(format!("client_id: {m}"));
    if client_id.len() > 2048 || client_id.bytes().any(|b| b <= 0x20 || b == 0x7f) || client_id.contains('\\') { return Err(bad("malformed")); }
    if client_id.contains('#') { return Err(bad("fragment")); }
    let u = Url::parse(client_id).map_err(|_| bad("not a URL"))?;
    if u.scheme() != "https" { return Err(bad("must use https")); }
    if !u.username().is_empty() || u.password().is_some() { return Err(bad("credentials")); }
    if u.host().is_none() { return Err(bad("no host")); }
    if u.path() == "/" || u.path().is_empty() { return Err(bad("must contain a path component")); }
    let after = client_id.split_once("://").map(|(_, r)| r).unwrap_or("");
    let path = after.find('/').map(|i| &after[i..]).unwrap_or("");
    let path = path.split('?').next().unwrap_or("");
    if path.split('/').any(|s| s == "." || s == ".." || s.eq_ignore_ascii_case("%2e") || s.eq_ignore_ascii_case("%2e%2e")) { return Err(bad("dot segments")); }
    Ok(u)
}

fn localhost_redirect(uri: &str) -> bool {
    Url::parse(uri).map(|u| u.scheme() == "http" && u.host_str() == Some("localhost") && u.fragment().is_none() && u.username().is_empty() && u.password().is_none() && !u.path().is_empty() && !uri.contains('\\')).unwrap_or(false)
}

impl ClientIdDocument {
    /// Validates a document fetched from `client_id`. Run [`ssrf_check`] on the URL before fetching and [`cache_lifetime`] after.
    pub fn parse(client_id: &str, body: &str, policy: &CimdPolicy) -> Result<ClientIdDocument> {
        let bad = |m: &str| Error::Malformed(format!("client metadata document: {m}"));
        let cid = check_client_id_url(client_id)?;
        if body.len() > CIMD_MAX_BYTES { return Err(bad("larger than 5 KiB")); }
        let o = crate::json::parse_object(body.as_bytes())?;
        match o.get("client_id").and_then(Value::as_str) {
            Some(s) if s == client_id => {}
            _ => return Err(Error::Claim("client_id in the document does not equal the URL it was fetched from".into())),
        }
        let s = |k: &str| -> Result<Option<String>> { match o.get(k) { None | Some(Value::Null) => Ok(None), Some(Value::String(v)) => Ok(Some(v.clone())), Some(_) => Err(bad(&format!("{k} must be a string"))) } };
        let list = |k: &str| -> Result<Vec<String>> { match o.get(k) {
            None => Ok(vec![]),
            Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| bad(&format!("{k} must hold strings")))).collect(),
            Some(_) => Err(bad(&format!("{k} must be an array"))) } };
        // No shared secrets, ever (draft section 4.1).
        for forbidden in ["client_secret", "client_secret_expires_at"] { if o.contains_key(forbidden) { return Err(bad(&format!("{forbidden} must not be used"))); } }
        let method = s("token_endpoint_auth_method")?.unwrap_or_else(|| "none".into());
        if method != "none" && method != "private_key_jwt" { return Err(bad("token_endpoint_auth_method must be none or private_key_jwt")); }
        let jwks_uri = s("jwks_uri")?;
        let jwks = match o.get("jwks") {
            None => None,
            Some(v) => { let set = crate::jwk::JwkSet::parse(&v.to_string())?; if set.keys.iter().any(Jwk::is_private) { return Err(bad("jwks must hold public keys only")); } Some(set.keys) }
        };
        if method == "private_key_jwt" && jwks.is_none() && jwks_uri.is_none() { return Err(bad("private_key_jwt needs jwks or jwks_uri")); }
        if jwks.is_some() && jwks_uri.is_some() { return Err(bad("jwks and jwks_uri are mutually exclusive")); }
        if let Some(j) = &jwks_uri { ssrf_check(j)?; }
        let client_name = s("client_name")?.filter(|n| !n.trim().is_empty()).ok_or_else(|| bad("client_name is required"))?;
        if client_name.chars().count() > 100 || client_name.chars().any(char::is_control) { return Err(bad("client_name is too long or has control characters")); }
        let grants = list("grant_types")?;
        if grants.iter().any(|g| g != "authorization_code" && g != "refresh_token") { return Err(bad("grant_types may only hold authorization_code and refresh_token")); }
        if list("response_types")?.iter().any(|r| r != "code") { return Err(bad("response_types may only hold code")); }
        let redirect_uris = list("redirect_uris")?;
        if redirect_uris.is_empty() || redirect_uris.len() > 16 { return Err(bad("redirect_uris must hold 1 to 16 URIs")); }
        let mut all_local = true;
        for r in &redirect_uris {
            if policy.allow_localhost && localhost_redirect(r) { continue; }
            let u = redirect::validate_registered(r, ClientKind::Native)?;
            let local = matches!(u.host(), Some(Host::Ipv4(a)) if a.is_loopback()) || matches!(u.host(), Some(Host::Ipv6(a)) if a.is_loopback());
            if u.scheme() == "https" {
                all_local = false;
                if policy.require_same_origin_redirects && u.origin() != cid.origin() { return Err(Error::Claim("redirect URI is not on the origin of client_id".into())); }
            } else if !local { all_local = false; }
        }
        if redirect_uris.iter().any(|r| !localhost_redirect(r) && Url::parse(r).map(|u| u.scheme() == "https").unwrap_or(false)) { all_local = false; }
        let uri_field = |k: &str| -> Result<Option<String>> { match s(k)? { None => Ok(None), Some(v) => { let u = Url::parse(&v).map_err(|_| bad(&format!("{k} is not a URL")))?; if u.scheme() != "https" { return Err(bad(&format!("{k} must be https"))); } Ok(Some(v)) } } };
        let scope = s("scope")?.map(|x| Scope::parse(&x)).transpose()?;
        Ok(ClientIdDocument {
            client_id: client_id.into(), client_name, redirect_uris, token_endpoint_auth_method: method, jwks, jwks_uri,
            client_uri: uri_field("client_uri")?, logo_uri: uri_field("logo_uri")?, scope,
            display_host: cid.host_str().unwrap_or("").to_string(), localhost_only: all_local,
        })
    }

    /// The client as the authorization endpoint sees it. `allowed_scopes` is the server's policy, not the document's claim:
    /// a client must not be able to grant itself scopes by writing them into its own metadata.
    pub fn client_info(&self, allowed_scopes: Scope) -> ClientInfo {
        let https_only = self.redirect_uris.iter().all(|r| r.starts_with("https://"));
        ClientInfo { client_id: self.client_id.clone(), redirect_uris: self.redirect_uris.clone(), kind: if https_only { ClientKind::Web } else { ClientKind::Native }, allowed_scopes, response_types: vec!["code".into()] }
    }

    /// Does the presented redirect URI match? Exact, except the RFC 8252 loopback IP port.
    pub fn redirect_matches(&self, presented: &str) -> bool { self.redirect_uris.iter().any(|r| redirect::matches(r, presented)) }

    /// Fields for a consent screen, already stripped of control characters.
    pub fn consent_summary(&self) -> Value {
        json!({ "name": self.client_name, "host": self.display_host, "client_id": self.client_id, "localhost_only": self.localhost_only,
            "redirect_hosts": self.redirect_uris.iter().filter_map(|r| Url::parse(r).ok().and_then(|u| u.host_str().map(String::from))).collect::<Vec<_>>() })
    }
}

/// Adds `client_id_metadata_document_supported` to authorization server metadata.
pub fn advertise_client_id_metadata(md: &mut AsMetadata) { md.extra.insert("client_id_metadata_document_supported".into(), Value::Bool(true)); }

/// Convenience: JSON object of a scope string for logs.
pub fn describe_principal(p: &Principal) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("sub".into(), json!(p.subject)); m.insert("client_id".into(), json!(p.client_id)); m.insert("scope".into(), json!(p.scope.to_string()));
    m
}
