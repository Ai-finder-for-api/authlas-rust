//! Authorization server metadata (RFC 8414) and protected resource metadata (RFC 9728).
//!
//! The mix-up defence lives here: the `issuer` (or `resource`) inside a fetched document must be identical to the
//! identifier used to build the well-known URL (RFC 8414 3.3, RFC 9728 3.3). A document that names someone else is refused.
use crate::{Error, Result};
use serde_json::{json, Map, Value};
use url::Url;

/// Inserts `/.well-known/<suffix>` between host and path (RFC 8414 3.1; RFC 9728 3.1).
pub fn well_known_url(identifier: &str, suffix: &str) -> Result<String> {
    let u = Url::parse(identifier).map_err(|_| Error::Malformed("identifier is not a URL".into()))?;
    check_identifier(&u)?;
    let path = u.path().trim_end_matches('/');
    let mut out = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
    if let Some(p) = u.port() { out.push_str(&format!(":{p}")); }
    out.push_str(&format!("/.well-known/{suffix}{path}"));
    Ok(out)
}

pub fn as_metadata_url(issuer: &str) -> Result<String> { well_known_url(issuer, "oauth-authorization-server") }
/// OpenID Connect Discovery 1.0 appends instead of inserting.
pub fn oidc_metadata_url(issuer: &str) -> Result<String> {
    let u = Url::parse(issuer).map_err(|_| Error::Malformed("issuer is not a URL".into()))?;
    check_identifier(&u)?;
    Ok(format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/')))
}
pub fn resource_metadata_url(resource: &str) -> Result<String> { well_known_url(resource, "oauth-protected-resource") }

/// https, no query, no fragment (RFC 8414 2: issuer).
fn check_identifier(u: &Url) -> Result<()> {
    if u.scheme() != "https" { return Err(Error::Malformed("identifier must use https".into())); }
    if u.query().is_some() || u.fragment().is_some() { return Err(Error::Malformed("identifier must not have a query or fragment".into())); }
    if u.host_str().is_none() { return Err(Error::Malformed("identifier needs a host".into())); }
    Ok(())
}

fn string_list(o: &Map<String, Value>, k: &str) -> Result<Vec<String>> {
    match o.get(k) {
        None => Ok(vec![]),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| Error::Malformed(format!("{k} entries must be strings")))).collect(),
        Some(_) => Err(Error::Malformed(format!("{k} must be an array of strings"))),
    }
}
fn opt_str(o: &Map<String, Value>, k: &str) -> Result<Option<String>> {
    match o.get(k) { None => Ok(None), Some(Value::String(s)) => Ok(Some(s.clone())), Some(_) => Err(Error::Malformed(format!("{k} must be a string"))) }
}
fn endpoint(o: &Map<String, Value>, k: &str) -> Result<Option<String>> {
    let Some(s) = opt_str(o, k)? else { return Ok(None) };
    let u = Url::parse(&s).map_err(|_| Error::Malformed(format!("{k} is not a URL")))?;
    // RFC 8414 2: endpoints use TLS. Loopback http is the only exception, for local development servers.
    let loopback = matches!(u.host(), Some(url::Host::Ipv4(a)) if a.is_loopback()) || matches!(u.host(), Some(url::Host::Ipv6(a)) if a.is_loopback());
    if u.scheme() != "https" && !(u.scheme() == "http" && loopback) { return Err(Error::Malformed(format!("{k} must use https"))); }
    Ok(Some(s))
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AsMetadata {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub registration_endpoint: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    pub pushed_authorization_request_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub dpop_signing_alg_values_supported: Vec<String>,
    pub authorization_details_types_supported: Vec<String>,
    pub require_pushed_authorization_requests: bool,
    pub authorization_response_iss_parameter_supported: bool,
    pub tls_client_certificate_bound_access_tokens: bool,
    pub extra: Map<String, Value>,
}

const AS_KNOWN: &[&str] = &["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "registration_endpoint", "introspection_endpoint",
    "revocation_endpoint", "device_authorization_endpoint", "pushed_authorization_request_endpoint", "userinfo_endpoint", "scopes_supported",
    "response_types_supported", "grant_types_supported", "token_endpoint_auth_methods_supported", "token_endpoint_auth_signing_alg_values_supported",
    "code_challenge_methods_supported", "dpop_signing_alg_values_supported", "authorization_details_types_supported",
    "require_pushed_authorization_requests", "authorization_response_iss_parameter_supported", "tls_client_certificate_bound_access_tokens"];

fn flag(o: &Map<String, Value>, k: &str) -> Result<bool> {
    match o.get(k) { None => Ok(false), Some(Value::Bool(b)) => Ok(*b), Some(_) => Err(Error::Malformed(format!("{k} must be a boolean"))) }
}

impl AsMetadata {
    /// Parses a fetched document. `expected_issuer` is the identifier the document was fetched for;
    /// anything else in `issuer` is a mix-up attack or a misconfiguration and is refused.
    pub fn parse(body: &str, expected_issuer: &str) -> Result<AsMetadata> {
        let o = crate::json::parse_object(body.as_bytes())?;
        let issuer = opt_str(&o, "issuer")?.ok_or_else(|| Error::Malformed("issuer is missing".into()))?;
        if issuer != expected_issuer { return Err(Error::Claim("issuer in metadata does not match the issuer it was fetched for".into())); }
        check_identifier(&Url::parse(&issuer).map_err(|_| Error::Malformed("issuer is not a URL".into()))?)?;
        let m = AsMetadata {
            issuer,
            authorization_endpoint: endpoint(&o, "authorization_endpoint")?, token_endpoint: endpoint(&o, "token_endpoint")?,
            jwks_uri: endpoint(&o, "jwks_uri")?, registration_endpoint: endpoint(&o, "registration_endpoint")?,
            introspection_endpoint: endpoint(&o, "introspection_endpoint")?, revocation_endpoint: endpoint(&o, "revocation_endpoint")?,
            device_authorization_endpoint: endpoint(&o, "device_authorization_endpoint")?,
            pushed_authorization_request_endpoint: endpoint(&o, "pushed_authorization_request_endpoint")?,
            userinfo_endpoint: endpoint(&o, "userinfo_endpoint")?,
            scopes_supported: string_list(&o, "scopes_supported")?, response_types_supported: string_list(&o, "response_types_supported")?,
            grant_types_supported: string_list(&o, "grant_types_supported")?,
            token_endpoint_auth_methods_supported: string_list(&o, "token_endpoint_auth_methods_supported")?,
            token_endpoint_auth_signing_alg_values_supported: string_list(&o, "token_endpoint_auth_signing_alg_values_supported")?,
            code_challenge_methods_supported: string_list(&o, "code_challenge_methods_supported")?,
            dpop_signing_alg_values_supported: string_list(&o, "dpop_signing_alg_values_supported")?,
            authorization_details_types_supported: string_list(&o, "authorization_details_types_supported")?,
            require_pushed_authorization_requests: flag(&o, "require_pushed_authorization_requests")?,
            authorization_response_iss_parameter_supported: flag(&o, "authorization_response_iss_parameter_supported")?,
            tls_client_certificate_bound_access_tokens: flag(&o, "tls_client_certificate_bound_access_tokens")?,
            extra: o.iter().filter(|(k, _)| !AS_KNOWN.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect(),
        };
        Ok(m)
    }

    pub fn to_json(&self) -> String {
        let mut m = Map::new();
        let s = |m: &mut Map<String, Value>, k: &str, v: &Option<String>| if let Some(v) = v { m.insert(k.into(), json!(v)); };
        let l = |m: &mut Map<String, Value>, k: &str, v: &Vec<String>| if !v.is_empty() { m.insert(k.into(), json!(v)); };
        m.insert("issuer".into(), json!(self.issuer));
        s(&mut m, "authorization_endpoint", &self.authorization_endpoint); s(&mut m, "token_endpoint", &self.token_endpoint);
        s(&mut m, "jwks_uri", &self.jwks_uri); s(&mut m, "registration_endpoint", &self.registration_endpoint);
        s(&mut m, "introspection_endpoint", &self.introspection_endpoint); s(&mut m, "revocation_endpoint", &self.revocation_endpoint);
        s(&mut m, "device_authorization_endpoint", &self.device_authorization_endpoint);
        s(&mut m, "pushed_authorization_request_endpoint", &self.pushed_authorization_request_endpoint);
        s(&mut m, "userinfo_endpoint", &self.userinfo_endpoint);
        l(&mut m, "scopes_supported", &self.scopes_supported); l(&mut m, "response_types_supported", &self.response_types_supported);
        l(&mut m, "grant_types_supported", &self.grant_types_supported);
        l(&mut m, "token_endpoint_auth_methods_supported", &self.token_endpoint_auth_methods_supported);
        l(&mut m, "token_endpoint_auth_signing_alg_values_supported", &self.token_endpoint_auth_signing_alg_values_supported);
        l(&mut m, "code_challenge_methods_supported", &self.code_challenge_methods_supported);
        l(&mut m, "dpop_signing_alg_values_supported", &self.dpop_signing_alg_values_supported);
        l(&mut m, "authorization_details_types_supported", &self.authorization_details_types_supported);
        for (k, b) in [("require_pushed_authorization_requests", self.require_pushed_authorization_requests),
            ("authorization_response_iss_parameter_supported", self.authorization_response_iss_parameter_supported),
            ("tls_client_certificate_bound_access_tokens", self.tls_client_certificate_bound_access_tokens)] { if b { m.insert(k.into(), json!(true)); } }
        for (k, v) in &self.extra { m.entry(k.clone()).or_insert_with(|| v.clone()); }
        Value::Object(m).to_string()
    }

    /// A conservative document for a server built from this library: S256 only, code grant, iss in responses.
    pub fn secure_defaults(issuer: &str, base: &str) -> AsMetadata {
        let base = base.trim_end_matches('/');
        AsMetadata {
            issuer: issuer.into(), authorization_endpoint: Some(format!("{base}/authorize")), token_endpoint: Some(format!("{base}/token")),
            jwks_uri: Some(format!("{base}/jwks")), revocation_endpoint: Some(format!("{base}/revoke")), introspection_endpoint: Some(format!("{base}/introspect")),
            response_types_supported: vec!["code".into()], grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
            code_challenge_methods_supported: vec!["S256".into()], token_endpoint_auth_methods_supported: vec!["client_secret_basic".into(), "private_key_jwt".into(), "none".into()],
            authorization_response_iss_parameter_supported: true, ..Default::default()
        }
    }

    /// For a client about to start a flow: does the server meet the minimum? Returns the reasons it does not.
    pub fn problems_for_code_flow(&self) -> Vec<&'static str> {
        let mut p = vec![];
        if self.authorization_endpoint.is_none() { p.push("no authorization_endpoint"); }
        if self.token_endpoint.is_none() { p.push("no token_endpoint"); }
        if !self.code_challenge_methods_supported.iter().any(|m| m == "S256") { p.push("server does not advertise PKCE S256"); }
        if !self.response_types_supported.is_empty() && !self.response_types_supported.iter().any(|m| m == "code") { p.push("server does not support response_type=code"); }
        p
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub jwks_uri: Option<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
    pub resource_signing_alg_values_supported: Vec<String>,
    pub dpop_signing_alg_values_supported: Vec<String>,
    pub dpop_bound_access_tokens_required: bool,
    pub tls_client_certificate_bound_access_tokens: bool,
    pub resource_name: Option<String>,
    pub resource_documentation: Option<String>,
}

impl ResourceMetadata {
    pub fn parse(body: &str, expected_resource: &str) -> Result<ResourceMetadata> {
        let o = crate::json::parse_object(body.as_bytes())?;
        let resource = opt_str(&o, "resource")?.ok_or_else(|| Error::Malformed("resource is missing".into()))?;
        if resource != expected_resource { return Err(Error::Claim("resource in metadata does not match the resource it was fetched for".into())); }
        let authorization_servers = string_list(&o, "authorization_servers")?;
        for a in &authorization_servers {
            check_identifier(&Url::parse(a).map_err(|_| Error::Malformed("authorization_servers entry is not a URL".into()))?)?;
        }
        let bm = string_list(&o, "bearer_methods_supported")?;
        // RFC 9728 2: header, body and query. We never accept query; a server advertising only that is unusable here.
        if bm.iter().any(|m| !["header", "body", "query"].contains(&m.as_str())) { return Err(Error::Malformed("unknown bearer method".into())); }
        Ok(ResourceMetadata {
            resource, authorization_servers, jwks_uri: endpoint(&o, "jwks_uri")?, scopes_supported: string_list(&o, "scopes_supported")?,
            bearer_methods_supported: bm, resource_signing_alg_values_supported: string_list(&o, "resource_signing_alg_values_supported")?,
            dpop_signing_alg_values_supported: string_list(&o, "dpop_signing_alg_values_supported")?,
            dpop_bound_access_tokens_required: flag(&o, "dpop_bound_access_tokens_required")?,
            tls_client_certificate_bound_access_tokens: flag(&o, "tls_client_certificate_bound_access_tokens")?,
            resource_name: opt_str(&o, "resource_name")?, resource_documentation: endpoint(&o, "resource_documentation")?,
        })
    }

    pub fn to_json(&self) -> String {
        let mut m = Map::new();
        m.insert("resource".into(), json!(self.resource));
        let l = |m: &mut Map<String, Value>, k: &str, v: &Vec<String>| if !v.is_empty() { m.insert(k.into(), json!(v)); };
        l(&mut m, "authorization_servers", &self.authorization_servers); l(&mut m, "scopes_supported", &self.scopes_supported);
        l(&mut m, "bearer_methods_supported", &self.bearer_methods_supported);
        l(&mut m, "resource_signing_alg_values_supported", &self.resource_signing_alg_values_supported);
        l(&mut m, "dpop_signing_alg_values_supported", &self.dpop_signing_alg_values_supported);
        if let Some(j) = &self.jwks_uri { m.insert("jwks_uri".into(), json!(j)); }
        if let Some(n) = &self.resource_name { m.insert("resource_name".into(), json!(n)); }
        if let Some(d) = &self.resource_documentation { m.insert("resource_documentation".into(), json!(d)); }
        if self.dpop_bound_access_tokens_required { m.insert("dpop_bound_access_tokens_required".into(), json!(true)); }
        if self.tls_client_certificate_bound_access_tokens { m.insert("tls_client_certificate_bound_access_tokens".into(), json!(true)); }
        Value::Object(m).to_string()
    }
}

/// Client side, after a 401 with `resource_metadata="..."` in WWW-Authenticate (RFC 9728 5.1): pull that URL out.
/// The URL is only a hint where to look; the caller must still check the document's `resource` against the URL it called.
pub fn resource_metadata_from_challenge(www_authenticate: &str) -> Option<String> {
    let idx = www_authenticate.find("resource_metadata=\"")? + "resource_metadata=\"".len();
    let rest = &www_authenticate[idx..];
    let end = rest.find('"')?;
    let url = &rest[..end];
    Url::parse(url).ok().filter(|u| u.scheme() == "https").map(|_| url.to_string())
}
