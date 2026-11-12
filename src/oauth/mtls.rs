//! OAuth 2.0 mutual-TLS client authentication and certificate-bound access tokens (RFC 8705).
//!
//! The TLS stack does the handshake: it validates the chain (PKI method) and proves the client holds the private key. This module
//! decides what the certificate means for OAuth:
//! * which client it authenticates (`tls_client_auth`, `self_signed_tls_client_auth`);
//! * the `cnf` / `x5t#S256` confirmation that binds an access token to it;
//! * whether a presented token is bound to the certificate on this connection;
//! * the `mtls_endpoint_aliases` a client must use (RFC 8705 5).
//!
//! Safety rules enforced here:
//! * a request may carry only one client authentication method (RFC 6749 2.3), so mTLS plus a secret or assertion is refused;
//! * PKI method: exactly one expected subject value is registered (RFC 8705 2.1.2), compared exactly, and a client with no
//!   registered value never authenticates;
//! * self-signed method: the certificate's public key must equal a registered key, compared by JWK thumbprint (RFC 8705 2.2);
//! * a certificate outside its validity period is refused;
//! * the certificate thumbprint comparison is constant time.
use super::error::{ErrorCode, OAuthError, OResult};
use super::form::Params;
use super::metadata::AsMetadata;
use crate::{crypto, jwa::Hash, jwk::Jwk, jwt::{unix_now, Claims}, x509::{Certificate, San}};
use serde_json::{json, Value};

pub const TLS_CLIENT_AUTH: &str = "tls_client_auth";
pub const SELF_SIGNED_TLS_CLIENT_AUTH: &str = "self_signed_tls_client_auth";

/// What a `tls_client_auth` client registered (RFC 8705 2.1.2). Exactly one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedSubject {
    /// RFC 4514 string of the subject DN. Compared exactly against the rendering of the certificate's subject.
    SubjectDn(String),
    SanDns(String),
    SanUri(String),
    SanIp(std::net::IpAddr),
    SanEmail(String),
}

impl ExpectedSubject {
    /// Builds from the five registration metadata members. Exactly one must be set.
    pub fn from_metadata(dn: Option<&str>, dns: Option<&str>, uri: Option<&str>, ip: Option<&str>, email: Option<&str>) -> Result<Self, OAuthError> {
        let bad = |m: &str| OAuthError::with(ErrorCode::InvalidClientMetadata, m);
        let count = [dn, dns, uri, ip, email].iter().filter(|x| x.is_some()).count();
        if count != 1 { return Err(bad("tls_client_auth needs exactly one tls_client_auth_* subject member")); }
        if let Some(v) = dn { return nonempty(v).map(|v| ExpectedSubject::SubjectDn(v.into())); }
        if let Some(v) = dns { return nonempty(v).map(|v| ExpectedSubject::SanDns(v.into())); }
        if let Some(v) = uri { return nonempty(v).map(|v| ExpectedSubject::SanUri(v.into())); }
        if let Some(v) = email { return nonempty(v).map(|v| ExpectedSubject::SanEmail(v.into())); }
        let v = ip.unwrap();
        v.parse().map(ExpectedSubject::SanIp).map_err(|_| bad("tls_client_auth_san_ip is not an IP address"))
    }

    fn matches(&self, cert: &Certificate) -> bool {
        match self {
            ExpectedSubject::SubjectDn(dn) => crypto::ct_eq(cert.subject_rfc4514.as_bytes(), dn.as_bytes()),
            ExpectedSubject::SanDns(d) => cert.sans.iter().any(|s| matches!(s, San::Dns(x) if x.eq_ignore_ascii_case(d))),
            ExpectedSubject::SanUri(u) => cert.sans.iter().any(|s| matches!(s, San::Uri(x) if x == u)),
            ExpectedSubject::SanIp(ip) => cert.sans.iter().any(|s| matches!(s, San::Ip(x) if x == ip)),
            ExpectedSubject::SanEmail(e) => cert.sans.iter().any(|s| matches!(s, San::Email(x) if email_eq(x, e))),
        }
    }
}

fn nonempty(v: &str) -> Result<&str, OAuthError> {
    if v.is_empty() { Err(OAuthError::with(ErrorCode::InvalidClientMetadata, "empty tls_client_auth subject value")) } else { Ok(v) }
}

/// Local part exact, domain case-insensitive (RFC 5321 2.4).
fn email_eq(a: &str, b: &str) -> bool {
    match (a.rsplit_once('@'), b.rsplit_once('@')) {
        (Some((la, da)), Some((lb, db))) => la == lb && da.eq_ignore_ascii_case(db),
        _ => false,
    }
}

/// How the client registered for mTLS.
#[derive(Debug, Clone)]
pub enum Registration {
    /// PKI: the TLS layer verified the chain against trusted CAs; the subject must be the registered one.
    Pki { client_id: String, expected: ExpectedSubject },
    /// Self-signed: the certificate's key must be one of the client's registered keys.
    SelfSigned { client_id: String, keys: Vec<Jwk> },
}

impl Registration {
    pub fn client_id(&self) -> &str { match self { Registration::Pki { client_id, .. } | Registration::SelfSigned { client_id, .. } => client_id } }
    pub fn method(&self) -> &'static str { match self { Registration::Pki { .. } => TLS_CLIENT_AUTH, Registration::SelfSigned { .. } => SELF_SIGNED_TLS_CLIENT_AUTH } }
}

/// Authenticates a token-endpoint style request (RFC 8705 2). `chain_verified` must be true only when the TLS stack
/// validated the client certificate chain; the PKI method refuses to proceed without it.
pub fn authenticate(cert: &Certificate, chain_verified: bool, authorization: Option<&str>, body: &Params, reg: &Registration, now: Option<u64>) -> OResult<String> {
    let denied = || OAuthError::invalid_client("client authentication failed");
    // One method only. A secret, assertion or Basic header next to a certificate is a malformed or hostile request.
    if authorization.is_some() || body.contains("client_secret") || body.contains("client_assertion") || body.contains("client_assertion_type") {
        return Err(OAuthError::invalid_request("more than one client authentication method used"));
    }
    // RFC 8705 2: the client identifies itself with client_id in the body, since there is no secret to carry it.
    let id = body.get("client_id").map_err(|_| OAuthError::invalid_request("client_id repeated"))?
        .ok_or_else(|| OAuthError::invalid_request("client_id is required with mutual-TLS client authentication"))?;
    let now = now.unwrap_or_else(unix_now);
    let valid = cert.valid_at(now);
    let matched = match reg {
        Registration::Pki { expected, .. } => chain_verified && expected.matches(cert),
        Registration::SelfSigned { keys, .. } => {
            // A self-signed client is authenticated by key equality, never by chain validation.
            match cert.public_jwk().and_then(|k| k.thumbprint(Hash::Sha256)) {
                Ok(t) => keys.iter().fold(false, |acc, k| acc | k.thumbprint(Hash::Sha256).map_or(false, |r| crypto::ct_eq(r.as_bytes(), t.as_bytes()))),
                Err(_) => false,
            }
        }
    };
    let id_ok = crypto::ct_eq(id.as_bytes(), reg.client_id().as_bytes());
    if valid & matched & id_ok { Ok(reg.client_id().to_string()) } else { Err(denied()) }
}

// ---------- certificate-bound tokens ----------

/// `cnf` member to place in an access token or introspection response (RFC 8705 3.1, 3.2).
pub fn cnf_for(cert: &Certificate) -> crate::Result<Value> { Ok(json!({ "x5t#S256": cert.x5t_s256()? })) }

/// Resource server (RFC 8705 3): the token's confirmation must equal the thumbprint of the certificate used on this connection.
/// A token with no `x5t#S256` is not certificate-bound and is refused here.
pub fn check_binding(token: &Claims, cert: &Certificate) -> OResult<()> {
    let denied = || OAuthError::with(ErrorCode::InvalidToken, "access token is not bound to this client certificate");
    let cnf = token.cnf().map_err(|_| denied())?.ok_or_else(denied)?;
    let t = cert.x5t_s256().map_err(|_| denied())?;
    if cnf.matches_x5t_s256(&t) { Ok(()) } else { Err(denied()) }
}

/// Authorization server, at the token endpoint for a refresh token or code issued to a certificate-bound client (RFC 8705 7.1):
/// the certificate must be the same one the grant was issued against.
pub fn same_certificate(bound_thumbprint: &str, cert: &Certificate) -> bool {
    cert.x5t_s256().map_or(false, |t| crypto::ct_eq(t.as_bytes(), bound_thumbprint.as_bytes()))
}

// ---------- metadata (RFC 8705 5) ----------

/// The endpoint a client must call. When `use_aliases` is true the `mtls_endpoint_aliases` entry is required to exist: silently
/// falling back to the non-mTLS endpoint would send a certificate-bound request over a channel without the certificate.
pub fn endpoint(meta: &AsMetadata, name: &str, use_aliases: bool) -> OResult<String> {
    let plain = || -> Option<String> {
        match name {
            "token_endpoint" => meta.token_endpoint.clone(),
            "authorization_endpoint" => meta.authorization_endpoint.clone(),
            "revocation_endpoint" => meta.revocation_endpoint.clone(),
            "introspection_endpoint" => meta.introspection_endpoint.clone(),
            "device_authorization_endpoint" => meta.device_authorization_endpoint.clone(),
            "pushed_authorization_request_endpoint" => meta.pushed_authorization_request_endpoint.clone(),
            "userinfo_endpoint" => meta.userinfo_endpoint.clone(),
            "registration_endpoint" => meta.registration_endpoint.clone(),
            _ => None,
        }
    };
    let missing = || OAuthError::with(ErrorCode::InvalidRequest, "endpoint is not advertised by the server");
    if !use_aliases { return plain().ok_or_else(missing); }
    let aliases = meta.extra.get("mtls_endpoint_aliases").and_then(Value::as_object).ok_or_else(missing)?;
    let url = aliases.get(name).and_then(Value::as_str).ok_or_else(missing)?;
    let u = url::Url::parse(url).map_err(|_| missing())?;
    if u.scheme() != "https" || u.fragment().is_some() { return Err(missing()); }
    Ok(url.to_string())
}

/// Sets `mtls_endpoint_aliases` and the bound-token flag on server metadata.
pub fn advertise(meta: &mut AsMetadata, aliases: &[(&str, &str)]) {
    meta.tls_client_certificate_bound_access_tokens = true;
    let mut o = serde_json::Map::new();
    for (k, v) in aliases { o.insert((*k).to_string(), Value::String((*v).to_string())); }
    meta.extra.insert("mtls_endpoint_aliases".into(), Value::Object(o));
    for m in [TLS_CLIENT_AUTH, SELF_SIGNED_TLS_CLIENT_AUTH] {
        if !meta.token_endpoint_auth_methods_supported.iter().any(|x| x == m) { meta.token_endpoint_auth_methods_supported.push(m.into()); }
    }
}
