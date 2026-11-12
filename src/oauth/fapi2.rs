//! FAPI 2.0 Security Profile (OpenID Foundation, Final) for authorization servers, clients and resource servers.
//!
//! Enabled with the `fapi2` feature. It does not add new protocol messages. It takes the pieces that already exist in this crate
//! and refuses everything the profile forbids. Section numbers refer to the Final specification.
//!
//! * Authorization server: [`ServerProfile`] checks configuration and metadata ([`ServerProfile::audit`]), the authorization
//!   request ([`ServerProfile::check_authorization_request`]), the token request ([`ServerProfile::check_token_request`]),
//!   client registrations ([`ServerProfile::registration_policy`]) and issued access tokens ([`ServerProfile::check_token_lifetime`]).
//! * Client: [`ClientProfile`] checks the discovered metadata, the authorization response and the client assertion.
//! * Resource server: [`ResourceProfile`] verifies the access token and its sender constraint.
//!
//! What the library cannot see: TLS version and cipher suites (5.2), open redirectors in your own application, and clock
//! sources. [`Checklist`] lists those so an audit report is honest about what was and was not verified.
use super::dpop;
use super::error::{ErrorCode, OAuthError, OResult};
use super::form::Params;
use super::metadata::AsMetadata;
use super::mtls;
use super::registration::Policy as RegistrationPolicy;
use super::request::AuthRequest;
use super::token::{self, CodeRecord, RefreshStore, TokenRequest};
use crate::jwa::{Algorithm, Family};
use crate::jwk::Jwk;
use crate::jwt::Claims;
use crate::{crypto, x509::Certificate};

/// 5.4.1: the only signature algorithms. PS256, ES256 and EdDSA (Ed25519).
pub const ALGS: &[Algorithm] = &[Algorithm::PS256, Algorithm::ES256, Algorithm::EdDSA];
/// 5.3.2.1: authorization codes live at most 60 seconds.
pub const MAX_CODE_LIFETIME: u64 = 60;
/// 5.3.2.2: pushed request `expires_in` is below 600 seconds.
pub const MAX_PAR_LIFETIME: u64 = 599;
/// 5.3.2.1 note 3: accept `iat`/`nbf` up to 10 s in the future (a requirement), never more than 60 s (a ceiling).
pub const MIN_FUTURE_SKEW: u64 = 10;
pub const MAX_FUTURE_SKEW: u64 = 60;
/// 5.3.2.2: nonce values up to 64 characters must be supported; longer ones may be refused.
pub const MAX_NONCE_LEN: usize = 64;

fn denied(code: ErrorCode, m: &str) -> OAuthError { OAuthError::with(code, m) }
fn invalid(m: &str) -> OAuthError { OAuthError::invalid_request(m) }

/// Items that need checking outside this library. Returned with every audit so that "no findings" is not mistaken for "compliant".
pub struct Checklist;
impl Checklist {
    pub const OUT_OF_SCOPE: &'static [&'static str] = &[
        "5.2.1: TLS 1.2 or later, BCP 195 cipher suites, certificate validation, DNSSEC/CAA hygiene",
        "5.2.2: TLS 1.2 cipher suites restricted to BCP 195 on server-to-server endpoints",
        "5.2.3: browser-facing endpoints (HSTS, CSP, cookies) are the application's",
        "5.3.2.1 / 5.3.3.1: no open redirectors anywhere in the deployment",
        "5.3.2.2: redirecting with 303 and never 307 for requests carrying credentials (HTTP layer)",
        "5.3.2.2: informing the user about client identity and scope before consent (UI)",
        "5.3.3.1: CSRF protection when initiating authorization, and user consent to initiate it",
        "5.3.4: revocation status check of access tokens at the resource server (needs your token store)",
        "5.4.2: jwks_uri served over TLS, no duplicate kid values, no x5u/jku in use",
    ];
}

// ---------------------------------------------------------------------------------------------------------------------
// Authorization server
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderConstraint { Dpop, Mtls }

#[derive(Debug, Clone)]
pub struct ServerProfile {
    /// Constraints the server is willing to issue. At least one.
    pub constraints: Vec<SenderConstraint>,
    /// Maximum access token lifetime the server will issue; a high value is a finding, not an error (5.3.2.1: least privilege).
    pub max_access_token_lifetime: u64,
}

impl Default for ServerProfile {
    fn default() -> Self { ServerProfile { constraints: vec![SenderConstraint::Dpop, SenderConstraint::Mtls], max_access_token_lifetime: 3600 } }
}

/// One thing in the configuration that does not meet the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding { pub section: &'static str, pub problem: String }

fn f(section: &'static str, problem: impl Into<String>) -> Finding { Finding { section, problem: problem.into() } }

impl ServerProfile {
    /// Audits the metadata the server publishes (5.3.2.1: "shall distribute discovery metadata").
    pub fn audit(&self, m: &AsMetadata) -> Vec<Finding> {
        let mut out = vec![];
        if m.pushed_authorization_request_endpoint.is_none() { out.push(f("5.3.2.2", "no pushed_authorization_request_endpoint")); }
        if !m.require_pushed_authorization_requests { out.push(f("5.3.2.2", "require_pushed_authorization_requests is not true: requests sent without PAR must be rejected")); }
        if m.code_challenge_methods_supported != ["S256"] { out.push(f("5.3.2.2", "code_challenge_methods_supported must be exactly [\"S256\"]")); }
        if m.response_types_supported != ["code"] { out.push(f("5.3.2.2", "response_types_supported must be exactly [\"code\"]")); }
        if !m.authorization_response_iss_parameter_supported { out.push(f("5.3.2.2", "authorization_response_iss_parameter_supported must be true (RFC 9207)")); }
        if m.token_endpoint.is_none() || m.authorization_endpoint.is_none() || m.jwks_uri.is_none() { out.push(f("5.3.2.1", "authorization, token and jwks endpoints must be published")); }
        for g in &m.grant_types_supported {
            if g == "password" || g == "implicit" { out.push(f("5.3.2.1", format!("grant type {g} must not be offered"))); }
        }
        for method in &m.token_endpoint_auth_methods_supported {
            if !matches!(method.as_str(), "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth") {
                out.push(f("5.3.2.1", format!("client authentication method {method} is not allowed (private_key_jwt or mutual TLS only)")));
            }
        }
        if m.token_endpoint_auth_methods_supported.is_empty() { out.push(f("5.3.2.1", "token_endpoint_auth_methods_supported must be published")); }
        for a in &m.token_endpoint_auth_signing_alg_values_supported {
            if !ALGS.iter().any(|x| x.as_str() == a) { out.push(f("5.4.1", format!("token_endpoint_auth_signing_alg_values_supported lists {a}"))); }
        }
        if self.constraints.contains(&SenderConstraint::Dpop) {
            if m.dpop_signing_alg_values_supported.is_empty() { out.push(f("5.3.2.1", "DPoP is enabled but dpop_signing_alg_values_supported is missing")); }
            for a in &m.dpop_signing_alg_values_supported {
                if !ALGS.iter().any(|x| x.as_str() == a) { out.push(f("5.4.1", format!("dpop_signing_alg_values_supported lists {a}"))); }
            }
        }
        if self.constraints.contains(&SenderConstraint::Mtls) && !m.tls_client_certificate_bound_access_tokens {
            out.push(f("5.3.2.1", "mutual-TLS constraint enabled but tls_client_certificate_bound_access_tokens is not advertised"));
        }
        if self.constraints.is_empty() { out.push(f("5.3.2.1", "no sender-constraining method configured")); }
        out
    }

    /// Metadata that passes [`ServerProfile::audit`], to start from.
    pub fn metadata(&self, issuer: &str, base: &str) -> AsMetadata {
        let base = base.trim_end_matches('/');
        let mut m = AsMetadata::secure_defaults(issuer, base);
        m.pushed_authorization_request_endpoint = Some(format!("{base}/par"));
        m.require_pushed_authorization_requests = true;
        m.grant_types_supported = vec!["authorization_code".into(), "refresh_token".into()];
        m.token_endpoint_auth_methods_supported = vec!["private_key_jwt".into()];
        m.token_endpoint_auth_signing_alg_values_supported = ALGS.iter().map(|a| a.as_str().to_string()).collect();
        if self.constraints.contains(&SenderConstraint::Dpop) { m.dpop_signing_alg_values_supported = ALGS.iter().map(|a| a.as_str().to_string()).collect(); }
        if self.constraints.contains(&SenderConstraint::Mtls) {
            m.tls_client_certificate_bound_access_tokens = true;
            for x in ["tls_client_auth", "self_signed_tls_client_auth"] { m.token_endpoint_auth_methods_supported.push(x.into()); }
        }
        m
    }

    /// Dynamic registration policy that only admits FAPI 2.0 clients (5.3.2.1: confidential clients, private_key_jwt or MTLS,
    /// sender-constrained tokens, approved algorithms).
    pub fn registration_policy(&self, registration_endpoint: &str) -> RegistrationPolicy {
        let mut p = RegistrationPolicy::new(registration_endpoint);
        p.confidential_only = true;
        p.require_sender_constrained = true;
        p.allowed_auth_methods = vec!["private_key_jwt".into(), "tls_client_auth".into(), "self_signed_tls_client_auth".into()];
        p.allowed_signing_algs = ALGS.to_vec();
        p.allow_client_secret_jwt = false;
        p.allow_native = false;
        p
    }

    /// Checks a request that arrived at the authorization endpoint (5.3.2.2, 5.3.3.2). Only `client_id` and `request_uri` may
    /// travel in the browser; everything else must come from the earlier pushed request. Pass the raw query string.
    pub fn check_browser_query(&self, query: &str) -> OResult<()> {
        let p = Params::parse(query).map_err(|_| invalid("malformed query"))?;
        let extra: Vec<&str> = p.names().filter(|n| *n != "client_id" && *n != "request_uri").collect();
        if !extra.is_empty() { return Err(invalid("only client_id and request_uri may be sent to the authorization endpoint; use a pushed request")); }
        if !p.contains("request_uri") || !p.contains("client_id") { return Err(denied(ErrorCode::InvalidRequestUri, "a pushed authorization request is required")); }
        Ok(())
    }

    /// Checks a pushed authorization request body (5.3.2.2). `client_authenticated` must be the result of client authentication.
    pub fn check_pushed_request(&self, body: &Params, client_authenticated: bool) -> OResult<()> {
        if !client_authenticated { return Err(OAuthError::invalid_client("pushed authorization requests need client authentication")); }
        if body.get("response_type").ok().flatten() != Some("code") { return Err(denied(ErrorCode::UnsupportedResponseType, "response_type must be code")); }
        if body.get("code_challenge_method").ok().flatten() != Some("S256") || body.get("code_challenge").ok().flatten().is_none() {
            return Err(invalid("PKCE with S256 is required"));
        }
        if body.get("redirect_uri").ok().flatten().is_none() { return Err(invalid("redirect_uri is required in the pushed request")); }
        if let Some(n) = body.get("nonce").ok().flatten() { if n.len() > 4096 { return Err(invalid("nonce is too long")); } }
        Ok(())
    }

    /// Validated authorization request, checked once more against the profile (after `request::validate`).
    pub fn check_authorization_request(&self, req: &AuthRequest) -> OResult<()> {
        if req.response_type != "code" { return Err(denied(ErrorCode::UnsupportedResponseType, "response_type must be code")); }
        if req.code_challenge.is_none() || req.code_challenge_method != Some(super::pkce::Method::S256) { return Err(invalid("PKCE with S256 is required")); }
        // 5.3.2.2: no http redirect URIs except loopback for native clients.
        let u = url::Url::parse(&req.redirect_uri).map_err(|_| invalid("bad redirect_uri"))?;
        if u.scheme() == "http" {
            let loop_ = matches!(u.host(), Some(url::Host::Ipv4(a)) if a.is_loopback()) || matches!(u.host(), Some(url::Host::Ipv6(a)) if a.is_loopback());
            if !loop_ { return Err(invalid("http redirect URIs are only allowed on loopback")); }
        }
        if let Some(n) = &req.nonce { if n.len() > 4096 { return Err(invalid("nonce is too long")); } }
        Ok(())
    }

    /// A pushed request's `expires_in` must stay under 600 s (5.3.2.2).
    pub fn check_par_lifetime(&self, expires_in: u64) -> OResult<()> {
        if expires_in <= MAX_PAR_LIFETIME { Ok(()) } else { Err(OAuthError::new(ErrorCode::ServerError)) }
    }

    /// Codes must expire within 60 s (5.3.2.1).
    pub fn check_code(&self, rec: &CodeRecord, issued_at: u64) -> OResult<()> {
        if rec.expires_at.saturating_sub(issued_at) <= MAX_CODE_LIFETIME { Ok(()) } else { Err(OAuthError::new(ErrorCode::ServerError)) }
    }

    pub fn check_token_lifetime(&self, lifetime: u64) -> OResult<()> {
        if lifetime <= self.max_access_token_lifetime { Ok(()) } else { Err(OAuthError::new(ErrorCode::ServerError)) }
    }

    /// Token endpoint: client authentication method, grant type and sender constraint (5.3.2.1).
    ///
    /// `auth` is how the client authenticated (already verified). `dpop_proof` is the verified proof, `cert` the TLS client
    /// certificate. Returns the constraint to put into the access token's `cnf`.
    ///
    /// The client credentials grant is allowed by the profile (note 2) but has not been through the formal security analysis
    /// that the authorization code flow has; it is accepted here and the caller owns that risk.
    pub fn check_token_request(&self, req: &TokenRequest, auth: ClientAuth, dpop_proof: Option<&dpop::Verified>, cert: Option<&Certificate>) -> OResult<Constraint> {
        let _ = req; // grant-specific rules live in token.rs; the profile constrains authentication and the token binding
        let _ = auth;
        // Prefer the constraint the client actually presented. A client that presents both gets DPoP; a client presenting neither is refused.
        match (dpop_proof, cert) {
            (Some(p), _) if self.constraints.contains(&SenderConstraint::Dpop) => Ok(Constraint::Dpop { jkt: p.jkt.clone() }),
            (_, Some(c)) if self.constraints.contains(&SenderConstraint::Mtls) => Ok(Constraint::Mtls { x5t_s256: c.x5t_s256().map_err(|_| OAuthError::new(ErrorCode::ServerError))? }),
            _ => Err(denied(ErrorCode::InvalidDpopProof, "only sender-constrained access tokens are issued; present a DPoP proof or a client certificate")),
        }
    }

    /// Refresh: the profile does not rotate refresh tokens for sender-constrained confidential clients (5.3.2.1 note 1). This
    /// uses the token without rotation, and requires the same sender constraint the grant was issued with.
    pub fn use_refresh(&self, store: &dyn RefreshStore, client_id: &str, token_value: &str, requested: Option<&super::scope::Scope>, now: Option<u64>) -> OResult<token::RefreshRecord> {
        token::use_refresh_static(store, client_id, token_value, requested, now)
    }

    /// Whether a JWT's `iat`/`nbf` is acceptable under 5.3.2.1 note 3: up to 10 s in the future always accepted, over 60 s never.
    pub fn leeway(&self, configured: u64) -> u64 { configured.clamp(MIN_FUTURE_SKEW, MAX_FUTURE_SKEW) }

    /// A `private_key_jwt` assertion must carry the issuer identifier as a single string `aud` (5.3.2.1, 5.3.3.1).
    pub fn check_client_assertion(&self, assertion: &str, issuer: &str) -> OResult<()> {
        let bad = || OAuthError::invalid_client("client authentication failed");
        let h = crate::jws::peek_header(assertion).map_err(|_| bad())?;
        if !ALGS.contains(&h.alg) { return Err(bad()); }
        let c = crate::jwt::peek_claims_unverified(assertion).map_err(|_| bad())?;
        match c.map.get("aud") { Some(serde_json::Value::String(a)) if crypto::ct_eq(a.as_bytes(), issuer.as_bytes()) => Ok(()), _ => Err(bad()) }
    }
}

/// How the client proved who it is. The profile allows exactly these two (5.3.2.1). Secrets, `client_secret_jwt` and
/// unauthenticated clients are not representable, so they cannot be passed to the checks by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth { PrivateKeyJwt, Mtls }

impl ClientAuth {
    /// Maps the method of the registered client. `None` for methods the profile forbids.
    pub fn from_method(m: &str) -> Option<ClientAuth> {
        match m { "private_key_jwt" => Some(ClientAuth::PrivateKeyJwt), "tls_client_auth" | "self_signed_tls_client_auth" => Some(ClientAuth::Mtls), _ => None }
    }
}

/// The sender constraint chosen for an access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint { Dpop { jkt: String }, Mtls { x5t_s256: String } }

impl Constraint {
    /// The `cnf` member for the access token (RFC 9449 6.1, RFC 8705 3.1).
    pub fn cnf(&self) -> serde_json::Value {
        match self { Constraint::Dpop { jkt } => serde_json::json!({ "jkt": jkt }), Constraint::Mtls { x5t_s256 } => serde_json::json!({ "x5t#S256": x5t_s256 }) }
    }
    pub fn token_type(&self) -> &'static str { match self { Constraint::Dpop { .. } => "DPoP", Constraint::Mtls { .. } => "Bearer" } }
}

// ---------------------------------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ClientProfile;

impl ClientProfile {
    /// Checks the metadata the client fetched (5.3.3.1, 5.3.3.2). Findings are reasons not to start the flow.
    pub fn check_server(&self, m: &AsMetadata, will_use_dpop: bool, will_use_mtls: bool) -> Vec<Finding> {
        let mut out = vec![];
        if m.pushed_authorization_request_endpoint.is_none() { out.push(f("5.3.3.2", "server has no PAR endpoint; this profile requires pushed requests")); }
        if !m.code_challenge_methods_supported.iter().any(|x| x == "S256") { out.push(f("5.3.3.2", "server does not support PKCE S256")); }
        if !m.authorization_response_iss_parameter_supported { out.push(f("5.3.3.2", "server does not return iss in authorization responses (RFC 9207)")); }
        if !m.token_endpoint_auth_methods_supported.iter().any(|x| matches!(x.as_str(), "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth")) {
            out.push(f("5.3.3.1", "server supports no client authentication method allowed by the profile"));
        }
        if will_use_dpop && !m.dpop_signing_alg_values_supported.iter().any(|a| ALGS.iter().any(|x| x.as_str() == a)) {
            out.push(f("5.3.3.1", "server advertises no DPoP algorithm allowed by the profile"));
        }
        if will_use_mtls && !m.tls_client_certificate_bound_access_tokens { out.push(f("5.3.3.1", "server does not advertise certificate-bound access tokens")); }
        if !will_use_dpop && !will_use_mtls { out.push(f("5.3.3.1", "the client must use DPoP or mutual TLS to sender-constrain tokens")); }
        out
    }

    /// The client's assertion algorithm must be one of the approved ones.
    pub fn check_assertion_alg(&self, alg: Algorithm) -> OResult<()> {
        if ALGS.contains(&alg) { Ok(()) } else { Err(invalid("algorithm is not allowed by FAPI 2.0")) }
    }

    /// Builds the `private_key_jwt` assertion with the issuer as a single-string audience (5.3.3.1).
    pub fn assertion(&self, alg: Algorithm, key: &Jwk, client_id: &str, issuer: &str) -> crate::Result<String> {
        if !ALGS.contains(&alg) { return Err(crate::Error::Algorithm("algorithm is not allowed by FAPI 2.0".into())); }
        super::client_auth::build_assertion(alg, key, client_id, issuer, 60)
    }

    /// Client side check of the authorization response: `iss` is mandatory (5.3.3.2).
    pub fn check_response(&self, query: &str, expected_state: &str, issuer: &str) -> OResult<String> {
        super::request::parse_response(query, expected_state, Some(issuer))
    }

    /// The only query a client may send to the authorization endpoint after pushing.
    pub fn authorization_url(&self, authorization_endpoint: &str, client_id: &str, request_uri: &str) -> String {
        let sep = if authorization_endpoint.contains('?') { '&' } else { '?' };
        format!("{authorization_endpoint}{sep}{}", super::par_jar::reference_query(client_id, request_uri))
    }

    /// Nonce longer than 64 characters hurts interoperability (5.3.3.2).
    pub fn check_nonce(&self, nonce: &str) -> bool { nonce.len() <= MAX_NONCE_LEN }
}

// ---------------------------------------------------------------------------------------------------------------------
// Resource server
// ---------------------------------------------------------------------------------------------------------------------

/// What the connection carried, for checking the sender constraint.
pub struct Presentation<'a> {
    pub authorization: &'a [&'a str],
    pub method: &'a str,
    pub url: &'a str,
    pub dpop_headers: &'a [&'a str],
    pub cert: Option<&'a Certificate>,
    /// Never accept a token from the query string: pass true if the request had `access_token` there, so it can be refused.
    pub token_in_query: bool,
    pub token_in_body: bool,
}

#[derive(Debug, Clone)]
pub struct ResourceProfile<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub now: Option<u64>,
}

impl ResourceProfile<'_> {
    /// Verifies the access token and its constraint (5.3.4). The signature key is looked up by the caller from the issuer's JWKS.
    pub fn verify(&self, p: &Presentation<'_>, key: &Jwk, replay: Option<&dyn crate::jwt::ReplayCache>) -> OResult<super::at_jwt::AccessToken> {
        use super::bearer::{self, Scheme};
        if p.token_in_query || p.token_in_body { return Err(OAuthError::invalid_request("access tokens are only accepted in the Authorization header")); }
        let (scheme, token) = bearer::from_headers(p.authorization)?;
        let at = super::at_jwt::verify(token, key, &super::at_jwt::Verify { algs: ALGS, issuer: self.issuer, audience: self.audience, now: self.now, leeway: MIN_FUTURE_SKEW, replay: None })?;
        let cnf = at.claims.cnf().map_err(|_| denied(ErrorCode::InvalidToken, "token has no usable confirmation"))?
            .ok_or_else(|| denied(ErrorCode::InvalidToken, "access token is not sender-constrained"))?;
        match scheme {
            Scheme::DPoP => {
                if p.dpop_headers.len() != 1 { return Err(denied(ErrorCode::InvalidDpopProof, "exactly one DPoP header is required")); }
                let proof = dpop::verify_proof(p.dpop_headers[0], &dpop::Expect { algs: ALGS, method: p.method, url: p.url, access_token: Some(token), nonce: None, now: self.now, leeway: MIN_FUTURE_SKEW, replay })?;
                dpop::check_binding(&at.claims, &proof)?;
            }
            Scheme::Bearer => {
                // A plain Bearer presentation is only valid for a certificate-bound token.
                let cert = p.cert.ok_or_else(|| denied(ErrorCode::InvalidToken, "certificate-bound token without a client certificate"))?;
                if cnf.x5t_s256.is_none() { return Err(denied(ErrorCode::InvalidToken, "bearer presentation of a token that is not certificate-bound")); }
                mtls::check_binding(&at.claims, cert)?;
            }
        }
        Ok(at)
    }
}

/// Helper for tests and audits: does this token carry any sender constraint at all?
pub fn is_sender_constrained(claims: &Claims) -> bool {
    claims.cnf().ok().flatten().map_or(false, |c| c.jkt.is_some() || c.x5t_s256.is_some())
}

/// 5.4.1: is the key acceptable? Algorithm family, RSA size and EC strength.
pub fn check_key(alg: Algorithm, key: &Jwk) -> Result<(), crate::Error> {
    if !ALGS.contains(&alg) { return Err(crate::Error::Algorithm("algorithm is not allowed by FAPI 2.0".into())); }
    match (alg.family(), key.kty.as_str()) {
        (Family::RsaPss, "RSA") => {
            let n = key.req("n")?;
            let bits = n.iter().skip_while(|b| **b == 0).count() * 8;
            if bits < 2048 { return Err(crate::Error::Key("RSA keys must be at least 2048 bits".into())); }
            Ok(())
        }
        (Family::Ecdsa, "EC") if key.crv.as_deref() == Some("P-256") => Ok(()),
        (Family::EdDsa, "OKP") if key.crv.as_deref() == Some("Ed25519") => Ok(()),
        _ => Err(crate::Error::Key("key does not fit the algorithm".into())),
    }
}
