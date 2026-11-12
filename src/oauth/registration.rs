//! Dynamic client registration (RFC 7591) and client configuration management (RFC 7592).
//!
//! Secure defaults:
//! * registration is closed. The server owner must either hand out initial access tokens or set `open` explicitly;
//! * implicit and password grants cannot be registered (RFC 9700, OAuth 2.1);
//! * redirect URIs pass the same checks as everywhere else (`redirect::validate_registered`);
//! * a client may not register private key material, only public keys (`jwks` with a `d` member is refused);
//! * `client_secret_jwt` is off by default because it needs the secret in plaintext at rest. Other client secrets are
//!   stored as SHA-256 and shown once;
//! * the registration access token is stored as a hash and compared in constant time; an unknown client and a wrong token
//!   give the same answer, so the endpoint does not reveal which client ids exist;
//! * the client cannot change `client_id`, `client_secret`, issue times, or the registration access token (RFC 7592 2.2).
use super::client_auth::{Method, Registered};
use super::error::{ErrorCode, OAuthError, OResult};
use super::redirect::{self, ClientKind};
use super::request::ClientInfo;
use super::scope::Scope;
use crate::{b64, crypto, jwa::{Algorithm, Hash}, jwk::Jwk, jws, json, jwt::unix_now};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

pub const MAX_BODY: usize = 64 * 1024;
const MAX_STR: usize = 2048;
const MAX_LIST: usize = 64;

pub const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";
pub const GRANT_REFRESH_TOKEN: &str = "refresh_token";
pub const GRANT_CLIENT_CREDENTIALS: &str = "client_credentials";
pub const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

const HUMAN_FIELDS: &[&str] = &["client_name", "client_uri", "logo_uri", "tos_uri", "policy_uri"];
const URL_FIELDS: &[&str] = &["client_uri", "logo_uri", "tos_uri", "policy_uri", "jwks_uri"];
const KNOWN: &[&str] = &["redirect_uris", "token_endpoint_auth_method", "grant_types", "response_types", "client_name", "client_uri", "logo_uri",
    "scope", "contacts", "tos_uri", "policy_uri", "jwks_uri", "jwks", "software_id", "software_version", "software_statement",
    "application_type", "token_endpoint_auth_signing_alg", "dpop_bound_access_tokens", "tls_client_certificate_bound_access_tokens",
    "tls_client_auth_subject_dn", "tls_client_auth_san_dns", "tls_client_auth_san_uri", "tls_client_auth_san_ip", "tls_client_auth_san_email",
    "use_mtls_endpoint_aliases", "require_pushed_authorization_requests", "authorization_details_types"];
/// Members the client may send on create/update but that the server owns (RFC 7591 3.2.1, RFC 7592 2).
const SERVER_OWNED: &[&str] = &["client_id", "client_secret", "client_id_issued_at", "client_secret_expires_at", "registration_access_token", "registration_client_uri"];

fn meta_err(m: &str) -> OAuthError { OAuthError::with(ErrorCode::InvalidClientMetadata, m) }

/// Validated client metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct Metadata {
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub token_endpoint_auth_signing_alg: Option<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scope: Scope,
    pub contacts: Vec<String>,
    pub jwks_uri: Option<String>,
    pub jwks: Option<Vec<Jwk>>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub application_type: String,
    pub dpop_bound_access_tokens: bool,
    pub tls_client_certificate_bound_access_tokens: bool,
    pub tls_subject: [Option<String>; 5],
    pub authorization_details_types: Vec<String>,
    pub require_pushed_authorization_requests: bool,
    /// client_name, client_uri, logo_uri, tos_uri, policy_uri, with optional `#lang` suffixes.
    pub human: BTreeMap<String, String>,
}

/// What the server accepts.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Accept registration without an initial access token. Off by default.
    pub open: bool,
    /// SHA-256 hashes of accepted initial access tokens (RFC 7591 3). Use [`hash_token`] to make them.
    pub initial_access_token_hashes: Vec<Vec<u8>>,
    pub allowed_grant_types: Vec<String>,
    pub allowed_auth_methods: Vec<String>,
    /// Scopes a registering client may ask for. Empty means none are allowed.
    pub allowed_scopes: Scope,
    pub default_scope: Scope,
    pub allowed_signing_algs: Vec<Algorithm>,
    /// `client_secret_jwt` needs the secret in plaintext; keep off unless you accept that.
    pub allow_client_secret_jwt: bool,
    pub allow_native: bool,
    /// Only confidential clients (FAPI 2.0 and similar).
    pub confidential_only: bool,
    pub require_software_statement: bool,
    /// Every client must ask for DPoP- or certificate-bound access tokens (FAPI 2.0 5.3.2.1).
    pub require_sender_constrained: bool,
    /// Keys that sign acceptable software statements. Empty means statements are not accepted.
    pub software_statement_keys: Vec<Jwk>,
    pub software_statement_algs: Vec<Algorithm>,
    /// Keep the registration access token the same on update (false), or issue a new one (true).
    pub rotate_registration_token: bool,
    /// Base URL for `registration_client_uri`, e.g. `https://as.example.com/register`.
    pub registration_endpoint: String,
}

impl Policy {
    pub fn new(registration_endpoint: &str) -> Policy {
        Policy {
            open: false, initial_access_token_hashes: vec![],
            allowed_grant_types: vec![GRANT_AUTHORIZATION_CODE.into(), GRANT_REFRESH_TOKEN.into()],
            allowed_auth_methods: ["client_secret_basic", "client_secret_post", "private_key_jwt", "none", "tls_client_auth", "self_signed_tls_client_auth"].map(String::from).to_vec(),
            allowed_scopes: Scope::default(), default_scope: Scope::default(),
            allowed_signing_algs: vec![Algorithm::PS256, Algorithm::ES256, Algorithm::EdDSA],
            allow_client_secret_jwt: false, allow_native: true, confidential_only: false,
            require_software_statement: false, require_sender_constrained: false, software_statement_keys: vec![], software_statement_algs: vec![Algorithm::ES256, Algorithm::PS256, Algorithm::EdDSA],
            rotate_registration_token: false, registration_endpoint: registration_endpoint.trim_end_matches('/').into(),
        }
    }
}

pub fn hash_token(token: &str) -> Vec<u8> { crypto::digest(Hash::Sha256, token.as_bytes()).unwrap_or_default() }

/// The stored client.
#[derive(Debug, Clone)]
pub struct ClientRecord {
    pub client_id: String,
    pub secret_hash: Option<Vec<u8>>,
    /// Only for `client_secret_jwt`, when the policy allows it.
    pub secret_plain: Option<Vec<u8>>,
    pub registration_token_hash: Vec<u8>,
    pub issued_at: u64,
    pub metadata: Metadata,
}

impl ClientRecord {
    pub fn kind(&self) -> ClientKind { if self.metadata.application_type == "native" { ClientKind::Native } else { ClientKind::Web } }

    /// For the authorization endpoint (`request::validate`).
    pub fn client_info(&self) -> ClientInfo {
        ClientInfo { client_id: self.client_id.clone(), redirect_uris: self.metadata.redirect_uris.clone(), kind: self.kind(),
            allowed_scopes: self.metadata.scope.clone(),
            response_types: self.metadata.response_types.clone() }
    }

    /// For the token endpoint (`client_auth::authenticate`). `assertion` is the presented JWT, used to pick the key by `kid`.
    pub fn registered(&self, assertion: Option<&str>) -> Option<Registered> {
        let m = Method::parse(&self.metadata.token_endpoint_auth_method);
        let algs: Vec<Algorithm> = self.metadata.token_endpoint_auth_signing_alg.as_deref().and_then(|s| s.parse::<Algorithm>().ok()).into_iter().collect();
        let jwk = match (&self.metadata.jwks, assertion) {
            (Some(keys), Some(a)) => {
                let kid = jws::peek_header(a).ok().and_then(|h| h.kid);
                match (kid, keys.as_slice()) {
                    (Some(k), ks) => ks.iter().find(|x| x.kid.as_deref() == Some(k.as_str())).cloned(),
                    (None, [only]) => Some(only.clone()),
                    _ => None,
                }
            }
            (Some(keys), None) if keys.len() == 1 => Some(keys[0].clone()),
            _ => None,
        };
        let (secret, is_hash) = match (&self.secret_hash, &self.secret_plain) {
            (_, Some(p)) => (Some(p.clone()), false),
            (Some(h), None) => (Some(h.clone()), true),
            _ => (None, false),
        };
        Some(Registered { client_id: self.client_id.clone(), method: m?, secret, secret_is_hash: is_hash, jwk, assertion_algs: algs })
    }
}

pub trait ClientStore {
    fn insert(&self, rec: ClientRecord) -> bool;
    fn get(&self, client_id: &str) -> Option<ClientRecord>;
    fn replace(&self, rec: ClientRecord) -> bool;
    fn remove(&self, client_id: &str) -> bool;
}

#[derive(Default)]
pub struct MemoryClientStore { m: Mutex<HashMap<String, ClientRecord>> }
impl MemoryClientStore { pub fn new() -> Self { Self::default() } }
impl ClientStore for MemoryClientStore {
    fn insert(&self, rec: ClientRecord) -> bool {
        let Ok(mut m) = self.m.lock() else { return false };
        if m.contains_key(&rec.client_id) { return false; }
        m.insert(rec.client_id.clone(), rec); true
    }
    fn get(&self, id: &str) -> Option<ClientRecord> { self.m.lock().ok()?.get(id).cloned() }
    fn replace(&self, rec: ClientRecord) -> bool {
        let Ok(mut m) = self.m.lock() else { return false };
        match m.get_mut(&rec.client_id) { Some(s) => { *s = rec; true } None => false }
    }
    fn remove(&self, id: &str) -> bool { self.m.lock().map(|mut m| m.remove(id).is_some()).unwrap_or(false) }
}

// ---------- metadata parsing ----------

fn str_of<'a>(o: &'a Map<String, Value>, k: &str) -> OResult<Option<&'a str>> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.len() <= MAX_STR && !s.chars().any(|c| c.is_control()) => Ok(Some(s)),
        Some(_) => Err(meta_err(&format!("{k} must be a short string without control characters"))),
    }
}
fn list_of(o: &Map<String, Value>, k: &str) -> OResult<Option<Vec<String>>> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(a)) if a.len() <= MAX_LIST => a.iter().map(|x| match x {
            Value::String(s) if s.len() <= MAX_STR && !s.chars().any(|c| c.is_control()) => Ok(s.clone()),
            _ => Err(meta_err(&format!("{k} must contain short strings"))),
        }).collect::<OResult<Vec<_>>>().map(Some),
        Some(_) => Err(meta_err(&format!("{k} must be an array of strings"))),
    }
}
fn bool_of(o: &Map<String, Value>, k: &str) -> OResult<bool> {
    match o.get(k) { None => Ok(false), Some(Value::Bool(b)) => Ok(*b), Some(_) => Err(meta_err(&format!("{k} must be a boolean"))) }
}
fn no_dups(v: &[String], what: &str) -> OResult<()> {
    let mut s = v.to_vec(); s.sort(); s.dedup();
    if s.len() != v.len() { Err(meta_err(&format!("{what} contains duplicates"))) } else { Ok(()) }
}
fn https_url(s: &str, what: &str) -> OResult<()> {
    let u = url::Url::parse(s).map_err(|_| meta_err(&format!("{what} is not a URL")))?;
    if u.scheme() != "https" || u.host().is_none() || !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() || s.contains('\\') {
        return Err(meta_err(&format!("{what} must be an https URL without credentials or fragment")));
    }
    Ok(())
}

impl Metadata {
    /// Parses and validates client metadata from a JSON object, applying the defaults from RFC 7591 2.
    /// `members` has already had any software statement merged in (see [`apply_software_statement`]).
    pub fn from_object(o: &Map<String, Value>, p: &Policy) -> OResult<Metadata> {
        let method = str_of(o, "token_endpoint_auth_method")?.unwrap_or("client_secret_basic").to_string();
        // client_secret_jwt is governed only by its own flag (it keeps the secret in plaintext), whatever the list says.
        let allowed = if method == "client_secret_jwt" { p.allow_client_secret_jwt } else { p.allowed_auth_methods.iter().any(|m| m == &method) };
        if !allowed { return Err(meta_err("token_endpoint_auth_method is not allowed")); }
        if method == "client_secret_post" || method == "client_secret_basic" || method == "client_secret_jwt" || method == "private_key_jwt" || method == "none"
            || method == "tls_client_auth" || method == "self_signed_tls_client_auth" {} else { return Err(meta_err("unknown token_endpoint_auth_method")); }
        if p.confidential_only && method == "none" { return Err(meta_err("only confidential clients may register")); }

        let grant_types = list_of(o, "grant_types")?.unwrap_or_else(|| vec![GRANT_AUTHORIZATION_CODE.into()]);
        no_dups(&grant_types, "grant_types")?;
        if grant_types.is_empty() { return Err(meta_err("grant_types must not be empty")); }
        for g in &grant_types {
            if g == "implicit" || g == "password" { return Err(meta_err("the implicit and password grants cannot be registered")); }
            if !p.allowed_grant_types.iter().any(|a| a == g) { return Err(meta_err("grant type is not allowed")); }
        }
        let has = |g: &str| grant_types.iter().any(|x| x == g);
        let response_types = list_of(o, "response_types")?.unwrap_or_else(|| if has(GRANT_AUTHORIZATION_CODE) { vec!["code".into()] } else { vec![] });
        no_dups(&response_types, "response_types")?;
        if response_types.iter().any(|r| r != "code") { return Err(meta_err("only the code response type can be registered")); }
        // RFC 7591 2.1: grant and response types must agree.
        if has(GRANT_AUTHORIZATION_CODE) != response_types.iter().any(|r| r == "code") { return Err(meta_err("grant_types and response_types disagree about the authorization code flow")); }
        if has(GRANT_REFRESH_TOKEN) && !(has(GRANT_AUTHORIZATION_CODE) || has(GRANT_DEVICE_CODE) || has(GRANT_JWT_BEARER) || has(GRANT_TOKEN_EXCHANGE)) {
            return Err(meta_err("refresh_token needs a grant that issues one"));
        }
        if method == "none" && (has(GRANT_CLIENT_CREDENTIALS) || has(GRANT_JWT_BEARER) || has(GRANT_TOKEN_EXCHANGE)) { return Err(meta_err("a public client cannot use this grant")); }

        let application_type = str_of(o, "application_type")?.unwrap_or("web").to_string();
        if application_type != "web" && application_type != "native" { return Err(meta_err("application_type must be web or native")); }
        if application_type == "native" && !p.allow_native { return Err(meta_err("native clients are not accepted")); }
        let kind = if application_type == "native" { ClientKind::Native } else { ClientKind::Web };

        let redirect_uris = list_of(o, "redirect_uris")?.unwrap_or_default();
        if has(GRANT_AUTHORIZATION_CODE) && redirect_uris.is_empty() { return Err(OAuthError::with(ErrorCode::InvalidRedirectUri, "redirect_uris is required for the authorization code grant")); }
        no_dups(&redirect_uris, "redirect_uris")?;
        for u in &redirect_uris { redirect::validate_registered(u, kind).map_err(|_| OAuthError::with(ErrorCode::InvalidRedirectUri, "a redirect URI is not acceptable"))?; }

        let scope = match str_of(o, "scope")? {
            Some(s) => Scope::parse(s).map_err(|_| meta_err("scope is malformed"))?,
            None => p.default_scope.clone(),
        };
        if !scope.excess(&p.allowed_scopes).is_empty() { return Err(meta_err("scope is not allowed")); }

        let contacts = list_of(o, "contacts")?.unwrap_or_default();
        if contacts.len() > 10 || contacts.iter().any(|c| c.len() > 254) { return Err(meta_err("too many or too long contacts")); }

        // Keys
        let jwks_uri = str_of(o, "jwks_uri")?.map(String::from);
        let jwks = match o.get("jwks") {
            None | Some(Value::Null) => None,
            Some(Value::Object(s)) => {
                let keys = s.get("keys").and_then(Value::as_array).ok_or_else(|| meta_err("jwks.keys is required"))?;
                if keys.is_empty() || keys.len() > 16 { return Err(meta_err("jwks must hold 1 to 16 keys")); }
                let mut out = vec![];
                for k in keys {
                    let j = Jwk::parse(&k.to_string()).map_err(|_| meta_err("jwks contains an invalid key"))?;
                    if j.is_private() { return Err(meta_err("jwks must contain public keys only")); }
                    out.push(j);
                }
                Some(out)
            }
            Some(_) => return Err(meta_err("jwks must be an object")),
        };
        if jwks.is_some() && jwks_uri.is_some() { return Err(meta_err("jwks and jwks_uri must not both be present")); }
        if let Some(u) = &jwks_uri { https_url(u, "jwks_uri")?; }
        if method == "private_key_jwt" && jwks.is_none() && jwks_uri.is_none() { return Err(meta_err("private_key_jwt needs jwks or jwks_uri")); }
        if method == "self_signed_tls_client_auth" && jwks.is_none() && jwks_uri.is_none() { return Err(meta_err("self_signed_tls_client_auth needs jwks or jwks_uri")); }
        let alg = str_of(o, "token_endpoint_auth_signing_alg")?.map(String::from);
        if let Some(a) = &alg {
            let parsed = a.parse::<Algorithm>().map_err(|_| meta_err("unknown token_endpoint_auth_signing_alg"))?;
            if !p.allowed_signing_algs.contains(&parsed) && !(method == "client_secret_jwt" && matches!(parsed, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)) {
                return Err(meta_err("token_endpoint_auth_signing_alg is not allowed"));
            }
        } else if method == "private_key_jwt" { return Err(meta_err("private_key_jwt needs token_endpoint_auth_signing_alg")); }
        if (method == "client_secret_basic" || method == "client_secret_post") && (jwks.is_some() || jwks_uri.is_some()) && false { unreachable!(); }

        // mTLS subject values (RFC 8705 2.1.2): exactly one for tls_client_auth.
        let tls = ["tls_client_auth_subject_dn", "tls_client_auth_san_dns", "tls_client_auth_san_uri", "tls_client_auth_san_ip", "tls_client_auth_san_email"];
        let mut tls_subject: [Option<String>; 5] = Default::default();
        for (i, k) in tls.iter().enumerate() { tls_subject[i] = str_of(o, k)?.map(String::from); }
        let n_tls = tls_subject.iter().flatten().count();
        if method == "tls_client_auth" && n_tls != 1 { return Err(meta_err("tls_client_auth needs exactly one tls_client_auth_* member")); }
        if method != "tls_client_auth" && n_tls != 0 { return Err(meta_err("tls_client_auth_* members need tls_client_auth")); }
        if n_tls == 1 {
            super::mtls::ExpectedSubject::from_metadata(tls_subject[0].as_deref(), tls_subject[1].as_deref(), tls_subject[2].as_deref(), tls_subject[3].as_deref(), tls_subject[4].as_deref())?;
        }

        // Human-readable members, with RFC 7591 2.2 language tags.
        let mut human = BTreeMap::new();
        for k in o.keys() {
            let (base, tag) = match k.split_once('#') { Some((b, t)) => (b, Some(t)), None => (k.as_str(), None) };
            if !HUMAN_FIELDS.contains(&base) { continue; }
            if let Some(t) = tag { if t.is_empty() || t.len() > 35 || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') { return Err(meta_err("invalid language tag")); } }
            let s = str_of(o, k)?.ok_or_else(|| meta_err("empty human-readable member"))?;
            if URL_FIELDS.contains(&base) { https_url(s, base)?; }
            human.insert(k.clone(), s.to_string());
        }

        let (dpop_bound, mtls_bound) = (bool_of(o, "dpop_bound_access_tokens")?, bool_of(o, "tls_client_certificate_bound_access_tokens")?);
        if p.require_sender_constrained && !(dpop_bound || mtls_bound) { return Err(meta_err("this server only issues sender-constrained access tokens")); }
        Ok(Metadata {
            redirect_uris, token_endpoint_auth_method: method, token_endpoint_auth_signing_alg: alg, grant_types, response_types, scope, contacts,
            jwks_uri, jwks, software_id: str_of(o, "software_id")?.map(String::from), software_version: str_of(o, "software_version")?.map(String::from),
            application_type, dpop_bound_access_tokens: dpop_bound,
            tls_client_certificate_bound_access_tokens: mtls_bound,
            tls_subject, authorization_details_types: list_of(o, "authorization_details_types")?.unwrap_or_default(),
            require_pushed_authorization_requests: bool_of(o, "require_pushed_authorization_requests")?, human,
        })
    }

    pub fn to_object(&self) -> Map<String, Value> {
        let mut o = Map::new();
        o.insert("redirect_uris".into(), json!(self.redirect_uris));
        o.insert("token_endpoint_auth_method".into(), json!(self.token_endpoint_auth_method));
        if let Some(a) = &self.token_endpoint_auth_signing_alg { o.insert("token_endpoint_auth_signing_alg".into(), json!(a)); }
        o.insert("grant_types".into(), json!(self.grant_types));
        o.insert("response_types".into(), json!(self.response_types));
        if !self.scope.is_empty() { o.insert("scope".into(), json!(self.scope.to_string())); }
        if !self.contacts.is_empty() { o.insert("contacts".into(), json!(self.contacts)); }
        if let Some(u) = &self.jwks_uri { o.insert("jwks_uri".into(), json!(u)); }
        if let Some(k) = &self.jwks { o.insert("jwks".into(), json!({ "keys": k.iter().map(|k| serde_json::from_str::<Value>(&k.to_json()).unwrap_or(Value::Null)).collect::<Vec<_>>() })); }
        if let Some(s) = &self.software_id { o.insert("software_id".into(), json!(s)); }
        if let Some(s) = &self.software_version { o.insert("software_version".into(), json!(s)); }
        o.insert("application_type".into(), json!(self.application_type));
        if self.dpop_bound_access_tokens { o.insert("dpop_bound_access_tokens".into(), json!(true)); }
        if self.tls_client_certificate_bound_access_tokens { o.insert("tls_client_certificate_bound_access_tokens".into(), json!(true)); }
        let tls = ["tls_client_auth_subject_dn", "tls_client_auth_san_dns", "tls_client_auth_san_uri", "tls_client_auth_san_ip", "tls_client_auth_san_email"];
        for (i, k) in tls.iter().enumerate() { if let Some(v) = &self.tls_subject[i] { o.insert((*k).into(), json!(v)); } }
        if !self.authorization_details_types.is_empty() { o.insert("authorization_details_types".into(), json!(self.authorization_details_types)); }
        if self.require_pushed_authorization_requests { o.insert("require_pushed_authorization_requests".into(), json!(true)); }
        for (k, v) in &self.human { o.insert(k.clone(), json!(v)); }
        o
    }
}

/// RFC 7591 2.3: verifies a software statement and lets its claims override the plain members.
fn apply_software_statement(o: &mut Map<String, Value>, p: &Policy) -> OResult<()> {
    let Some(st) = o.remove("software_statement") else {
        if p.require_software_statement { return Err(OAuthError::with(ErrorCode::InvalidSoftwareStatement, "a software statement is required")); }
        return Ok(());
    };
    let st = st.as_str().ok_or_else(|| OAuthError::with(ErrorCode::InvalidSoftwareStatement, "software_statement must be a string"))?;
    if p.software_statement_keys.is_empty() { return Err(OAuthError::with(ErrorCode::UnapprovedSoftwareStatement, "software statements are not accepted")); }
    let bad = || OAuthError::with(ErrorCode::InvalidSoftwareStatement, "software statement did not verify");
    let hdr = jws::peek_header(st).map_err(|_| bad())?;
    let key = match (&hdr.kid, p.software_statement_keys.as_slice()) {
        (Some(k), keys) => keys.iter().find(|x| x.kid.as_deref() == Some(k)).ok_or_else(bad)?,
        (None, [only]) => only,
        _ => return Err(bad()),
    };
    let (_, payload) = jws::verify(st, key, &jws::Policy::new(&p.software_statement_algs)).map_err(|_| bad())?;
    let claims = json::parse_object(&payload).map_err(|_| bad())?;
    // The statement must carry an expiry that has not passed when it has one (RFC 7591 2.3 leaves this to the server).
    if let Some(exp) = claims.get("exp") {
        let e = exp.as_u64().ok_or_else(bad)?;
        if unix_now() >= e { return Err(bad()); }
    }
    for (k, v) in claims { if KNOWN.contains(&k.split('#').next().unwrap_or("")) || k == "software_id" { o.insert(k, v); } }
    Ok(())
}

// ---------- registration (RFC 7591) ----------

fn random_id(prefix: &str, bytes: usize) -> crate::Result<String> {
    let mut b = vec![0u8; bytes];
    crypto::random(&mut b)?;
    Ok(format!("{prefix}{}", b64::encode(b)))
}

fn check_bearer(presented: Option<&str>, accepted: &[Vec<u8>]) -> bool {
    let h = presented.map(hash_token).unwrap_or_default();
    // Compare against every accepted hash so timing does not reveal which one was close.
    accepted.iter().fold(false, |acc, a| acc | (!h.is_empty() && crypto::ct_eq(&h, a)))
}

fn needs_secret(m: &Metadata) -> bool { matches!(m.token_endpoint_auth_method.as_str(), "client_secret_basic" | "client_secret_post" | "client_secret_jwt") }

fn response(rec: &ClientRecord, secret: Option<&str>, reg_token: Option<&str>, p: &Policy) -> Value {
    let mut o = rec.metadata.to_object();
    o.insert("client_id".into(), json!(rec.client_id));
    o.insert("client_id_issued_at".into(), json!(rec.issued_at));
    if let Some(s) = secret { o.insert("client_secret".into(), json!(s)); o.insert("client_secret_expires_at".into(), json!(0)); }
    if let Some(t) = reg_token { o.insert("registration_access_token".into(), json!(t)); }
    o.insert("registration_client_uri".into(), json!(format!("{}/{}", p.registration_endpoint, rec.client_id)));
    Value::Object(o)
}

/// RFC 7591 3.1 / 3.2. `initial_access_token` is the Bearer token from the request, if any.
/// Returns the stored record and the JSON response (201). The secret and registration token appear only here.
pub fn register(store: &dyn ClientStore, body: &str, initial_access_token: Option<&str>, p: &Policy, now: Option<u64>) -> OResult<(ClientRecord, String)> {
    if body.len() > MAX_BODY { return Err(meta_err("request body too large")); }
    if !p.open && !check_bearer(initial_access_token, &p.initial_access_token_hashes) {
        return Err(OAuthError::with(ErrorCode::InvalidToken, "an initial access token is required"));
    }
    let mut o = json::parse_object(body.as_bytes()).map_err(|_| meta_err("body is not a JSON object"))?;
    // Server-owned members are ignored on create (RFC 7591 3.1: the server MUST NOT trust client_id/secret sent by the client).
    for k in SERVER_OWNED { o.remove(*k); }
    apply_software_statement(&mut o, p)?;
    let metadata = Metadata::from_object(&o, p)?;
    let srv = || OAuthError::new(ErrorCode::ServerError);
    let (secret, secret_hash, secret_plain) = if needs_secret(&metadata) {
        let s = random_id("", 32).map_err(|_| srv())?;
        if metadata.token_endpoint_auth_method == "client_secret_jwt" { (Some(s.clone()), None, Some(s.into_bytes())) }
        else { (Some(s.clone()), Some(hash_token(&s)), None) }
    } else { (None, None, None) };
    let reg_token = random_id("", 32).map_err(|_| srv())?;
    let rec = ClientRecord { client_id: random_id("c_", 16).map_err(|_| srv())?, secret_hash, secret_plain, registration_token_hash: hash_token(&reg_token),
        issued_at: now.unwrap_or_else(unix_now), metadata };
    if !store.insert(rec.clone()) { return Err(srv()); }
    let out = response(&rec, secret.as_deref(), Some(&reg_token), p).to_string();
    Ok((rec, out))
}

// ---------- management (RFC 7592) ----------

fn authorize(store: &dyn ClientStore, client_id: &str, bearer: Option<&str>) -> OResult<ClientRecord> {
    // One answer for "no such client" and "wrong token" (RFC 7592 2.1: 401 for both).
    let denied = || OAuthError::with(ErrorCode::InvalidToken, "invalid registration access token");
    let rec = store.get(client_id);
    let stored = rec.as_ref().map(|r| r.registration_token_hash.clone()).unwrap_or_default();
    let ok = check_bearer(bearer, &[stored]);
    match (rec, ok) { (Some(r), true) => Ok(r), _ => Err(denied()) }
}

/// GET on the registration client URI. Returns the configuration; the client secret is not repeated.
pub fn read(store: &dyn ClientStore, client_id: &str, bearer: Option<&str>, p: &Policy) -> OResult<String> {
    let rec = authorize(store, client_id, bearer)?;
    Ok(response(&rec, None, None, p).to_string())
}

/// PUT on the registration client URI. The body replaces all metadata (RFC 7592 2.2).
pub fn update(store: &dyn ClientStore, client_id: &str, bearer: Option<&str>, body: &str, p: &Policy) -> OResult<String> {
    let rec = authorize(store, client_id, bearer)?;
    if body.len() > MAX_BODY { return Err(meta_err("request body too large")); }
    let mut o = json::parse_object(body.as_bytes()).map_err(|_| meta_err("body is not a JSON object"))?;
    match o.remove("client_id") {
        Some(Value::String(id)) if id == client_id => {}
        _ => return Err(meta_err("client_id is required and must match the URL")),
    }
    // The client may repeat its secret, but it must be the right one; it cannot choose a new one.
    let mut secret_sent = None;
    if let Some(s) = o.remove("client_secret") { secret_sent = Some(s.as_str().map(String::from).ok_or_else(|| meta_err("client_secret must be a string"))?); }
    for k in ["registration_access_token", "registration_client_uri", "client_id_issued_at", "client_secret_expires_at"] {
        if o.remove(k).is_some() { return Err(meta_err(&format!("{k} cannot be changed by the client"))); }
    }
    if let Some(s) = &secret_sent {
        let ok = match (&rec.secret_hash, &rec.secret_plain) {
            (Some(h), _) => crypto::ct_eq(&hash_token(s), h),
            (_, Some(pl)) => crypto::ct_eq(s.as_bytes(), pl),
            _ => false,
        };
        if !ok { return Err(meta_err("client_secret does not match")); }
    }
    apply_software_statement(&mut o, p)?;
    let metadata = Metadata::from_object(&o, p)?;
    let srv = || OAuthError::new(ErrorCode::ServerError);
    let mut next = ClientRecord { metadata, ..rec.clone() };
    let mut new_secret = None;
    if needs_secret(&next.metadata) {
        if next.secret_hash.is_none() && next.secret_plain.is_none() || (next.metadata.token_endpoint_auth_method == "client_secret_jwt") != next.secret_plain.is_some() {
            let s = random_id("", 32).map_err(|_| srv())?;
            if next.metadata.token_endpoint_auth_method == "client_secret_jwt" { next.secret_plain = Some(s.clone().into_bytes()); next.secret_hash = None; }
            else { next.secret_hash = Some(hash_token(&s)); next.secret_plain = None; }
            new_secret = Some(s);
        }
    } else { next.secret_hash = None; next.secret_plain = None; }
    let mut new_token = None;
    if p.rotate_registration_token {
        let t = random_id("", 32).map_err(|_| srv())?;
        next.registration_token_hash = hash_token(&t);
        new_token = Some(t);
    }
    if !store.replace(next.clone()) { return Err(srv()); }
    Ok(response(&next, new_secret.as_deref(), new_token.as_deref(), p).to_string())
}

/// DELETE on the registration client URI (RFC 7592 2.3). The caller should also revoke the client's tokens.
pub fn delete(store: &dyn ClientStore, client_id: &str, bearer: Option<&str>) -> OResult<()> {
    authorize(store, client_id, bearer)?;
    if store.remove(client_id) { Ok(()) } else { Err(OAuthError::new(ErrorCode::ServerError)) }
}
