//! Token introspection (RFC 7662) and JWT responses for it (RFC 9701).
//!
//! An inactive token is answered with exactly `{"active":false}` and nothing else (RFC 7662 2.2), so the
//! endpoint is not an oracle for why a token is dead.
use super::error::{ErrorCode, OAuthError, OResult};
use super::form::Params;
use super::scope::Scope;
use crate::{jwa::Algorithm, jwk::Jwk, jwt::{self, Claims}, Error, Result};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenTypeHint { AccessToken, RefreshToken }

impl TokenTypeHint {
    pub fn as_str(self) -> &'static str { match self { Self::AccessToken => "access_token", Self::RefreshToken => "refresh_token" } }
    /// Unknown hints are ignored, not errors (RFC 7009 2.1, RFC 7662 2.1).
    pub fn parse(s: &str) -> Option<Self> { match s { "access_token" => Some(Self::AccessToken), "refresh_token" => Some(Self::RefreshToken), _ => None } }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request { pub token: String, pub hint: Option<TokenTypeHint> }

pub fn parse_request(body: &Params) -> OResult<Request> {
    let token = body.get("token").map_err(|_| OAuthError::invalid_request("token must not repeat"))?
        .ok_or_else(|| OAuthError::invalid_request("token is required"))?.to_string();
    let hint = body.get("token_type_hint").map_err(|_| OAuthError::invalid_request("token_type_hint must not repeat"))?.and_then(TokenTypeHint::parse);
    Ok(Request { token, hint })
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Introspection {
    pub active: bool,
    pub scope: Option<Scope>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub nbf: Option<u64>,
    pub sub: Option<String>,
    pub aud: Vec<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
    pub cnf: Option<Value>,
    pub extra: Map<String, Value>,
}

const CORE: &[&str] = &["active", "scope", "client_id", "username", "token_type", "exp", "iat", "nbf", "sub", "aud", "iss", "jti", "cnf"];

impl Introspection {
    pub fn inactive() -> Self { Introspection::default() }

    /// Active response from a validated JWT access token's claims.
    pub fn from_claims(c: &Claims) -> Result<Self> {
        let scope = match c.str_claim("scope")? { Some(s) if !s.is_empty() => Some(Scope::parse(s)?), _ => None };
        Ok(Introspection {
            active: true, scope, client_id: c.str_claim("client_id")?.map(String::from), username: None,
            token_type: Some("Bearer".into()), exp: c.date("exp")?, iat: c.date("iat")?, nbf: c.date("nbf")?,
            sub: c.str_claim("sub")?.map(String::from),
            aud: c.aud_list()?.unwrap_or_default().into_iter().map(String::from).collect(),
            iss: c.str_claim("iss")?.map(String::from), jti: c.str_claim("jti")?.map(String::from),
            cnf: c.map.get("cnf").cloned(), extra: Map::new(),
        })
    }

    pub fn to_value(&self) -> Value {
        if !self.active { return json!({ "active": false }); }
        let mut m = Map::new();
        for (k, v) in &self.extra { if !CORE.contains(&k.as_str()) { m.insert(k.clone(), v.clone()); } }
        m.insert("active".into(), Value::Bool(true));
        if let Some(s) = &self.scope { m.insert("scope".into(), json!(s.to_string())); }
        let st = |m: &mut Map<String, Value>, k: &str, v: &Option<String>| if let Some(v) = v { m.insert(k.into(), json!(v)); };
        st(&mut m, "client_id", &self.client_id); st(&mut m, "username", &self.username); st(&mut m, "token_type", &self.token_type);
        st(&mut m, "sub", &self.sub); st(&mut m, "iss", &self.iss); st(&mut m, "jti", &self.jti);
        for (k, v) in [("exp", self.exp), ("iat", self.iat), ("nbf", self.nbf)] { if let Some(v) = v { m.insert(k.into(), json!(v)); } }
        match self.aud.as_slice() { [] => {}, [one] => { m.insert("aud".into(), json!(one)); }, many => { m.insert("aud".into(), json!(many)); } }
        if let Some(c) = &self.cnf { m.insert("cnf".into(), c.clone()); }
        Value::Object(m)
    }

    pub fn to_json(&self) -> String { self.to_value().to_string() }

    /// Strict: `active` must be a JSON boolean (a string "true" is not accepted).
    pub fn from_value(v: &Value) -> Result<Self> {
        let o = v.as_object().ok_or_else(|| Error::Malformed("introspection response must be an object".into()))?;
        let active = match o.get("active") { Some(Value::Bool(b)) => *b, _ => return Err(Error::Malformed("active must be a boolean".into())) };
        if !active { return Ok(Introspection::inactive()); }
        let s = |k: &str| match o.get(k) { None => Ok(None), Some(Value::String(x)) => Ok(Some(x.clone())), Some(_) => Err(Error::Malformed(format!("{k} must be a string"))) };
        let n = |k: &str| match o.get(k) { None => Ok(None), Some(x) => x.as_u64().map(Some).ok_or_else(|| Error::Malformed(format!("{k} must be a non-negative integer"))) };
        let aud = match o.get("aud") {
            None => vec![], Some(Value::String(a)) => vec![a.clone()],
            Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| Error::Malformed("aud entries must be strings".into()))).collect::<Result<_>>()?,
            Some(_) => return Err(Error::Malformed("aud has the wrong type".into())),
        };
        Ok(Introspection {
            active, scope: s("scope")?.map(|x| Scope::parse(&x)).transpose()?, client_id: s("client_id")?, username: s("username")?,
            token_type: s("token_type")?, exp: n("exp")?, iat: n("iat")?, nbf: n("nbf")?, sub: s("sub")?, aud, iss: s("iss")?, jti: s("jti")?,
            cnf: o.get("cnf").cloned(), extra: o.iter().filter(|(k, _)| !CORE.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect(),
        })
    }

    pub fn parse(body: &str) -> Result<Self> { Self::from_value(&serde_json::from_str(body)?) }

    /// Resource-server check after a successful introspection call: `active` is the server's word, but a stale
    /// cached answer or a clock-skewed server should not be trusted past `exp`/`nbf`.
    pub fn is_usable(&self, now: u64, leeway: u64) -> bool {
        self.active && self.exp.map_or(true, |e| now < e.saturating_add(leeway)) && self.nbf.map_or(true, |n| now + leeway >= n)
    }

    /// The token was issued for this resource server (RFC 8707, RFC 9068 4).
    pub fn is_for_audience(&self, me: &str) -> bool { self.aud.iter().any(|a| a == me) }
}

// ---------- RFC 9701: introspection response as a JWT ----------

pub const JWT_TYP: &str = "token-introspection+jwt";
pub const JWT_CONTENT_TYPE: &str = "application/token-introspection+jwt";

/// Signs a response for the caller `audience` (the resource server that asked).
pub fn sign_jwt_response(alg: Algorithm, key: &Jwk, issuer: &str, audience: &str, resp: &Introspection) -> Result<String> {
    let now = jwt::unix_now();
    let c = Claims::new().issuer(issuer).audience(&[audience]).issued_at(now).set("token_introspection", resp.to_value());
    jwt::sign(alg, key, &c, Some(JWT_TYP))
}

/// Verifies a JWT response and returns the embedded introspection result.
pub fn verify_jwt_response(token: &str, key: &Jwk, algs: &[Algorithm], expected_issuer: &str, me: &str, now: Option<u64>) -> OResult<Introspection> {
    let bad = |m: &str| OAuthError::with(ErrorCode::ServerError, m);
    let mut v = jwt::Validation::new(algs, expected_issuer, me);
    v.typ = Some(JWT_TYP);
    v.require = &["iat"];
    v.require_exp = false;
    v.now = now;
    let (_, c) = jwt::verify(token, key, &v).map_err(|_| bad("introspection response JWT rejected"))?;
    let inner = c.map.get("token_introspection").ok_or_else(|| bad("token_introspection claim is missing"))?;
    Introspection::from_value(inner).map_err(|_| bad("token_introspection claim is malformed"))
}
