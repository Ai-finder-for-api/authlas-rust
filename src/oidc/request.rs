//! OIDC authentication requests (Core 3.1.2.1): `openid` scope, `prompt`, `max_age`, `claims`, `acr_values`, `login_hint`,
//! `id_token_hint`, and the decision the OP must take for each (show login, show consent, go straight through, or fail).
//!
//! [`decide`] is the part most OPs get subtly wrong: it turns the request and the state of the user's session into exactly one
//! [`Next`], and returns the error code the spec names when `prompt=none` makes interaction impossible.
use crate::jwt::unix_now;
use crate::oauth::error::{ErrorCode, OAuthError, OResult};
use crate::oauth::request::AuthRequest;
use crate::oauth::scope::Scope;
use crate::{Error, Result};
use serde_json::{Map, Value};

/// Scopes that map to groups of claims (Core 5.4).
pub fn scope_claims(scope: &str) -> &'static [&'static str] {
    match scope {
        "profile" => &["name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"],
        "email" => &["email", "email_verified"],
        "address" => &["address"],
        "phone" => &["phone_number", "phone_number_verified"],
        _ => &[],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt { None, Login, Consent, SelectAccount }

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prompts(pub Vec<Prompt>);

impl Prompts {
    pub fn parse(s: &str) -> Result<Prompts> {
        let mut v = vec![];
        for t in s.split(' ') {
            let p = match t { "none" => Prompt::None, "login" => Prompt::Login, "consent" => Prompt::Consent, "select_account" => Prompt::SelectAccount,
                // Values the OP does not understand are ignored (Core 3.1.2.1: "MAY return an error or MAY ignore it").
                _ if !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic()) => continue,
                _ => return Err(Error::Malformed("prompt is malformed".into())) };
            if !v.contains(&p) { v.push(p); }
        }
        if v.contains(&Prompt::None) && v.len() > 1 { return Err(Error::Malformed("prompt=none cannot be combined with other values".into())); }
        Ok(Prompts(v))
    }
    pub fn has(&self, p: Prompt) -> bool { self.0.contains(&p) }
}

/// One entry of the `claims` request parameter (Core 5.5).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ClaimRequest {
    pub essential: bool,
    pub value: Option<Value>,
    pub values: Vec<Value>,
}

/// The parsed `claims` parameter. `userinfo` and `id_token` map claim names to optional constraints.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ClaimsRequest {
    pub userinfo: Vec<(String, ClaimRequest)>,
    pub id_token: Vec<(String, ClaimRequest)>,
}

const MAX_CLAIMS_PARAM: usize = 8 * 1024;

impl ClaimsRequest {
    pub fn parse(json: &str) -> Result<ClaimsRequest> {
        let bad = |m: &str| Error::Malformed(format!("claims parameter: {m}"));
        if json.len() > MAX_CLAIMS_PARAM { return Err(bad("too large")); }
        let o = crate::json::parse_object(json.as_bytes())?;
        let section = |name: &str| -> Result<Vec<(String, ClaimRequest)>> {
            let Some(v) = o.get(name) else { return Ok(vec![]) };
            let m = v.as_object().ok_or_else(|| bad(&format!("{name} must be an object")))?;
            if m.len() > 64 { return Err(bad("too many claims")); }
            m.iter().map(|(k, spec)| {
                let r = match spec {
                    Value::Null => ClaimRequest::default(),
                    Value::Object(s) => ClaimRequest {
                        essential: match s.get("essential") { None => false, Some(Value::Bool(b)) => *b, Some(_) => return Err(bad("essential must be a boolean")) },
                        value: s.get("value").cloned(),
                        values: match s.get("values") { None => vec![], Some(Value::Array(a)) => a.clone(), Some(_) => return Err(bad("values must be an array")) },
                    },
                    _ => return Err(bad("a claim request must be null or an object")),
                };
                Ok((k.clone(), r))
            }).collect()
        };
        for k in o.keys() { if k != "userinfo" && k != "id_token" { /* other members (e.g. "verified_claims") are ignored, as the spec allows */ } }
        Ok(ClaimsRequest { userinfo: section("userinfo")?, id_token: section("id_token")? })
    }

    pub fn id_token_claim(&self, name: &str) -> Option<&ClaimRequest> { self.id_token.iter().find(|(k, _)| k == name).map(|(_, r)| r) }

    /// Claim names asked for in the UserInfo response, from `claims` only (scope-based claims come from [`scope_claims`]).
    pub fn userinfo_names(&self) -> Vec<&str> { self.userinfo.iter().map(|(k, _)| k.as_str()).collect() }

    /// `acr_values` asked for through `claims.id_token.acr`, and whether the request is essential.
    pub fn acr(&self) -> Option<(&ClaimRequest, Vec<&str>)> {
        let r = self.id_token_claim("acr")?;
        let mut v: Vec<&str> = r.values.iter().filter_map(Value::as_str).collect();
        if let Some(x) = r.value.as_ref().and_then(Value::as_str) { v.push(x); }
        Some((r, v))
    }

    /// Does the request make `auth_time` mandatory? (essential `auth_time` claim)
    pub fn requires_auth_time(&self) -> bool { self.id_token_claim("auth_time").map_or(false, |r| r.essential) }
}

/// An OIDC authentication request, on top of the OAuth [`AuthRequest`].
#[derive(Debug, Clone)]
pub struct AuthenticationRequest {
    pub oauth: AuthRequest,
    pub prompt: Prompts,
    pub max_age: Option<u64>,
    pub acr_values: Vec<String>,
    pub login_hint: Option<String>,
    pub id_token_hint: Option<String>,
    pub claims: ClaimsRequest,
    pub ui_locales: Vec<String>,
    pub display: Option<String>,
}

impl AuthenticationRequest {
    /// `true` when the OAuth request asks for `openid`. Without it this is a plain OAuth request and none of this module applies.
    pub fn is_openid(req: &AuthRequest) -> bool { req.scope.contains("openid") }

    /// Reads the OIDC parameters from a request already validated by [`crate::oauth::request::validate`]. Errors carry the code the
    /// spec asks for (`invalid_request`, `invalid_scope`) so they can be sent through [`crate::oauth::request::Failure`].
    pub fn from_oauth(req: AuthRequest) -> OResult<AuthenticationRequest> {
        if !Self::is_openid(&req) { return Err(OAuthError::with(ErrorCode::InvalidScope, "the openid scope is required")); }
        if req.response_type != "code" { return Err(OAuthError::new(ErrorCode::UnsupportedResponseType)); }
        let get = |n: &str| req.oidc.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
        let bad = |m: &str| OAuthError::invalid_request(m);
        let prompt = match get("prompt") { None => Prompts::default(), Some(p) => Prompts::parse(p).map_err(|_| bad("invalid prompt"))? };
        let max_age = match get("max_age") {
            None => None,
            Some(s) if !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit()) => Some(s.parse::<u64>().map_err(|_| bad("invalid max_age"))?),
            Some(_) => return Err(bad("max_age must be a non-negative integer")),
        };
        let acr_values: Vec<String> = get("acr_values").map(|s| s.split(' ').filter(|x| !x.is_empty()).map(String::from).collect()).unwrap_or_default();
        if acr_values.len() > 16 { return Err(bad("too many acr_values")); }
        let claims = match get("claims") { None => ClaimsRequest::default(), Some(c) => ClaimsRequest::parse(c).map_err(|_| bad("invalid claims parameter"))? };
        let single = |n: &str, max: usize| -> OResult<Option<String>> {
            match get(n) { None => Ok(None), Some(s) if s.len() <= max && !s.chars().any(char::is_control) => Ok(Some(s.to_string())), Some(_) => Err(bad(&format!("invalid {n}"))) }
        };
        Ok(AuthenticationRequest {
            prompt, max_age, acr_values, claims, login_hint: single("login_hint", 512)?, id_token_hint: single("id_token_hint", 8192)?,
            ui_locales: get("ui_locales").map(|s| s.split(' ').filter(|x| !x.is_empty()).map(String::from).collect()).unwrap_or_default(),
            display: single("display", 16)?, oauth: req,
        })
    }

    /// Must the ID token include `auth_time`? (`max_age` was sent, or `auth_time` is an essential claim)
    pub fn requires_auth_time(&self) -> bool { self.max_age.is_some() || self.claims.requires_auth_time() }

    /// Scopes for the ID token and UserInfo: claim names the granted scopes entitle the client to, plus the `claims` request.
    pub fn userinfo_claim_names(&self, granted: &Scope) -> Vec<String> {
        let mut v: Vec<String> = vec!["sub".into()];
        for s in granted.tokens() { for c in scope_claims(s) { if !v.iter().any(|x| x == c) { v.push((*c).into()); } } }
        for c in self.claims.userinfo_names() { if !v.iter().any(|x| x == c) { v.push(c.into()); } }
        v
    }
}

/// What the OP knows about the browser session when a request arrives.
#[derive(Debug, Clone, Default)]
pub struct SessionState {
    /// Subject of the logged-in user. `None`: nobody is logged in.
    pub subject: Option<String>,
    /// When the user last actively authenticated (not when the session was last used).
    pub auth_time: Option<u64>,
    pub acr: Option<String>,
    /// Does this user already have a standing consent for this client and these scopes?
    pub has_consent: bool,
}

/// The single next step for the OP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Issue the code now: the user is logged in, recent enough, consenting, and nothing asked to see them again.
    Proceed,
    /// Show the login page. `force` means the existing session must not be reused (`prompt=login`, `max_age`, acr, or a hint mismatch).
    Login { force: bool },
    Consent,
    SelectAccount,
    /// Fail the request with this error (sent to the redirect URI).
    Error(ErrorCode),
}

/// Policy knobs on the OP.
#[derive(Debug, Clone, Default)]
pub struct DecidePolicy {
    pub now: Option<u64>,
    /// `acr` values this OP can satisfy at all. A request that demands (essentially) only values outside this list gets an error.
    pub supported_acr: Vec<String>,
}

/// Turns request plus session into one next step (Core 3.1.2.1 and 3.1.2.6).
///
/// Order of reasoning:
/// 1. `prompt=none` forbids any UI. It succeeds only if the session is good as it stands; otherwise `login_required`,
///    `consent_required`, `interaction_required` or `account_selection_required` as the spec names.
/// 2. `prompt=login`, an expired `max_age`, an `id_token_hint` for another user and an unmet acr each force re-authentication.
/// 3. `prompt=select_account` and `prompt=consent` force those screens.
/// 4. A first-time user gets login, then consent.
pub fn decide(r: &AuthenticationRequest, s: &SessionState, p: &DecidePolicy, hint_subject: Option<&str>) -> Next {
    let now = p.now.unwrap_or_else(unix_now);
    let none = r.prompt.has(Prompt::None);

    // Is the existing session unusable for this request?
    let mut reauth = r.prompt.has(Prompt::Login);
    let logged_in = s.subject.is_some();
    if logged_in {
        if let Some(max) = r.max_age {
            // max_age=0 means "authenticate now", the same as prompt=login (Core 3.1.2.1 note on max_age).
            if max == 0 || s.auth_time.map_or(true, |t| now.saturating_sub(t) > max) { reauth = true; }
        }
        if let (Some(h), Some(sub)) = (hint_subject, s.subject.as_deref()) { if h != sub { reauth = true; } }
    }
    // acr: the session's level must be one of the requested values. If it is not, a new login is the only way to reach it.
    let mut wanted: Vec<&str> = r.acr_values.iter().map(String::as_str).collect();
    let mut acr_essential = false;
    if let Some((req, vals)) = r.claims.acr() { wanted.extend(vals); acr_essential = req.essential; }
    if !wanted.is_empty() {
        if !p.supported_acr.is_empty() && !wanted.iter().any(|w| p.supported_acr.iter().any(|a| a == w)) && acr_essential {
            return Next::Error(ErrorCode::UnmetAuthenticationRequirements);
        }
        if logged_in && !s.acr.as_deref().map_or(false, |a| wanted.contains(&a)) { reauth = true; }
    }

    if none {
        if !logged_in { return Next::Error(ErrorCode::LoginRequired); }
        if reauth { return Next::Error(ErrorCode::LoginRequired); }
        if !s.has_consent { return Next::Error(ErrorCode::ConsentRequired); }
        return Next::Proceed;
    }
    if !logged_in || reauth { return Next::Login { force: reauth }; }
    if r.prompt.has(Prompt::SelectAccount) { return Next::SelectAccount; }
    if r.prompt.has(Prompt::Consent) || !s.has_consent { return Next::Consent; }
    Next::Proceed
}

/// Checks the mandatory outcomes before an ID token is signed. Call it right before issuing. `auth_time` must be present when the
/// request needed it, and a user authenticated before `max_age` allows must not receive a token.
pub fn check_issuable(r: &AuthenticationRequest, s: &SessionState, now: Option<u64>) -> OResult<()> {
    let now = now.unwrap_or_else(unix_now);
    if r.requires_auth_time() && s.auth_time.is_none() { return Err(OAuthError::new(ErrorCode::ServerError)); }
    if let (Some(max), Some(t)) = (r.max_age, s.auth_time) {
        if now.saturating_sub(t) > max.saturating_add(5) { return Err(OAuthError::new(ErrorCode::LoginRequired)); }
    }
    Ok(())
}

/// Convenience for building the `claims`-driven extra members of an ID token: copies the requested claims out of `profile`
/// (a JSON object of everything the OP knows about the user), honouring `value`/`values` constraints. Claims the user does not have
/// are left out; an essential one that is missing is reported in the second return value.
pub fn pick_claims(requested: &[(String, ClaimRequest)], profile: &Map<String, Value>) -> (Vec<(String, Value)>, Vec<String>) {
    let mut out = vec![];
    let mut missing = vec![];
    for (name, req) in requested {
        match profile.get(name) {
            Some(v) if req.value.as_ref().map_or(true, |w| w == v) && (req.values.is_empty() || req.values.contains(v)) => out.push((name.clone(), v.clone())),
            _ => if req.essential { missing.push(name.clone()) },
        }
    }
    (out, missing)
}
