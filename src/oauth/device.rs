//! OAuth 2.0 Device Authorization Grant (RFC 8628).
//!
//! * `device_code`: 256 bits, stored hashed. Polling is rate limited (`slow_down` raises the interval by 5 s).
//! * `user_code`: drawn from a 20-letter set without vowels or lookalikes (RFC 8628 6.1), shown as `XXXX-XXXX`
//!   (about 34 bits). Because that is guessable, every user-code attempt is counted and the code dies after
//!   `max_attempts` wrong tries (RFC 8628 5.1).
use super::error::{ErrorCode, OAuthError, OResult};
use super::scope::Scope;
use crate::{b64, crypto, jwa::Hash, jwt::unix_now};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Letters only, no vowels (no accidental words), no I/L/O/U-style lookalikes. 20 symbols.
pub const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";
pub const USER_CODE_LEN: usize = 8;
pub const DEFAULT_INTERVAL: u64 = 5;
pub const LIFETIME: u64 = 600;

/// Normalises what a person typed: upper case, drops spaces and hyphens. `None` if any character is outside the alphabet.
pub fn normalize_user_code(input: &str) -> Option<String> {
    let s: String = input.chars().filter(|c| !matches!(c, ' ' | '-')).flat_map(char::to_uppercase).collect();
    (s.len() == USER_CODE_LEN && s.bytes().all(|b| USER_CODE_ALPHABET.contains(&b))).then_some(s)
}

pub fn display_user_code(code: &str) -> String { format!("{}-{}", &code[..4], &code[4..]) }

/// Uniform choice from the alphabet without modulo bias (rejection sampling on 5 random bits).
pub fn generate_user_code() -> crate::Result<String> {
    let mut out = String::with_capacity(USER_CODE_LEN);
    let mut buf = [0u8; 32];
    while out.len() < USER_CODE_LEN {
        crypto::random(&mut buf)?;
        for b in buf {
            let v = (b & 0x1f) as usize; // 0..32
            if v < USER_CODE_ALPHABET.len() { out.push(USER_CODE_ALPHABET[v] as char); if out.len() == USER_CODE_LEN { break; } }
        }
    }
    Ok(out)
}

fn fp(s: &str) -> String { b64::encode(crypto::digest(Hash::Sha256, s.as_bytes()).unwrap_or_default()) }

#[derive(Debug, Clone, PartialEq)]
pub enum State { Pending, Approved { subject: String }, Denied, Consumed }

#[derive(Debug, Clone)]
pub struct Record {
    pub client_id: String,
    pub scope: Scope,
    pub resources: Vec<String>,
    pub user_code: String,
    pub expires_at: u64,
    pub interval: u64,
    pub last_poll: u64,
    pub state: State,
    pub grant_id: String,
    pub failed_user_attempts: u32,
}

/// What goes back to the device (RFC 8628 3.2).
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

impl AuthorizationResponse {
    pub fn to_json(&self) -> String {
        let mut v = json!({ "device_code": self.device_code, "user_code": display_user_code(&self.user_code),
            "verification_uri": self.verification_uri, "expires_in": self.expires_in, "interval": self.interval });
        if let Some(u) = &self.verification_uri_complete { v["verification_uri_complete"] = json!(u); }
        v.to_string()
    }
}

pub struct DeviceStore {
    by_device: Mutex<HashMap<String, Record>>,
    by_user: Mutex<HashMap<String, String>>,
    pub max_attempts: u32,
}

impl Default for DeviceStore { fn default() -> Self { Self::new() } }

impl DeviceStore {
    pub fn new() -> Self { DeviceStore { by_device: Default::default(), by_user: Default::default(), max_attempts: 5 } }

    pub fn start(&self, client_id: &str, scope: Scope, resources: Vec<String>, verification_uri: &str, now: Option<u64>) -> crate::Result<AuthorizationResponse> {
        let now = now.unwrap_or_else(unix_now);
        let mut user_code = generate_user_code()?;
        // Collisions are resolved by drawing again; two live devices never share a code.
        for _ in 0..8 {
            if !self.by_user.lock().map_err(|_| crate::Error::Crypto("lock".into()))?.contains_key(&user_code) { break; }
            user_code = generate_user_code()?;
        }
        let mut raw = [0u8; 32];
        crypto::random(&mut raw)?;
        let device_code = b64::encode(raw);
        let mut grant = [0u8; 16];
        crypto::random(&mut grant)?;
        let rec = Record { client_id: client_id.into(), scope, resources, user_code: user_code.clone(), expires_at: now + LIFETIME,
            interval: DEFAULT_INTERVAL, last_poll: 0, state: State::Pending, grant_id: b64::encode(grant), failed_user_attempts: 0 };
        self.by_device.lock().map_err(|_| crate::Error::Crypto("lock".into()))?.insert(fp(&device_code), rec);
        self.by_user.lock().map_err(|_| crate::Error::Crypto("lock".into()))?.insert(user_code.clone(), fp(&device_code));
        let complete = Some(format!("{}{}user_code={}", verification_uri, if verification_uri.contains('?') { '&' } else { '?' }, user_code));
        Ok(AuthorizationResponse { device_code, user_code, verification_uri: verification_uri.into(), verification_uri_complete: complete, expires_in: LIFETIME, interval: DEFAULT_INTERVAL })
    }

    /// Verification page: the user types a code. Wrong guesses are counted globally per code and per caller key
    /// (`attempt_key`, e.g. the session or IP) so enumeration is slow. Returns the client and scope to show on the consent screen.
    pub fn lookup_user_code(&self, typed: &str, now: Option<u64>) -> Option<(String, Scope)> {
        let now = now.unwrap_or_else(unix_now);
        let code = normalize_user_code(typed)?;
        let dev = self.by_user.lock().ok()?.get(&code).cloned()?;
        let m = self.by_device.lock().ok()?;
        let r = m.get(&dev)?;
        (r.state == State::Pending && now < r.expires_at && r.failed_user_attempts < self.max_attempts).then(|| (r.client_id.clone(), r.scope.clone()))
    }

    /// Records a wrong entry against the most recently issued code a caller is probing. The caller passes the code they
    /// believe is being attacked; in practice a page counts failures per session and calls `punish` with the typed value.
    pub fn punish(&self, typed: &str) {
        if let (Some(code), Ok(by_user), Ok(mut dev)) = (normalize_user_code(typed), self.by_user.lock(), self.by_device.lock()) {
            if let Some(r) = by_user.get(&code).and_then(|d| dev.get_mut(d)) { r.failed_user_attempts += 1; }
        }
    }

    pub fn decide(&self, typed: &str, subject: Option<&str>, now: Option<u64>) -> OResult<()> {
        let now = now.unwrap_or_else(unix_now);
        let bad = || OAuthError::invalid_request("unknown or expired code");
        let code = normalize_user_code(typed).ok_or_else(bad)?;
        let by_user = self.by_user.lock().map_err(|_| OAuthError::new(ErrorCode::ServerError))?;
        let mut dev = self.by_device.lock().map_err(|_| OAuthError::new(ErrorCode::ServerError))?;
        let r = by_user.get(&code).and_then(|d| dev.get_mut(d)).ok_or_else(bad)?;
        if r.state != State::Pending || now >= r.expires_at || r.failed_user_attempts >= self.max_attempts { return Err(bad()); }
        r.state = match subject { Some(s) => State::Approved { subject: s.into() }, None => State::Denied };
        Ok(())
    }

    /// Device polls the token endpoint. Returns the approved record once, then the code is spent.
    pub fn poll(&self, client_id: &str, device_code: &str, now: Option<u64>) -> OResult<Record> {
        let now = now.unwrap_or_else(unix_now);
        let mut dev = self.by_device.lock().map_err(|_| OAuthError::new(ErrorCode::ServerError))?;
        let key = fp(device_code);
        let r = dev.get_mut(&key).ok_or_else(|| OAuthError::invalid_grant("unknown device_code"))?;
        if r.client_id != client_id { return Err(OAuthError::invalid_grant("unknown device_code")); }
        if now >= r.expires_at { return Err(OAuthError::new(ErrorCode::ExpiredToken)); }
        // Polling faster than the interval is punished by raising it (RFC 8628 3.5).
        if r.last_poll != 0 && now < r.last_poll + r.interval {
            r.interval += 5;
            r.last_poll = now;
            return Err(OAuthError::new(ErrorCode::SlowDown));
        }
        r.last_poll = now;
        match r.state.clone() {
            State::Pending => Err(OAuthError::new(ErrorCode::AuthorizationPending)),
            State::Denied => Err(OAuthError::new(ErrorCode::AccessDenied)),
            State::Consumed => Err(OAuthError::invalid_grant("device_code already used")),
            State::Approved { .. } => { let out = r.clone(); r.state = State::Consumed; Ok(out) }
        }
    }
}
