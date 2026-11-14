//! C ABI slice 5: client registration (RFC 7591 / 7592) through host callbacks.
//! See docs/CALLBACKS.md. Shared helpers (`run`, `text`, `CErr`, `put`, `AuthlasBuf`) come from `capi.rs`.

use super::*;
use crate::b64;
use crate::oauth::registration::{self as reg, ClientRecord, ClientStore, Policy};
use std::ffi::CString;

/// Storage for registered clients. Callbacks receive `user` unchanged. Return 0 on success, non-zero on failure.
///
/// `get(user, client_id, out)`: write the record as JSON into `out`. Write an empty buffer when the client is unknown.
/// `insert(user, record_json)`: store a new record. Fail when the client_id already exists.
/// `replace(user, record_json)`: store an updated record. Fail when the client_id is unknown.
/// `remove(user, client_id)`: delete the record.
///
/// Record JSON: `{"client_id", "secret_hash", "secret_plain", "registration_token_hash", "issued_at", "metadata"}`.
/// Byte fields are base64url. `secret_hash` and `secret_plain` are null when absent. The record holds secret material,
/// so the host must keep it out of logs.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuthlasClientStore {
    pub user: *mut std::ffi::c_void,
    pub get: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, client_id: *const c_char, out: *mut AuthlasBuf) -> c_int>,
    pub insert: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, record_json: *const c_char) -> c_int>,
    pub replace: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, record_json: *const c_char) -> c_int>,
    pub remove: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, client_id: *const c_char) -> c_int>,
}

fn record_to_json(r: &ClientRecord) -> Value {
    json!({
        "client_id": r.client_id,
        "secret_hash": r.secret_hash.as_ref().map(|b| b64::encode(b)),
        "secret_plain": r.secret_plain.as_ref().map(|b| b64::encode(b)),
        "registration_token_hash": b64::encode(&r.registration_token_hash),
        "issued_at": r.issued_at,
        "metadata": Value::Object(r.metadata.to_object()),
    })
}

fn record_from_json(v: &Value) -> Result<ClientRecord, String> {
    let bytes = |k: &str| -> Result<Option<Vec<u8>>, String> {
        match v.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => b64::decode(s).map(Some).map_err(|_| format!("{k} is not base64url")),
            _ => Err(format!("{k} must be a string")),
        }
    };
    let client_id = v.get("client_id").and_then(Value::as_str).ok_or("record missing client_id")?.to_string();
    let metadata = v.get("metadata").and_then(Value::as_object).ok_or("record missing metadata")?;
    // The record was validated when it was first registered, so read it back with a permissive policy.
    let metadata = reg::Metadata::from_object(metadata, &Policy::new("")).map_err(|e| format!("bad stored metadata: {e:?}"))?;
    Ok(ClientRecord {
        client_id,
        secret_hash: bytes("secret_hash")?,
        secret_plain: bytes("secret_plain")?,
        registration_token_hash: bytes("registration_token_hash")?.ok_or("record missing registration_token_hash")?,
        issued_at: v.get("issued_at").and_then(Value::as_u64).unwrap_or(0),
        metadata,
    })
}

struct CClientStore(AuthlasClientStore);

fn cstring(s: &str) -> Option<CString> {
    CString::new(s).ok()
}

impl ClientStore for CClientStore {
    fn insert(&self, rec: ClientRecord) -> bool {
        let (Some(f), Some(c)) = (self.0.insert, cstring(&record_to_json(&rec).to_string())) else { return false };
        unsafe { f(self.0.user, c.as_ptr()) == 0 }
    }

    fn get(&self, client_id: &str) -> Option<ClientRecord> {
        let (Some(f), Some(c)) = (self.0.get, cstring(client_id)) else { return None };
        let mut out = AuthlasBuf { data: std::ptr::null_mut(), len: 0 };
        let status = unsafe { f(self.0.user, c.as_ptr(), &mut out) };
        let bytes = if status == 0 && !out.data.is_null() {
            unsafe { std::slice::from_raw_parts(out.data, out.len) }.to_vec()
        } else {
            Vec::new()
        };
        unsafe { authlas_buf_free(&mut out) };
        if bytes.is_empty() {
            return None;
        }
        let v: Value = serde_json::from_slice(&bytes).ok()?;
        record_from_json(&v).ok()
    }

    fn replace(&self, rec: ClientRecord) -> bool {
        let (Some(f), Some(c)) = (self.0.replace, cstring(&record_to_json(&rec).to_string())) else { return false };
        unsafe { f(self.0.user, c.as_ptr()) == 0 }
    }

    fn remove(&self, client_id: &str) -> bool {
        let (Some(f), Some(c)) = (self.0.remove, cstring(client_id)) else { return false };
        unsafe { f(self.0.user, c.as_ptr()) == 0 }
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Builds the registration policy from JSON. Missing fields keep the secure defaults from `Policy::new`.
/// Recognised keys: `open`, `allow_client_secret_jwt`, `allow_native`, `confidential_only`, `require_sender_constrained`
/// (booleans), and `initial_access_token_hashes` (array of hex SHA-256 strings).
fn policy_from_json(endpoint: &str, v: &Value) -> Result<Policy, CErr> {
    let mut p = Policy::new(endpoint);
    let flag = |k: &str| v.get(k).and_then(Value::as_bool);
    if let Some(b) = flag("open") {
        p.open = b;
    }
    if let Some(b) = flag("allow_client_secret_jwt") {
        p.allow_client_secret_jwt = b;
    }
    if let Some(b) = flag("allow_native") {
        p.allow_native = b;
    }
    if let Some(b) = flag("confidential_only") {
        p.confidential_only = b;
    }
    if let Some(b) = flag("require_sender_constrained") {
        p.require_sender_constrained = b;
    }
    if let Some(list) = v.get("initial_access_token_hashes").and_then(Value::as_array) {
        p.initial_access_token_hashes = list
            .iter()
            .map(|h| h.as_str().and_then(hex_decode).ok_or_else(|| CErr::Arg("initial_access_token_hashes must be hex SHA-256".into())))
            .collect::<Result<_, _>>()?;
    }
    Ok(p)
}

unsafe fn policy_arg(endpoint: *const c_char, policy_json: *const c_char) -> Result<Policy, CErr> {
    let ep = text(endpoint, "endpoint")?;
    if policy_json.is_null() {
        return Ok(Policy::new(ep));
    }
    let v: Value = serde_json::from_str(text(policy_json, "policy_json")?).map_err(|_| CErr::Arg("policy_json is not JSON".into()))?;
    policy_from_json(ep, &v)
}

/// Registers a client (RFC 7591). `policy_json` may be NULL for secure defaults. `initial_access_token` may be NULL.
/// `now` may be 0 to use the system clock. Output: the registration response JSON. It holds the client secret and the
/// registration access token when issued, so show them once and never log them.
#[no_mangle]
pub unsafe extern "C" fn authlas_client_register(
    store: AuthlasClientStore,
    endpoint: *const c_char,
    policy_json: *const c_char,
    body: *const c_char,
    initial_access_token: *const c_char,
    now: u64,
    out: *mut AuthlasBuf,
) -> c_int {
    run(out, || {
        let p = policy_arg(endpoint, policy_json)?;
        let iat = if initial_access_token.is_null() { None } else { Some(text(initial_access_token, "initial_access_token")?) };
        let s = CClientStore(store);
        let (_, response) = reg::register(&s, text(body, "body")?, iat, &p, if now == 0 { None } else { Some(now) }).map_err(CErr::from)?;
        Ok(response.into_bytes())
    })
}

/// Reads a registered client (RFC 7592). `bearer` is the registration access token, or NULL. Output: client metadata JSON.
#[no_mangle]
pub unsafe extern "C" fn authlas_client_read(
    store: AuthlasClientStore,
    endpoint: *const c_char,
    policy_json: *const c_char,
    client_id: *const c_char,
    bearer: *const c_char,
    out: *mut AuthlasBuf,
) -> c_int {
    run(out, || {
        let p = policy_arg(endpoint, policy_json)?;
        let b = if bearer.is_null() { None } else { Some(text(bearer, "bearer")?) };
        let s = CClientStore(store);
        Ok(reg::read(&s, text(client_id, "client_id")?, b, &p).map_err(CErr::from)?.into_bytes())
    })
}

/// Deletes a registered client (RFC 7592). Output: `"deleted"`.
#[no_mangle]
pub unsafe extern "C" fn authlas_client_delete(store: AuthlasClientStore, client_id: *const c_char, bearer: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let b = if bearer.is_null() { None } else { Some(text(bearer, "bearer")?) };
        let s = CClientStore(store);
        reg::delete(&s, text(client_id, "client_id")?, b).map_err(CErr::from)?;
        Ok(b"deleted".to_vec())
    })
}
