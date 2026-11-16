//! C ABI slice 6: device grant (RFC 8628) with host storage and per-device-code locking.
//!
//! Contract (docs/CALLBACKS.md): the host serialises every operation on one device code, holding its own lock from
//! the moment it reads the record until it has saved the result. The library computes each change with the rules in
//! `oauth::device_rules` and returns the new record. The host saves it.
//!
//! Wrong user codes are counted per `attempt_key` (the session or IP making the guess), because a wrong guess matches
//! no record. The count is checked before any record lookup, so an exhausted caller is refused even for a real code.

use super::*;
use crate::oauth::device::{self, DEFAULT_INTERVAL, LIFETIME};
use crate::oauth::device_rules::{decide_step, device_hash, poll_step, usable, DeviceRecord};
use crate::oauth::scope::Scope;
use crate::{b64, crypto};
use std::ffi::CString;

fn record_to_json(r: &DeviceRecord) -> Value {
    json!({
        "device_hash": r.device_hash, "client_id": r.client_id, "scope": r.scope, "user_code": r.user_code,
        "expires_at": r.expires_at, "interval": r.interval, "last_poll": r.last_poll, "state": r.state,
        "subject": r.subject, "grant_id": r.grant_id, "failed_user_attempts": r.failed_user_attempts,
    })
}

fn record_from_json(v: &Value) -> Result<DeviceRecord, String> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string).ok_or(format!("record missing {k}"));
    let n = |k: &str| v.get(k).and_then(Value::as_u64).ok_or(format!("record missing {k}"));
    Ok(DeviceRecord {
        device_hash: s("device_hash")?,
        client_id: s("client_id")?,
        scope: s("scope")?,
        user_code: s("user_code")?,
        expires_at: n("expires_at")?,
        interval: n("interval")?,
        last_poll: n("last_poll")?,
        state: s("state")?,
        subject: v.get("subject").and_then(Value::as_str).map(str::to_string),
        grant_id: s("grant_id")?,
        failed_user_attempts: n("failed_user_attempts")? as u32,
    })
}

/// Host storage for device grants. Every callback returns 0 on success. Byte and string fields are JSON strings.
///
/// Locking: the host must hold a lock keyed by `device_hash` (or by `user_code` for user-code lookups) from the first
/// read until the final `save` returns, so two operations on one device never interleave. A per-key mutex is enough.
/// Attempt counters need their own lock keyed by `attempt_key`.
///
/// `insert(user, record_json)`: store a new record.
/// `find_by_user_code(user, user_code, out)`: write the record JSON, or an empty buffer when none exists.
/// `find_by_device_hash(user, device_hash, out)`: write the record JSON, or an empty buffer when none exists.
/// `save(user, record_json)`: overwrite the record with the one the library computed.
/// `find_attempts(user, attempt_key, out)`: write the failure count as a decimal string, or an empty buffer for zero.
/// `save_attempts(user, attempt_key, count)`: store the failure count for an attempt key.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuthlasDeviceStore {
    pub user: *mut std::ffi::c_void,
    pub insert: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, record_json: *const c_char) -> c_int>,
    pub find_by_user_code: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, user_code: *const c_char, out: *mut AuthlasBuf) -> c_int>,
    pub find_by_device_hash: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, device_hash: *const c_char, out: *mut AuthlasBuf) -> c_int>,
    pub save: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, record_json: *const c_char) -> c_int>,
    pub find_attempts: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, attempt_key: *const c_char, out: *mut AuthlasBuf) -> c_int>,
    pub save_attempts: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, attempt_key: *const c_char, count: u32) -> c_int>,
}

type FindFn = Option<unsafe extern "C" fn(*mut std::ffi::c_void, *const c_char, *mut AuthlasBuf) -> c_int>;
type WriteFn = Option<unsafe extern "C" fn(*mut std::ffi::c_void, *const c_char) -> c_int>;

unsafe fn host_find(f: FindFn, user: *mut std::ffi::c_void, key: &str) -> Result<Option<DeviceRecord>, CErr> {
    let f = f.ok_or_else(|| CErr::Arg("device store callback missing".into()))?;
    let c = CString::new(key).map_err(|_| CErr::Arg("key contains NUL".into()))?;
    let mut out = AuthlasBuf { data: std::ptr::null_mut(), len: 0 };
    let status = f(user, c.as_ptr(), &mut out);
    let bytes = if status == 0 && !out.data.is_null() { std::slice::from_raw_parts(out.data, out.len).to_vec() } else { Vec::new() };
    authlas_buf_free(&mut out);
    if status != 0 {
        return Err(CErr::Arg(format!("device store lookup returned {status}")));
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    let v: Value = serde_json::from_slice(&bytes)?;
    record_from_json(&v).map(Some).map_err(CErr::Arg)
}

unsafe fn host_write(f: WriteFn, user: *mut std::ffi::c_void, r: &DeviceRecord) -> Result<(), CErr> {
    let f = f.ok_or_else(|| CErr::Arg("device store callback missing".into()))?;
    let c = CString::new(record_to_json(r).to_string()).map_err(|_| CErr::Arg("record contains NUL".into()))?;
    match f(user, c.as_ptr()) {
        0 => Ok(()),
        s => Err(CErr::Arg(format!("device store write returned {s}"))),
    }
}

/// Reads the failure count for an attempt key. Zero when the host has none.
unsafe fn attempts_get(store: &AuthlasDeviceStore, key: &str) -> Result<u32, CErr> {
    let f = store.find_attempts.ok_or_else(|| CErr::Arg("find_attempts callback missing".into()))?;
    let c = CString::new(key).map_err(|_| CErr::Arg("attempt_key contains NUL".into()))?;
    let mut out = AuthlasBuf { data: std::ptr::null_mut(), len: 0 };
    let status = f(store.user, c.as_ptr(), &mut out);
    let bytes = if status == 0 && !out.data.is_null() { std::slice::from_raw_parts(out.data, out.len).to_vec() } else { Vec::new() };
    authlas_buf_free(&mut out);
    if status != 0 {
        return Err(CErr::Arg(format!("find_attempts returned {status}")));
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    std::str::from_utf8(&bytes).ok().and_then(|s| s.parse().ok()).ok_or_else(|| CErr::Arg("attempt count is not a number".into()))
}

unsafe fn attempts_set(store: &AuthlasDeviceStore, key: &str, count: u32) -> Result<(), CErr> {
    let f = store.save_attempts.ok_or_else(|| CErr::Arg("save_attempts callback missing".into()))?;
    let c = CString::new(key).map_err(|_| CErr::Arg("attempt_key contains NUL".into()))?;
    match f(store.user, c.as_ptr(), count) {
        0 => Ok(()),
        s => Err(CErr::Arg(format!("save_attempts returned {s}"))),
    }
}

/// Refuses a caller who has used up their guesses. Checked before any lookup, so a real code gives no answer either.
unsafe fn check_not_exhausted(store: &AuthlasDeviceStore, key: &str, max_attempts: u32) -> Result<(), CErr> {
    if attempts_get(store, key)? >= max_attempts {
        return Err(CErr::Arg("too many attempts".into()));
    }
    Ok(())
}

/// Starts a device authorization (RFC 8628 3.1). `verification_uri` is the host's page. `scope` may be NULL.
/// Output: `{"device_code", "user_code", "verification_uri", "verification_uri_complete", "expires_in", "interval"}`.
/// The raw device code is returned once and only its hash is stored.
#[no_mangle]
pub unsafe extern "C" fn authlas_device_start(store: AuthlasDeviceStore, client_id: *const c_char, scope: *const c_char, verification_uri: *const c_char, now: u64, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let scope = if scope.is_null() { Scope::default() } else { Scope::parse(text(scope, "scope")?)? };
        let uri = text(verification_uri, "verification_uri")?;
        let now = if now == 0 { crate::jwt::unix_now() } else { now };
        let user_code = device::generate_user_code()?;
        let mut raw = [0u8; 32];
        crypto::random(&mut raw)?;
        let device_code = b64::encode(raw);
        let mut grant = [0u8; 16];
        crypto::random(&mut grant)?;
        let rec = DeviceRecord {
            device_hash: device_hash(&device_code),
            client_id: text(client_id, "client_id")?.to_string(),
            scope: scope.to_string(),
            user_code: user_code.clone(),
            expires_at: now + LIFETIME,
            interval: DEFAULT_INTERVAL,
            last_poll: 0,
            state: "pending".into(),
            subject: None,
            grant_id: b64::encode(grant),
            failed_user_attempts: 0,
        };
        let f = store.insert.ok_or_else(|| CErr::Arg("insert callback missing".into()))?;
        let c = CString::new(record_to_json(&rec).to_string()).map_err(|_| CErr::Arg("record contains NUL".into()))?;
        if f(store.user, c.as_ptr()) != 0 {
            return Err(CErr::Arg("device store insert failed".into()));
        }
        let complete = format!("{}{}user_code={}", uri, if uri.contains('?') { '&' } else { '?' }, device::display_user_code(&user_code));
        Ok(json!({
            "device_code": device_code,
            "user_code": device::display_user_code(&user_code),
            "verification_uri": uri,
            "verification_uri_complete": complete,
            "expires_in": LIFETIME,
            "interval": DEFAULT_INTERVAL,
        }).to_string().into_bytes())
    })
}

/// Verification page lookup. `attempt_key` identifies the caller (session or IP). Output: `{"client_id", "scope"}` when
/// the typed code is usable. A code that is unknown or unusable counts as a failed attempt against `attempt_key`.
#[no_mangle]
pub unsafe extern "C" fn authlas_device_lookup(store: AuthlasDeviceStore, attempt_key: *const c_char, typed_user_code: *const c_char, max_attempts: u32, now: u64, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let key = text(attempt_key, "attempt_key")?;
        check_not_exhausted(&store, key, max_attempts)?;
        let now = if now == 0 { crate::jwt::unix_now() } else { now };
        let typed = text(typed_user_code, "user_code")?;
        let usable_rec = match device::normalize_user_code(typed) {
            Some(code) => host_find(store.find_by_user_code, store.user, &code)?.filter(|r| usable(r, now, max_attempts)),
            None => None,
        };
        match usable_rec {
            Some(r) => Ok(json!({ "client_id": r.client_id, "scope": r.scope }).to_string().into_bytes()),
            None => {
                attempts_set(&store, key, attempts_get(&store, key)? + 1)?;
                Err(CErr::Arg("unknown or expired code".into()))
            }
        }
    })
}

/// Approves (`subject` non-NULL) or denies (`subject` NULL) a pending code from the verification page. A wrong code
/// counts against `attempt_key`, and a code that matches a record also counts against that record. Output:
/// `"approved"` or `"denied"`.
#[no_mangle]
pub unsafe extern "C" fn authlas_device_decide(store: AuthlasDeviceStore, attempt_key: *const c_char, typed_user_code: *const c_char, subject: *const c_char, max_attempts: u32, now: u64, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let key = text(attempt_key, "attempt_key")?;
        check_not_exhausted(&store, key, max_attempts)?;
        let now = if now == 0 { crate::jwt::unix_now() } else { now };
        let typed = text(typed_user_code, "user_code")?;
        let subj = if subject.is_null() { None } else { Some(text(subject, "subject")?) };
        let found = match device::normalize_user_code(typed) {
            Some(code) => host_find(store.find_by_user_code, store.user, &code)?,
            None => None,
        };
        let Some(mut r) = found else {
            attempts_set(&store, key, attempts_get(&store, key)? + 1)?;
            return Err(CErr::Arg("unknown or expired code".into()));
        };
        match decide_step(&mut r, subj, now, max_attempts) {
            Ok(()) => {
                host_write(store.save, store.user, &r)?;
                Ok(if subj.is_some() { b"approved".to_vec() } else { b"denied".to_vec() })
            }
            Err(()) => {
                // The guess matched a record that is not usable: count it against the record and the caller.
                r.failed_user_attempts += 1;
                host_write(store.save, store.user, &r)?;
                attempts_set(&store, key, attempts_get(&store, key)? + 1)?;
                Err(CErr::Arg("unknown or expired code".into()))
            }
        }
    })
}

/// Device poll at the token endpoint (RFC 8628 3.4 and 3.5). On success the output is
/// `{"grant_id", "client_id", "scope", "subject"}`; the caller issues tokens for that grant. The grant is consumed
/// and cannot be polled again. Errors carry the RFC 8628 error code in the message.
#[no_mangle]
pub unsafe extern "C" fn authlas_device_poll(store: AuthlasDeviceStore, client_id: *const c_char, device_code: *const c_char, now: u64, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let now = if now == 0 { crate::jwt::unix_now() } else { now };
        let client = text(client_id, "client_id")?;
        let hash = device_hash(text(device_code, "device_code")?);
        let mut r = host_find(store.find_by_device_hash, store.user, &hash)?.ok_or_else(|| CErr::Arg("invalid_grant".into()))?;
        let result = poll_step(&mut r, client, now);
        host_write(store.save, store.user, &r)?;
        match result {
            Ok(()) => Ok(json!({
                "grant_id": r.grant_id, "client_id": r.client_id, "scope": r.scope, "subject": r.subject,
            }).to_string().into_bytes()),
            Err(code) => Err(CErr::Arg(code.into())),
        }
    })
}
