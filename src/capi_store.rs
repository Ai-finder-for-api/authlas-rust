//! C ABI slice 3: host-supplied storage through callbacks (see docs/CALLBACKS.md).
//!
//! The host passes a table of function pointers plus a `user` pointer. The library calls them when it needs state.
//! Rules: a callback returns 0 for success, any other value for an error. Strings and buffers that cross the boundary
//! are copied, and the library owns every buffer it passes out.

use super::*;
use crate::oauth::form::Params;
use crate::oauth::par_host::{self, PushStorage, StoredPush};
use std::ffi::CString;

/// Storage for pushed authorization requests (RFC 9126). All callbacks receive `user` unchanged.
///
/// `save(user, json)`: store the record given as a JSON object with `request_uri`, `client_id`, `query`, `expires_at`.
/// Return 0 on success.
///
/// `take(user, request_uri, out)`: remove the record for `request_uri` and write it as JSON into `out` (use
/// `authlas_buf_write`). Return 0 and an empty buffer when no record exists. The record must be removed in the same
/// step, so a reference works once.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuthlasPushStore {
    pub user: *mut std::ffi::c_void,
    pub save: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, record_json: *const c_char) -> c_int>,
    pub take: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, request_uri: *const c_char, out: *mut AuthlasBuf) -> c_int>,
}

/// Adapter: implements the Rust `PushStorage` trait by calling the host's C callbacks.
struct CPushStore(AuthlasPushStore);

impl PushStorage for CPushStore {
    fn save(&self, rec: StoredPush) -> Result<(), String> {
        let save = self.0.save.ok_or("save callback missing")?;
        let json = json!({
            "request_uri": rec.request_uri, "client_id": rec.client_id,
            "query": rec.query, "expires_at": rec.expires_at,
        })
        .to_string();
        let c = CString::new(json).map_err(|_| "record contains NUL".to_string())?;
        let status = unsafe { save(self.0.user, c.as_ptr()) };
        if status == 0 { Ok(()) } else { Err(format!("save callback returned {status}")) }
    }

    fn take(&self, request_uri: &str) -> Result<Option<StoredPush>, String> {
        let take = self.0.take.ok_or("take callback missing")?;
        let c = CString::new(request_uri).map_err(|_| "request_uri contains NUL".to_string())?;
        let mut out = AuthlasBuf { data: std::ptr::null_mut(), len: 0 };
        let status = unsafe { take(self.0.user, c.as_ptr(), &mut out) };
        if status != 0 {
            unsafe { authlas_buf_free(&mut out) };
            return Err(format!("take callback returned {status}"));
        }
        if out.data.is_null() || out.len == 0 {
            unsafe { authlas_buf_free(&mut out) };
            return Ok(None);
        }
        let bytes = unsafe { std::slice::from_raw_parts(out.data, out.len) }.to_vec();
        unsafe { authlas_buf_free(&mut out) };
        let v: Value = serde_json::from_slice(&bytes).map_err(|e| format!("take returned bad JSON: {e}"))?;
        let get = |k: &str| v.get(k).cloned().ok_or_else(|| format!("take record missing {k}"));
        Ok(Some(StoredPush {
            request_uri: get("request_uri")?.as_str().unwrap_or_default().to_string(),
            client_id: get("client_id")?.as_str().unwrap_or_default().to_string(),
            query: get("query")?.as_str().unwrap_or_default().to_string(),
            expires_at: get("expires_at")?.as_u64().unwrap_or(0),
        }))
    }
}

/// Writes a JSON or text result from a host callback into `out`. The library frees the buffer. Returns 0.
#[no_mangle]
pub unsafe extern "C" fn authlas_buf_write(out: *mut AuthlasBuf, data: *const u8, len: usize) -> c_int {
    if out.is_null() { return AuthlasStatus::InvalidArgument as c_int; }
    let bytes = if data.is_null() || len == 0 { Vec::new() } else { std::slice::from_raw_parts(data, len).to_vec() };
    put(out, bytes);
    AuthlasStatus::Ok as c_int
}

/// Pushes a client-authenticated request into the host's store. `form_body` is the raw `application/x-www-form-urlencoded`
/// body. Output: `{"request_uri", "expires_in"}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_par_push(store: AuthlasPushStore, authenticated_client: *const c_char, form_body: *const c_char, now: u64, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let raw = text(form_body, "form_body")?;
        let params = Params::parse(raw)?;
        let client = text(authenticated_client, "authenticated_client")?;
        let s = CPushStore(store);
        let (uri, life) = par_host::push(&s, client, &params, raw, if now == 0 { None } else { Some(now) })?;
        json_bytes(json!({ "request_uri": uri, "expires_in": life }))
    })
}

/// Redeems a `request_uri` at the authorization endpoint. Output: the stored query string.
#[no_mangle]
pub unsafe extern "C" fn authlas_par_redeem(store: AuthlasPushStore, client_id: *const c_char, request_uri: *const c_char, now: u64, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let s = CPushStore(store);
        let q = par_host::redeem(&s, text(client_id, "client_id")?, text(request_uri, "request_uri")?, if now == 0 { None } else { Some(now) })?;
        Ok(q.into_bytes())
    })
}
