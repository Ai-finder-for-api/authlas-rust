//! Device grant state rules (RFC 8628), as pure functions over a record.
//!
//! These are the single copy of the rules. The C ABI host callbacks (`capi_device.rs`) call them, and so do the Rust
//! tests. The host stores the record and serialises operations per device code; these functions only decide the change.

use crate::{b64, crypto, jwa::Hash};

/// Device record as the host stores it. `device_hash` is the base64url SHA-256 of the device code; the raw device code
/// is never stored.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceRecord {
    pub device_hash: String,
    pub client_id: String,
    pub scope: String,
    pub user_code: String,
    pub expires_at: u64,
    pub interval: u64,
    pub last_poll: u64,
    /// "pending", "approved", "denied" or "consumed".
    pub state: String,
    pub subject: Option<String>,
    pub grant_id: String,
    pub failed_user_attempts: u32,
}

pub fn device_hash(device_code: &str) -> String {
    b64::encode(crypto::digest(Hash::Sha256, device_code.as_bytes()).unwrap_or_default())
}

/// A code can be shown on the verification page or approved only while pending, unexpired and under the attempt
/// limit (RFC 8628 5.1).
pub fn usable(r: &DeviceRecord, now: u64, max_attempts: u32) -> bool {
    r.state == "pending" && now < r.expires_at && r.failed_user_attempts < max_attempts
}

/// Outcome of one device poll (RFC 8628 3.5). Mutates `r` (interval, last_poll, state) and returns the error code the
/// device gets, or `Ok(())` when the grant is ready to issue. A ready grant moves to "consumed" so it issues once.
pub fn poll_step(r: &mut DeviceRecord, client_id: &str, now: u64) -> Result<(), &'static str> {
    if r.client_id != client_id {
        return Err("invalid_grant");
    }
    if now >= r.expires_at {
        return Err("expired_token");
    }
    // Polling faster than the interval raises the interval by 5 s and returns slow_down.
    if r.last_poll != 0 && now < r.last_poll + r.interval {
        r.interval += 5;
        r.last_poll = now;
        return Err("slow_down");
    }
    r.last_poll = now;
    match r.state.as_str() {
        "pending" => Err("authorization_pending"),
        "denied" => Err("access_denied"),
        "consumed" => Err("invalid_grant"),
        "approved" => {
            r.state = "consumed".into();
            Ok(())
        }
        _ => Err("invalid_grant"),
    }
}

/// Records the user's decision. `subject` of `Some` approves, `None` denies. Refused unless the code is usable.
pub fn decide_step(r: &mut DeviceRecord, subject: Option<&str>, now: u64, max_attempts: u32) -> Result<(), ()> {
    if !usable(r, now, max_attempts) {
        return Err(());
    }
    match subject {
        Some(s) => {
            r.state = "approved".into();
            r.subject = Some(s.into());
        }
        None => r.state = "denied".into(),
    }
    Ok(())
}
