//! PAR with host-supplied storage (RFC 9126). Same rules as `ParStore` in `par_jar.rs`; the difference is that the
//! pushed-request records live in the host application's database, reached through [`PushStorage`].
//!
//! The validation here is shared with `ParStore` through the same checks (`request_uri` refused, client_id must match,
//! client authentication parameters dropped before storing). The storage is the only difference.

use super::error::{ErrorCode, OAuthError, OResult};
use super::form::Params;
use super::par_jar::{PAR_LIFETIME, REQUEST_URI_PREFIX};
use crate::{b64, crypto, jwt::unix_now};

/// One stored pushed request. The host stores it as given and returns it on redeem. It holds no secrets: client
/// authentication parameters are removed before the record is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPush {
    pub request_uri: String,
    pub client_id: String,
    pub query: String,
    pub expires_at: u64,
}

/// Storage the host provides. The library calls `save` once per push and `take` once per redeem. `take` must remove the
/// record in the same step it returns it, so a `request_uri` works once even under concurrent use.
pub trait PushStorage {
    fn save(&self, rec: StoredPush) -> Result<(), String>;
    /// Removes and returns the record for `request_uri`, or `None` when it does not exist.
    fn take(&self, request_uri: &str) -> Result<Option<StoredPush>, String>;
}

/// Pushes an already client-authenticated request. Returns the `request_uri` and its lifetime.
pub fn push(store: &dyn PushStorage, authenticated_client: &str, body: &Params, raw_body: &str, now: Option<u64>) -> OResult<(String, u64)> {
    if body.contains("request_uri") {
        return Err(OAuthError::invalid_request("request_uri is not allowed in a pushed request"));
    }
    if let Some(c) = body.get("client_id").map_err(|_| OAuthError::invalid_request("client_id repeated"))? {
        if c != authenticated_client {
            return Err(OAuthError::invalid_client("client_id does not match the authenticated client"));
        }
    }
    let kept: Vec<(String, String)> = url::form_urlencoded::parse(raw_body.as_bytes())
        .filter(|(k, _)| !matches!(k.as_ref(), "client_secret" | "client_assertion" | "client_assertion_type"))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &kept {
        ser.append_pair(k, v);
    }
    if !body.contains("client_id") {
        ser.append_pair("client_id", authenticated_client);
    }
    let mut raw = [0u8; 32];
    crypto::random(&mut raw).map_err(|_| OAuthError::new(ErrorCode::ServerError))?;
    let uri = format!("{REQUEST_URI_PREFIX}{}", b64::encode(raw));
    let now = now.unwrap_or_else(unix_now);
    store
        .save(StoredPush {
            request_uri: uri.clone(),
            client_id: authenticated_client.into(),
            query: ser.finish(),
            expires_at: now + PAR_LIFETIME,
        })
        .map_err(|_| OAuthError::new(ErrorCode::ServerError))?;
    Ok((uri, PAR_LIFETIME))
}

/// Redeems a `request_uri` at the authorization endpoint. One use, only by the client that pushed it (RFC 9126 4).
/// The record is removed even when the client or the time does not match, so a leaked reference cannot be retried.
pub fn redeem(store: &dyn PushStorage, client_id: &str, request_uri: &str, now: Option<u64>) -> OResult<String> {
    let bad = || OAuthError::with(ErrorCode::InvalidRequestUri, "request_uri is unknown, expired or already used");
    if !request_uri.starts_with(REQUEST_URI_PREFIX) {
        return Err(bad());
    }
    let rec = store.take(request_uri).map_err(|_| OAuthError::new(ErrorCode::ServerError))?.ok_or_else(bad)?;
    if rec.client_id != client_id || now.unwrap_or_else(unix_now) >= rec.expires_at {
        return Err(bad());
    }
    Ok(rec.query)
}
