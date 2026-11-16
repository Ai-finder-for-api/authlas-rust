//! C ABI slice 7: client authentication (RFC 6749 2.3, RFC 7523) and DPoP (RFC 9449), stateless except for the replay
//! cache, which the host supplies through a callback so every instance shares one view of seen assertions and proofs.

use super::*;
use crate::oauth::client_auth::{self, Method, Presented, Registered};
use crate::oauth::dpop::{self, Expect, NonceSource};
use crate::jwt::ReplayCache;
use std::ffi::CString;

/// Replay cache the host provides. `first_use(user, key, exp, now)` returns 1 when `key` is new (and records it until
/// `exp`), 0 when it was already seen, and a negative value on failure. Share one store across instances.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuthlasReplayCache {
    pub user: *mut std::ffi::c_void,
    pub first_use: Option<unsafe extern "C" fn(user: *mut std::ffi::c_void, key: *const c_char, exp: u64, now: u64) -> c_int>,
}

/// Adapter from the C callback to the Rust `ReplayCache` trait. A failing host store is treated as "seen" so that
/// authentication fails closed rather than accepting a possible replay.
struct CReplay(AuthlasReplayCache);

impl ReplayCache for CReplay {
    fn first_use(&self, key: &str, exp: u64, now: u64) -> bool {
        let Some(f) = self.0.first_use else { return false };
        let Ok(c) = CString::new(key) else { return false };
        unsafe { f(self.0.user, c.as_ptr(), exp, now) == 1 }
    }
}

fn presented_from_json(v: &Value) -> Result<Presented, CErr> {
    let o = v.as_object().ok_or_else(|| CErr::Arg("presented must be a JSON object".into()))?;
    let client_id = o_str(o, "client_id")?.map(str::to_string);
    let secret = o_str(o, "secret")?.map(str::to_string);
    let assertion = o_str(o, "assertion")?.map(str::to_string);
    match o_str(o, "method")? {
        Some("client_secret_basic") => Ok(Presented::Basic {
            client_id: client_id.ok_or_else(|| CErr::Arg("client_id is required".into()))?,
            secret: secret.ok_or_else(|| CErr::Arg("secret is required".into()))?,
        }),
        Some("client_secret_post") => Ok(Presented::Post {
            client_id: client_id.ok_or_else(|| CErr::Arg("client_id is required".into()))?,
            secret: secret.ok_or_else(|| CErr::Arg("secret is required".into()))?,
        }),
        Some("private_key_jwt") | Some("client_secret_jwt") => Ok(Presented::Assertion {
            client_id,
            assertion: assertion.ok_or_else(|| CErr::Arg("assertion is required".into()))?,
        }),
        Some("none") => Ok(Presented::None { client_id: client_id.ok_or_else(|| CErr::Arg("client_id is required".into()))? }),
        _ => Err(CErr::Arg("method must be client_secret_basic, client_secret_post, private_key_jwt, client_secret_jwt or none".into())),
    }
}

fn registered_from_json(v: &Value) -> Result<Registered, CErr> {
    let o = v.as_object().ok_or_else(|| CErr::Arg("registered must be a JSON object".into()))?;
    let method = Method::parse(o_str(o, "method")?.ok_or_else(|| CErr::Arg("method is required".into()))?)
        .ok_or_else(|| CErr::Arg("unknown method".into()))?;
    let secret = match o_str(o, "secret")? {
        Some(s) => Some(s.as_bytes().to_vec()),
        None => None,
    };
    let secret_is_hash = o.get("secret_is_hash").and_then(Value::as_bool).unwrap_or(false);
    let jwk = match o.get("jwk") {
        None | Some(Value::Null) => None,
        Some(j) => Some(Jwk::parse(&j.to_string())?),
    };
    Ok(Registered {
        client_id: o_str(o, "client_id")?.ok_or_else(|| CErr::Arg("client_id is required".into()))?.to_string(),
        method,
        secret,
        secret_is_hash,
        jwk,
        assertion_algs: match o.get("assertion_algs") {
            None | Some(Value::Null) => Vec::new(),
            Some(_) => o_algs(o, "assertion_algs")?,
        },
    })
}

/// Authenticates a client against its registration (RFC 6749 2.3, RFC 7523 3). `presented_json` and `registered_json`
/// are the JSON forms of the two structs. `replay` may be a NULL callback set; in that case assertion replay is not
/// checked, so production callers must supply one. `issuer` may be NULL. Output: the authenticated client_id.
#[no_mangle]
pub unsafe extern "C" fn authlas_client_authenticate(
    presented_json: *const c_char,
    registered_json: *const c_char,
    token_endpoint: *const c_char,
    issuer: *const c_char,
    replay: AuthlasReplayCache,
    now: u64,
    out: *mut AuthlasBuf,
) -> c_int {
    run(out, || {
        let p: Value = serde_json::from_str(text(presented_json, "presented_json")?)?;
        let r: Value = serde_json::from_str(text(registered_json, "registered_json")?)?;
        let presented = presented_from_json(&p)?;
        let registered = registered_from_json(&r)?;
        let iss = if issuer.is_null() { None } else { Some(text(issuer, "issuer")?) };
        let cache = CReplay(replay);
        let cache_ref: Option<&dyn ReplayCache> = if replay.first_use.is_some() { Some(&cache) } else { None };
        let id = client_auth::authenticate(
            &presented,
            &registered,
            text(token_endpoint, "token_endpoint")?,
            iss,
            if now == 0 { None } else { Some(now) },
            cache_ref,
        )
        .map_err(CErr::from)?;
        Ok(id.into_bytes())
    })
}

/// Builds a DPoP proof (RFC 9449 4.2). `key_json` is the private JWK. `access_token` and `nonce` may be NULL (no access
/// token on a token request; no server nonce when the server did not ask for one). Output: the compact proof JWT.
#[no_mangle]
pub unsafe extern "C" fn authlas_dpop_build(key_json: *const c_char, method: *const c_char, url: *const c_char, access_token: *const c_char, nonce: *const c_char, alg: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let key = jwk(key_json, "key_json")?;
        let alg: Algorithm = text(alg, "alg")?.parse().map_err(|_| CErr::Arg("unknown alg".into()))?;
        let at = if access_token.is_null() { None } else { Some(text(access_token, "access_token")?) };
        let nc = if nonce.is_null() { None } else { Some(text(nonce, "nonce")?) };
        let builder = dpop::ProofBuilder {
            alg,
            key: &key,
            method: text(method, "method")?,
            url: text(url, "url")?,
            access_token: at,
            nonce: nc,
        };
        Ok(builder.build()?.into_bytes())
    })
}

/// Hashes an access token for the `ath` claim (RFC 9449 4.2). Output: base64url SHA-256.
#[no_mangle]
pub unsafe extern "C" fn authlas_dpop_ath(access_token: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(dpop::access_token_hash(text(access_token, "access_token")?)?.into_bytes()))
}

/// Normalises an HTTP URL for the `htu` claim (RFC 9449 4.3). Output: the normalised URL. Fails for URLs with query
/// or fragment components the spec says must not be compared.
#[no_mangle]
pub unsafe extern "C" fn authlas_dpop_normalize_htu(url: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let u = text(url, "url")?;
        dpop::normalize_htu(u).map(String::into_bytes).ok_or_else(|| CErr::Arg("url cannot be normalised".into()))
    })
}

/// Issues a DPoP server nonce (RFC 9449 8). `secret` is a host secret, kept by the host and reused across instances.
/// `lifetime` is in seconds. Output: the nonce.
#[no_mangle]
pub unsafe extern "C" fn authlas_dpop_nonce_issue(secret: *const u8, secret_len: usize, lifetime: u64, now: u64, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        if secret.is_null() || secret_len < 16 {
            return Err(CErr::Arg("nonce secret must be at least 16 bytes".into()));
        }
        let s = std::slice::from_raw_parts(secret, secret_len);
        let src = NonceSource::new(s, lifetime)?;
        Ok(src.issue(if now == 0 { None } else { Some(now) })?.into_bytes())
    })
}

/// Checks a DPoP nonce against the host secret and lifetime. Output: `"valid"` or an error.
#[no_mangle]
pub unsafe extern "C" fn authlas_dpop_nonce_check(secret: *const u8, secret_len: usize, lifetime: u64, nonce: *const c_char, now: u64, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        if secret.is_null() || secret_len < 16 {
            return Err(CErr::Arg("nonce secret must be at least 16 bytes".into()));
        }
        let s = std::slice::from_raw_parts(secret, secret_len);
        let src = NonceSource::new(s, lifetime)?;
        if src.is_valid(text(nonce, "nonce")?, if now == 0 { None } else { Some(now) }) {
            Ok(b"valid".to_vec())
        } else {
            Err(CErr::Arg("nonce is invalid or expired".into()))
        }
    })
}
