//! C ABI for Authlas.
//!
//! Design rules, so every language binding can stay thin and safe:
//! * Text is UTF-8, NUL-terminated. Binary input is `(pointer, length)`. Inputs larger than 16 MiB are refused.
//! * Structured inputs and outputs are JSON. This keeps the ABI small and stable: a new option is a new JSON member, not a new
//!   function signature.
//! * Every function returns `0` on success and a non-zero [`AuthlasStatus`] on failure. Results come back in an
//!   [`AuthlasBuf`] that the caller releases with [`authlas_buf_free`], which also wipes it (results can hold private keys).
//! * The reason for a failure is on the calling thread: [`authlas_last_error`] returns a JSON object
//!   `{"kind": "...", "message": "..."}`, and for OAuth protocol errors `{"kind":"oauth","error":"invalid_token","status":401,...}`.
//! * No function panics across the boundary. A Rust panic becomes `AUTHLAS_PANIC`.
//! * Nothing here keeps state except the replay cache handle (`AuthlasReplay`). Stores for codes, refresh tokens and clients stay in
//!   the host language, where the application's database is.
#![allow(clippy::missing_safety_doc)]
use crate::jwa::{Algorithm, Hash};
use crate::jwe::{self, Enc, KeyAlg};
use crate::jwk::Jwk;
use crate::jwt::{self, Claims, MemoryReplayCache, ReplayCache};
use crate::oauth::{at_jwt, bearer, dpop, error::ErrorCode, metadata, pkce, redirect, scope::Scope, OAuthError};
use crate::{b64, jws, sdjwt, x509, Error};
use serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

const MAX_INPUT: usize = 16 * 1024 * 1024;

/// Result buffer. `data` is NUL-terminated for convenience; `len` does not count that NUL.
#[repr(C)]
pub struct AuthlasBuf {
    pub data: *mut u8,
    pub len: usize,
}

/// Status codes returned by every function.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthlasStatus {
    Ok = 0,
    Malformed = 1,
    Algorithm = 2,
    Key = 3,
    BadSignature = 4,
    Claim = 5,
    Crypto = 6,
    Unsupported = 7,
    Decrypt = 8,
    /// An OAuth protocol error; the JSON error has `error`, `status` and `description`.
    Oauth = 9,
    /// The caller passed a null pointer, bad UTF-8, bad JSON options or an out-of-range value.
    InvalidArgument = 10,
    Panic = 11,
}

/// Opaque replay cache for `jti` values. Create with [`authlas_replay_new`], free with [`authlas_replay_free`].
pub struct AuthlasReplay(MemoryReplayCache);

// ---------------------------------------------------------------------------------------------------------------------
// plumbing
// ---------------------------------------------------------------------------------------------------------------------

enum CErr { Lib(Error), OAuth(OAuthError), Arg(String) }
impl From<Error> for CErr { fn from(e: Error) -> Self { CErr::Lib(e) } }
impl From<OAuthError> for CErr { fn from(e: OAuthError) -> Self { CErr::OAuth(e) } }
impl From<serde_json::Error> for CErr { fn from(e: serde_json::Error) -> Self { CErr::Arg(format!("json: {e}")) } }
fn arg(m: &str) -> CErr { CErr::Arg(m.to_string()) }

thread_local! { static LAST: RefCell<CString> = RefCell::new(CString::default()); }

fn set_last(v: Value) {
    let s = CString::new(v.to_string().replace('\0', "")).unwrap_or_default();
    LAST.with(|l| *l.borrow_mut() = s);
}

fn fail(e: CErr) -> c_int {
    let (st, v) = match e {
        CErr::Lib(e) => {
            let (st, kind) = match &e {
                Error::Malformed(_) => (AuthlasStatus::Malformed, "malformed"), Error::Algorithm(_) => (AuthlasStatus::Algorithm, "algorithm"),
                Error::Key(_) => (AuthlasStatus::Key, "key"), Error::BadSignature => (AuthlasStatus::BadSignature, "bad_signature"),
                Error::Claim(_) => (AuthlasStatus::Claim, "claim"), Error::Crypto(_) => (AuthlasStatus::Crypto, "crypto"),
                Error::Unsupported(_) => (AuthlasStatus::Unsupported, "unsupported"), Error::Decrypt => (AuthlasStatus::Decrypt, "decrypt"),
                #[allow(unreachable_patterns)]
                _ => (AuthlasStatus::Crypto, "error"),
            };
            (st, json!({ "kind": kind, "message": e.to_string() }))
        }
        CErr::OAuth(e) => (AuthlasStatus::Oauth, json!({ "kind": "oauth", "error": e.code.as_str(), "description": e.description, "status": e.status() })),
        CErr::Arg(m) => (AuthlasStatus::InvalidArgument, json!({ "kind": "invalid_argument", "message": m })),
    };
    set_last(v);
    st as c_int
}

fn put(out: *mut AuthlasBuf, mut bytes: Vec<u8>) {
    let len = bytes.len();
    bytes.push(0);
    let b = bytes.into_boxed_slice();
    let p = Box::into_raw(b) as *mut u8;
    unsafe { (*out).data = p; (*out).len = len; }
}

/// Runs `f`, converts panics and errors, and writes the result.
fn run(out: *mut AuthlasBuf, f: impl FnOnce() -> Result<Vec<u8>, CErr>) -> c_int {
    if out.is_null() { set_last(json!({"kind":"invalid_argument","message":"out is null"})); return AuthlasStatus::InvalidArgument as c_int; }
    unsafe { (*out).data = std::ptr::null_mut(); (*out).len = 0; }
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(b)) => { put(out, b); AuthlasStatus::Ok as c_int }
        Ok(Err(e)) => fail(e),
        Err(_) => { set_last(json!({"kind":"panic","message":"internal error"})); AuthlasStatus::Panic as c_int }
    }
}

fn text<'a>(p: *const c_char, name: &str) -> Result<&'a str, CErr> {
    if p.is_null() { return Err(CErr::Arg(format!("{name} is null"))); }
    let s = unsafe { CStr::from_ptr(p) }.to_str().map_err(|_| CErr::Arg(format!("{name} is not UTF-8")))?;
    if s.len() > MAX_INPUT { return Err(CErr::Arg(format!("{name} is too large"))); }
    Ok(s)
}
fn opt_text<'a>(p: *const c_char, name: &str) -> Result<Option<&'a str>, CErr> { if p.is_null() { Ok(None) } else { text(p, name).map(Some) } }
fn blob<'a>(p: *const u8, len: usize, name: &str) -> Result<&'a [u8], CErr> {
    if len > MAX_INPUT { return Err(CErr::Arg(format!("{name} is too large"))); }
    if len == 0 { return Ok(&[]); }
    if p.is_null() { return Err(CErr::Arg(format!("{name} is null"))); }
    Ok(unsafe { std::slice::from_raw_parts(p, len) })
}
fn options(p: *const c_char) -> Result<Map<String, Value>, CErr> {
    match opt_text(p, "options")? { None => Ok(Map::new()), Some(s) => crate::json::parse_object(s.as_bytes()).map_err(|e| CErr::Arg(format!("options: {e}"))) }
}
fn jwk(p: *const c_char, name: &str) -> Result<Jwk, CErr> { Ok(Jwk::parse(text(p, name)?)?) }

fn o_str<'a>(o: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>, CErr> {
    match o.get(k) { None | Some(Value::Null) => Ok(None), Some(Value::String(s)) => Ok(Some(s)), Some(_) => Err(CErr::Arg(format!("{k} must be a string"))) }
}
fn o_req<'a>(o: &'a Map<String, Value>, k: &str) -> Result<&'a str, CErr> { o_str(o, k)?.ok_or_else(|| CErr::Arg(format!("{k} is required"))) }
fn o_u64(o: &Map<String, Value>, k: &str) -> Result<Option<u64>, CErr> {
    match o.get(k) { None | Some(Value::Null) => Ok(None), Some(v) => v.as_u64().map(Some).ok_or_else(|| CErr::Arg(format!("{k} must be a non-negative integer"))) }
}
fn o_list(o: &Map<String, Value>, k: &str) -> Result<Vec<String>, CErr> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| CErr::Arg(format!("{k} must contain strings")))).collect(),
        Some(_) => Err(CErr::Arg(format!("{k} must be an array"))),
    }
}
fn o_algs(o: &Map<String, Value>, k: &str) -> Result<Vec<Algorithm>, CErr> {
    let names = o_list(o, k)?;
    if names.is_empty() { return Err(CErr::Arg(format!("{k} is required: list the algorithms you accept"))); }
    names.iter().map(|n| n.parse::<Algorithm>().map_err(CErr::from)).collect()
}
fn o_hash(s: &str) -> Result<Hash, CErr> {
    match s { "sha-256" => Ok(Hash::Sha256), "sha-384" => Ok(Hash::Sha384), "sha-512" => Ok(Hash::Sha512), _ => Err(arg("unknown hash")) }
}
fn replay_ref<'a>(p: *const AuthlasReplay) -> Option<&'a dyn ReplayCache> { if p.is_null() { None } else { Some(unsafe { &(*p).0 }) } }
fn json_bytes(v: Value) -> Result<Vec<u8>, CErr> { Ok(serde_json::to_vec(&v)?) }

// ---------------------------------------------------------------------------------------------------------------------
// general
// ---------------------------------------------------------------------------------------------------------------------

/// ABI version. Bumped only on breaking changes to existing functions.
pub const AUTHLAS_ABI_VERSION: u32 = 1;

#[no_mangle]
pub extern "C" fn authlas_abi_version() -> u32 { AUTHLAS_ABI_VERSION }

/// Library version, NUL-terminated, static.
#[no_mangle]
pub extern "C" fn authlas_version() -> *const c_char { concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char }

/// Name of the active crypto backend (e.g. "awslc", "hardened"), NUL-terminated, valid for the process lifetime.
#[no_mangle]
pub extern "C" fn authlas_backend() -> *const c_char {
    static NAME: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
    NAME.get_or_init(|| CString::new(crate::crypto::backend_name()).unwrap_or_default()).as_ptr()
}

/// JSON description of the last failure on this thread. Valid until the next Authlas call on this thread. Never null.
#[no_mangle]
pub extern "C" fn authlas_last_error() -> *const c_char { LAST.with(|l| l.borrow().as_ptr()) }

/// Wipes and frees a result buffer. Accepts a zeroed buffer. Safe to call twice on the same struct.
#[no_mangle]
pub unsafe extern "C" fn authlas_buf_free(buf: *mut AuthlasBuf) {
    if buf.is_null() { return; }
    let b = &mut *buf;
    if !b.data.is_null() {
        let n = b.len + 1;
        let s = std::slice::from_raw_parts_mut(b.data, n);
        for x in s.iter_mut() { std::ptr::write_volatile(x, 0); }
        drop(Box::from_raw(s as *mut [u8]));
    }
    b.data = std::ptr::null_mut();
    b.len = 0;
}

#[no_mangle]
pub extern "C" fn authlas_replay_new() -> *mut AuthlasReplay { Box::into_raw(Box::new(AuthlasReplay(MemoryReplayCache::new()))) }

#[no_mangle]
pub unsafe extern "C" fn authlas_replay_free(r: *mut AuthlasReplay) { if !r.is_null() { drop(Box::from_raw(r)); } }

// ---------------------------------------------------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------------------------------------------------

/// Generates an EC key (`crv`: "P-256", "P-384" or "P-521"). Output: the private JWK as JSON.
#[no_mangle]
pub unsafe extern "C" fn authlas_jwk_generate_ec(crv: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(crate::crypto::ec_generate(text(crv, "crv")?)?.to_json().into_bytes()))
}

/// Public part of a JWK. Fails for symmetric keys.
#[no_mangle]
pub unsafe extern "C" fn authlas_jwk_public(key: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(jwk(key, "key")?.public()?.to_json().into_bytes()))
}

/// RFC 7638 thumbprint (SHA-256, base64url).
#[no_mangle]
pub unsafe extern "C" fn authlas_jwk_thumbprint(key: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(jwk(key, "key")?.thumbprint(Hash::Sha256)?.into_bytes()))
}

// ---------------------------------------------------------------------------------------------------------------------
// JWS / JWT / JWE
// ---------------------------------------------------------------------------------------------------------------------

/// Signs `payload` as a compact JWS. `header_json` is an optional object of extra header members (`typ`, `kid`, ...).
#[no_mangle]
pub unsafe extern "C" fn authlas_jws_sign(alg: *const c_char, key: *const c_char, header_json: *const c_char, payload: *const u8, payload_len: usize, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let alg: Algorithm = text(alg, "alg")?.parse()?;
        let extra = options(header_json)?;
        Ok(jws::sign(alg, &jwk(key, "key")?, &extra, blob(payload, payload_len, "payload")?)?.into_bytes())
    })
}

/// Verifies a compact JWS. `options`: `{"algs": ["ES256"], "typ": "...", "crit": ["..."]}`. `algs` is required.
/// Output: `{"header": {...}, "payload": "<base64url>"}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_jws_verify(token: *const c_char, key: *const c_char, options_json: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let algs = o_algs(&o, "algs")?;
        let crit = o_list(&o, "crit")?;
        let crit_refs: Vec<&str> = crit.iter().map(String::as_str).collect();
        let mut p = jws::Policy::new(&algs);
        p.typ = o_str(&o, "typ")?;
        p.understood_crit = &crit_refs;
        let (h, payload) = jws::verify(text(token, "token")?, &jwk(key, "key")?, &p)?;
        json_bytes(json!({ "header": h.raw, "payload": b64::encode(payload) }))
    })
}

/// Signs a JWT. `claims_json` is the claims object. `typ` may be null (defaults to "JWT").
#[no_mangle]
pub unsafe extern "C" fn authlas_jwt_sign(alg: *const c_char, key: *const c_char, claims_json: *const c_char, typ: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let alg: Algorithm = text(alg, "alg")?.parse()?;
        let claims = Claims::parse(text(claims_json, "claims")?.as_bytes())?;
        Ok(jwt::sign(alg, &jwk(key, "key")?, &claims, opt_text(typ, "typ")?)?.into_bytes())
    })
}

/// Verifies a JWT. `options`: `{"algs": [...], "issuer": "...", "audience": "...", "typ": "...", "leeway": 30, "now": 0,
/// "require": ["sub"], "max_age": 600}`. `algs`, `issuer` and `audience` are required. `replay` may be null.
/// Output: `{"header": {...}, "claims": {...}}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_jwt_verify(token: *const c_char, key: *const c_char, options_json: *const c_char, replay: *const AuthlasReplay, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let algs = o_algs(&o, "algs")?;
        let require = o_list(&o, "require")?;
        let require_refs: Vec<&str> = require.iter().map(String::as_str).collect();
        let mut v = jwt::Validation::new(&algs, o_req(&o, "issuer")?, o_req(&o, "audience")?);
        if let Some(l) = o_u64(&o, "leeway")? { v.leeway = l; }
        v.now = o_u64(&o, "now")?;
        v.typ = o_str(&o, "typ")?;
        v.require = &require_refs;
        v.max_age = o_u64(&o, "max_age")?;
        v.replay = replay_ref(replay);
        let (h, c) = jwt::verify(text(token, "token")?, &jwk(key, "key")?, &v)?;
        json_bytes(json!({ "header": h.raw, "claims": c.map }))
    })
}

/// Encrypts `plaintext` as a compact JWE. `header_json` may carry extra protected header members (e.g. `p2c`, `kid`).
#[no_mangle]
pub unsafe extern "C" fn authlas_jwe_encrypt(alg: *const c_char, enc: *const c_char, key: *const c_char, header_json: *const c_char, plaintext: *const u8, plaintext_len: usize, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let alg: KeyAlg = text(alg, "alg")?.parse()?;
        let enc: Enc = text(enc, "enc")?.parse()?;
        let extra = options(header_json)?;
        Ok(jwe::encrypt(alg, enc, &jwk(key, "key")?, &extra, blob(plaintext, plaintext_len, "plaintext")?)?.into_bytes())
    })
}

/// Decrypts a compact JWE. `options`: `{"algs": ["A256KW"], "encs": ["A256GCM"]}`, both required. Output: the plaintext bytes.
#[no_mangle]
pub unsafe extern "C" fn authlas_jwe_decrypt(token: *const c_char, key: *const c_char, options_json: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let algs: Vec<KeyAlg> = o_list(&o, "algs")?.iter().map(|s| s.parse::<KeyAlg>().map_err(CErr::from)).collect::<Result<_, _>>()?;
        let encs: Vec<Enc> = o_list(&o, "encs")?.iter().map(|s| s.parse::<Enc>().map_err(CErr::from)).collect::<Result<_, _>>()?;
        if algs.is_empty() || encs.is_empty() { return Err(arg("algs and encs are required: list what you accept")); }
        let (_, pt) = jwe::decrypt(text(token, "token")?, &jwk(key, "key")?, &jwe::Policy::new(&algs, &encs))?;
        Ok(pt)
    })
}

// ---------------------------------------------------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------------------------------------------------

/// New PKCE pair. Output: `{"verifier": "...", "challenge": "...", "method": "S256"}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_pkce_new(out: *mut AuthlasBuf) -> c_int {
    run(out, || { let v = pkce::generate_verifier()?; let c = pkce::s256_challenge(&v)?; json_bytes(json!({ "verifier": v, "challenge": c, "method": "S256" })) })
}

/// Checks an S256 verifier against the stored challenge. Output is empty on success.
#[no_mangle]
pub unsafe extern "C" fn authlas_pkce_verify(challenge: *const c_char, verifier: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || { pkce::verify(text(challenge, "challenge")?, pkce::Method::S256, text(verifier, "verifier")?)?; Ok(vec![]) })
}

/// Validates a redirect URI at registration time. `kind`: "web" or "native".
#[no_mangle]
pub unsafe extern "C" fn authlas_redirect_validate(uri: *const c_char, kind: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let k = match text(kind, "kind")? { "web" => redirect::ClientKind::Web, "native" => redirect::ClientKind::Native, _ => return Err(arg("kind must be web or native")) };
        redirect::validate_registered(text(uri, "uri")?, k)?;
        Ok(vec![])
    })
}

/// Exact redirect URI comparison (with the RFC 8252 loopback port exception). `*matches` is set to 1 or 0.
#[no_mangle]
pub unsafe extern "C" fn authlas_redirect_matches(registered: *const c_char, presented: *const c_char, matches: *mut c_int) -> c_int {
    let mut sink = AuthlasBuf { data: std::ptr::null_mut(), len: 0 };
    if matches.is_null() { set_last(json!({"kind":"invalid_argument","message":"matches is null"})); return AuthlasStatus::InvalidArgument as c_int; }
    let rc = run(&mut sink, || { let r = redirect::matches(text(registered, "registered")?, text(presented, "presented")?); *matches = r as c_int; Ok(vec![]) });
    authlas_buf_free(&mut sink);
    rc
}

/// Splits an `Authorization` header. Output: `{"scheme": "Bearer"|"DPoP", "token": "..."}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_bearer_parse(header: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let (s, t) = bearer::parse_authorization(text(header, "header")?)?;
        json_bytes(json!({ "scheme": match s { bearer::Scheme::Bearer => "Bearer", bearer::Scheme::DPoP => "DPoP" }, "token": t }))
    })
}

/// Builds a `WWW-Authenticate` value. `options`: `{"scheme": "Bearer", "realm": "...", "error": "invalid_token",
/// "description": "...", "scope": "...", "resource_metadata": "..."}`; only `realm` is required.
#[no_mangle]
pub unsafe extern "C" fn authlas_bearer_challenge(options_json: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let scheme = match o_str(&o, "scheme")?.unwrap_or("Bearer") { "Bearer" => bearer::Scheme::Bearer, "DPoP" => bearer::Scheme::DPoP, _ => return Err(arg("scheme must be Bearer or DPoP")) };
        let err = match o_str(&o, "error")? { None => None, Some(e) => Some(ErrorCode::parse(e).ok_or_else(|| arg("unknown error code"))?) };
        Ok(bearer::challenge(scheme, o_req(&o, "realm")?, err, o_str(&o, "description")?, o_str(&o, "scope")?, o_str(&o, "resource_metadata")?).into_bytes())
    })
}

/// Verifies an RFC 9068 JWT access token at a resource server. `options`: `{"algs", "issuer", "audience", "now", "leeway"}`.
/// Output: `{"subject", "client_id", "scope", "jti", "exp", "claims"}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_at_jwt_verify(token: *const c_char, key: *const c_char, options_json: *const c_char, replay: *const AuthlasReplay, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let algs = o_algs(&o, "algs")?;
        let t = at_jwt::verify(text(token, "token")?, &jwk(key, "key")?, &at_jwt::Verify {
            algs: &algs, issuer: o_req(&o, "issuer")?, audience: o_req(&o, "audience")?, now: o_u64(&o, "now")?, leeway: o_u64(&o, "leeway")?.unwrap_or(30), replay: replay_ref(replay) })?;
        json_bytes(json!({ "subject": t.subject, "client_id": t.client_id, "scope": t.scope.to_string(), "jti": t.jti, "exp": t.exp, "claims": t.claims.map }))
    })
}

/// Builds a DPoP proof (RFC 9449). `access_token` and `nonce` may be null.
#[no_mangle]
pub unsafe extern "C" fn authlas_dpop_proof(alg: *const c_char, key: *const c_char, method: *const c_char, url: *const c_char, access_token: *const c_char, nonce: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let k = jwk(key, "key")?;
        Ok(dpop::ProofBuilder { alg: text(alg, "alg")?.parse()?, key: &k, method: text(method, "method")?, url: text(url, "url")?,
            access_token: opt_text(access_token, "access_token")?, nonce: opt_text(nonce, "nonce")? }.build()?.into_bytes())
    })
}

/// Verifies a DPoP proof. `options`: `{"algs", "method", "url", "access_token", "nonce", "now", "leeway"}`; `algs`, `method` and `url`
/// are required. Output: `{"jkt": "...", "jwk": {...}, "claims": {...}}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_dpop_verify(proof: *const c_char, options_json: *const c_char, replay: *const AuthlasReplay, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let algs = o_algs(&o, "algs")?;
        let v = dpop::verify_proof(text(proof, "proof")?, &dpop::Expect { algs: &algs, method: o_req(&o, "method")?, url: o_req(&o, "url")?,
            access_token: o_str(&o, "access_token")?, nonce: o_str(&o, "nonce")?, now: o_u64(&o, "now")?, leeway: o_u64(&o, "leeway")?.unwrap_or(5), replay: replay_ref(replay) })?;
        json_bytes(json!({ "jkt": v.jkt, "jwk": serde_json::from_str::<Value>(&v.jwk.to_json())?, "claims": v.claims.map }))
    })
}

/// Parses and validates authorization server metadata (RFC 8414) fetched for `expected_issuer`. Output:
/// `{"metadata": {...}, "problems_for_code_flow": [...]}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_as_metadata_parse(body: *const c_char, expected_issuer: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let m = metadata::AsMetadata::parse(text(body, "body")?, text(expected_issuer, "expected_issuer")?)?;
        json_bytes(json!({ "metadata": serde_json::from_str::<Value>(&m.to_json())?, "problems_for_code_flow": m.problems_for_code_flow() }))
    })
}

/// Scope string helper: checks that `requested` is a subset of `allowed`. Output: `{"ok": bool, "excess": [...]}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_scope_check(requested: *const c_char, allowed: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let (r, a) = (Scope::parse(text(requested, "requested")?)?, Scope::parse(text(allowed, "allowed")?)?);
        let excess: Vec<&str> = r.excess(&a);
        json_bytes(json!({ "ok": excess.is_empty(), "excess": excess }))
    })
}

// ---------------------------------------------------------------------------------------------------------------------
// X.509 for mutual TLS
// ---------------------------------------------------------------------------------------------------------------------

#[path = "capi_ext.rs"]
mod ext;
#[path = "capi_oauth.rs"]
mod oauth_ext;
#[path = "capi_store.rs"]
mod store_ext;

fn cert_json(c: &x509::Certificate) -> Result<Vec<u8>, CErr> {
    let sans: Vec<Value> = c.sans.iter().map(|s| match s {
        x509::San::Dns(v) => json!({"type": "dns", "value": v}), x509::San::Uri(v) => json!({"type": "uri", "value": v}),
        x509::San::Ip(v) => json!({"type": "ip", "value": v.to_string()}), x509::San::Email(v) => json!({"type": "email", "value": v}),
    }).collect();
    let jwk = c.public_jwk().ok().and_then(|k| serde_json::from_str::<Value>(&k.to_json()).ok());
    json_bytes(json!({ "x5t_s256": c.x5t_s256()?, "subject": c.subject_rfc4514, "sans": sans, "not_before": c.not_before, "not_after": c.not_after, "jwk": jwk }))
}

/// Reads a DER certificate. Output: `{"x5t_s256", "subject", "sans", "not_before", "not_after", "jwk"}`. Does not validate the chain.
#[no_mangle]
pub unsafe extern "C" fn authlas_cert_info(der: *const u8, der_len: usize, out: *mut AuthlasBuf) -> c_int {
    run(out, || cert_json(&x509::Certificate::from_der(blob(der, der_len, "der")?)?))
}

/// Same as [`authlas_cert_info`] for a certificate a TLS proxy forwarded in a header (base64 DER, PEM or URL-encoded PEM).
#[no_mangle]
pub unsafe extern "C" fn authlas_cert_info_from_header(value: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || cert_json(&x509::from_forwarded_header(text(value, "value")?)?))
}

// ---------------------------------------------------------------------------------------------------------------------
// SD-JWT (RFC 9901)
// ---------------------------------------------------------------------------------------------------------------------

/// Issues an SD-JWT. `options`: `{"alg", "hash": "sha-256", "decoys": 0, "typ": "dc+sd-jwt", "holder_jwk": {...},
/// "hide": ["given_name", "address/street", "nationalities/1"]}`; `alg` and `typ` are required.
/// Output: `{"sd_jwt": "jwt~d1~d2~", "disclosures": [...]}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_sdjwt_issue(claims_json: *const c_char, key: *const c_char, options_json: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let claims = crate::json::parse_object(text(claims_json, "claims")?.as_bytes())?;
        let k = jwk(key, "key")?;
        let holder = match o.get("holder_jwk") { None | Some(Value::Null) => None, Some(v) => Some(Jwk::parse(&v.to_string())?) };
        let hide: Vec<Vec<sdjwt::Seg>> = o_list(&o, "hide")?.iter().map(|p| sdjwt::path(p)).collect();
        let issuer = sdjwt::Issuer { alg: o_req(&o, "alg")?.parse()?, key: &k, hash: o_hash(o_str(&o, "hash")?.unwrap_or("sha-256"))?,
            decoys: o_u64(&o, "decoys")?.unwrap_or(0).min(1000) as usize, holder_key: holder.as_ref(), typ: o_req(&o, "typ")? };
        let issued = issuer.issue(&claims, &hide)?;
        json_bytes(json!({ "sd_jwt": issued.compact, "disclosures": issued.disclosures }))
    })
}

/// Holder: chooses disclosures and optionally adds a key-binding JWT. `options`: `{"reveal": [0, 2], "key_binding":
/// {"alg", "jwk": {...private...}, "audience", "nonce", "hash": "sha-256"}}`. Output: the presentation string.
#[no_mangle]
pub unsafe extern "C" fn authlas_sdjwt_present(sd_jwt: *const c_char, options_json: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let reveal: Vec<usize> = match o.get("reveal") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(a)) => a.iter().map(|x| x.as_u64().map(|n| n as usize).ok_or_else(|| arg("reveal must contain indexes"))).collect::<Result<_, _>>()?,
            Some(_) => return Err(arg("reveal must be an array")),
        };
        let pres = sdjwt::Presentation { sd_jwt: text(sd_jwt, "sd_jwt")?, reveal: &reveal }.build()?;
        let Some(kb) = o.get("key_binding").and_then(Value::as_object) else { return Ok(pres.into_bytes()) };
        let k = Jwk::parse(&kb.get("jwk").ok_or_else(|| arg("key_binding.jwk is required"))?.to_string())?;
        Ok(sdjwt::Presentation::with_key_binding(&pres, o_hash(o_str(kb, "hash")?.unwrap_or("sha-256"))?, o_req(kb, "alg")?.parse()?, &k, o_req(kb, "audience")?, o_req(kb, "nonce")?)?.into_bytes())
    })
}

/// Verifier. `options`: `{"algs", "issuer", "hashes": ["sha-256"], "audience", "typ", "now", "leeway", "require": [...],
/// "key_binding": {"algs", "audience", "nonce", "max_age"}}`. Key binding is required exactly when `key_binding` is present
/// in the options, whatever the holder sent. Output: `{"claims", "header", "key_binding_verified"}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_sdjwt_verify(sd_jwt: *const c_char, issuer_key: *const c_char, options_json: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let algs = o_algs(&o, "algs")?;
        let hash_names = o_list(&o, "hashes")?;
        let hashes: Vec<Hash> = if hash_names.is_empty() { vec![Hash::Sha256, Hash::Sha384, Hash::Sha512] } else { hash_names.iter().map(|h| o_hash(h)).collect::<Result<_, _>>()? };
        let require = o_list(&o, "require")?;
        let require_refs: Vec<&str> = require.iter().map(String::as_str).collect();
        let kb_algs;
        let kb = match o.get("key_binding") {
            None | Some(Value::Null) => None,
            Some(Value::Object(k)) => { kb_algs = o_algs(k, "algs")?; Some(sdjwt::KeyBindingPolicy { algs: &kb_algs, audience: o_req(k, "audience")?, nonce: o_req(k, "nonce")?, max_age: o_u64(k, "max_age")?.unwrap_or(300) }) }
            Some(_) => return Err(arg("key_binding must be an object")),
        };
        let r = sdjwt::verify(text(sd_jwt, "sd_jwt")?, &jwk(issuer_key, "issuer_key")?, &sdjwt::VerifyPolicy {
            algs: &algs, issuer: o_req(&o, "issuer")?, hashes: &hashes, key_binding: kb, audience: o_str(&o, "audience")?, typ: o_str(&o, "typ")?,
            now: o_u64(&o, "now")?, leeway: o_u64(&o, "leeway")?.unwrap_or(30), require: &require_refs })?;
        json_bytes(json!({ "claims": r.claims, "header": r.header.raw, "key_binding_verified": r.key_binding_verified }))
    })
}
