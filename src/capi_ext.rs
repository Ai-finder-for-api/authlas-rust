//! Extended C ABI, slice 1: JOSE and JWT inspection, nested JWT, SD-JWT parsing helpers, status list checks, SSRF
//! checks and time. Same rules as `capi.rs`: JSON in and out, a status code per call, panics caught at the boundary.

use super::*;
use crate::jwa::Hash;

/// Header of a compact JWS, without verifying anything. Output: the raw header object.
#[no_mangle]
pub unsafe extern "C" fn authlas_jws_peek_header(token: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let h = jws::peek_header(text(token, "token")?)?;
        json_bytes(Value::Object(h.raw))
    })
}

/// Header of a compact JWE, without decrypting. Output: the raw header object.
#[no_mangle]
pub unsafe extern "C" fn authlas_jwe_peek_header(token: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let h = jwe::peek_header(text(token, "token")?)?;
        json_bytes(Value::Object(h.raw))
    })
}

/// Claims of a compact JWS, without verifying. For routing and logs only, never for decisions.
#[no_mangle]
pub unsafe extern "C" fn authlas_jwt_peek_claims(token: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let c = jwt::peek_claims_unverified(text(token, "token")?)?;
        json_bytes(Value::Object(c.map))
    })
}

/// Sign, then encrypt. Options: `{"alg": "...", "enc": "...", "key": <recipient JWK>}`, wrapping a compact JWS.
#[no_mangle]
pub unsafe extern "C" fn authlas_jwt_encrypt_nested(inner_jws: *const c_char, options_json: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let alg: KeyAlg = o_req(&o, "alg")?.parse()?;
        let enc: Enc = o_req(&o, "enc")?.parse()?;
        let key = o.get("key").ok_or_else(|| arg("key is required"))?;
        let recipient = Jwk::parse(&key.to_string())?;
        let token = jwt::encrypt_nested(text(inner_jws, "inner_jws")?, alg, enc, &recipient)?;
        Ok(token.into_bytes())
    })
}

/// Splits `JWT~D1~...~[KB]` into its parts. Output: `{"jwt", "disclosures": [...], "kb_jwt"}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_sdjwt_split(sd_jwt: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let p = sdjwt::split(text(sd_jwt, "sd_jwt")?)?;
        json_bytes(json!({ "jwt": p.jwt, "disclosures": p.disclosures, "kb_jwt": p.kb_jwt }))
    })
}

/// Reads one disclosure. Output: `{"name": "..." or null, "value": ...}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_sdjwt_describe(disclosure: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let (name, value) = sdjwt::describe(text(disclosure, "disclosure")?)?;
        json_bytes(json!({ "name": name, "value": value }))
    })
}

/// Digest of one disclosure (base64url). `hash`: "sha-256", "sha-384" or "sha-512".
#[no_mangle]
pub unsafe extern "C" fn authlas_sdjwt_disclosure_digest(disclosure: *const c_char, hash: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let h = o_hash(text(hash, "hash")?)?;
        Ok(sdjwt::disclosure_digest(text(disclosure, "disclosure")?, h)?.into_bytes())
    })
}

/// Name of a status value (0 = VALID, 1 = INVALID, 2 = SUSPENDED, and so on).
#[no_mangle]
pub unsafe extern "C" fn authlas_status_name(value: u8, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(crate::status_list::status_name(value).as_bytes().to_vec()))
}

/// Verifies a Status List Token and returns the list plus its freshness data.
/// Options: `{"algs": [...], "uri": "...", "now"?, "leeway"?, "max_age"?, "issuer"?, "max_bytes"?, "allow_mac"?}`.
/// Output: `{"uri", "iat", "exp", "ttl", "bits", "entries"}` where `entries` is the status value per index.
#[no_mangle]
pub unsafe extern "C" fn authlas_status_list_verify(token: *const c_char, key: *const c_char, options_json: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let o = options(options_json)?;
        let algs = o_algs(&o, "algs")?;
        let uri = o_req(&o, "uri")?;
        let mut p = crate::status_list::TokenPolicy::new(&algs, uri);
        p.now = o_u64(&o, "now")?;
        if let Some(l) = o_u64(&o, "leeway")? { p.leeway = l; }
        p.max_age = o_u64(&o, "max_age")?;
        p.issuer = o_str(&o, "issuer")?;
        if let Some(m) = o_u64(&o, "max_bytes")? { p.max_bytes = m as usize; }
        if let Some(Value::Bool(b)) = o.get("allow_mac") { p.allow_mac = *b; }
        let v = crate::status_list::verify_token(text(token, "token")?, &jwk(key, "key")?, &p)?;
        let entries: Vec<u8> = (0..v.list.len()).map(|i| v.list.get(i).unwrap_or(0)).collect();
        json_bytes(json!({
            "uri": v.uri, "iat": v.iat, "exp": v.exp, "ttl": v.ttl,
            "bits": v.list.bits(), "entries": entries
        }))
    })
}

/// SSRF guard for a URL a client gave you. Output: the parsed URL as text. Refuses anything not public https.
#[no_mangle]
pub unsafe extern "C" fn authlas_ssrf_check(url: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(crate::ssrf::ssrf_check(text(url, "url")?)?.to_string().into_bytes()))
}

/// Returns 1 when the IP address is public and routable, 0 when it is private, reserved or loopback.
#[no_mangle]
pub unsafe extern "C" fn authlas_is_public_ip(ip: *const c_char, is_public: *mut c_int) -> c_int {
    let addr = match text(ip, "ip") {
        Ok(s) => s,
        Err(_) => return AuthlasStatus::InvalidArgument as c_int,
    };
    match addr.parse::<std::net::IpAddr>() {
        Ok(a) => {
            if !is_public.is_null() { *is_public = crate::ssrf::is_public_ip(a) as c_int; }
            AuthlasStatus::Ok as c_int
        }
        Err(_) => AuthlasStatus::InvalidArgument as c_int,
    }
}

/// Current Unix time in seconds.
#[no_mangle]
pub extern "C" fn authlas_unix_now() -> u64 {
    crate::jwt::unix_now()
}
