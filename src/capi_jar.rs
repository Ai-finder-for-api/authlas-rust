//! C ABI slice 10: request objects (RFC 9101, JAR). Verification is strict: the caller states the expected issuer, client
//! and algorithms, and the object cannot change them. Parameters outside the signed object are discarded.

use super::*;
use crate::oauth::par_jar::{self, RequestObjectRules};

/// Verifies a signed request object (RFC 9101 6.3). Inputs:
/// - `object`: the compact JWT the client sent as `request`.
/// - `key_json`: the client's public JWK, selected by the host from its registration.
/// - `algs_json`: a JSON array of allowed algorithms. Empty is refused.
/// - `client_id`: the authenticated client; must match `client_id` in the object if present.
/// - `issuer`: this authorization server's issuer (the required `aud`).
/// - `max_lifetime`: the longest allowed `exp - iat` in seconds; 0 uses 600.
/// - `require_typ`: 1 to require `typ = oauth-authz-req+jwt` (RFC 9101 10.8).
///
/// Output: the request parameters as a query string. Feed it to the authorization request validator in place of the
/// query string the browser sent.
#[no_mangle]
pub unsafe extern "C" fn authlas_request_object_verify(
    object: *const c_char,
    key_json: *const c_char,
    algs_json: *const c_char,
    client_id: *const c_char,
    issuer: *const c_char,
    max_lifetime: u64,
    require_typ: c_int,
    now: u64,
    out: *mut AuthlasBuf,
) -> c_int {
    run(out, || {
        let key = jwk(key_json, "key_json")?;
        let names: Vec<String> = serde_json::from_str(text(algs_json, "algs_json")?)?;
        if names.is_empty() {
            return Err(CErr::Arg("algs_json must list at least one algorithm".into()));
        }
        let algs: Vec<Algorithm> = names.iter().map(|n| n.parse::<Algorithm>()).collect::<Result<_, _>>().map_err(CErr::from)?;
        let rules = RequestObjectRules {
            algs: &algs,
            client_id: text(client_id, "client_id")?,
            issuer: text(issuer, "issuer")?,
            now: if now == 0 { None } else { Some(now) },
            max_lifetime: if max_lifetime == 0 { 600 } else { max_lifetime },
            require_typ: require_typ != 0,
        };
        let query = par_jar::verify_request_object(text(object, "object")?, &key, &rules).map_err(CErr::from)?;
        Ok(query.into_bytes())
    })
}

/// Builds and signs a request object (RFC 9101, client side). `params_json` is a JSON object of request parameters.
/// Lifetime is capped at 600 seconds by the library. Output: the compact JWT.
#[no_mangle]
pub unsafe extern "C" fn authlas_request_object_build(
    alg: *const c_char,
    key_json: *const c_char,
    client_id: *const c_char,
    issuer: *const c_char,
    params_json: *const c_char,
    lifetime: u64,
    out: *mut AuthlasBuf,
) -> c_int {
    run(out, || {
        let alg: Algorithm = text(alg, "alg")?.parse().map_err(|_| CErr::Arg("unknown alg".into()))?;
        let key = jwk(key_json, "key_json")?;
        let params: Map<String, Value> = serde_json::from_str(text(params_json, "params_json")?)?;
        let pairs: Vec<(&str, Value)> = params.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let token = par_jar::build_request_object(alg, &key, text(client_id, "client_id")?, text(issuer, "issuer")?, &pairs, lifetime)?;
        Ok(token.into_bytes())
    })
}

/// Fingerprint of a `request_uri` for logs, so the reference itself is not written to logs. Output: 12 characters.
#[no_mangle]
pub unsafe extern "C" fn authlas_request_uri_fingerprint(request_uri: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(par_jar::request_uri_fingerprint(text(request_uri, "request_uri")?).into_bytes()))
}
