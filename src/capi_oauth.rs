//! C ABI slice 2: OAuth and MCP one-shot functions. Stateless: JSON or plain strings in, JSON or plain strings out.
//! Stores that hold state (clients, revocation, device codes, PAR) come in slice 3 through callbacks, see docs/CALLBACKS.md.

use super::*;
use crate::mcp;
use crate::oauth::{metadata as md, pkce, rar_stepup, scope::Scope as OScope};

/// Random PKCE verifier (RFC 7636). Output: `{"verifier", "challenge", "method": "S256"}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_pkce_generate(out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let v = pkce::generate_verifier()?;
        let c = pkce::s256_challenge(&v)?;
        json_bytes(json!({ "verifier": v, "challenge": c, "method": "S256" }))
    })
}

/// S256 challenge for a verifier. Output: the challenge as text.
#[no_mangle]
pub unsafe extern "C" fn authlas_pkce_s256_challenge(verifier: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(pkce::s256_challenge(text(verifier, "verifier")?)?.into_bytes()))
}

/// Checks that a verifier is well formed (RFC 7636 section 4.1).
#[no_mangle]
pub unsafe extern "C" fn authlas_pkce_valid_verifier(verifier: *const c_char) -> c_int {
    match text(verifier, "verifier") {
        Ok(v) => if pkce::valid_verifier(v) { 1 } else { 0 },
        Err(_) => -1,
    }
}

/// Parses a scope string. Output: the normalized scope tokens as a JSON array.
#[no_mangle]
pub unsafe extern "C" fn authlas_scope_parse(scope: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let s = OScope::parse(text(scope, "scope")?)?;
        json_bytes(Value::Array(s.tokens().map(|t| Value::String(t.to_string())).collect()))
    })
}

/// Parses an Authorization Server metadata document (RFC 8414) and checks its issuer.
/// Output: the validated metadata as JSON.
#[no_mangle]
pub unsafe extern "C" fn authlas_as_metadata_normalize(body: *const c_char, expected_issuer: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let m = md::AsMetadata::parse(text(body, "body")?, text(expected_issuer, "expected_issuer")?)?;
        Ok(m.to_json().into_bytes())
    })
}

/// Builds secure default AS metadata for an issuer. Output: JSON.
#[no_mangle]
pub unsafe extern "C" fn authlas_as_metadata_defaults(issuer: *const c_char, base: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(md::AsMetadata::secure_defaults(text(issuer, "issuer")?, text(base, "base")?).to_json().into_bytes()))
}

/// Parses Protected Resource metadata (RFC 9728). Output: JSON.
#[no_mangle]
pub unsafe extern "C" fn authlas_resource_metadata_parse(body: *const c_char, expected_resource: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let r = md::ResourceMetadata::parse(text(body, "body")?, text(expected_resource, "expected_resource")?)?;
        Ok(r.to_json().into_bytes())
    })
}

/// Well-known URL of AS metadata for an issuer (RFC 8414 section 3). Output: the URL as text.
#[no_mangle]
pub unsafe extern "C" fn authlas_as_metadata_url(issuer: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(md::as_metadata_url(text(issuer, "issuer")?)?.into_bytes()))
}

/// Well-known URL of OpenID Connect discovery for an issuer. Output: the URL as text.
#[no_mangle]
pub unsafe extern "C" fn authlas_oidc_metadata_url(issuer: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(md::oidc_metadata_url(text(issuer, "issuer")?)?.into_bytes()))
}

/// Well-known URL of Protected Resource metadata for a resource. Output: the URL as text.
#[no_mangle]
pub unsafe extern "C" fn authlas_resource_metadata_url(resource: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(md::resource_metadata_url(text(resource, "resource")?)?.into_bytes()))
}

/// Canonical form of a resource URI (RFC 8707). Output: the canonical URI as text.
#[no_mangle]
pub unsafe extern "C" fn authlas_canonical_resource(input: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(mcp::canonical_resource(text(input, "input")?)?.into_bytes()))
}

/// Candidate resource metadata URLs for an MCP server URL, in the order to try them. Output: a JSON array.
#[no_mangle]
pub unsafe extern "C" fn authlas_mcp_resource_metadata_urls(mcp_url: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || json_bytes(Value::Array(mcp::resource_metadata_urls(text(mcp_url, "mcp_url")?)?.into_iter().map(Value::String).collect())))
}

/// Candidate authorization server metadata URLs for an issuer. Output: a JSON array.
#[no_mangle]
pub unsafe extern "C" fn authlas_mcp_as_discovery_urls(issuer: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || json_bytes(Value::Array(mcp::as_discovery_urls(text(issuer, "issuer")?)?.into_iter().map(Value::String).collect())))
}

/// Parses a `WWW-Authenticate` header into challenges (RFC 9110 section 11). Output: a JSON array of
/// `{"scheme", "params": {...}}` objects.
#[no_mangle]
pub unsafe extern "C" fn authlas_www_authenticate_parse(header: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let cs = mcp::parse_challenges(text(header, "header")?)?;
        let arr: Vec<Value> = cs.iter().map(|c| {
            let mut p = Map::new();
            for (k, v) in &c.params { p.insert(k.clone(), Value::String(v.clone())); }
            json!({ "scheme": c.scheme, "params": p })
        }).collect();
        json_bytes(Value::Array(arr))
    })
}

/// Parses `authorization_details` (RAR, RFC 9396) against the server's allowed types. Output: the details as JSON.
#[no_mangle]
pub unsafe extern "C" fn authlas_rar_parse(text_json: *const c_char, allowed_types: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let allowed = o_list(&options(allowed_types)?, "types").unwrap_or_default();
        let refs: Vec<&str> = allowed.iter().map(String::as_str).collect();
        let d = rar_stepup::parse(text(text_json, "authorization_details")?, &refs)?;
        Ok(rar_stepup::to_json(&d).into_bytes())
    })
}

/// True when every requested RAR detail is covered by the granted set (a reduction). Returns 1 or 0.
#[no_mangle]
pub unsafe extern "C" fn authlas_rar_is_reduction(requested_json: *const c_char, granted_json: *const c_char, allowed_types: *const c_char) -> c_int {
    let run_it = || -> Result<bool, CErr> {
        let allowed = o_list(&options(allowed_types)?, "types").unwrap_or_default();
        let refs: Vec<&str> = allowed.iter().map(String::as_str).collect();
        let req = rar_stepup::parse(text(requested_json, "requested")?, &refs)?;
        let gr = rar_stepup::parse(text(granted_json, "granted")?, &refs)?;
        Ok(rar_stepup::is_reduction(&req, &gr))
    };
    match run_it() { Ok(true) => 1, Ok(false) => 0, Err(_) => -1 }
}

/// Basic auth header value for a client secret (RFC 6749 section 2.3.1).
#[no_mangle]
pub unsafe extern "C" fn authlas_basic_header(client_id: *const c_char, secret: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || Ok(crate::oauth::client_auth::basic_header(text(client_id, "client_id")?, text(secret, "secret")?).into_bytes()))
}
