//! C ABI slice 9: mutual-TLS client authentication and certificate-bound tokens (RFC 8705).
//!
//! The TLS stack does the handshake and chain validation. The host passes the DER certificate it received, and says
//! whether the TLS stack verified the chain. Everything below is stateless.

use super::*;
use crate::oauth::form::Params;
use crate::oauth::mtls::{self, ExpectedSubject, Registration};
use crate::x509::Certificate;
use crate::jwt::Claims;

fn registration_from_json(v: &Value) -> Result<Registration, CErr> {
    let o = v.as_object().ok_or_else(|| CErr::Arg("registration must be a JSON object".into()))?;
    let client_id = o_req(o, "client_id")?.to_string();
    match o_req(o, "method")? {
        "tls_client_auth" => {
            // Exactly one of these must be set (RFC 8705 2.1.2). Refuse none and refuse more than one.
            let expected = ExpectedSubject::from_metadata(
                o_str(o, "subject_dn")?,
                o_str(o, "san_dns")?,
                o_str(o, "san_uri")?,
                o_str(o, "san_ip")?,
                o_str(o, "san_email")?,
            )
            .map_err(CErr::from)?;
            Ok(Registration::Pki { client_id, expected })
        }
        "self_signed_tls_client_auth" => {
            let keys: Vec<crate::jwk::Jwk> = match o.get("jwks") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|k| crate::jwk::Jwk::parse(&k.to_string()))
                    .collect::<Result<_, _>>()
                    .map_err(CErr::from)?,
                Some(_) => return Err(CErr::Arg("jwks must be an array".into())),
            };
            if keys.is_empty() {
                return Err(CErr::Arg("a self-signed client must register at least one key".into()));
            }
            Ok(Registration::SelfSigned { client_id, keys })
        }
        _ => Err(CErr::Arg("method must be tls_client_auth or self_signed_tls_client_auth".into())),
    }
}

/// Authenticates a client by its mutual-TLS certificate (RFC 8705 2). `der` is the certificate the TLS layer received.
/// `chain_verified` must be 1 only when the TLS stack validated the chain against trusted CAs; the PKI method refuses
/// without it. `form_body` is the token request body (its `client_id` is used). `authorization` may be NULL. Output:
/// the authenticated client_id.
#[no_mangle]
pub unsafe extern "C" fn authlas_mtls_authenticate(
    der: *const u8,
    der_len: usize,
    chain_verified: c_int,
    authorization: *const c_char,
    form_body: *const c_char,
    registration_json: *const c_char,
    now: u64,
    out: *mut AuthlasBuf,
) -> c_int {
    run(out, || {
        if der.is_null() || der_len == 0 {
            return Err(CErr::Arg("der must be the client certificate".into()));
        }
        let cert = Certificate::from_der(std::slice::from_raw_parts(der, der_len)).map_err(CErr::from)?;
        let reg = registration_from_json(&serde_json::from_str(text(registration_json, "registration_json")?)?)?;
        let params = Params::parse(text(form_body, "form_body")?)?;
        let auth = if authorization.is_null() { None } else { Some(text(authorization, "authorization")?) };
        let id = mtls::authenticate(&cert, chain_verified != 0, auth, &params, &reg, if now == 0 { None } else { Some(now) })
            .map_err(CErr::from)?;
        Ok(id.into_bytes())
    })
}

/// The `cnf` claim that binds an access token to this certificate (RFC 8705 3.1). Output: `{"x5t#S256": "..."}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_mtls_cnf(der: *const u8, der_len: usize, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        if der.is_null() || der_len == 0 {
            return Err(CErr::Arg("der must be the client certificate".into()));
        }
        let cert = Certificate::from_der(std::slice::from_raw_parts(der, der_len)).map_err(CErr::from)?;
        Ok(mtls::cnf_for(&cert).map_err(CErr::from)?.to_string().into_bytes())
    })
}

/// Resource server check (RFC 8705 3): the access token's `cnf.x5t#S256` must match the certificate on this connection.
/// `token_claims_json` is the verified JWT claims object. Output: `"bound"`. A token with no binding, or a binding to
/// another certificate, is an error.
#[no_mangle]
pub unsafe extern "C" fn authlas_mtls_check_binding(der: *const u8, der_len: usize, token_claims_json: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        if der.is_null() || der_len == 0 {
            return Err(CErr::Arg("der must be the client certificate".into()));
        }
        let cert = Certificate::from_der(std::slice::from_raw_parts(der, der_len)).map_err(CErr::from)?;
        let claims = Claims::parse(text(token_claims_json, "token_claims_json")?.as_bytes())?;
        mtls::check_binding(&claims, &cert).map_err(CErr::from)?;
        Ok(b"bound".to_vec())
    })
}

/// Authorization server check (RFC 8705 7.1): a refresh token or code bound to a certificate may only be used with that
/// same certificate. `bound_x5t_s256` is the stored thumbprint. Output: `"same"`, or an error.
#[no_mangle]
pub unsafe extern "C" fn authlas_mtls_same_certificate(der: *const u8, der_len: usize, bound_x5t_s256: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        if der.is_null() || der_len == 0 {
            return Err(CErr::Arg("der must be the client certificate".into()));
        }
        let cert = Certificate::from_der(std::slice::from_raw_parts(der, der_len)).map_err(CErr::from)?;
        if mtls::same_certificate(text(bound_x5t_s256, "bound_x5t_s256")?, &cert) {
            Ok(b"same".to_vec())
        } else {
            Err(CErr::Arg("a different client certificate was presented".into()))
        }
    })
}
