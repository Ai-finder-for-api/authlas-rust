//! C ABI slice 8: token introspection (RFC 7662, RFC 9701) and token exchange (RFC 8693). Both are stateless: the caller
//! supplies the verified inputs and gets back the decision or the wire response. No host callbacks are needed.

use super::*;
use crate::jwt::Claims;
use crate::oauth::exchange::{self, Rule, Subject};
use crate::oauth::introspection::{self, Introspection};
use crate::oauth::scope::Scope;

fn rule_from_json(v: &Value) -> Result<Rule, CErr> {
    let o = v.as_object().ok_or_else(|| CErr::Arg("rule must be a JSON object".into()))?;
    Ok(Rule {
        client_id: o_str(o, "client_id")?.ok_or_else(|| CErr::Arg("client_id is required".into()))?.to_string(),
        subject_token_types: o_list(o, "subject_token_types")?,
        requested_token_types: o_list(o, "requested_token_types")?,
        allowed_targets: o_list(o, "allowed_targets")?,
        allow_delegation: o.get("allow_delegation").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// Parses a token introspection request (RFC 7662 2.1) from a form body. Output: `{"token", "token_type_hint"}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_introspection_parse_request(form_body: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let params = crate::oauth::form::Params::parse(text(form_body, "form_body")?)?;
        let req = introspection::parse_request(&params).map_err(CErr::from)?;
        Ok(json!({ "token": req.token, "token_type_hint": req.hint.map(|h| h.as_str()) }).to_string().into_bytes())
    })
}

/// Parses an introspection response (RFC 7662 2.2). Output: the normalised response JSON. An inactive token comes back
/// as `{"active": false}`.
#[no_mangle]
pub unsafe extern "C" fn authlas_introspection_parse_response(body: *const c_char, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let i = Introspection::parse(text(body, "body")?).map_err(CErr::from)?;
        Ok(i.to_json().into_bytes())
    })
}

/// Checks a parsed introspection response for use at a resource server: active, unexpired, not before its start time
/// (with `leeway` seconds), and issued for `resource`. Output: `"usable"`. Any other result is an error.
#[no_mangle]
pub unsafe extern "C" fn authlas_introspection_check(body: *const c_char, resource: *const c_char, now: u64, leeway: u64, out: *mut AuthlasBuf) -> c_int {
    run(out, || {
        let i = Introspection::parse(text(body, "body")?).map_err(CErr::from)?;
        let now = if now == 0 { crate::jwt::unix_now() } else { now };
        if !i.is_usable(now, leeway) {
            return Err(CErr::Arg("token is not active".into()));
        }
        if !i.is_for_audience(text(resource, "resource")?) {
            return Err(CErr::Arg("token was not issued for this resource".into()));
        }
        Ok(b"usable".to_vec())
    })
}

/// Signs an introspection response as a JWT (RFC 9701). `alg` is the signing algorithm, `key_json` the private JWK.
/// Output: the compact JWT.
#[no_mangle]
pub unsafe extern "C" fn authlas_introspection_sign_jwt(
    alg: *const c_char,
    key_json: *const c_char,
    issuer: *const c_char,
    audience: *const c_char,
    response_json: *const c_char,
    out: *mut AuthlasBuf,
) -> c_int {
    run(out, || {
        let alg: Algorithm = text(alg, "alg")?.parse().map_err(|_| CErr::Arg("unknown alg".into()))?;
        let key = jwk(key_json, "key_json")?;
        let resp = Introspection::parse(text(response_json, "response_json")?).map_err(CErr::from)?;
        let token = introspection::sign_jwt_response(alg, &key, text(issuer, "issuer")?, text(audience, "audience")?, &resp)?;
        Ok(token.into_bytes())
    })
}

/// Verifies a signed introspection response (RFC 9701) and returns the embedded result. `algs_json` is a JSON array of
/// allowed algorithm names; an empty array is refused. Output: the normalised introspection JSON.
#[no_mangle]
pub unsafe extern "C" fn authlas_introspection_verify_jwt(
    token: *const c_char,
    key_json: *const c_char,
    algs_json: *const c_char,
    expected_issuer: *const c_char,
    me: *const c_char,
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
        let r = introspection::verify_jwt_response(
            text(token, "token")?,
            &key,
            &algs,
            text(expected_issuer, "expected_issuer")?,
            text(me, "me")?,
            if now == 0 { None } else { Some(now) },
        )
        .map_err(CErr::from)?;
        Ok(r.to_json().into_bytes())
    })
}

/// Decides a token exchange (RFC 8693). The caller has already verified the subject token (and the actor token, when
/// present) and passes their claims. `rules_json` is an array of exchange rules. `req_json` describes the request:
/// `{"subject_token_type", "actor_token_type", "requested_token_type", "audiences": [], "resources": [], "scope"}`.
/// Output: `{"targets", "token_type", "act", "subject", "scope"}`. The caller issues the token.
#[no_mangle]
pub unsafe extern "C" fn authlas_exchange_decide(
    rules_json: *const c_char,
    client_id: *const c_char,
    subject_claims_json: *const c_char,
    subject_scope: *const c_char,
    actor_claims_json: *const c_char,
    req_json: *const c_char,
    out: *mut AuthlasBuf,
) -> c_int {
    run(out, || {
        let rules: Vec<Rule> = serde_json::from_str::<Vec<Value>>(text(rules_json, "rules_json")?)?
            .iter()
            .map(rule_from_json)
            .collect::<Result<_, _>>()?;
        let req: Value = serde_json::from_str(text(req_json, "req_json")?)?;
        let ro = req.as_object().ok_or_else(|| CErr::Arg("req_json must be an object".into()))?;

        let subject_claims = Claims::parse(text(subject_claims_json, "subject_claims_json")?.as_bytes())?;
        let subject_scope = Scope::parse(text(subject_scope, "subject_scope")?)?;
        let actor = if actor_claims_json.is_null() {
            None
        } else {
            Some(Claims::parse(text(actor_claims_json, "actor_claims_json")?.as_bytes())?)
        };

        let list = |k: &str| -> Result<Vec<String>, CErr> { Ok(o_list(ro, k)?) };
        let scope = match o_str(ro, "scope")? {
            Some(s) => Some(Scope::parse(s).map_err(|_| CErr::Arg("scope is invalid".into()))?),
            None => None,
        };
        let request = exchange::Request {
            subject_token: "(verified by caller)".into(),
            subject_token_type: o_req(ro, "subject_token_type")?.to_string(),
            actor_token: actor.as_ref().map(|_| "(verified by caller)".to_string()),
            actor_token_type: o_str(ro, "actor_token_type")?.map(str::to_string),
            requested_token_type: o_str(ro, "requested_token_type")?.map(str::to_string),
            audiences: list("audiences")?,
            resources: list("resources")?,
            scope,
        };
        let subject = Subject { claims: &subject_claims, scope: &subject_scope };
        let decision = exchange::authorize(&rules, text(client_id, "client_id")?, &request, &subject, actor.as_ref()).map_err(CErr::from)?;

        let mut o = json!({
            "targets": decision.targets,
            "token_type": decision.token_type,
            "subject": decision.subject,
            "scope": decision.scope.to_string(),
        });
        if let Some(act) = decision.act {
            o["act"] = act;
        }
        Ok(o.to_string().into_bytes())
    })
}

/// Builds the exchange response body (RFC 8693 2.2.1). `expires_in` of 0 means omit it. `scope` may be NULL.
#[no_mangle]
pub unsafe extern "C" fn authlas_exchange_response(
    access_token: *const c_char,
    issued_token_type: *const c_char,
    expires_in: u64,
    scope: *const c_char,
    out: *mut AuthlasBuf,
) -> c_int {
    run(out, || {
        let sc = if scope.is_null() { None } else { Some(Scope::parse(text(scope, "scope")?)?) };
        let exp = if expires_in == 0 { None } else { Some(expires_in) };
        let body = exchange::response_json(
            text(access_token, "access_token")?,
            text(issued_token_type, "issued_token_type")?,
            "Bearer",
            exp,
            sc.as_ref(),
        );
        Ok(body.into_bytes())
    })
}
