#![cfg(feature = "fapi2")]
//! FAPI 2.0 Security Profile: a full compliant flow, then one deliberate violation per requirement.
use authlas::jwa::Algorithm::{self, *};
use authlas::jwk::Jwk;
use authlas::oauth::at_jwt;
use authlas::oauth::dpop::{self, ProofBuilder};
use authlas::oauth::fapi2::{self, ClientAuth, ClientProfile, Constraint, Presentation, ResourceProfile, SenderConstraint, ServerProfile};
use authlas::oauth::form::Params;
use authlas::oauth::metadata::AsMetadata;
use authlas::oauth::par_jar::ParStore;
use authlas::oauth::redirect::ClientKind;
use authlas::oauth::request::{self, ClientInfo, ServerPolicy};
use authlas::oauth::scope::Scope;
use authlas::oauth::token::{self, MemoryCodeStore, MemoryRefreshStore, TokenRequest};
use authlas::oauth::{registration, ErrorCode};
use authlas::Error;
use serde_json::{json, Value};

const ISSUER: &str = "https://as.example.com";
const BASE: &str = "https://as.example.com";
const RS: &str = "https://rs.example.com";
const CB: &str = "https://app.example.com/cb";

fn ec() -> Option<Jwk> {
    match authlas::crypto::ec_generate("P-256") { Ok(k) => Some(k), Err(Error::Unsupported(m)) => { eprintln!("SKIP: {m}"); None }, Err(e) => panic!("{e}") }
}
fn profile() -> ServerProfile { ServerProfile::default() }
fn codes(f: &[authlas::oauth::fapi2::Finding]) -> Vec<&'static str> { f.iter().map(|x| x.section).collect() }

// ---------- 5.3.2.1 / 5.3.2.2: server metadata ----------

#[test]
fn generated_metadata_passes_the_audit_and_survives_json() {
    let m = profile().metadata(ISSUER, BASE);
    assert!(profile().audit(&m).is_empty(), "{:?}", profile().audit(&m));
    let back = AsMetadata::parse(&m.to_json(), ISSUER).unwrap();
    assert!(profile().audit(&back).is_empty());
    assert_eq!(back.token_endpoint_auth_signing_alg_values_supported, vec!["PS256", "ES256", "EdDSA"]);
    // Per-constraint variants.
    let dpop_only = ServerProfile { constraints: vec![SenderConstraint::Dpop], ..profile() };
    assert!(dpop_only.audit(&dpop_only.metadata(ISSUER, BASE)).is_empty());
    let mtls_only = ServerProfile { constraints: vec![SenderConstraint::Mtls], ..profile() };
    let mm = mtls_only.metadata(ISSUER, BASE);
    assert!(mtls_only.audit(&mm).is_empty() && mm.dpop_signing_alg_values_supported.is_empty());
}

#[test]
fn each_metadata_violation_is_reported() {
    let good = profile().metadata(ISSUER, BASE);
    let audit = |f: &dyn Fn(&mut AsMetadata)| { let mut m = good.clone(); f(&mut m); profile().audit(&m) };
    assert!(codes(&audit(&|m| m.pushed_authorization_request_endpoint = None)).contains(&"5.3.2.2"));
    assert!(codes(&audit(&|m| m.require_pushed_authorization_requests = false)).contains(&"5.3.2.2"));
    assert!(!audit(&|m| m.code_challenge_methods_supported = vec!["S256".into(), "plain".into()]).is_empty(), "plain advertised");
    assert!(!audit(&|m| m.code_challenge_methods_supported = vec![]).is_empty());
    assert!(!audit(&|m| m.response_types_supported = vec!["code".into(), "token".into()]).is_empty(), "implicit response type");
    assert!(!audit(&|m| m.authorization_response_iss_parameter_supported = false).is_empty(), "RFC 9207");
    assert!(!audit(&|m| m.grant_types_supported.push("password".into())).is_empty());
    assert!(!audit(&|m| m.grant_types_supported.push("implicit".into())).is_empty());
    assert!(!audit(&|m| m.token_endpoint_auth_methods_supported.push("client_secret_basic".into())).is_empty());
    assert!(!audit(&|m| m.token_endpoint_auth_methods_supported.push("none".into())).is_empty(), "public clients");
    assert!(!audit(&|m| m.token_endpoint_auth_methods_supported.clear()).is_empty());
    assert!(codes(&audit(&|m| m.token_endpoint_auth_signing_alg_values_supported.push("RS256".into()))).contains(&"5.4.1"));
    assert!(codes(&audit(&|m| m.dpop_signing_alg_values_supported.push("none".into()))).contains(&"5.4.1"));
    assert!(!audit(&|m| m.dpop_signing_alg_values_supported.clear()).is_empty(), "DPoP on but no algorithms");
    assert!(!audit(&|m| m.tls_client_certificate_bound_access_tokens = false).is_empty(), "mTLS on but not advertised");
    assert!(!audit(&|m| m.jwks_uri = None).is_empty());
    assert!(!ServerProfile { constraints: vec![], ..profile() }.audit(&good).is_empty(), "no constraint at all");
    assert!(!fapi2::Checklist::OUT_OF_SCOPE.is_empty());
}

// ---------- 5.3.2.2: authorization endpoint ----------

#[test]
fn only_client_id_and_request_uri_reach_the_browser() {
    let p = profile();
    assert!(p.check_browser_query("client_id=c1&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc").is_ok());
    for q in ["client_id=c1&request_uri=u&scope=read", "client_id=c1&request_uri=u&redirect_uri=https%3A%2F%2Fa.example", "client_id=c1&request_uri=u&state=x",
              "client_id=c1&request_uri=u&request=jwt", "client_id=c1&request_uri=u&code_challenge=x"] {
        assert!(p.check_browser_query(q).is_err(), "{q}");
    }
    assert_eq!(p.check_browser_query("response_type=code&client_id=c1&redirect_uri=x&scope=read").unwrap_err().code, ErrorCode::InvalidRequest, "a classic request without PAR is refused");
    assert_eq!(p.check_browser_query("client_id=c1").unwrap_err().code, ErrorCode::InvalidRequestUri);
    assert!(p.check_browser_query("client_id=c1&client_id=c2&request_uri=u").is_err(), "repeated parameter");
}

#[test]
fn pushed_requests_need_authentication_pkce_and_redirect_uri() {
    let p = profile();
    let ok = "response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Fa.example%2Fcb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=read";
    assert!(p.check_pushed_request(&Params::parse(ok).unwrap(), true).is_ok());
    assert_eq!(p.check_pushed_request(&Params::parse(ok).unwrap(), false).unwrap_err().code, ErrorCode::InvalidClient, "unauthenticated PAR");
    let without = |name: &str| { let q: Vec<_> = ok.split('&').filter(|kv| !kv.starts_with(&format!("{name}="))).collect(); p.check_pushed_request(&Params::parse(&q.join("&")).unwrap(), true) };
    assert!(without("redirect_uri").is_err(), "redirect_uri is mandatory in PAR for this profile");
    assert!(without("code_challenge").is_err());
    assert!(without("code_challenge_method").is_err());
    assert!(without("response_type").is_err());
    assert!(p.check_pushed_request(&Params::parse(&ok.replace("S256", "plain")).unwrap(), true).is_err());
    assert!(p.check_pushed_request(&Params::parse(&ok.replace("response_type=code", "response_type=token")).unwrap(), true).is_err());
    assert!(p.check_pushed_request(&Params::parse(&ok.replace("response_type=code", "response_type=code%20id_token")).unwrap(), true).is_err());
    // Lifetimes.
    assert!(p.check_par_lifetime(599).is_ok() && p.check_par_lifetime(600).is_err());
    assert!(p.check_token_lifetime(3600).is_ok() && p.check_token_lifetime(3601).is_err());
}

#[test]
fn validated_authorization_request_must_still_meet_the_profile() {
    let info = ClientInfo { client_id: "c1".into(), redirect_uris: vec![CB.into(), "http://127.0.0.1:8123/cb".into()], kind: ClientKind::Native,
        allowed_scopes: Scope::parse("read").unwrap(), response_types: vec!["code".into()] };
    let q = |ru: &str| format!("response_type=code&client_id=c1&redirect_uri={ru}&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");
    let req = request::validate(&q("https%3A%2F%2Fapp.example.com%2Fcb"), &info, &ServerPolicy::default()).unwrap();
    assert!(profile().check_authorization_request(&req).is_ok());
    let loopback = request::validate(&q("http%3A%2F%2F127.0.0.1%3A8123%2Fcb"), &info, &ServerPolicy::default()).unwrap();
    assert!(profile().check_authorization_request(&loopback).is_ok(), "loopback http is the allowed exception");
    let mut bad = req.clone(); bad.response_type = "token".into();
    assert!(profile().check_authorization_request(&bad).is_err());
    let mut bad = req.clone(); bad.code_challenge = None;
    assert!(profile().check_authorization_request(&bad).is_err());
    let mut bad = req.clone(); bad.code_challenge_method = Some(authlas::oauth::pkce::Method::Plain);
    assert!(profile().check_authorization_request(&bad).is_err());
    let mut bad = req.clone(); bad.redirect_uri = "http://app.example.com/cb".into();
    assert!(profile().check_authorization_request(&bad).is_err(), "http redirect off loopback");
    // 64-character nonces must work, and the client helper reflects it.
    assert!(ClientProfile.check_nonce(&"n".repeat(64)) && !ClientProfile.check_nonce(&"n".repeat(65)));
}

// ---------- 5.3.2.1: clients, algorithms, tokens ----------

#[test]
fn registration_policy_admits_only_profile_clients() {
    let Some(k) = ec() else { return };
    let mut pol = profile().registration_policy("https://as.example.com/register");
    pol.open = true;
    pol.allowed_scopes = Scope::parse("read").unwrap(); pol.default_scope = Scope::parse("read").unwrap();
    let store = registration::MemoryClientStore::new();
    let good = json!({"redirect_uris": [CB], "token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "ES256", "jwks": {"keys": [k.public().unwrap()]}, "dpop_bound_access_tokens": true});
    assert!(registration::register(&store, &good.to_string(), None, &pol, None).is_ok());
    let try_ = |f: &dyn Fn(&mut Value)| { let mut b = good.clone(); f(&mut b); registration::register(&store, &b.to_string(), None, &pol, None).is_err() };
    assert!(try_(&|b| b["token_endpoint_auth_method"] = json!("client_secret_basic")), "shared secrets");
    assert!(try_(&|b| b["token_endpoint_auth_method"] = json!("client_secret_post")));
    assert!(try_(&|b| b["token_endpoint_auth_method"] = json!("none")), "public clients");
    assert!(try_(&|b| b["token_endpoint_auth_signing_alg"] = json!("RS256")), "PS256, ES256, EdDSA only");
    assert!(try_(&|b| b["token_endpoint_auth_signing_alg"] = json!("ES384")));
    assert!(try_(&|b| { b.as_object_mut().unwrap().remove("dpop_bound_access_tokens"); }), "bearer tokens");
    assert!(try_(&|b| b["application_type"] = json!("native")));
    assert!(try_(&|b| b["redirect_uris"] = json!(["http://app.example.com/cb"])));
    // mTLS clients qualify through the certificate-bound flag.
    let m = json!({"redirect_uris": [CB], "token_endpoint_auth_method": "tls_client_auth", "tls_client_auth_san_dns": "c.example.org", "tls_client_certificate_bound_access_tokens": true});
    assert!(registration::register(&store, &m.to_string(), None, &pol, None).is_ok());
}

#[test]
fn only_private_key_jwt_and_mtls_authenticate() {
    assert_eq!(ClientAuth::from_method("private_key_jwt"), Some(ClientAuth::PrivateKeyJwt));
    assert_eq!(ClientAuth::from_method("tls_client_auth"), Some(ClientAuth::Mtls));
    assert_eq!(ClientAuth::from_method("self_signed_tls_client_auth"), Some(ClientAuth::Mtls));
    for m in ["client_secret_basic", "client_secret_post", "client_secret_jwt", "none", "bogus", ""] { assert_eq!(ClientAuth::from_method(m), None, "{m}"); }
}

#[test]
fn client_assertion_audience_is_the_issuer_as_a_string() {
    let Some(k) = ec() else { return };
    let good = ClientProfile.assertion(ES256, &k, "c1", ISSUER).unwrap();
    assert!(profile().check_client_assertion(&good, ISSUER).is_ok());
    // The token endpoint URL as audience is the classic setup the profile moved away from.
    let token_aud = authlas::oauth::client_auth::build_assertion(ES256, &k, "c1", "https://as.example.com/token", 60).unwrap();
    assert!(profile().check_client_assertion(&token_aud, ISSUER).is_err());
    // Array audience.
    let now = authlas::jwt::unix_now();
    let arr = authlas::jwt::sign(ES256, &k, &authlas::jwt::Claims::new().issuer("c1").subject("c1").set("aud", json!([ISSUER])).issued_at(now).expires_at(now + 60).jti("x"), None).unwrap();
    assert!(profile().check_client_assertion(&arr, ISSUER).is_err(), "aud as an array");
    assert!(ClientProfile.assertion(RS256, &k, "c1", ISSUER).is_err());
    assert!(ClientProfile.assertion(HS256, &k, "c1", ISSUER).is_err());
    assert!(ClientProfile.check_assertion_alg(PS256).is_ok() && ClientProfile.check_assertion_alg(PS384).is_err());
    assert!(profile().check_client_assertion("garbage", ISSUER).is_err());
}

#[test]
fn token_requests_require_a_sender_constraint() {
    let Some(k) = ec() else { return };
    let req = TokenRequest::AuthorizationCode { code: "c".into(), redirect_uri: Some(CB.into()), code_verifier: Some("v".into()), resources: vec![] };
    let proof = ProofBuilder { alg: ES256, key: &k, method: "POST", url: "https://as.example.com/token", access_token: None, nonce: None }.build().unwrap();
    let verified = dpop::verify_proof(&proof, &dpop::Expect { algs: &[ES256], method: "POST", url: "https://as.example.com/token", access_token: None, nonce: None, now: None, leeway: 5, replay: None }).unwrap();
    let c = profile().check_token_request(&req, ClientAuth::PrivateKeyJwt, Some(&verified), None).unwrap();
    assert_eq!(c, Constraint::Dpop { jkt: verified.jkt.clone() });
    assert_eq!(c.cnf(), json!({"jkt": verified.jkt}));
    assert_eq!(c.token_type(), "DPoP");
    let e = profile().check_token_request(&req, ClientAuth::PrivateKeyJwt, None, None).unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidDpopProof, "no proof and no certificate: no token, never a bearer token");
    // A server configured for mTLS only ignores a DPoP proof.
    let mtls_only = ServerProfile { constraints: vec![SenderConstraint::Mtls], ..profile() };
    assert!(mtls_only.check_token_request(&req, ClientAuth::Mtls, Some(&verified), None).is_err());
    let dpop_only = ServerProfile { constraints: vec![SenderConstraint::Dpop], ..profile() };
    assert!(dpop_only.check_token_request(&req, ClientAuth::PrivateKeyJwt, None, None).is_err());
}

#[test]
fn clock_skew_window() {
    let p = profile();
    assert_eq!(p.leeway(0), 10, "must accept 10 s in the future even when configured lower");
    assert_eq!(p.leeway(30), 30);
    assert_eq!(p.leeway(3600), 60, "never more than 60 s");
}

#[test]
fn codes_live_at_most_sixty_seconds_and_are_single_use() {
    let store = MemoryCodeStore::new();
    let refresh = MemoryRefreshStore::new();
    let info = ClientInfo { client_id: "c1".into(), redirect_uris: vec![CB.into()], kind: ClientKind::Web, allowed_scopes: Scope::parse("read").unwrap(), response_types: vec!["code".into()] };
    let q = format!("response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");
    let req = request::validate(&q, &info, &ServerPolicy::default()).unwrap();
    let (code, _) = token::issue_code(&store, &req, "alice", Scope::parse("read").unwrap(), Some(1000)).unwrap();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let rec = token::redeem_code(&store, &refresh, "c1", &code, Some(CB), Some(verifier), Some(1010)).unwrap();
    assert!(profile().check_code(&rec, 1000).is_ok());
    let mut long = rec.clone(); long.expires_at = 1000 + 61;
    assert!(profile().check_code(&long, 1000).is_err());
    assert_eq!(token::CODE_LIFETIME, fapi2::MAX_CODE_LIFETIME);
    assert!(token::redeem_code(&store, &refresh, "c1", &code, Some(CB), Some(verifier), Some(1011)).is_err(), "second redemption");
}

#[test]
fn refresh_tokens_are_not_rotated() {
    let store = MemoryRefreshStore::new();
    let rec = token::CodeRecord { client_id: "c1".into(), subject: "alice".into(), redirect_uri: CB.into(), scope: Scope::parse("read write").unwrap(), resources: vec![], challenge: None,
        method: None, expires_at: 0, grant_id: "g1".into(), nonce: None, extra: vec![], redirect_uri_was_sent: true };
    let t = token::issue_refresh(&store, &rec, Some(1000)).unwrap();
    let p = profile();
    // The same token works repeatedly (a lost response does not strand the client).
    for i in 0..3 { assert_eq!(p.use_refresh(&store, "c1", &t, None, Some(2000 + i)).unwrap().subject, "alice"); }
    assert_eq!(p.use_refresh(&store, "c1", &t, Some(&Scope::parse("read").unwrap()), Some(2000)).unwrap().scope.to_string(), "read", "narrowing is fine");
    assert_eq!(p.use_refresh(&store, "c1", &t, Some(&Scope::parse("admin").unwrap()), Some(2000)).unwrap_err().code, ErrorCode::InvalidScope);
    assert!(p.use_refresh(&store, "c1", &t, None, Some(1000 + token::REFRESH_LIFETIME + 1)).is_err(), "expiry still applies");
    // A different client presenting the token kills the grant.
    assert!(p.use_refresh(&store, "evil", &t, None, Some(2000)).is_err());
    assert!(p.use_refresh(&store, "c1", &t, None, Some(2000)).is_err(), "grant revoked after misuse");
    assert!(p.use_refresh(&store, "c1", "unknown", None, Some(2000)).is_err());
    // Default store implementation fails closed.
    struct NoPeek; impl token::RefreshStore for NoPeek { fn put(&self, _: String, _: token::RefreshRecord) {} fn take(&self, _: &str) -> token::RefreshTake { token::RefreshTake::Unknown } fn revoke_grant(&self, _: &str) {} }
    assert!(p.use_refresh(&NoPeek, "c1", &t, None, Some(2000)).is_err());
    let _ = ParStore::new();
}

// ---------- 5.3.3: client ----------

#[test]
fn client_checks_the_server_before_starting() {
    let m = profile().metadata(ISSUER, BASE);
    assert!(ClientProfile.check_server(&m, true, false).is_empty());
    assert!(ClientProfile.check_server(&m, false, true).is_empty());
    assert!(!ClientProfile.check_server(&m, false, false).is_empty(), "must sender-constrain");
    let bad = |f: &dyn Fn(&mut AsMetadata), dpop: bool, mtls: bool| { let mut x = m.clone(); f(&mut x); ClientProfile.check_server(&x, dpop, mtls) };
    assert!(!bad(&|x| x.pushed_authorization_request_endpoint = None, true, false).is_empty());
    assert!(!bad(&|x| x.code_challenge_methods_supported = vec!["plain".into()], true, false).is_empty());
    assert!(!bad(&|x| x.authorization_response_iss_parameter_supported = false, true, false).is_empty());
    assert!(!bad(&|x| x.token_endpoint_auth_methods_supported = vec!["client_secret_basic".into()], true, false).is_empty());
    assert!(!bad(&|x| x.dpop_signing_alg_values_supported = vec!["RS256".into()], true, false).is_empty());
    assert!(!bad(&|x| x.tls_client_certificate_bound_access_tokens = false, false, true).is_empty());
}

#[test]
fn client_flow_urls_and_issuer_check() {
    let url = ClientProfile.authorization_url("https://as.example.com/authorize", "c1", "urn:ietf:params:oauth:request_uri:abc");
    let q = url.split_once('?').unwrap().1;
    assert!(profile().check_browser_query(q).is_ok(), "the URL the client builds satisfies the server's rule");
    assert_eq!(ClientProfile.check_response("code=abc&state=s1&iss=https%3A%2F%2Fas.example.com", "s1", ISSUER).unwrap(), "abc");
    assert!(ClientProfile.check_response("code=abc&state=s1", "s1", ISSUER).is_err(), "iss is mandatory");
    assert!(ClientProfile.check_response("code=abc&state=s1&iss=https%3A%2F%2Fevil.example", "s1", ISSUER).is_err(), "mix-up");
    assert!(ClientProfile.check_response("code=abc&state=other&iss=https%3A%2F%2Fas.example.com", "s1", ISSUER).is_err());
}

// ---------- 5.3.4: resource server ----------

fn access_token(issuer_key: &Jwk, alg: Algorithm, cnf: Option<Value>, scope: &str) -> String {
    let s = Scope::parse(scope).unwrap();
    let mut k = issuer_key.clone(); k.kid = Some("as1".into());
    at_jwt::Issue { alg, key: &k, issuer: ISSUER, audience: &[RS], subject: "alice", client_id: "c1", scope: &s, lifetime: 600, now: None, extra: &[], cnf }.sign().unwrap()
}

#[test]
fn resource_server_requires_a_matching_dpop_proof() {
    let (Some(as_key), Some(client_key)) = (ec(), ec()) else { return };
    let jkt = client_key.public().unwrap().thumbprint(authlas::jwa::Hash::Sha256).unwrap();
    let at = access_token(&as_key, ES256, Some(json!({"jkt": jkt})), "read");
    let url = "https://rs.example.com/accounts";
    let proof = |tok: Option<&str>, key: &Jwk| ProofBuilder { alg: ES256, key, method: "GET", url, access_token: tok, nonce: None }.build().unwrap();
    let rp = ResourceProfile { issuer: ISSUER, audience: RS, now: None };
    let verify_key = as_key.public().unwrap();
    let hdr = format!("DPoP {at}");
    let p = proof(Some(&at), &client_key);
    let ok = rp.verify(&Presentation { authorization: &[&hdr], method: "GET", url, dpop_headers: &[&p], cert: None, token_in_query: false, token_in_body: false }, &verify_key, None).unwrap();
    assert_eq!(ok.subject, "alice");
    let run = |auth: &str, proofs: &[&str], q: bool, b: bool| rp.verify(&Presentation { authorization: &[auth], method: "GET", url, dpop_headers: proofs, cert: None, token_in_query: q, token_in_body: b }, &verify_key, None);
    assert!(run(&hdr, &[], false, false).is_err(), "no proof");
    assert!(run(&hdr, &[&p, &p], false, false).is_err(), "two proofs");
    assert!(run(&format!("Bearer {at}"), &[], false, false).is_err(), "a DPoP-bound token presented as Bearer");
    assert!(run(&hdr, &[&p], true, false).is_err(), "token also in the query string");
    assert!(run(&hdr, &[&p], false, true).is_err(), "token also in the body");
    let stranger = ec().unwrap();
    assert!(run(&hdr, &[&proof(Some(&at), &stranger)], false, false).is_err(), "proof from a different key: a stolen token is useless");
    assert!(run(&hdr, &[&proof(None, &client_key)], false, false).is_err(), "proof without ath");
    assert!(run(&hdr, &[&proof(Some("other-token"), &client_key)], false, false).is_err(), "ath for another token");
}

#[test]
fn resource_server_refuses_unconstrained_and_badly_signed_tokens() {
    let (Some(as_key), Some(client_key)) = (ec(), ec()) else { return };
    let rp = ResourceProfile { issuer: ISSUER, audience: RS, now: None };
    let vk = as_key.public().unwrap();
    let url = "https://rs.example.com/accounts";
    let unconstrained = access_token(&as_key, ES256, None, "read");
    let pr = ProofBuilder { alg: ES256, key: &client_key, method: "GET", url, access_token: Some(&unconstrained), nonce: None }.build().unwrap();
    let hdr = format!("Bearer {unconstrained}");
    assert!(rp.verify(&Presentation { authorization: &[&hdr], method: "GET", url, dpop_headers: &[&pr], cert: None, token_in_query: false, token_in_body: false }, &vk, None).is_err(), "plain bearer tokens are not accepted");
    // The algorithm list is the profile's: an RS256-signed token is refused even with a correct key.
    // (Signing with RS256 needs an RSA key; use the wrong-key case to prove signature checking.)
    let other = ec().unwrap();
    let forged = access_token(&other, ES256, Some(json!({"jkt": "x"})), "read");
    assert!(rp.verify(&Presentation { authorization: &[&format!("DPoP {forged}")], method: "GET", url, dpop_headers: &[&pr], cert: None, token_in_query: false, token_in_body: false }, &vk, None).is_err());
    assert!(fapi2::is_sender_constrained(&authlas::jwt::Claims::new().set("cnf", json!({"jkt": "x"}))));
    assert!(fapi2::is_sender_constrained(&authlas::jwt::Claims::new().set("cnf", json!({"x5t#S256": "x"}))));
    assert!(!fapi2::is_sender_constrained(&authlas::jwt::Claims::new()));
    assert!(!fapi2::is_sender_constrained(&authlas::jwt::Claims::new().set("cnf", json!({"jwe": "x"}))));
}

// ---------- 5.4.1: keys ----------

#[test]
fn key_strength_rules() {
    let Some(k) = ec() else { return };
    assert!(fapi2::check_key(ES256, &k).is_ok());
    assert!(fapi2::check_key(RS256, &k).is_err() && fapi2::check_key(HS256, &k).is_err() && fapi2::check_key(ES384, &k).is_err());
    assert!(fapi2::check_key(PS256, &k).is_err(), "EC key with an RSA algorithm");
    assert!(fapi2::check_key(EdDSA, &k).is_err());
    let ed = Jwk::parse(r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#).unwrap();
    assert!(fapi2::check_key(EdDSA, &ed).is_ok());
    let small = Jwk::parse(&json!({"kty": "RSA", "n": authlas::b64::encode(vec![0xffu8; 128]), "e": "AQAB"}).to_string()).unwrap();
    assert!(fapi2::check_key(PS256, &small).is_err(), "1024-bit RSA");
    let ok = Jwk::parse(&json!({"kty": "RSA", "n": authlas::b64::encode(vec![0xffu8; 256]), "e": "AQAB"}).to_string()).unwrap();
    assert!(fapi2::check_key(PS256, &ok).is_ok());
    // Leading zero bytes do not count towards the size.
    let padded = Jwk::parse(&json!({"kty": "RSA", "n": authlas::b64::encode([vec![0u8; 8], vec![0xffu8; 128]].concat()), "e": "AQAB"}).to_string()).unwrap();
    assert!(fapi2::check_key(PS256, &padded).is_err());
}
