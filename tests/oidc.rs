#![cfg(feature = "oidc")]
//! OpenID Connect: ID token issue/validate, authentication request decisions, claims, pairwise subjects, discovery, logout.
use authlas::jwa::Algorithm::{self, *};
use authlas::jwk::{Jwk, JwkSet};
use authlas::jwt::{self, Claims, MemoryReplayCache};
use authlas::oauth::error::ErrorCode;
use authlas::oauth::request::{self, ClientInfo, ServerPolicy};
use authlas::oauth::redirect::ClientKind;
use authlas::oauth::scope::Scope;
use authlas::oidc::claims::*;
use authlas::oidc::id_token::{self, half_hash, IdTokenIssue, Validate};
use authlas::oidc::provider::*;
use authlas::oidc::request::*;
use authlas::Error;
use serde_json::{json, Map, Value};

const ISS: &str = "https://op.example.com";
const CID: &str = "s6BhdRkqt3";
const NOW: u64 = 1_800_000_000;

fn ec() -> Option<Jwk> {
    match authlas::crypto::ec_generate("P-256") { Ok(k) => Some(k), Err(Error::Unsupported(m)) => { eprintln!("SKIP: {m}"); None }, Err(e) => panic!("{e}") }
}
fn scope(s: &str) -> Scope { Scope::parse(s).unwrap() }
fn issue(k: &Jwk) -> IdTokenIssue<'_> { let mut i = IdTokenIssue::new(ES256, k, ISS, CID, "248289761001"); i.now = Some(NOW); i }
fn val<'a>(algs: &'a [Algorithm]) -> Validate<'a> { let mut v = Validate::new(algs, ISS, CID); v.now = Some(NOW + 10); v }

// ---------- hashes: OIDC Core appendix A.3 and A.4 ----------

#[test]
fn at_hash_and_c_hash_match_the_spec_examples() {
    assert_eq!(half_hash(RS256, "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y").unwrap(), "77QmUPtjPfzWtF2AnpK9RQ");
    assert_eq!(half_hash(RS256, "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk").unwrap(), "LDktKdoQak3Pk0cnXxCltA");
    // The hash follows the algorithm: SHA-384 for ES384 gives 24 bytes (32 base64url characters), SHA-512 for ES512 gives 32 (43).
    assert_eq!(half_hash(ES384, "x").unwrap().len(), 32);
    assert_eq!(half_hash(ES512, "x").unwrap().len(), 43);
    assert_eq!(half_hash(EdDSA, "x").unwrap().len(), 43, "EdDSA (Ed25519) uses SHA-512");
}

// ---------- ID token ----------

#[test]
fn issued_id_token_validates() {
    let Some(k) = ec() else { return };
    let mut i = issue(&k);
    i.nonce = Some("n-0S6_WzA2Mj"); i.auth_time = Some(NOW - 30); i.acr = Some("urn:mace:incommon:iap:silver"); i.amr = &["pwd", "otp"]; i.sid = Some("sess-1");
    i.access_token = Some("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y");
    let t = i.sign().unwrap();
    let algs = [ES256];
    let mut v = val(&algs);
    v.nonce = Some("n-0S6_WzA2Mj"); v.max_age = Some(300); v.access_token = i.access_token; v.require_at_hash = true;
    let pk = k.public().unwrap();
    let id = id_token::validate(&t, &pk, &v).unwrap();
    assert_eq!(id.subject, "248289761001");
    assert_eq!(id.auth_time, Some(NOW - 30));
    assert_eq!(id.amr, ["pwd", "otp"]);
    assert_eq!(id.sid.as_deref(), Some("sess-1"));
    assert_eq!(id.header.typ.as_deref(), Some("JWT"));
}

#[test]
fn nonce_rules() {
    let Some(k) = ec() else { return };
    let pk = k.public().unwrap();
    let algs = [ES256];
    let mut i = issue(&k); i.nonce = Some("abc");
    let t = i.sign().unwrap();
    let mut v = val(&algs);
    v.nonce = Some("abc"); assert!(id_token::validate(&t, &pk, &v).is_ok());
    v.nonce = Some("abd"); assert!(matches!(id_token::validate(&t, &pk, &v), Err(Error::Claim(_))));
    v.nonce = Some("ab"); assert!(id_token::validate(&t, &pk, &v).is_err());
    // Nonce was sent but the token has none: refused (replay/injection defence).
    let t2 = issue(&k).sign().unwrap();
    v.nonce = Some("abc"); assert!(id_token::validate(&t2, &pk, &v).is_err());
    // No nonce was sent: a nonce in the token is not an error.
    v.nonce = None; assert!(id_token::validate(&t, &pk, &v).is_ok());
}

#[test]
fn audience_and_azp_rules() {
    let Some(k) = ec() else { return };
    let pk = k.public().unwrap();
    let algs = [ES256];
    // Not for this client.
    let other = IdTokenIssue { client_id: "someone-else", ..issue(&k) }.sign().unwrap();
    assert!(id_token::validate(&other, &pk, &val(&algs)).is_err());
    // Extra audience the client does not trust.
    let mut i = issue(&k); i.extra_audiences = &["https://api.evil.example"];
    let t = i.sign().unwrap();
    assert!(id_token::validate(&t, &pk, &val(&algs)).is_err(), "untrusted additional audience");
    let mut v = val(&algs); v.trusted_audiences = &["https://api.evil.example"];
    let id = id_token::validate(&t, &pk, &v).unwrap();
    assert_eq!(id.claims.str_claim("azp").unwrap(), Some(CID), "issuer sets azp when there are several audiences");
    // Several audiences without azp are refused.
    let c = Claims::new().issuer(ISS).subject("s").audience(&[CID, "https://api.evil.example"]).expires_at(NOW + 100).issued_at(NOW);
    let no_azp = jwt::sign(ES256, &k, &c, None).unwrap();
    assert!(id_token::validate(&no_azp, &pk, &v).is_err());
    // azp naming somebody else.
    let c = c.set("azp", "someone-else");
    let bad_azp = jwt::sign(ES256, &k, &c, None).unwrap();
    assert!(id_token::validate(&bad_azp, &pk, &v).is_err());
}

#[test]
fn issuer_expiry_signature_and_algorithm() {
    let Some(k) = ec() else { return };
    let Some(evil) = ec() else { return };
    let pk = k.public().unwrap();
    let algs = [ES256];
    let t = issue(&k).sign().unwrap();
    assert!(id_token::validate(&t, &pk, &Validate { issuer: "https://other.example.com", ..val(&algs) }).is_err());
    assert!(id_token::validate(&t, &pk, &Validate { now: Some(NOW + 301 + 30), ..val(&algs) }).is_err(), "expired");
    assert!(id_token::validate(&t, &evil.public().unwrap(), &val(&algs)).is_err(), "wrong key");
    assert!(id_token::validate(&t, &pk, &val(&[RS256])).is_err(), "alg not on the RP's list");
    // Missing sub / iat.
    let c = Claims::new().issuer(ISS).audience(&[CID]).expires_at(NOW + 100).issued_at(NOW);
    assert!(id_token::validate(&jwt::sign(ES256, &k, &c, None).unwrap(), &pk, &val(&algs)).is_err(), "no sub");
    let c = Claims::new().issuer(ISS).subject("s").audience(&[CID]).expires_at(NOW + 100);
    assert!(id_token::validate(&jwt::sign(ES256, &k, &c, None).unwrap(), &pk, &val(&algs)).is_err(), "no iat");
    // sub longer than 255.
    let c = Claims::new().issuer(ISS).subject(&"x".repeat(256)).audience(&[CID]).expires_at(NOW + 100).issued_at(NOW);
    assert!(id_token::validate(&jwt::sign(ES256, &k, &c, None).unwrap(), &pk, &val(&algs)).is_err());
}

#[test]
fn an_access_token_is_not_an_id_token() {
    let Some(k) = ec() else { return };
    let c = Claims::new().issuer(ISS).subject("s").audience(&[CID]).expires_at(NOW + 100).issued_at(NOW);
    let at = jwt::sign(ES256, &k, &c, Some("at+jwt")).unwrap();
    assert!(id_token::validate(&at, &k.public().unwrap(), &val(&[ES256])).is_err());
}

#[test]
fn max_age_and_auth_time() {
    let Some(k) = ec() else { return };
    let pk = k.public().unwrap();
    let algs = [ES256];
    let mut v = val(&algs); v.max_age = Some(300);
    let mut i = issue(&k); i.auth_time = Some(NOW - 100);
    assert!(id_token::validate(&i.sign().unwrap(), &pk, &v).is_ok());
    i.auth_time = Some(NOW - 1000);
    assert!(id_token::validate(&i.sign().unwrap(), &pk, &v).is_err(), "authentication too old for max_age");
    assert!(id_token::validate(&issue(&k).sign().unwrap(), &pk, &v).is_err(), "max_age requires auth_time");
    // auth_time in the future.
    let c = Claims::new().issuer(ISS).subject("s").audience(&[CID]).expires_at(NOW + 100).issued_at(NOW).set("auth_time", NOW + 5000);
    assert!(id_token::validate(&jwt::sign(ES256, &k, &c, None).unwrap(), &pk, &val(&algs)).is_err());
    // The issuer side refuses to sign without auth_time when the request needed it.
    let mut j = issue(&k); j.require_auth_time = true;
    assert!(j.sign().is_err());
}

#[test]
fn at_hash_and_c_hash_are_verified() {
    let Some(k) = ec() else { return };
    let pk = k.public().unwrap();
    let algs = [ES256];
    let mut i = issue(&k); i.access_token = Some("access-token-1"); i.code = Some("code-1");
    let t = i.sign().unwrap();
    let mut v = val(&algs); v.access_token = Some("access-token-1"); v.code = Some("code-1"); v.require_at_hash = true; v.require_c_hash = true;
    assert!(id_token::validate(&t, &pk, &v).is_ok());
    v.access_token = Some("a-different-token");
    assert!(id_token::validate(&t, &pk, &v).is_err(), "token substitution");
    v.access_token = Some("access-token-1"); v.code = Some("other-code");
    assert!(id_token::validate(&t, &pk, &v).is_err());
    // Required but absent.
    let plain = issue(&k).sign().unwrap();
    let mut w = val(&algs); w.require_at_hash = true; w.access_token = Some("x");
    assert!(id_token::validate(&plain, &pk, &w).is_err());
}

#[test]
fn acr_and_iat_age() {
    let Some(k) = ec() else { return };
    let pk = k.public().unwrap();
    let algs = [ES256];
    let mut i = issue(&k); i.acr = Some("loa2");
    let t = i.sign().unwrap();
    let mut v = val(&algs); v.acr_values = &["loa2", "loa3"];
    assert!(id_token::validate(&t, &pk, &v).is_ok());
    v.acr_values = &["loa3"]; assert!(id_token::validate(&t, &pk, &v).is_err());
    v.acr_values = &["loa2"]; assert!(id_token::validate(&issue(&k).sign().unwrap(), &pk, &v).is_err(), "acr required but missing");
    let mut w = val(&algs); w.max_iat_age = Some(5); w.leeway = 0; w.now = Some(NOW + 100);
    assert!(id_token::validate(&t, &pk, &w).is_err());
}

#[test]
fn issuer_limits() {
    let Some(k) = ec() else { return };
    let mut i = issue(&k);
    i.lifetime = 0; assert!(i.sign().is_err());
    i.lifetime = 3601; assert!(i.sign().is_err());
    i.lifetime = 3600; assert!(i.sign().is_ok());
    let hk = Jwk::parse(r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#).unwrap();
    assert!(IdTokenIssue { alg: HS256, key: &hk, ..issue(&k) }.sign().is_err(), "symmetric ID tokens are not issued");
    // Registered claims cannot be overridden through `extra`.
    let extra = [("sub", json!("attacker")), ("email", json!("a@example.com"))];
    let mut j = issue(&k); j.extra = &extra;
    let t = j.sign().unwrap();
    let id = id_token::validate(&t, &k.public().unwrap(), &val(&[ES256])).unwrap();
    assert_eq!(id.subject, "248289761001");
    assert_eq!(id.claims.str_claim("email").unwrap(), Some("a@example.com"));
}

#[test]
fn id_token_hint_ignores_expiry_but_not_signature_or_issuer() {
    let Some(k) = ec() else { return };
    let Some(evil) = ec() else { return };
    let t = issue(&k).sign().unwrap();
    let c = id_token::verify_hint(&t, &k.public().unwrap(), &[ES256], ISS, Some(CID)).unwrap();
    assert_eq!(c.str_claim("sub").unwrap(), Some("248289761001"));
    assert!(id_token::verify_hint(&t, &evil.public().unwrap(), &[ES256], ISS, None).is_err());
    assert!(id_token::verify_hint(&t, &k.public().unwrap(), &[ES256], "https://other", None).is_err());
    assert!(id_token::verify_hint(&t, &k.public().unwrap(), &[ES256], ISS, Some("another-client")).is_err());
}

#[test]
fn jwk_set_selection() {
    let (Some(a), Some(b)) = (ec(), ec()) else { return };
    let mk = |k: &Jwk, kid: &str| { let mut p = k.public().unwrap(); p.kid = Some(kid.into()); p };
    let set = JwkSet { keys: vec![mk(&a, "a"), mk(&b, "b")] };
    assert_eq!(set.select(Some("b"), ES256).unwrap().kid.as_deref(), Some("b"));
    assert!(set.select(Some("zzz"), ES256).is_err());
    assert!(set.select(None, ES256).is_err(), "no kid and two candidates: the token must not choose");
    assert!(set.select(Some("a"), RS256).is_err(), "wrong key type for the algorithm");
    assert!(set.select(Some("a"), ES384).is_err(), "wrong curve for the algorithm");
    assert!(set.select(Some("a"), HS256).is_err(), "never pick a symmetric key from a set");
    assert!(JwkSet { keys: vec![mk(&a, "a")] }.select(None, ES256).is_ok());
    let dup = JwkSet { keys: vec![mk(&a, "same"), mk(&b, "same")] };
    assert!(dup.select(Some("same"), ES256).is_err(), "two keys with one kid");
    let mut enc = mk(&a, "e"); enc.use_ = Some("enc".into());
    assert!(JwkSet { keys: vec![enc] }.select(Some("e"), ES256).is_err(), "encryption key");
    assert!(JwkSet { keys: vec![a.clone()] }.select(None, ES256).is_err(), "private keys are not served from a set");
}

// ---------- authentication requests ----------

fn client() -> ClientInfo {
    ClientInfo { client_id: CID.into(), redirect_uris: vec!["https://rp.example.org/cb".into()], kind: ClientKind::Web, allowed_scopes: scope("openid profile email"), response_types: vec!["code".into()] }
}
fn authn(extra: &str) -> Result<AuthenticationRequest, authlas::oauth::OAuthError> {
    let q = format!("response_type=code&client_id={CID}&redirect_uri=https%3A%2F%2Frp.example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256{extra}");
    let r = request::validate(&q, &client(), &ServerPolicy::default()).unwrap_or_else(|e| panic!("{:?}", e.error()));
    AuthenticationRequest::from_oauth(r)
}

#[test]
fn parses_the_oidc_parameters() {
    let r = authn("&prompt=login%20consent&max_age=300&acr_values=loa2%20loa3&login_hint=alice%40example.com&ui_locales=en%20de").unwrap();
    assert!(r.prompt.has(Prompt::Login) && r.prompt.has(Prompt::Consent));
    assert_eq!(r.max_age, Some(300));
    assert_eq!(r.acr_values, ["loa2", "loa3"]);
    assert_eq!(r.login_hint.as_deref(), Some("alice@example.com"));
    assert_eq!(r.ui_locales, ["en", "de"]);
    assert_eq!(r.oauth.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    assert!(r.requires_auth_time());
    assert!(!authn("").unwrap().requires_auth_time());
}

#[test]
fn bad_oidc_parameters_are_invalid_request() {
    for extra in ["&prompt=none%20login", "&max_age=-1", "&max_age=abc", "&max_age=99999999999", "&claims=%7Bnot-json", "&prompt=login%20%01", "&login_hint=a%0Ab"] {
        assert_eq!(authn(extra).unwrap_err().code, ErrorCode::InvalidRequest, "{extra}");
    }
    // Unknown prompt values are ignored (Core 3.1.2.1).
    assert!(authn("&prompt=future_value").is_ok());
}

#[test]
fn requires_the_openid_scope_and_code_flow() {
    let q = format!("response_type=code&client_id={CID}&redirect_uri=https%3A%2F%2Frp.example.org%2Fcb&scope=profile&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");
    let r = request::validate(&q, &client(), &ServerPolicy::default()).unwrap();
    assert_eq!(AuthenticationRequest::from_oauth(r).unwrap_err().code, ErrorCode::InvalidScope);
}

#[test]
fn claims_parameter() {
    let spec = r#"{"userinfo":{"given_name":{"essential":true},"nickname":null,"email":{"essential":true},"email_verified":{"essential":true},"picture":null},"id_token":{"auth_time":{"essential":true},"acr":{"values":["urn:mace:incommon:iap:silver"]}}}"#;
    let c = ClaimsRequest::parse(spec).unwrap();
    assert_eq!(c.userinfo.len(), 5);
    assert!(c.userinfo.iter().find(|(k, _)| k == "email").unwrap().1.essential);
    assert!(!c.userinfo.iter().find(|(k, _)| k == "nickname").unwrap().1.essential);
    assert!(c.requires_auth_time());
    let (r, vals) = c.acr().unwrap();
    assert!(!r.essential);
    assert_eq!(vals, ["urn:mace:incommon:iap:silver"]);
    for bad in [r#"{"userinfo":[]}"#, r#"{"userinfo":{"a":5}}"#, r#"{"userinfo":{"a":{"essential":"yes"}}}"#, r#"{"userinfo":{"a":{"values":3}}}"#, "[]", "5"] {
        assert!(ClaimsRequest::parse(bad).is_err(), "{bad}");
    }
    assert!(ClaimsRequest::parse(&format!(r#"{{"userinfo":{{"{}":null}}}}"#, "x".repeat(9000))).is_err());
    let e = ClaimsRequest::parse("{}").unwrap();
    assert!(e.userinfo.is_empty() && !e.requires_auth_time());
}

#[test]
fn pick_claims_honours_value_constraints_and_reports_missing_essentials() {
    let c = ClaimsRequest::parse(r#"{"userinfo":{"email":{"essential":true},"locale":{"values":["en","de"]},"phone_number":{"essential":true},"zoneinfo":{"value":"Europe/Berlin"}}}"#).unwrap();
    let mut profile = Map::new();
    profile.insert("email".into(), json!("a@example.com")); profile.insert("locale".into(), json!("fr")); profile.insert("zoneinfo".into(), json!("Europe/Berlin"));
    let (got, missing) = pick_claims(&c.userinfo, &profile);
    let names: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
    assert!(names.contains(&"email") && names.contains(&"zoneinfo"));
    assert!(!names.contains(&"locale"), "fr is not in the allowed values");
    assert_eq!(missing, ["phone_number"]);
}

// ---------- prompt / max_age decisions ----------

fn session(logged_in: bool, auth_age: u64, consent: bool) -> SessionState {
    SessionState { subject: logged_in.then(|| "alice".to_string()), auth_time: logged_in.then(|| NOW - auth_age), acr: None, has_consent: consent }
}
fn pol() -> DecidePolicy { DecidePolicy { now: Some(NOW), supported_acr: vec![] } }

#[test]
fn decide_normal_flows() {
    let r = authn("").unwrap();
    assert_eq!(decide(&r, &session(false, 0, false), &pol(), None), Next::Login { force: false });
    assert_eq!(decide(&r, &session(true, 10, false), &pol(), None), Next::Consent);
    assert_eq!(decide(&r, &session(true, 10, true), &pol(), None), Next::Proceed);
}

#[test]
fn decide_prompt_none_never_shows_ui() {
    let r = authn("&prompt=none").unwrap();
    assert_eq!(decide(&r, &session(false, 0, false), &pol(), None), Next::Error(ErrorCode::LoginRequired));
    assert_eq!(decide(&r, &session(true, 10, false), &pol(), None), Next::Error(ErrorCode::ConsentRequired));
    assert_eq!(decide(&r, &session(true, 10, true), &pol(), None), Next::Proceed);
    // none + a stale session (max_age) cannot re-authenticate silently.
    let m = authn("&prompt=none&max_age=60").unwrap();
    assert_eq!(decide(&m, &session(true, 600, true), &pol(), None), Next::Error(ErrorCode::LoginRequired));
    assert_eq!(decide(&m, &session(true, 30, true), &pol(), None), Next::Proceed);
}

#[test]
fn decide_login_consent_and_select_account_prompts() {
    let consenting = session(true, 10, true);
    assert_eq!(decide(&authn("&prompt=login").unwrap(), &consenting, &pol(), None), Next::Login { force: true });
    assert_eq!(decide(&authn("&prompt=consent").unwrap(), &consenting, &pol(), None), Next::Consent);
    assert_eq!(decide(&authn("&prompt=select_account").unwrap(), &consenting, &pol(), None), Next::SelectAccount);
    // login wins over consent: authenticate again first.
    assert_eq!(decide(&authn("&prompt=login%20consent").unwrap(), &consenting, &pol(), None), Next::Login { force: true });
}

#[test]
fn decide_max_age() {
    let r = authn("&max_age=300").unwrap();
    assert_eq!(decide(&r, &session(true, 299, true), &pol(), None), Next::Proceed);
    assert_eq!(decide(&r, &session(true, 301, true), &pol(), None), Next::Login { force: true });
    // max_age=0 means authenticate now.
    assert_eq!(decide(&authn("&max_age=0").unwrap(), &session(true, 0, true), &pol(), None), Next::Login { force: true });
    // A session with no recorded auth_time cannot satisfy max_age.
    let mut s = session(true, 0, true); s.auth_time = None;
    assert_eq!(decide(&r, &s, &pol(), None), Next::Login { force: true });
}

#[test]
fn decide_id_token_hint_for_another_user_forces_login() {
    let r = authn("").unwrap();
    assert_eq!(decide(&r, &session(true, 10, true), &pol(), Some("alice")), Next::Proceed);
    assert_eq!(decide(&r, &session(true, 10, true), &pol(), Some("bob")), Next::Login { force: true });
    assert_eq!(decide(&authn("&prompt=none").unwrap(), &session(true, 10, true), &pol(), Some("bob")), Next::Error(ErrorCode::LoginRequired));
}

#[test]
fn decide_acr() {
    let r = authn("&acr_values=loa2").unwrap();
    let mut s = session(true, 10, true);
    s.acr = Some("loa1".into());
    assert_eq!(decide(&r, &s, &pol(), None), Next::Login { force: true }, "session level too low: step up");
    s.acr = Some("loa2".into());
    assert_eq!(decide(&r, &s, &pol(), None), Next::Proceed);
    // An essential acr request the OP can never meet.
    let e = authn("&claims=%7B%22id_token%22%3A%7B%22acr%22%3A%7B%22essential%22%3Atrue%2C%22values%22%3A%5B%22loa9%22%5D%7D%7D%7D").unwrap();
    let p = DecidePolicy { now: Some(NOW), supported_acr: vec!["loa1".into(), "loa2".into()] };
    assert_eq!(decide(&e, &s, &p, None), Next::Error(ErrorCode::UnmetAuthenticationRequirements));
}

#[test]
fn check_issuable_enforces_auth_time_and_max_age() {
    let r = authn("&max_age=60").unwrap();
    assert!(check_issuable(&r, &session(true, 30, true), Some(NOW)).is_ok());
    assert!(check_issuable(&r, &session(true, 300, true), Some(NOW)).is_err());
    let mut s = session(true, 0, true); s.auth_time = None;
    assert_eq!(check_issuable(&r, &s, Some(NOW)).unwrap_err().code, ErrorCode::ServerError);
    assert!(check_issuable(&authn("").unwrap(), &s, Some(NOW)).is_ok());
}

// ---------- claims and UserInfo ----------

fn profile() -> Map<String, Value> {
    serde_json::from_value(json!({"sub": "248289761001", "name": "Jane Doe", "given_name": "Jane", "family_name": "Doe", "email": "janedoe@example.com", "email_verified": true,
        "phone_number": "+1 (425) 555-1212", "birthdate": "0000-03-22", "address": {"formatted": "1 Main St", "country": "US"}, "internal_risk_score": 97, "locale": "en-US"})).unwrap()
}

#[test]
fn userinfo_returns_only_what_the_scope_entitles() {
    let u = userinfo_response(&profile(), "248289761001", &scope("openid profile"), &ClaimsRequest::default()).unwrap();
    assert_eq!(u["name"], "Jane Doe");
    assert!(!u.contains_key("email") && !u.contains_key("phone_number") && !u.contains_key("address"));
    assert!(!u.contains_key("internal_risk_score"), "claims outside any scope never leave");
    let u = userinfo_response(&profile(), "248289761001", &scope("openid email"), &ClaimsRequest::default()).unwrap();
    assert_eq!(u["email"], "janedoe@example.com");
    assert_eq!(u["email_verified"], true);
    assert!(!u.contains_key("name"));
    // The claims request can add claims, but only ones the profile has and that are standard-typed.
    let c = ClaimsRequest::parse(r#"{"userinfo":{"phone_number":{"essential":true},"nope":null}}"#).unwrap();
    let u = userinfo_response(&profile(), "248289761001", &scope("openid"), &c).unwrap();
    assert!(u.contains_key("phone_number") && !u.contains_key("nope"));
    let only_sub = userinfo_response(&profile(), "248289761001", &scope("openid"), &ClaimsRequest::default()).unwrap();
    assert_eq!(only_sub.len(), 1);
}

#[test]
fn userinfo_needs_openid_scope_and_a_sane_sub() {
    assert!(userinfo_authorize(&scope("openid")).is_ok());
    assert_eq!(userinfo_authorize(&scope("profile")).unwrap_err().code, ErrorCode::InsufficientScope);
    assert!(userinfo_response(&profile(), "", &scope("openid"), &ClaimsRequest::default()).is_err());
    assert!(userinfo_response(&profile(), &"x".repeat(256), &scope("openid"), &ClaimsRequest::default()).is_err());
}

#[test]
fn rp_checks_userinfo_sub_against_the_id_token() {
    let body = json!({"sub": "248289761001", "name": "Jane Doe"}).to_string();
    assert!(validate_userinfo(&body, "248289761001").is_ok());
    assert!(matches!(validate_userinfo(&body, "someone-else"), Err(Error::Claim(_))), "mixed-up token: refuse the profile");
    assert!(validate_userinfo(&json!({"name": "x"}).to_string(), "248289761001").is_err());
    assert!(validate_userinfo(&json!({"sub": "248289761001", "email_verified": "true"}).to_string(), "248289761001").is_err(), "string where a boolean belongs");
}

#[test]
fn standard_claim_types() {
    let ok = |v: Value| check_standard_claims(v.as_object().unwrap()).is_ok();
    assert!(ok(json!({"birthdate": "1990-05-17"})) && ok(json!({"birthdate": "0000-03-22"})) && ok(json!({"birthdate": "1990"})));
    assert!(!ok(json!({"birthdate": "1990-13-01"})) && !ok(json!({"birthdate": "17/05/1990"})) && !ok(json!({"birthdate": "1990-05-32"})));
    assert!(!ok(json!({"email": "no-at-sign"})) && !ok(json!({"email": "a b@example.com"})));
    assert!(!ok(json!({"email_verified": "true"})) && !ok(json!({"phone_number_verified": 1})));
    assert!(!ok(json!({"picture": "javascript:alert(1)"})) && !ok(json!({"website": 5})));
    assert!(!ok(json!({"address": "somewhere"})) && !ok(json!({"address": {"country": 1}})));
    assert!(!ok(json!({"updated_at": "yesterday"})) && ok(json!({"updated_at": 1311280970})));
    assert!(ok(json!({"unknown_claim": {"anything": 1}})));
}

// ---------- pairwise ----------

#[test]
fn pairwise_subjects() {
    let p = PairwiseSubjects::new(&[7u8; 32]).unwrap();
    let a = p.subject("rp.example.org", "user-1").unwrap();
    assert_eq!(a, p.subject("rp.example.org", "user-1").unwrap(), "deterministic");
    assert_ne!(a, p.subject("other.example.net", "user-1").unwrap(), "different sector, different sub");
    assert_ne!(a, p.subject("rp.example.org", "user-2").unwrap());
    assert_ne!(p.subject("ab", "c").unwrap(), p.subject("a", "bc").unwrap(), "length prefixes prevent concatenation ambiguity");
    assert!(a.len() <= 255 && !a.contains("user-1"));
    assert_ne!(a, PairwiseSubjects::new(&[8u8; 32]).unwrap().subject("rp.example.org", "user-1").unwrap(), "a different secret gives different values");
    assert!(PairwiseSubjects::new(&[0u8; 31]).is_err());
    assert!(p.subject("", "u").is_err() && p.subject("s", "").is_err());
}

#[test]
fn sector_identifier_rules() {
    let one = vec!["https://rp.example.org/cb".to_string(), "https://RP.example.org/cb2".to_string()];
    assert_eq!(sector_identifier(&one, None).unwrap(), "rp.example.org");
    let many = vec!["https://a.example.org/cb".to_string(), "https://b.example.org/cb".to_string()];
    assert!(sector_identifier(&many, None).is_err(), "several hosts need a sector_identifier_uri");
    assert_eq!(sector_identifier(&many, Some("https://group.example.org/sector.json")).unwrap(), "group.example.org");
    assert!(sector_identifier(&many, Some("https://169.254.169.254/x")).is_err(), "SSRF: the sector document is fetched");
    assert!(sector_identifier(&many, Some("http://group.example.org/s.json")).is_err());
    assert!(sector_identifier(&[], None).is_err());
    let doc = json!(["https://a.example.org/cb", "https://b.example.org/cb", "https://c.example.org/cb"]).to_string();
    assert!(validate_sector_document(&doc, &many).is_ok());
    assert!(validate_sector_document(&json!(["https://a.example.org/cb"]).to_string(), &many).is_err(), "must list every registered URI");
    assert!(validate_sector_document("{}", &many).is_err());
    assert!(validate_sector_document(&json!([1, 2]).to_string(), &many).is_err());
}

// ---------- discovery ----------

#[test]
fn discovery_document_round_trip_and_checks() {
    let m = ProviderMetadata::secure_defaults(ISS, ISS, &[ES256, EdDSA]);
    let json = m.to_json();
    let parsed = ProviderMetadata::parse(&json, ISS).unwrap();
    assert!(parsed.problems_for_rp().is_empty(), "{:?}", parsed.problems_for_rp());
    assert_eq!(parsed.id_token_signing_alg_values_supported, ["ES256", "EdDSA"]);
    assert_eq!(parsed.base.userinfo_endpoint.as_deref(), Some("https://op.example.com/userinfo"));
    assert_eq!(parsed.end_session_endpoint.as_deref(), Some("https://op.example.com/logout"));
    assert!(parsed.base.code_challenge_methods_supported.contains(&"S256".to_string()), "MCP clients refuse OPs that do not advertise this");
    assert_eq!(parsed.usable_algs(&[ES256, RS256, HS256]), [ES256]);
    // A document for another issuer (mix-up).
    assert!(matches!(ProviderMetadata::parse(&json, "https://other.example.com"), Err(Error::Claim(_))));
}

#[test]
fn discovery_problem_reporting() {
    let mut v: Value = serde_json::from_str(&ProviderMetadata::secure_defaults(ISS, ISS, &[ES256]).to_json()).unwrap();
    v.as_object_mut().unwrap().remove("jwks_uri");
    v["id_token_signing_alg_values_supported"] = json!(["ES256", "none"]);
    v["subject_types_supported"] = json!([]);
    v["scopes_supported"] = json!(["profile"]);
    let m = ProviderMetadata::parse(&v.to_string(), ISS).unwrap();
    let p = m.problems_for_rp();
    for want in ["no jwks_uri", "no subject_types_supported", "OP offers unsigned ID tokens (alg none)", "scopes_supported lacks openid"] { assert!(p.contains(&want), "missing {want}: {p:?}"); }
    let mut v2: Value = serde_json::from_str(&ProviderMetadata::secure_defaults(ISS, ISS, &[ES256]).to_json()).unwrap();
    v2["end_session_endpoint"] = json!("http://op.example.com/logout");
    assert!(ProviderMetadata::parse(&v2.to_string(), ISS).is_err());
    v2["end_session_endpoint"] = json!(5);
    assert!(ProviderMetadata::parse(&v2.to_string(), ISS).is_err());
}

// ---------- RP-initiated logout ----------

fn lookup(id: &str) -> Option<LogoutClient> {
    (id == CID).then(|| LogoutClient { client_id: CID.into(), post_logout_redirect_uris: vec!["https://rp.example.org/bye".into()] })
}

#[test]
fn logout_redirect_only_to_registered_uris() {
    let Some(k) = ec() else { return };
    let hint = id_token::verify_hint(&issue(&k).sign().unwrap(), &k.public().unwrap(), &[ES256], ISS, None).unwrap();
    let q = |uri: &str| format!("client_id={CID}&post_logout_redirect_uri={}&state=xyz", url::form_urlencoded::byte_serialize(uri.as_bytes()).collect::<String>());
    let plan = LogoutRequest::parse(&q("https://rp.example.org/bye"), Some(hint.clone())).unwrap().plan(&lookup).unwrap();
    assert_eq!(plan.redirect.as_deref(), Some("https://rp.example.org/bye?state=xyz"));
    assert!(!plan.needs_confirmation);
    assert_eq!(plan.subject.as_deref(), Some("248289761001"));
    for bad in ["https://evil.example/bye", "https://rp.example.org/bye/", "https://rp.example.org/bye?x=1", "https://rp.example.org/", "http://rp.example.org/bye"] {
        let plan = LogoutRequest::parse(&q(bad), Some(hint.clone())).unwrap().plan(&lookup).unwrap();
        assert_eq!(plan.redirect, None, "{bad} must not be redirected to");
    }
    // Unknown client: no redirect, whatever the URI.
    let p = LogoutRequest::parse("client_id=nobody&post_logout_redirect_uri=https%3A%2F%2Frp.example.org%2Fbye", None).unwrap().plan(&lookup).unwrap();
    assert_eq!(p.redirect, None);
}

#[test]
fn logout_without_a_hint_needs_user_confirmation() {
    let p = LogoutRequest::parse(&format!("client_id={CID}"), None).unwrap().plan(&lookup).unwrap();
    assert!(p.needs_confirmation, "any web page could otherwise sign users out");
    assert_eq!(p.subject, None);
}

#[test]
fn logout_client_id_must_match_the_hint_audience() {
    let Some(k) = ec() else { return };
    let hint = id_token::verify_hint(&issue(&k).sign().unwrap(), &k.public().unwrap(), &[ES256], ISS, None).unwrap();
    assert!(LogoutRequest::parse("client_id=another", Some(hint.clone())).unwrap().plan(&lookup).is_err());
    // client_id may be omitted when the hint names exactly one audience.
    let p = LogoutRequest::parse("", Some(hint)).unwrap().plan(&lookup).unwrap();
    assert_eq!(p.client_id.as_deref(), Some(CID));
}

#[test]
fn logout_request_parsing_limits() {
    assert!(LogoutRequest::parse("state=a&state=b", None).is_err());
    assert!(LogoutRequest::parse(&format!("state={}", "x".repeat(600)), None).is_err());
    assert!(LogoutRequest::parse("state=a%00b", None).is_err());
}

#[test]
fn rp_builds_a_logout_url() {
    let (url, state) = build_logout_url("https://op.example.com/logout", Some("hint.jwt.here"), CID, Some("https://rp.example.org/bye")).unwrap();
    let u = url::Url::parse(&url).unwrap();
    let get = |k: &str| u.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.to_string());
    assert_eq!(get("id_token_hint").as_deref(), Some("hint.jwt.here"));
    assert_eq!(get("client_id").as_deref(), Some(CID));
    assert_eq!(get("post_logout_redirect_uri").as_deref(), Some("https://rp.example.org/bye"));
    assert_eq!(get("state"), state);
    assert!(state.is_some());
    let (plain, no_state) = build_logout_url("https://op.example.com/logout", None, CID, None).unwrap();
    assert!(no_state.is_none() && !plain.contains("state="));
    assert!(build_logout_url("http://op.example.com/logout", None, CID, None).is_err());
}

// ---------- back-channel logout ----------

fn logout_issue(k: &Jwk) -> LogoutTokenIssue<'_> {
    LogoutTokenIssue { alg: ES256, key: k, issuer: ISS, client_id: CID, subject: Some("248289761001"), sid: Some("sess-1"), lifetime: 60, now: Some(NOW) }
}
fn lval<'a>(algs: &'a [Algorithm]) -> LogoutValidate<'a> { let mut v = LogoutValidate::new(algs, ISS, CID); v.now = Some(NOW + 5); v }

#[test]
fn logout_token_round_trip() {
    let Some(k) = ec() else { return };
    let t = logout_issue(&k).sign().unwrap();
    let r = validate_logout_token(&t, &k.public().unwrap(), &lval(&[ES256])).unwrap();
    assert_eq!(r.subject.as_deref(), Some("248289761001"));
    assert_eq!(r.sid.as_deref(), Some("sess-1"));
    let body = format!("logout_token={t}");
    assert_eq!(logout_token_from_body(&body).unwrap(), t);
    assert!(logout_token_from_body("logout_token=a&logout_token=b").is_err());
    assert!(logout_token_from_body("x=1").is_err());
    // sub only, sid only.
    let only_sid = LogoutTokenIssue { subject: None, ..logout_issue(&k) }.sign().unwrap();
    assert!(validate_logout_token(&only_sid, &k.public().unwrap(), &lval(&[ES256])).is_ok());
    let only_sub = LogoutTokenIssue { sid: None, ..logout_issue(&k) }.sign().unwrap();
    assert!(validate_logout_token(&only_sub, &k.public().unwrap(), &lval(&[ES256])).is_ok());
    let mut need_sid = lval(&[ES256]); need_sid.require_sid = true;
    assert!(validate_logout_token(&only_sub, &k.public().unwrap(), &need_sid).is_err());
    assert!(LogoutTokenIssue { subject: None, sid: None, ..logout_issue(&k) }.sign().is_err());
    assert!(LogoutTokenIssue { lifetime: 121, ..logout_issue(&k) }.sign().is_err());
}

#[test]
fn an_id_token_is_not_a_logout_token() {
    let Some(k) = ec() else { return };
    let pk = k.public().unwrap();
    // A legitimate ID token, presented as a logout token: no events claim, wrong typ, has a nonce, has no jti.
    let mut i = issue(&k); i.nonce = Some("n");
    assert!(validate_logout_token(&i.sign().unwrap(), &pk, &lval(&[ES256])).is_err());
    // Even with typ forgiven, it still lacks events.
    let mut lenient = lval(&[ES256]); lenient.require_typ = false;
    assert!(validate_logout_token(&i.sign().unwrap(), &pk, &lenient).is_err());
    // A forged logout token that carries a nonce.
    let c = Claims::new().issuer(ISS).audience(&[CID]).subject("s").issued_at(NOW).expires_at(NOW + 60).jti("j1").set("nonce", "n").set("events", json!({"http://schemas.openid.net/event/backchannel-logout": {}}));
    assert!(validate_logout_token(&jwt::sign(ES256, &k, &c, Some("logout+jwt")).unwrap(), &pk, &lval(&[ES256])).is_err(), "nonce is prohibited");
}

#[test]
fn logout_token_rejections() {
    let Some(k) = ec() else { return };
    let Some(evil) = ec() else { return };
    let pk = k.public().unwrap();
    let t = logout_issue(&k).sign().unwrap();
    assert!(validate_logout_token(&t, &evil.public().unwrap(), &lval(&[ES256])).is_err(), "wrong key");
    assert!(validate_logout_token(&t, &pk, &LogoutValidate { issuer: "https://other", ..lval(&[ES256]) }).is_err());
    assert!(validate_logout_token(&t, &pk, &LogoutValidate { client_id: "other", ..lval(&[ES256]) }).is_err(), "aud");
    assert!(validate_logout_token(&t, &pk, &LogoutValidate { now: Some(NOW + 1000), ..lval(&[ES256]) }).is_err(), "expired");
    let ev = |events: Value| { let c = Claims::new().issuer(ISS).audience(&[CID]).subject("s").issued_at(NOW).expires_at(NOW + 60).jti("j").set("events", events); jwt::sign(ES256, &k, &c, Some("logout+jwt")).unwrap() };
    assert!(validate_logout_token(&ev(json!({})), &pk, &lval(&[ES256])).is_err());
    assert!(validate_logout_token(&ev(json!({"http://schemas.openid.net/event/other": {}})), &pk, &lval(&[ES256])).is_err());
    assert!(validate_logout_token(&ev(json!({"http://schemas.openid.net/event/backchannel-logout": 1})), &pk, &lval(&[ES256])).is_err(), "event value must be an object");
    assert!(validate_logout_token(&ev(json!("http://schemas.openid.net/event/backchannel-logout")), &pk, &lval(&[ES256])).is_err());
    assert!(validate_logout_token(&ev(json!({"http://schemas.openid.net/event/backchannel-logout": {}})), &pk, &lval(&[ES256])).is_ok());
    // No sub and no sid.
    let c = Claims::new().issuer(ISS).audience(&[CID]).issued_at(NOW).expires_at(NOW + 60).jti("j").set("events", json!({"http://schemas.openid.net/event/backchannel-logout": {}}));
    assert!(validate_logout_token(&jwt::sign(ES256, &k, &c, Some("logout+jwt")).unwrap(), &pk, &lval(&[ES256])).is_err());
    // Missing jti.
    let c = Claims::new().issuer(ISS).audience(&[CID]).subject("s").issued_at(NOW).expires_at(NOW + 60).set("events", json!({"http://schemas.openid.net/event/backchannel-logout": {}}));
    assert!(validate_logout_token(&jwt::sign(ES256, &k, &c, Some("logout+jwt")).unwrap(), &pk, &lval(&[ES256])).is_err());
}

#[test]
fn logout_token_replay() {
    let Some(k) = ec() else { return };
    let cache = MemoryReplayCache::new();
    let t = logout_issue(&k).sign().unwrap();
    let mut v = lval(&[ES256]); v.replay = Some(&cache);
    assert!(validate_logout_token(&t, &k.public().unwrap(), &v).is_ok());
    assert!(validate_logout_token(&t, &k.public().unwrap(), &v).is_err(), "same jti twice");
}

// ---------- end to end ----------

struct NullRevoker;
impl authlas::oauth::token::RevocationSink for NullRevoker { fn revoke_grant(&self, _: &str) {} }

#[test]
fn full_code_flow_with_id_token_userinfo_and_logout() {
    use authlas::oauth::token::{self, MemoryCodeStore};
    let Some(k) = ec() else { return };
    let pk = k.public().unwrap();
    let store = MemoryCodeStore::new();

    // RP builds the request; OP validates it.
    let mut b = authlas::oauth::request::Builder::new("https://op.example.com/authorize", CID, "https://rp.example.org/cb");
    let sc = scope("openid profile email");
    b.scope = Some(&sc);
    b.with_nonce = true;
    b.extra = &[("max_age", "600"), ("prompt", "login"), ("claims", r#"{"id_token":{"auth_time":{"essential":true},"email":null}}"#)];
    let out = b.build().unwrap();
    let query = out.url.split_once('?').unwrap().1.to_string();
    let req = request::validate(&query, &client(), &ServerPolicy::default()).unwrap_or_else(|e| panic!("{:?}", e.error()));
    let areq = AuthenticationRequest::from_oauth(req.clone()).unwrap();
    assert_eq!(areq.max_age, Some(600));
    assert!(areq.requires_auth_time());

    // prompt=login forces a fresh login even though a session exists; without it the session is good.
    let st = SessionState { subject: Some("alice".into()), auth_time: Some(NOW - 20), acr: Some("loa2".into()), has_consent: true };
    assert_eq!(decide(&areq, &st, &pol(), None), Next::Login { force: true });
    let no_prompt = AuthenticationRequest { prompt: Prompts::default(), ..areq.clone() };
    assert_eq!(decide(&no_prompt, &st, &pol(), None), Next::Proceed);
    assert_eq!(decide(&no_prompt, &SessionState { auth_time: Some(NOW - 5000), ..st.clone() }, &pol(), None), Next::Login { force: true });
    check_issuable(&areq, &st, Some(NOW)).unwrap();

    // OP issues a code carrying the session facts. A client-sent auth_time cannot get in.
    let mut hostile = req.clone();
    hostile.oidc.push(("auth_time".into(), "1".into()));
    let at = (NOW - 20).to_string();
    let (code, _) = token::issue_code_with(&store, &hostile, "248289761001", scope("openid profile email"), Some(NOW), &[("auth_time", &at), ("acr", "loa2"), ("sid", "sess-1")]).unwrap();

    // Token endpoint: redeem, then build the ID token.
    let rec = token::redeem_code(&store, &NullRevoker, CID, &code, Some("https://rp.example.org/cb"), Some(&out.code_verifier), Some(NOW + 1)).unwrap();
    let access_token = token::random_token().unwrap();
    let profile = serde_json::from_value::<Map<String, Value>>(json!({"email": "janedoe@example.com", "name": "Jane Doe"})).unwrap();
    let idt = id_token::for_code(&rec, &k, ES256, ISS, "248289761001", &access_token, 300, &profile, Some(NOW + 1)).unwrap().expect("openid grant gets an ID token");

    // RP validates it with everything it sent.
    let algs = [ES256];
    let mut v = Validate::new(&algs, ISS, CID);
    v.now = Some(NOW + 2); v.nonce = out.nonce.as_deref(); v.max_age = Some(600); v.access_token = Some(&access_token); v.require_at_hash = true;
    let id = id_token::validate(&idt, &pk, &v).unwrap();
    assert_eq!(id.auth_time, Some(NOW - 20), "the OP's value, not the client's");
    assert_eq!(id.acr.as_deref(), Some("loa2"));
    assert_eq!(id.sid.as_deref(), Some("sess-1"));
    assert_eq!(id.claims.str_claim("email").unwrap(), Some("janedoe@example.com"), "requested through claims.id_token");
    assert!(id.claims.str_claim("name").unwrap().is_none(), "scope claims stay out of the ID token");

    // UserInfo with the same grant.
    let ui = userinfo_response(&profile, &id.subject, &rec.scope, &areq.claims).unwrap();
    let checked = validate_userinfo(&Value::Object(ui).to_string(), &id.subject).unwrap();
    assert_eq!(checked["name"], "Jane Doe");

    // Replaying the code is refused.
    assert!(token::redeem_code(&store, &NullRevoker, CID, &code, Some("https://rp.example.org/cb"), Some(&out.code_verifier), Some(NOW + 2)).is_err());

    // A plain OAuth grant (no openid) gets no ID token.
    let plain_scope = scope("profile");
    let (c2, _) = token::issue_code(&store, &req, "u", plain_scope, Some(NOW)).unwrap();
    let rec2 = token::redeem_code(&store, &NullRevoker, CID, &c2, Some("https://rp.example.org/cb"), Some(&out.code_verifier), Some(NOW + 1)).unwrap();
    assert!(id_token::for_code(&rec2, &k, ES256, ISS, "u", "at", 300, &profile, Some(NOW)).unwrap().is_none());

    // Logout: the OP notifies the RP, which ties the token to the session it knows.
    let lt = LogoutTokenIssue { alg: ES256, key: &k, issuer: ISS, client_id: CID, subject: Some(&id.subject), sid: id.sid.as_deref(), lifetime: 60, now: Some(NOW + 100) }.sign().unwrap();
    let mut lv = LogoutValidate::new(&algs, ISS, CID); lv.now = Some(NOW + 101);
    let got = validate_logout_token(&lt, &pk, &lv).unwrap();
    assert_eq!(got.sid, id.sid);
    assert_eq!(got.subject.as_deref(), Some(id.subject.as_str()));
}
