use authlas::jwa::Algorithm::*;
use authlas::jwk::Jwk;
use authlas::jwt::{self, Claims};
use authlas::oauth::at_jwt::{self, Issue, Verify};
use authlas::oauth::device::{self, DeviceStore};
use authlas::oauth::error::ErrorCode;
use authlas::oauth::exchange::{self, Rule, Subject};
use authlas::oauth::form::Params;
use authlas::oauth::introspection::{self as intro, Introspection, TokenTypeHint};
use authlas::oauth::metadata::{self, AsMetadata, ResourceMetadata};
use authlas::oauth::revocation::{self, Found, Outcome, Revoker};
use authlas::oauth::scope::Scope;
use authlas::{b64, Error};
use serde_json::json;
use std::sync::Mutex;

fn hs() -> Jwk { Jwk::parse(&json!({"kty": "oct", "k": b64::encode([5u8; 32])}).to_string()).unwrap() }
fn sc(s: &str) -> Scope { Scope::parse(s).unwrap() }
const NOW: u64 = 1_700_000_000;
const ISS: &str = "https://as.example";
const RS: &str = "https://rs.example/api";

// ---------- RFC 9068 access tokens ----------

fn at(extra: &[(&str, serde_json::Value)], lifetime: u64) -> String {
    Issue { alg: HS256, key: &hs(), issuer: ISS, audience: &[RS], subject: "alice", client_id: "c1", scope: &sc("read write"),
        lifetime, now: Some(NOW), extra, cnf: None }.sign().unwrap()
}
fn vfy<'a>() -> Verify<'a> { Verify { algs: &[HS256], issuer: ISS, audience: RS, now: Some(NOW + 10), leeway: 0, replay: None } }

#[test]
fn access_token_round_trip_and_scope_checks() {
    let t = at(&[("roles", json!(["admin"]))], 600);
    let h = authlas::jws::peek_header(&t).unwrap();
    assert_eq!(h.typ.as_deref(), Some("at+jwt"));
    let a = at_jwt::verify(&t, &hs(), &vfy()).unwrap();
    assert_eq!((a.subject.as_str(), a.client_id.as_str()), ("alice", "c1"));
    assert_eq!(a.claims.map["roles"], json!(["admin"]));
    a.require_scope("read").unwrap();
    let e = a.require_scope("admin").unwrap_err();
    assert_eq!((e.code, e.status()), (ErrorCode::InsufficientScope, 403));
}

#[test]
fn access_token_rejections_are_all_invalid_token() {
    let k = hs();
    let good = at(&[], 600);
    let mut cases: Vec<(&str, String, Verify)> = vec![];
    let mut v = vfy(); v.audience = "https://other.example/api";
    cases.push(("wrong audience", good.clone(), v));
    let mut v = vfy(); v.issuer = "https://evil.example";
    cases.push(("wrong issuer", good.clone(), v));
    let mut v = vfy(); v.now = Some(NOW + 601);
    cases.push(("expired", good.clone(), v));
    let mut v = vfy(); v.algs = &[HS384];
    cases.push(("alg not allowed", good.clone(), v));
    // An ordinary JWT (typ JWT) with all the right claims is not an access token: it could be an ID token.
    let plain = jwt::sign(HS256, &k, &Claims::new().issuer(ISS).subject("alice").audience(&[RS]).issued_at(NOW).expires_at(NOW + 600).jti("j").set("client_id", "c1"), None).unwrap();
    cases.push(("typ JWT instead of at+jwt", plain, vfy()));
    let missing = jwt::sign(HS256, &k, &Claims::new().issuer(ISS).audience(&[RS]).issued_at(NOW).expires_at(NOW + 600), Some("at+jwt")).unwrap();
    cases.push(("missing sub/client_id/jti", missing, vfy()));
    cases.push(("garbage", "x.y.z".into(), vfy()));
    for (label, tok, v) in cases {
        let e = at_jwt::verify(&tok, &k, &v).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidToken, "{label}");
        assert_eq!(e.status(), 401, "{label}");
    }
    let other = Jwk::parse(&json!({"kty": "oct", "k": b64::encode([6u8; 32])}).to_string()).unwrap();
    assert_eq!(at_jwt::verify(&good, &other, &vfy()).unwrap_err().code, ErrorCode::InvalidToken);
}

#[test]
fn issuer_cannot_be_overridden_by_extra_claims() {
    let t = at(&[("sub", json!("root")), ("exp", json!(99_999_999_999u64)), ("aud", json!("x"))], 600);
    let a = at_jwt::verify(&t, &hs(), &vfy()).unwrap();
    assert_eq!(a.subject, "alice");
    assert_eq!(a.exp, NOW + 600);
}

// ---------- RFC 7662 / 9701 ----------

#[test]
fn inactive_is_exactly_active_false() {
    assert_eq!(Introspection::inactive().to_json(), r#"{"active":false}"#);
    // Even if fields were filled in, an inactive answer leaks nothing.
    let mut i = Introspection::inactive();
    i.sub = Some("alice".into()); i.scope = Some(sc("read"));
    assert_eq!(i.to_json(), r#"{"active":false}"#);
}

#[test]
fn introspection_round_trip_from_claims() {
    let c = Claims::new().issuer(ISS).subject("alice").audience(&["a", "b"]).issued_at(NOW).expires_at(NOW + 60).jti("j").set("client_id", "c1").set("scope", "read write")
        .confirm_jkt(&authlas::crypto::ec_generate("P-256").unwrap_or_else(|_| hs()).public().unwrap_or_else(|_| hs())).unwrap_or_else(|_| Claims::new());
    let i = Introspection::from_claims(&c).unwrap();
    assert!(i.active);
    assert_eq!(i.scope.as_ref().unwrap().to_string(), "read write");
    let back = Introspection::parse(&i.to_json()).unwrap();
    assert_eq!(back, i);
    assert!(i.is_for_audience("b") && !i.is_for_audience("c"));
    assert!(i.is_usable(NOW + 59, 0) && !i.is_usable(NOW + 60, 0));
    assert!(i.is_usable(NOW + 60, 5), "leeway");
    let mut nb = i.clone(); nb.nbf = Some(NOW + 100);
    assert!(!nb.is_usable(NOW, 0));
}

#[test]
fn introspection_parsing_is_strict() {
    assert!(Introspection::parse(r#"{"active":"true"}"#).is_err(), "string true is not a boolean");
    assert!(Introspection::parse(r#"{"active":1}"#).is_err());
    assert!(Introspection::parse(r#"{}"#).is_err());
    assert!(Introspection::parse(r#"[]"#).is_err());
    assert!(Introspection::parse(r#"{"active":true,"exp":"soon"}"#).is_err());
    assert!(Introspection::parse(r#"{"active":true,"exp":-1}"#).is_err());
    assert!(Introspection::parse(r#"{"active":true,"aud":5}"#).is_err());
    assert!(Introspection::parse(r#"{"active":true,"scope":"a\"b"}"#).is_err());
    assert!(!Introspection::parse(r#"{"active":false,"sub":"x","exp":5}"#).unwrap().active);
    assert_eq!(Introspection::parse(r#"{"active":true,"x-custom":7}"#).unwrap().extra["x-custom"], 7);
    // Extension members cannot shadow core ones when serialised.
    let mut i = Introspection { active: true, sub: Some("real".into()), ..Default::default() };
    i.extra.insert("sub".into(), json!("fake"));
    i.extra.insert("active".into(), json!(false));
    let v = i.to_value();
    assert_eq!((v["sub"].as_str(), v["active"].as_bool()), (Some("real"), Some(true)));
}

#[test]
fn introspection_request_parsing() {
    let r = intro::parse_request(&Params::parse("token=abc&token_type_hint=refresh_token").unwrap()).unwrap();
    assert_eq!((r.token.as_str(), r.hint), ("abc", Some(TokenTypeHint::RefreshToken)));
    assert_eq!(intro::parse_request(&Params::parse("token=abc&token_type_hint=whatever").unwrap()).unwrap().hint, None, "unknown hint ignored");
    assert!(intro::parse_request(&Params::parse("token_type_hint=access_token").unwrap()).is_err());
}

#[test]
fn rfc9701_jwt_response() {
    let k = hs();
    let resp = Introspection { active: true, sub: Some("alice".into()), scope: Some(sc("read")), exp: Some(NOW + 60), ..Default::default() };
    let jwt_resp = intro::sign_jwt_response(HS256, &k, ISS, RS, &resp).unwrap();
    assert_eq!(authlas::jws::peek_header(&jwt_resp).unwrap().typ.as_deref(), Some("token-introspection+jwt"));
    let got = intro::verify_jwt_response(&jwt_resp, &k, &[HS256], ISS, RS, None).unwrap();
    assert_eq!(got, resp);
    // Meant for another resource server.
    assert!(intro::verify_jwt_response(&jwt_resp, &k, &[HS256], ISS, "https://other", None).is_err());
    assert!(intro::verify_jwt_response(&jwt_resp, &k, &[HS256], "https://evil", RS, None).is_err());
    // A plain access token must not be accepted as an introspection response.
    assert!(intro::verify_jwt_response(&at(&[], 600), &k, &[HS256], ISS, RS, Some(NOW)).is_err());
    // An inactive answer round-trips as inactive.
    let off = intro::sign_jwt_response(HS256, &k, ISS, RS, &Introspection::inactive()).unwrap();
    assert!(!intro::verify_jwt_response(&off, &k, &[HS256], ISS, RS, None).unwrap().active);
}

// ---------- RFC 7009 ----------

struct Rev { tokens: Vec<(String, Found)>, log: Mutex<Vec<String>> }
impl Revoker for Rev {
    fn lookup(&self, t: &str, _: Option<TokenTypeHint>) -> Found { self.tokens.iter().find(|(k, _)| k == t).map(|(_, f)| f.clone()).unwrap_or(Found::NotFound) }
    fn revoke_grant(&self, g: &str) { self.log.lock().unwrap().push(format!("grant:{g}")); }
    fn revoke_access_jti(&self, j: &str) { self.log.lock().unwrap().push(format!("jti:{j}")); }
}

#[test]
fn revocation_rules() {
    let r = Rev { log: Mutex::new(vec![]), tokens: vec![
        ("rt".into(), Found::Refresh { client_id: "c1".into(), grant_id: "g1".into() }),
        ("at".into(), Found::Access { client_id: "c1".into(), grant_id: "g1".into(), jti: "j1".into() }),
    ] };
    let req = |t: &str| revocation::parse_request(&Params::parse(&format!("token={t}")).unwrap()).unwrap();
    assert_eq!(revocation::revoke(&r, "c1", &req("rt")), Outcome::Revoked);
    assert_eq!(revocation::revoke(&r, "c1", &req("at")), Outcome::Revoked);
    assert_eq!(*r.log.lock().unwrap(), vec!["grant:g1", "jti:j1"], "refresh revocation kills the grant, access only its jti");
    r.log.lock().unwrap().clear();
    // Someone else's token and unknown tokens look the same to the caller and change nothing.
    let other = revocation::revoke(&r, "c2", &req("rt"));
    let none = revocation::revoke(&r, "c1", &req("nope"));
    assert_eq!((other, none), (Outcome::NotYours, Outcome::NothingToDo));
    assert_eq!((other.http_status(), none.http_status()), (200, 200));
    assert!(other.is_notable() && !none.is_notable());
    assert!(r.log.lock().unwrap().is_empty());
    assert!(revocation::parse_request(&Params::parse("token_type_hint=refresh_token").unwrap()).is_err());
    assert_eq!(revocation::unsupported_token_type().code, ErrorCode::UnsupportedTokenType);
}

// ---------- RFC 8628 ----------

#[test]
fn user_code_alphabet_and_normalisation() {
    // RFC 8628 section 3.2 example: "WDJB-MJHT" uses only consonants from the recommended set.
    assert_eq!(device::normalize_user_code("WDJB-MJHT").unwrap(), "WDJBMJHT");
    assert_eq!(device::normalize_user_code("wdjb mjht").unwrap(), "WDJBMJHT");
    for bad in ["WDJB-MJH", "WDJB-MJHTT", "WDJB-MJH1", "AEIOUAEI", "WDJB-MJH0", ""] { assert!(device::normalize_user_code(bad).is_none(), "{bad:?}"); }
    assert_eq!(device::display_user_code("WDJBMJHT"), "WDJB-MJHT");
    let mut seen = std::collections::HashSet::new();
    let mut counts = std::collections::HashMap::new();
    for _ in 0..400 {
        let c = device::generate_user_code().unwrap();
        assert_eq!(c.len(), 8);
        assert!(device::normalize_user_code(&c).is_some(), "{c}");
        seen.insert(c.clone());
        for ch in c.chars() { *counts.entry(ch).or_insert(0u32) += 1; }
    }
    assert!(seen.len() > 395, "codes must not repeat");
    assert_eq!(counts.len(), 20, "all 20 symbols appear");
    // 3200 draws over 20 symbols: expect 160 each; a modulo-biased generator would skew badly.
    assert!(counts.values().all(|&n| (90..=240).contains(&n)), "{counts:?}");
}

#[test]
fn device_flow_happy_path() {
    let s = DeviceStore::new();
    let a = s.start("c1", sc("read"), vec![], "https://as.example/device", Some(1000)).unwrap();
    assert_eq!((a.expires_in, a.interval), (600, 5));
    assert!(a.verification_uri_complete.as_deref().unwrap().starts_with("https://as.example/device?user_code="));
    let j: serde_json::Value = serde_json::from_str(&a.to_json()).unwrap();
    assert_eq!(j["user_code"].as_str().unwrap().len(), 9, "displayed with a hyphen");
    assert_eq!(s.poll("c1", &a.device_code, Some(1001)).unwrap_err().code, ErrorCode::AuthorizationPending);
    assert_eq!(s.lookup_user_code(&device::display_user_code(&a.user_code), Some(1002)).unwrap().0, "c1");
    s.decide(&a.user_code.to_lowercase(), Some("alice"), Some(1003)).unwrap();
    let rec = s.poll("c1", &a.device_code, Some(1010)).unwrap();
    assert!(matches!(rec.state, device::State::Approved { ref subject } if subject == "alice"));
    // The code works once.
    assert_eq!(s.poll("c1", &a.device_code, Some(1020)).unwrap_err().code, ErrorCode::InvalidGrant);
    // And the user code can't be decided again.
    assert!(s.decide(&a.user_code, Some("mallory"), Some(1021)).is_err());
}

#[test]
fn device_polling_denial_expiry_and_binding() {
    let s = DeviceStore::new();
    let a = s.start("c1", sc("read"), vec![], "https://as.example/device", Some(1000)).unwrap();
    // Too fast -> slow_down, and the interval grows by 5 each time (RFC 8628 3.5).
    assert_eq!(s.poll("c1", &a.device_code, Some(1010)).unwrap_err().code, ErrorCode::AuthorizationPending);
    assert_eq!(s.poll("c1", &a.device_code, Some(1011)).unwrap_err().code, ErrorCode::SlowDown);
    assert_eq!(s.poll("c1", &a.device_code, Some(1017)).unwrap_err().code, ErrorCode::SlowDown, "interval is now 10");
    assert_eq!(s.poll("c1", &a.device_code, Some(1030)).unwrap_err().code, ErrorCode::SlowDown, "interval is now 15 from the last poll at 1017");
    assert_eq!(s.poll("c1", &a.device_code, Some(1050)).unwrap_err().code, ErrorCode::AuthorizationPending);
    // Another client cannot use the device code, and gets no hint it exists.
    assert_eq!(s.poll("c2", &a.device_code, Some(1100)).unwrap_err().code, ErrorCode::InvalidGrant);
    assert_eq!(s.poll("c1", "made-up", Some(1100)).unwrap_err().to_json(), s.poll("c2", &a.device_code, Some(1100)).unwrap_err().to_json());
    assert_eq!(s.poll("c1", &a.device_code, Some(1000 + 600)).unwrap_err().code, ErrorCode::ExpiredToken);
    let b = s.start("c1", sc("read"), vec![], "https://as.example/device", Some(2000)).unwrap();
    s.decide(&b.user_code, None, Some(2001)).unwrap();
    assert_eq!(s.poll("c1", &b.device_code, Some(2010)).unwrap_err().code, ErrorCode::AccessDenied);
}

#[test]
fn user_code_brute_force_locks_the_code() {
    let s = DeviceStore::new();
    let a = s.start("c1", sc("read"), vec![], "https://as.example/device", Some(1000)).unwrap();
    for _ in 0..5 { s.punish(&a.user_code); }
    assert!(s.lookup_user_code(&a.user_code, Some(1001)).is_none(), "locked after max attempts");
    assert!(s.decide(&a.user_code, Some("attacker"), Some(1001)).is_err());
    assert!(s.lookup_user_code("WDJB-MJHT", Some(1001)).is_none());
}

// ---------- RFC 8693 ----------

fn rules() -> Vec<Rule> {
    vec![Rule { client_id: "svc".into(), subject_token_types: vec![exchange::ACCESS_TOKEN.into()], requested_token_types: vec![exchange::ACCESS_TOKEN.into()],
        allowed_targets: vec!["https://billing.example".into()], allow_delegation: true }]
}
fn xreq(extra: &str) -> exchange::Request {
    exchange::parse_request(&Params::parse(&format!("grant_type={}&subject_token=st&subject_token_type={}{extra}", "x", exchange::ACCESS_TOKEN)).unwrap()).unwrap()
}

#[test]
fn exchange_request_parsing() {
    let r = xreq("&audience=https%3A%2F%2Fbilling.example&scope=read&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token");
    assert_eq!(r.audiences, vec!["https://billing.example"]);
    for bad in ["&actor_token=a", "&actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token", "&requested_token_type=bogus", "&scope=a%22"] {
        let body = format!("subject_token=st&subject_token_type={}{bad}", exchange::ACCESS_TOKEN);
        assert!(exchange::parse_request(&Params::parse(&body).unwrap()).is_err(), "{bad}");
    }
    assert!(exchange::parse_request(&Params::parse("subject_token=st").unwrap()).is_err());
}

#[test]
fn exchange_is_default_deny_and_narrowing_only() {
    let claims = Claims::new().subject("alice");
    let subj = Subject { claims: &claims, scope: &sc("read write") };
    let ok = exchange::authorize(&rules(), "svc", &xreq("&audience=https%3A%2F%2Fbilling.example&scope=read"), &subj, None).unwrap();
    assert_eq!((ok.scope.to_string().as_str(), ok.subject.as_str()), ("read", "alice"));
    assert!(ok.act.is_none());
    assert_eq!(exchange::authorize(&rules(), "svc", &xreq(""), &subj, None).unwrap().scope.to_string(), "read write", "scope defaults to the subject's");
    let code = |r: Result<_, authlas::oauth::OAuthError>| r.map(|_: exchange::Decision| ()).unwrap_err().code;
    assert_eq!(code(exchange::authorize(&rules(), "stranger", &xreq(""), &subj, None)), ErrorCode::UnauthorizedClient);
    assert_eq!(code(exchange::authorize(&rules(), "svc", &xreq("&audience=https%3A%2F%2Fother.example"), &subj, None)), ErrorCode::InvalidTarget);
    assert_eq!(code(exchange::authorize(&rules(), "svc", &xreq("&resource=https%3A%2F%2Fother.example"), &subj, None)), ErrorCode::InvalidTarget);
    assert_eq!(code(exchange::authorize(&rules(), "svc", &xreq("&scope=read+admin"), &subj, None)), ErrorCode::InvalidScope);
    assert_eq!(code(exchange::authorize(&rules(), "svc", &xreq("&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token"), &subj, None)), ErrorCode::InvalidRequest);
    let id_subj = exchange::parse_request(&Params::parse(&format!("subject_token=st&subject_token_type={}", exchange::ID_TOKEN)).unwrap()).unwrap();
    assert_eq!(code(exchange::authorize(&rules(), "svc", &id_subj, &subj, None)), ErrorCode::InvalidGrant);
    let nosub = Claims::new();
    assert!(exchange::authorize(&rules(), "svc", &xreq(""), &Subject { claims: &nosub, scope: &sc("read") }, None).is_err());
}

#[test]
fn exchange_delegation_and_may_act() {
    let at = exchange::ACCESS_TOKEN;
    let with_actor = xreq(&format!("&actor_token=at&actor_token_type={}", at.replace(':', "%3A")));
    let actor = Claims::new().subject("agent-7").issuer("https://idp.example");
    let subj_claims = Claims::new().subject("alice");
    let subj = Subject { claims: &subj_claims, scope: &sc("read") };
    // No actor claims validated -> refused.
    assert!(exchange::authorize(&rules(), "svc", &with_actor, &subj, None).is_err());
    let d = exchange::authorize(&rules(), "svc", &with_actor, &subj, Some(&actor)).unwrap();
    assert_eq!(d.act.unwrap(), json!({"sub": "agent-7", "iss": "https://idp.example"}));
    // may_act restricts who can act.
    let restricted = Claims::new().subject("alice").set("may_act", json!({"sub": "someone-else"}));
    let r = exchange::authorize(&rules(), "svc", &with_actor, &Subject { claims: &restricted, scope: &sc("read") }, Some(&actor));
    assert_eq!(r.unwrap_err().code, ErrorCode::InvalidGrant);
    let permitted = Claims::new().subject("alice").set("may_act", json!({"sub": "agent-7", "iss": "https://idp.example"}));
    exchange::authorize(&rules(), "svc", &with_actor, &Subject { claims: &permitted, scope: &sc("read") }, Some(&actor)).unwrap();
    let wrong_iss = Claims::new().subject("alice").set("may_act", json!({"sub": "agent-7", "iss": "https://evil.example"}));
    assert!(exchange::authorize(&rules(), "svc", &with_actor, &Subject { claims: &wrong_iss, scope: &sc("read") }, Some(&actor)).is_err());
    // Chain history is nested, outermost actor is the current one.
    let chained = Claims::new().subject("alice").set("act", json!({"sub": "agent-1"}));
    let d = exchange::authorize(&rules(), "svc", &with_actor, &Subject { claims: &chained, scope: &sc("read") }, Some(&actor)).unwrap();
    assert_eq!(d.act.unwrap(), json!({"sub": "agent-7", "iss": "https://idp.example", "act": {"sub": "agent-1"}}));
    // Delegation switched off for the client.
    let mut r = rules(); r[0].allow_delegation = false;
    assert!(exchange::authorize(&r, "svc", &with_actor, &subj, Some(&actor)).is_err());
    let body: serde_json::Value = serde_json::from_str(&exchange::response_json("tok", exchange::ACCESS_TOKEN, "Bearer", Some(60), Some(&sc("read")))).unwrap();
    assert_eq!(body["issued_token_type"], exchange::ACCESS_TOKEN);
}

// ---------- metadata ----------

#[test]
fn well_known_url_construction() {
    assert_eq!(metadata::as_metadata_url("https://as.example").unwrap(), "https://as.example/.well-known/oauth-authorization-server");
    assert_eq!(metadata::as_metadata_url("https://as.example/").unwrap(), "https://as.example/.well-known/oauth-authorization-server");
    // RFC 8414 3.1 example: issuer with a path.
    assert_eq!(metadata::as_metadata_url("https://example.com/issuer1").unwrap(), "https://example.com/.well-known/oauth-authorization-server/issuer1");
    assert_eq!(metadata::oidc_metadata_url("https://example.com/issuer1").unwrap(), "https://example.com/issuer1/.well-known/openid-configuration");
    assert_eq!(metadata::resource_metadata_url("https://rs.example:8443/api/v1").unwrap(), "https://rs.example:8443/.well-known/oauth-protected-resource/api/v1");
    for bad in ["http://as.example", "https://as.example?x=1", "https://as.example#f", "not a url", "ftp://as.example"] {
        assert!(metadata::as_metadata_url(bad).is_err(), "{bad}");
    }
}

#[test]
fn as_metadata_mixup_defence_and_validation() {
    let m = AsMetadata::secure_defaults(ISS, "https://as.example");
    let doc = m.to_json();
    assert_eq!(AsMetadata::parse(&doc, ISS).unwrap(), m);
    assert!(AsMetadata::parse(&doc, "https://other.example").is_err(), "document names a different issuer");
    assert!(AsMetadata::parse(&doc.replace("https://as.example/token", "http://as.example/token"), ISS).is_err(), "http endpoint");
    assert!(AsMetadata::parse(&doc.replace("https://as.example/token", "http://127.0.0.1:9/token"), ISS).is_ok(), "loopback http is allowed for development");
    assert!(AsMetadata::parse(r#"{"issuer":"https://as.example","issuer":"https://as.example"}"#, ISS).is_err(), "duplicate members");
    assert!(AsMetadata::parse(r#"{"token_endpoint":"https://as.example/t"}"#, ISS).is_err());
    assert!(AsMetadata::parse(r#"{"issuer":"https://as.example","scopes_supported":"read"}"#, ISS).is_err());
    assert!(AsMetadata::parse(r#"{"issuer":"https://as.example","require_pushed_authorization_requests":"yes"}"#, ISS).is_err());
    assert!(m.problems_for_code_flow().is_empty());
    let mut weak = m.clone(); weak.code_challenge_methods_supported = vec![];
    assert_eq!(weak.problems_for_code_flow(), vec!["server does not advertise PKCE S256"]);
    let ext = AsMetadata::parse(r#"{"issuer":"https://as.example","x_custom":1}"#, ISS).unwrap();
    assert_eq!(ext.extra["x_custom"], 1);
}

#[test]
fn resource_metadata_and_challenge_discovery() {
    let rm = ResourceMetadata { resource: RS.into(), authorization_servers: vec![ISS.into()], scopes_supported: vec!["read".into()],
        bearer_methods_supported: vec!["header".into()], dpop_bound_access_tokens_required: true, ..Default::default() };
    assert_eq!(ResourceMetadata::parse(&rm.to_json(), RS).unwrap(), rm);
    assert!(ResourceMetadata::parse(&rm.to_json(), "https://rs.example/other").is_err());
    assert!(ResourceMetadata::parse(&rm.to_json().replace(ISS, "http://as.example"), RS).is_err());
    assert!(ResourceMetadata::parse(&rm.to_json().replace("header", "carrier-pigeon"), RS).is_err());
    let h = r#"Bearer realm="api", error="invalid_token", resource_metadata="https://rs.example/.well-known/oauth-protected-resource/api""#;
    assert_eq!(metadata::resource_metadata_from_challenge(h).unwrap(), "https://rs.example/.well-known/oauth-protected-resource/api");
    assert!(metadata::resource_metadata_from_challenge(r#"Bearer resource_metadata="http://rs.example/x""#).is_none(), "https only");
    assert!(metadata::resource_metadata_from_challenge(r#"Bearer realm="api""#).is_none());
    let _ = Error::Decrypt;
}
