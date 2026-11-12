use authlas::jwa::Algorithm::{self, *};
use authlas::jwk::Jwk;
use authlas::jwt;
use authlas::oauth::bearer::{self, Scheme};
use authlas::oauth::client_auth::{self, Method as CM, Presented, Registered};
use authlas::oauth::error::{sanitize_description, ErrorCode, OAuthError};
use authlas::oauth::form::Params;
use authlas::oauth::pkce::{self, Method};
use authlas::oauth::redirect::{self, ClientKind, ResponseMode};
use authlas::oauth::request::{self, AuthRequest, Builder, ClientInfo, Failure, ServerPolicy};
use authlas::oauth::scope::Scope;
use authlas::oauth::token::{self, *};
use authlas::{b64, Error};
use serde_json::json;
use std::sync::Mutex;

// ---------- PKCE ----------

#[test]
fn rfc7636_appendix_b_vector() {
    let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(pkce::s256_challenge(v).unwrap(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    pkce::verify("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Method::S256, v).unwrap();
}

#[test]
fn pkce_verifier_rules() {
    assert!(!pkce::valid_verifier(&"a".repeat(42)));
    assert!(pkce::valid_verifier(&"a".repeat(43)));
    assert!(pkce::valid_verifier(&"a".repeat(128)));
    assert!(!pkce::valid_verifier(&"a".repeat(129)));
    assert!(!pkce::valid_verifier(&format!("{}+", "a".repeat(43))), "+ is not unreserved");
    assert!(!pkce::valid_verifier(&format!("{} ", "a".repeat(43))));
    let g = pkce::generate_verifier().unwrap();
    assert_eq!(g.len(), 43);
    assert_ne!(g, pkce::generate_verifier().unwrap());
}

#[test]
fn pkce_wrong_verifier_and_plain_policy() {
    let v = pkce::generate_verifier().unwrap();
    let ch = pkce::s256_challenge(&v).unwrap();
    assert!(pkce::verify(&ch, Method::S256, &pkce::generate_verifier().unwrap()).is_err());
    assert!(pkce::verify(&ch, Method::S256, "short").is_err());
    // The challenge itself is not an acceptable verifier under S256.
    assert!(pkce::verify(&ch, Method::S256, &ch).is_err());
    assert!(Method::parse(Some("plain"), false).is_err());
    assert!(Method::parse(None, false).is_err());
    assert_eq!(Method::parse(None, true).unwrap(), Method::Plain);
    assert!(Method::parse(Some("S512"), true).is_err());
    assert!(pkce::check_challenge_syntax("tooshort", Method::S256).is_err());
    assert!(pkce::check_challenge_syntax(&"A".repeat(44), Method::S256).is_err());
    pkce::check_challenge_syntax(&ch, Method::S256).unwrap();
}

// ---------- form / scope ----------

#[test]
fn duplicate_and_empty_parameters() {
    assert!(Params::parse("a=1&a=2").is_err(), "repeated parameter must fail, not first-wins");
    let p = Params::parse("a=&b=2").unwrap();
    assert!(!p.contains("a"), "empty value counts as omitted");
    let p = Params::parse("resource=https%3A%2F%2Fa&resource=https%3A%2F%2Fb").unwrap();
    assert_eq!(p.get_all("resource").len(), 2);
    assert!(p.get("resource").is_err());
    assert!(Params::parse(&"a=1&".repeat(200)).is_err(), "parameter count limit");
    assert!(Params::parse(&format!("a={}", "x".repeat(70_000))).is_err(), "size limit");
    assert_eq!(Params::parse("a=b%20c+d").unwrap().get("a").unwrap(), Some("b c d"));
}

#[test]
fn scope_grammar() {
    let s = Scope::parse("read write read").unwrap();
    assert_eq!(s.to_string(), "read write");
    for bad in ["", " read", "read ", "read  write", "re\"ad", "re\\ad", "read\twrite", "r\u{e9}ad"] {
        assert!(Scope::parse(bad).is_err(), "{bad:?}");
    }
    let all = Scope::parse("a b c").unwrap();
    let some = Scope::parse("b a").unwrap();
    assert!(some.is_subset_of(&all));
    assert!(!all.is_subset_of(&some));
    assert_eq!(all.excess(&some), vec!["c"]);
    assert_eq!(all.intersect(&some).to_string(), "a b");
    assert!(Scope::parse(&(0..70).map(|i| format!("s{i}")).collect::<Vec<_>>().join(" ")).is_err());
}

// ---------- redirect URIs ----------

#[test]
fn redirect_registration_rules() {
    use ClientKind::*;
    for ok in ["https://app.example/cb", "https://app.example:8443/cb?x=1"] {
        redirect::validate_registered(ok, Web).unwrap();
    }
    for bad in [
        "http://app.example/cb", "https://app.example/cb#frag", "https://u:p@app.example/cb", "/relative",
        "javascript:alert(1)", "data:text/html,x", "https://app.example/cb x", "http://localhost/cb",
        "http://127.0.0.1/cb", "com.example.app:/cb", "https:///nohost", "file:///etc/passwd", "https://a.example/cb\n",
        "https://app.example\\@evil.example/cb", "https:/\\evil.example/cb",
    ] {
        assert!(redirect::validate_registered(bad, Web).is_err(), "web: {bad:?}");
    }
    redirect::validate_registered("http://127.0.0.1:8080/cb", Web).unwrap();
    redirect::validate_registered("http://[::1]:8080/cb", Web).unwrap();
    // Native apps: port-less loopback and reverse-domain schemes.
    redirect::validate_registered("http://127.0.0.1/cb", Native).unwrap();
    redirect::validate_registered("com.example.app:/oauth2redirect", Native).unwrap();
    assert!(redirect::validate_registered("myapp:/cb", Native).is_err(), "private-use scheme needs a dot");
    assert!(redirect::validate_registered("http://localhost/cb", Native).is_err(), "localhost is refused");
    assert!(redirect::validate_registered("javascript:alert(1)", Native).is_err());
    assert!(redirect::validate_registered(&format!("https://a.example/{}", "x".repeat(3000)), Web).is_err());
}

#[test]
fn redirect_matching_is_exact() {
    let reg = "https://app.example/cb";
    assert!(redirect::matches(reg, reg));
    for bad in [
        "https://app.example/cb/", "https://app.example/cb?x=1", "https://app.example/CB", "https://APP.example/cb",
        "https://app.example/cb/../cb", "https://app.example.evil/cb", "https://app.example@evil/cb",
        "https://app.example:443/cb ", "http://app.example/cb", "https://app.example/cbx", "https://app.example/c",
        "https://evil.example/cb?https://app.example/cb", "https://app.example/cb#x",
    ] {
        assert!(!redirect::matches(reg, bad), "{bad:?}");
    }
}

#[test]
fn loopback_port_is_the_only_flexible_part() {
    let reg = "http://127.0.0.1/cb";
    assert!(redirect::matches(reg, "http://127.0.0.1:51234/cb"));
    assert!(!redirect::matches(reg, "http://127.0.0.1:51234/other"));
    assert!(!redirect::matches(reg, "http://127.0.0.1:51234/cb?x=1"));
    assert!(!redirect::matches(reg, "http://localhost:51234/cb"));
    assert!(!redirect::matches(reg, "http://[::1]:51234/cb"));
    assert!(!redirect::matches(reg, "https://127.0.0.1:51234/cb"));
    // A registration that pins a port is compared exactly.
    assert!(!redirect::matches("http://127.0.0.1:8080/cb", "http://127.0.0.1:9090/cb"));
    // A non-loopback host never gets port flexibility.
    assert!(!redirect::matches("https://app.example/cb", "https://app.example:8443/cb"));
}

#[test]
fn redirect_resolution() {
    let one = vec!["https://a.example/cb".to_string()];
    let two = vec!["https://a.example/cb".to_string(), "https://a.example/cb2".to_string()];
    assert_eq!(redirect::resolve(&one, None).unwrap(), "https://a.example/cb");
    assert!(redirect::resolve(&two, None).is_err(), "omitted redirect_uri with several registered");
    assert!(redirect::resolve(&[], None).is_err());
    assert!(redirect::resolve(&one, Some("https://a.example/other")).is_err());
}

#[test]
fn response_uri_building_and_escaping() {
    let p = vec![("code".to_string(), "a b&c=d".to_string()), ("state".to_string(), "x".to_string())];
    let u = redirect::build_response_uri("https://a.example/cb?keep=1", ResponseMode::Query, &p).unwrap();
    assert!(u.starts_with("https://a.example/cb?keep=1&code=a+b%26c%3Dd&state=x"), "{u}");
    let f = redirect::build_response_uri("https://a.example/cb", ResponseMode::Fragment, &p).unwrap();
    assert!(f.contains("#code=a+b%26c%3Dd&state=x"), "{f}");
    let html = redirect::form_post_html("https://a.example/cb\"><script>", &[("state".into(), "\"><img src=x onerror=alert(1)>".into())]);
    assert!(!html.contains("<script>") && !html.contains("<img"), "{html}");
    assert!(html.contains("&quot;&gt;&lt;img"));
}

// ---------- authorization request ----------

fn client() -> ClientInfo {
    ClientInfo {
        client_id: "c1".into(), redirect_uris: vec!["https://app.example/cb".into()], kind: ClientKind::Web,
        allowed_scopes: Scope::parse("read write").unwrap(), response_types: vec!["code".into()],
    }
}

fn auth_query(extra: &str) -> String {
    let ch = pkce::s256_challenge(&"a".repeat(43)).unwrap();
    format!("response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read&state=xyz&code_challenge={ch}&code_challenge_method=S256{extra}")
}

#[test]
fn valid_authorization_request() {
    let r = request::validate(&auth_query(""), &client(), &ServerPolicy::default()).unwrap();
    assert_eq!(r.scope.to_string(), "read");
    assert_eq!(r.state.as_deref(), Some("xyz"));
    assert_eq!(r.code_challenge_method, Some(Method::S256));
    let r = request::validate(&auth_query("&utm=1"), &client(), &ServerPolicy::default()).unwrap();
    assert_eq!(r.extra, vec![("utm".to_string(), "1".to_string())]);
}

#[test]
fn bad_client_or_redirect_is_never_redirected() {
    let p = ServerPolicy::default();
    let q = auth_query("").replace("client_id=c1", "client_id=zzz");
    assert!(matches!(request::validate(&q, &client(), &p), Err(Failure::Direct(_))));
    let q = auth_query("").replace("app.example%2Fcb", "evil.example%2Fcb");
    match request::validate(&q, &client(), &p) { Err(Failure::Direct(e)) => assert_eq!(e.code, ErrorCode::InvalidRequest), o => panic!("{o:?}") }
    // Repeated redirect_uri must also be direct (it could be a parameter-pollution attempt).
    let q = format!("{}&redirect_uri=https%3A%2F%2Fevil.example%2Fcb", auth_query(""));
    assert!(matches!(request::validate(&q, &client(), &p), Err(Failure::Direct(_))));
    assert!(matches!(request::validate("response_type=code", &client(), &p), Err(Failure::Direct(_))));
}

fn redirect_err(q: &str) -> OAuthError {
    match request::validate(q, &client(), &ServerPolicy::default()) {
        Err(Failure::Redirect { redirect_uri, error, .. }) => { assert_eq!(redirect_uri, "https://app.example/cb"); error }
        o => panic!("expected redirectable failure, got {o:?}"),
    }
}

#[test]
fn errors_after_trust_are_redirected_with_state() {
    let q = auth_query("").replace("response_type=code", "response_type=token");
    let e = redirect_err(&q);
    assert_eq!(e.code, ErrorCode::UnsupportedResponseType);
    assert_eq!(e.state.as_deref(), Some("xyz"));
    assert_eq!(redirect_err(&auth_query("").replace("scope=read", "scope=admin")).code, ErrorCode::InvalidScope);
    assert_eq!(redirect_err(&auth_query("").replace("scope=read", "scope=read+write+admin")).code, ErrorCode::InvalidScope);
    assert_eq!(redirect_err(&auth_query("&resource=urn%3Ax")).code, ErrorCode::InvalidTarget);
    assert_eq!(redirect_err(&auth_query("&resource=https%3A%2F%2Fr.example%2F%23f")).code, ErrorCode::InvalidTarget);
    assert_eq!(redirect_err(&auth_query("&response_mode=weird")).code, ErrorCode::InvalidRequest);
    // Malformed state is not echoed.
    let e = redirect_err(&auth_query("").replace("state=xyz", "state=%00bad"));
    assert!(e.state.is_none());
}

#[test]
fn pkce_is_mandatory_and_plain_is_refused() {
    let no_pkce = "response_type=code&client_id=c1&scope=read&state=s";
    assert_eq!(redirect_err(no_pkce).description.as_deref(), Some("code_challenge is required"));
    let ch = pkce::s256_challenge(&"a".repeat(43)).unwrap();
    let plain = format!("{no_pkce}&code_challenge={}&code_challenge_method=plain", "a".repeat(43));
    assert_eq!(redirect_err(&plain).code, ErrorCode::InvalidRequest);
    let missing_method = format!("{no_pkce}&code_challenge={ch}");
    assert_eq!(redirect_err(&missing_method).code, ErrorCode::InvalidRequest, "absent method means plain, which is refused");
    let method_only = format!("{no_pkce}&code_challenge_method=S256");
    assert_eq!(redirect_err(&method_only).code, ErrorCode::InvalidRequest);
    let bad_ch = format!("{no_pkce}&code_challenge=short&code_challenge_method=S256");
    assert_eq!(redirect_err(&bad_ch).code, ErrorCode::InvalidRequest);
    // plain can be enabled deliberately.
    let mut p = ServerPolicy::default();
    p.allow_plain_pkce = true;
    request::validate(&plain.replace("response_type=code&", "response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&"), &client(), &p).unwrap();
}

#[test]
fn state_and_resource_policy() {
    let mut p = ServerPolicy::default();
    p.require_state = true;
    let q = auth_query("").replace("&state=xyz", "");
    assert!(matches!(request::validate(&q, &client(), &p), Err(Failure::Redirect { .. })));
    p.require_state = false;
    p.max_state_len = 3;
    assert!(matches!(request::validate(&auth_query("").replace("state=xyz", "state=toolong"), &client(), &p), Err(Failure::Redirect { .. })));
    p.max_state_len = 512;
    p.allowed_resources = vec!["https://r.example/".into()];
    request::validate(&auth_query("&resource=https%3A%2F%2Fr.example%2F"), &client(), &p).unwrap();
    assert!(request::validate(&auth_query("&resource=https%3A%2F%2Fother.example%2F"), &client(), &p).is_err());
    p.default_scope = Some(Scope::parse("read").unwrap());
    request::validate(&auth_query("").replace("scope=read&", ""), &client(), &p).unwrap();
}

#[test]
fn redirect_failure_builds_target_with_iss() {
    let f = request::validate(&auth_query("").replace("scope=read", "scope=admin"), &client(), &ServerPolicy::default()).unwrap_err();
    let u = f.redirect_target(Some("https://as.example")).unwrap().unwrap();
    assert!(u.contains("error=invalid_scope") && u.contains("state=xyz") && u.contains("iss=https%3A%2F%2Fas.example"), "{u}");
    assert!(Failure::Direct(OAuthError::new(ErrorCode::InvalidRequest)).redirect_target(None).is_none());
}

#[test]
fn client_side_request_and_response_checks() {
    let scope = Scope::parse("read").unwrap();
    let mut b = Builder::new("https://as.example/authorize", "c1", "https://app.example/cb");
    b.scope = Some(&scope);
    b.resources = &["https://r.example/"];
    b.with_nonce = true;
    let out = b.build().unwrap();
    assert!(out.url.contains("code_challenge_method=S256") && out.url.contains("resource=https%3A%2F%2Fr.example%2F"));
    assert_eq!(out.state.len(), 43);
    assert!(out.nonce.is_some());
    // What we built must pass our own server-side validation (round trip).
    let q = out.url.split_once('?').unwrap().1;
    let req = request::validate(q, &client(), &{ let mut p = ServerPolicy::default(); p.allowed_resources = vec!["https://r.example/".into()]; p }).unwrap();
    assert_eq!(req.state.as_deref(), Some(out.state.as_str()));
    pkce::verify(req.code_challenge.as_deref().unwrap(), Method::S256, &out.code_verifier).unwrap();
    // Response handling.
    let ok = format!("code=abc&state={}&iss=https%3A%2F%2Fas.example", out.state);
    assert_eq!(request::parse_response(&ok, &out.state, Some("https://as.example")).unwrap(), "abc");
    assert!(request::parse_response(&ok, "other-state", None).is_err(), "state mismatch");
    assert!(request::parse_response("code=abc", &out.state, None).is_err(), "missing state");
    assert!(request::parse_response(&ok, &out.state, Some("https://evil.example")).is_err(), "mix-up: wrong iss");
    assert!(request::parse_response(&format!("code=abc&state={}", out.state), &out.state, Some("https://as.example")).is_err(), "mix-up: iss absent");
    let err = request::parse_response(&format!("error=access_denied&state={}", out.state), &out.state, None).unwrap_err();
    assert_eq!(err.code, ErrorCode::AccessDenied);
    // An error with a wrong state is not trusted either.
    assert_eq!(request::parse_response("error=access_denied&state=forged", &out.state, None).unwrap_err().description.as_deref(), Some("state mismatch"));
}

// ---------- codes, tokens, refresh ----------

struct Sink(Mutex<Vec<String>>);
impl RevocationSink for Sink { fn revoke_grant(&self, g: &str) { self.0.lock().unwrap().push(g.to_string()); } }

fn issued() -> (MemoryCodeStore, AuthRequest, String, String, String) {
    let verifier = pkce::generate_verifier().unwrap();
    let ch = pkce::s256_challenge(&verifier).unwrap();
    let q = format!("response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read&state=s&code_challenge={ch}&code_challenge_method=S256");
    let req = request::validate(&q, &client(), &ServerPolicy::default()).unwrap();
    let store = MemoryCodeStore::new();
    let (code, grant) = issue_code(&store, &req, "alice", req.scope.clone(), Some(1000)).unwrap();
    (store, req, code, grant, verifier)
}

const CB: Option<&str> = Some("https://app.example/cb");

#[test]
fn code_redeems_once_and_reuse_revokes_the_grant() {
    let (store, _, code, grant, v) = issued();
    let sink = Sink(Mutex::new(vec![]));
    let rec = redeem_code(&store, &sink, "c1", &code, CB, Some(&v), Some(1010)).unwrap();
    assert_eq!((rec.subject.as_str(), rec.scope.to_string().as_str()), ("alice", "read"));
    let again = redeem_code(&store, &sink, "c1", &code, CB, Some(&v), Some(1011)).unwrap_err();
    assert_eq!(again.code, ErrorCode::InvalidGrant);
    assert_eq!(*sink.0.lock().unwrap(), vec![grant], "reuse must revoke what the first redemption issued");
}

#[test]
fn code_binding_checks_all_fail_identically() {
    let sink = Sink(Mutex::new(vec![]));
    let cases: Vec<(&str, Option<&str>, Option<&str>, u64, &str)> = vec![
        ("c2", CB, None, 1010, "wrong client"),
        ("c1", Some("https://app.example/other"), None, 1010, "wrong redirect_uri"),
        ("c1", None, None, 1010, "missing redirect_uri"),
        ("c1", CB, Some("x"), 1010, "wrong verifier"),
        ("c1", CB, None, 1010, "missing verifier"),
        ("c1", CB, None, 1000 + token::CODE_LIFETIME, "expired"),
    ];
    for (client_id, ru, ver_override, now, label) in cases {
        let (store, _, code, _, v) = issued();
        let ver = match (label, ver_override) { ("missing verifier", _) => None, (_, Some(o)) => Some(o.to_string()), _ => Some(v) };
        let e = redeem_code(&store, &sink, client_id, &code, ru, ver.as_deref(), Some(now)).unwrap_err();
        assert_eq!(e.to_json(), r#"{"error":"invalid_grant","error_description":"authorization code is invalid, expired or already used"}"#, "{label}");
    }
    let (store, ..) = issued();
    assert_eq!(redeem_code(&store, &sink, "c1", "never-issued", CB, None, Some(1)).unwrap_err().code, ErrorCode::InvalidGrant);
}

#[test]
fn verifier_without_a_stored_challenge_is_a_downgrade_signal() {
    let store = MemoryCodeStore::new();
    let mut p = ServerPolicy::default();
    p.require_pkce = false;
    let req = request::validate("response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read", &client(), &p).unwrap();
    let (code, _) = issue_code(&store, &req, "alice", req.scope.clone(), Some(1000)).unwrap();
    let sink = Sink(Mutex::new(vec![]));
    assert!(redeem_code(&store, &sink, "c1", &code, CB, Some(&"a".repeat(43)), Some(1001)).is_err());
}

#[test]
fn refresh_rotation_narrowing_and_theft_detection() {
    let (cstore, _, code, grant, v) = issued();
    let sink = Sink(Mutex::new(vec![]));
    let rec = redeem_code(&cstore, &sink, "c1", &code, CB, Some(&v), Some(1010)).unwrap();
    let rs = MemoryRefreshStore::new();
    let r1 = issue_refresh(&rs, &rec, Some(1010)).unwrap();
    let (r2, rr) = rotate_refresh(&rs, "c1", &r1, None, Some(2000)).unwrap();
    assert_ne!(r1, r2);
    assert_eq!(rr.grant_id, grant);
    // Widening is refused. The failure consumes the token (it is single use), so issue a fresh chain to test the rest.
    let (r3, _) = rotate_refresh(&rs, "c1", &r2, Some(&Scope::parse("read").unwrap()), Some(2001)).unwrap();
    assert_eq!(rotate_refresh(&rs, "c1", &r3, Some(&Scope::parse("read write").unwrap()), Some(2002)).unwrap_err().code, ErrorCode::InvalidScope);
    // Theft: the OLD token r1 shows up again -> whole family dies, including the newest token.
    assert_eq!(rotate_refresh(&rs, "c1", &r1, None, Some(2003)).unwrap_err().code, ErrorCode::InvalidGrant);
    assert!(rotate_refresh(&rs, "c1", &r3, None, Some(2004)).is_err(), "family must be revoked after reuse");
}

#[test]
fn refresh_wrong_client_expiry_and_family_cap() {
    let (cstore, _, code, _, v) = issued();
    let sink = Sink(Mutex::new(vec![]));
    let rec = redeem_code(&cstore, &sink, "c1", &code, CB, Some(&v), Some(1010)).unwrap();
    let rs = MemoryRefreshStore::new();
    let r1 = issue_refresh(&rs, &rec, Some(1000)).unwrap();
    assert!(rotate_refresh(&rs, "c2", &r1, None, Some(1001)).is_err(), "other client");
    // That attempt was a theft signal: the family is dead for the real client too.
    assert!(rotate_refresh(&rs, "c1", &r1, None, Some(1002)).is_err());
    // A refresh token is dead at exactly its own expiry.
    let rs = MemoryRefreshStore::new();
    let r = issue_refresh(&rs, &rec, Some(1000)).unwrap();
    assert!(rotate_refresh(&rs, "c1", &r, None, Some(1000 + REFRESH_LIFETIME)).is_err(), "expired at expires_at");
    let r = issue_refresh(&rs, &rec, Some(1000)).unwrap();
    assert!(rotate_refresh(&rs, "c1", &r, None, Some(1000 + REFRESH_LIFETIME - 1)).is_ok());
    // Walk a chain of rotations every 29 days: the family ends at its absolute cap no matter how often it is used.
    let rs = MemoryRefreshStore::new();
    let mut tok = issue_refresh(&rs, &CodeRecord { grant_id: "g3".into(), ..rec.clone() }, Some(1000)).unwrap();
    let family_end = 1000 + REFRESH_FAMILY_LIFETIME;
    let mut now = 1000;
    let mut rotations = 0;
    loop {
        now += 29 * 24 * 3600;
        match rotate_refresh(&rs, "c1", &tok, None, Some(now)) {
            Ok((next, r)) => { assert!(r.expires_at <= family_end, "rotation extended past the family cap"); tok = next; rotations += 1; }
            Err(_) => break,
        }
        assert!(rotations < 100, "family never ended");
    }
    assert!(now >= family_end - 29 * 24 * 3600, "chain ended early at {now}");
    assert!(rotations >= 5, "{rotations}");
}

#[test]
fn token_request_parsing() {
    let p = |s: &str| token::parse_request(&Params::parse(s).unwrap());
    match p("grant_type=authorization_code&code=c&redirect_uri=https%3A%2F%2Fa&code_verifier=v").unwrap() {
        TokenRequest::AuthorizationCode { code, redirect_uri, code_verifier, .. } => {
            assert_eq!((code.as_str(), redirect_uri.as_deref(), code_verifier.as_deref()), ("c", Some("https://a"), Some("v")));
        }
        o => panic!("{o:?}"),
    }
    assert!(matches!(p("grant_type=refresh_token&refresh_token=r&scope=a+b").unwrap(), TokenRequest::RefreshToken { .. }));
    assert!(matches!(p("grant_type=client_credentials").unwrap(), TokenRequest::ClientCredentials { .. }));
    assert_eq!(p("grant_type=password&username=a&password=b").unwrap_err().code, ErrorCode::UnsupportedGrantType);
    assert_eq!(p("grant_type=implicit").unwrap_err().code, ErrorCode::UnsupportedGrantType);
    assert_eq!(p("code=c").unwrap_err().code, ErrorCode::InvalidRequest);
    assert_eq!(p("grant_type=authorization_code").unwrap_err().code, ErrorCode::InvalidRequest);
    assert!(Params::parse("grant_type=authorization_code&grant_type=refresh_token").is_err());
    assert_eq!(p("grant_type=client_credentials&scope=a%22b").unwrap_err().code, ErrorCode::InvalidScope);
}

#[test]
fn token_response_round_trip_and_hardening() {
    let mut r = TokenResponse::bearer("at", 3600);
    r.refresh_token = Some("rt".into());
    r.scope = Some(Scope::parse("read").unwrap());
    r.extra = vec![("access_token".into(), json!("evil")), ("id_token".into(), json!("x.y.z"))];
    let j = r.to_json();
    let back = TokenResponse::parse(&j).unwrap();
    assert_eq!((back.access_token.as_str(), back.expires_in, back.refresh_token.as_deref()), ("at", Some(3600), Some("rt")));
    assert_eq!(back.extra, vec![("id_token".to_string(), json!("x.y.z"))], "extensions cannot overwrite core members");
    assert_eq!(TokenResponse::parse(r#"{"access_token":"a","token_type":"bearer","expires_in":"60"}"#).unwrap().expires_in, Some(60));
    for bad in [r#"{"token_type":"Bearer"}"#, r#"{"access_token":"","token_type":"Bearer"}"#, r#"{"access_token":1,"token_type":"Bearer"}"#,
        r#"{"access_token":"a"}"#, r#"[]"#, r#"{"access_token":"a","token_type":"Bearer","expires_in":-5}"#, "not json",
        r#"{"access_token":"a","token_type":"Bearer","scope":"a\"b"}"#] {
        assert!(TokenResponse::parse(bad).is_err(), "{bad}");
    }
}

// ---------- client authentication ----------

fn reg(method: CM, secret: Option<&[u8]>) -> Registered {
    Registered { client_id: "c1".into(), method, secret: secret.map(|s| s.to_vec()), secret_is_hash: false, jwk: None, assertion_algs: vec![] }
}

#[test]
fn basic_and_post_authentication() {
    let h = client_auth::basic_header("c1", "s3cr:et %+");
    let body = Params::parse("grant_type=client_credentials").unwrap();
    let p = client_auth::extract(Some(&h), &body).unwrap();
    assert_eq!(p, Presented::Basic { client_id: "c1".into(), secret: "s3cr:et %+".into() });
    let r = reg(CM::SecretBasic, Some(b"s3cr:et %+"));
    assert_eq!(client_auth::authenticate(&p, &r, "https://as/token", None, None, None).unwrap(), "c1");
    let wrong = Presented::Basic { client_id: "c1".into(), secret: "nope".into() };
    assert_eq!(client_auth::authenticate(&wrong, &r, "https://as/token", None, None, None).unwrap_err().code, ErrorCode::InvalidClient);
    // Presenting by POST when registered for Basic is refused (method downgrade/confusion).
    let post = Presented::Post { client_id: "c1".into(), secret: "s3cr:et %+".into() };
    assert!(client_auth::authenticate(&post, &r, "https://as/token", None, None, None).is_err());
    let p = client_auth::extract(None, &Params::parse("client_id=c1&client_secret=abc").unwrap()).unwrap();
    assert_eq!(p.method(), CM::SecretPost);
    assert!(client_auth::authenticate(&p, &reg(CM::SecretPost, Some(b"abc")), "t", None, None, None).is_ok());
}

#[test]
fn hashed_secret_storage() {
    let stored = authlas::crypto::digest(authlas::jwa::Hash::Sha256, b"abc").unwrap();
    let mut r = reg(CM::SecretPost, Some(&stored));
    r.secret_is_hash = true;
    let ok = Presented::Post { client_id: "c1".into(), secret: "abc".into() };
    assert!(client_auth::authenticate(&ok, &r, "t", None, None, None).is_ok());
    let no = Presented::Post { client_id: "c1".into(), secret: "abd".into() };
    assert!(client_auth::authenticate(&no, &r, "t", None, None, None).is_err());
}

#[test]
fn only_one_authentication_method_and_malformed_headers() {
    let h = client_auth::basic_header("c1", "s");
    let both = Params::parse("client_id=c1&client_secret=s").unwrap();
    assert_eq!(client_auth::extract(Some(&h), &both).unwrap_err().code, ErrorCode::InvalidRequest);
    let mismatch = Params::parse("client_id=other").unwrap();
    assert_eq!(client_auth::extract(Some(&h), &mismatch).unwrap_err().code, ErrorCode::InvalidClient);
    for bad in ["Basic", "Basic !!!", "Basic Zm9v", "Basic "] {
        assert!(client_auth::extract(Some(bad), &Params::default()).is_err(), "{bad:?}");
    }
    let public = client_auth::extract(None, &Params::parse("client_id=c1").unwrap()).unwrap();
    assert_eq!(public.method(), CM::None);
    assert!(client_auth::authenticate(&public, &reg(CM::None, None), "t", None, None, None).is_ok());
    // A confidential client cannot be impersonated by omitting the secret.
    assert!(client_auth::authenticate(&public, &reg(CM::SecretBasic, Some(b"s")), "t", None, None, None).is_err());
    assert!(client_auth::extract(None, &Params::default()).is_err());
    assert!(client_auth::extract(None, &Params::parse("client_assertion=a.b.c&client_assertion_type=wrong").unwrap()).is_err());
}

fn ec_pair() -> Option<(Jwk, Jwk)> {
    match authlas::crypto::ec_generate("P-256") {
        Ok(sk) => { let pk = sk.public().unwrap(); Some((sk, pk)) }
        Err(Error::Unsupported(m)) => { eprintln!("SKIP: {m}"); None }
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn private_key_jwt_authentication() {
    let Some((sk, pk)) = ec_pair() else { return };
    let mut r = reg(CM::PrivateKeyJwt, None);
    r.jwk = Some(pk);
    r.assertion_algs = vec![ES256];
    let a = client_auth::build_assertion(ES256, &sk, "c1", "https://as/token", 60).unwrap();
    let body = Params::from_pairs([("client_assertion_type", client_auth::ASSERTION_TYPE), ("client_assertion", a.as_str()), ("client_id", "c1")]).unwrap();
    let p = client_auth::extract(None, &body).unwrap();
    let cache = jwt::MemoryReplayCache::new();
    assert_eq!(client_auth::authenticate(&p, &r, "https://as/token", None, None, Some(&cache)).unwrap(), "c1");
    // Same assertion again: replay.
    assert!(client_auth::authenticate(&p, &r, "https://as/token", None, None, Some(&cache)).is_err(), "jti replay");
    // Wrong audience.
    let a2 = client_auth::build_assertion(ES256, &sk, "c1", "https://other/token", 60).unwrap();
    let p2 = Presented::Assertion { client_id: None, assertion: a2 };
    assert!(client_auth::authenticate(&p2, &r, "https://as/token", None, None, None).is_err());
    // Issuer identifier is an accepted audience when the server says so.
    let a3 = client_auth::build_assertion(ES256, &sk, "c1", "https://as", 60).unwrap();
    let p3 = Presented::Assertion { client_id: None, assertion: a3 };
    assert!(client_auth::authenticate(&p3, &r, "https://as/token", Some("https://as"), None, None).is_ok());
    // Signed by somebody else.
    let (other_sk, _) = ec_pair().unwrap();
    let a4 = client_auth::build_assertion(ES256, &other_sk, "c1", "https://as/token", 60).unwrap();
    let p4 = Presented::Assertion { client_id: None, assertion: a4 };
    assert!(client_auth::authenticate(&p4, &r, "https://as/token", None, None, None).is_err());
    // Algorithm outside the client's registered list.
    let hs: Algorithm = HS256;
    r.assertion_algs = vec![hs];
    let a5 = client_auth::build_assertion(ES256, &sk, "c1", "https://as/token", 60).unwrap();
    assert!(client_auth::authenticate(&Presented::Assertion { client_id: None, assertion: a5 }, &r, "https://as/token", None, None, None).is_err());
}

// ---------- bearer and errors ----------

#[test]
fn bearer_header_parsing() {
    assert_eq!(bearer::parse_authorization("Bearer abc.def-ghi_jkl~+/=").unwrap(), (Scheme::Bearer, "abc.def-ghi_jkl~+/="));
    assert_eq!(bearer::parse_authorization("bearer abc").unwrap().0, Scheme::Bearer);
    assert_eq!(bearer::parse_authorization("DPoP abc").unwrap().0, Scheme::DPoP);
    for bad in ["Bearer", "Bearer ", "Bearer  abc", "Bearer a b", "Bearer a\"b", "Basic abc", "Bearerabc", "Bearer =", &format!("Bearer {}", "a".repeat(9000))] {
        assert!(bearer::parse_authorization(bad).is_err(), "{bad:?}");
    }
    assert!(bearer::from_headers(&[]).is_err());
    assert!(bearer::from_headers(&["Bearer a", "Bearer b"]).is_err(), "two headers are ambiguous");
    assert_eq!(bearer::from_headers(&["Bearer a"]).unwrap().1, "a");
}

#[test]
fn www_authenticate_challenges() {
    let c = bearer::challenge(Scheme::Bearer, "api", None, None, None, Some("https://rs.example/.well-known/oauth-protected-resource"));
    assert_eq!(c, r#"Bearer realm="api", resource_metadata="https://rs.example/.well-known/oauth-protected-resource""#);
    let e = OAuthError::with(ErrorCode::InvalidToken, "expired \"token\"\r\nX-Evil: 1");
    let (status, h) = bearer::challenge_for(Scheme::Bearer, "api", &e, None, None);
    assert_eq!(status, 401);
    assert!(!h.contains('\n') && !h.contains('\r'), "header injection: {h:?}");
    let e = OAuthError::new(ErrorCode::InsufficientScope);
    let (status, h) = bearer::challenge_for(Scheme::Bearer, "api", &e, Some("write"), None);
    assert_eq!(status, 403);
    assert!(h.contains(r#"error="insufficient_scope""#) && h.contains(r#"scope="write""#));
    // A request with no credentials gets no error code (RFC 6750 3.1).
    let (status, h) = bearer::challenge_for(Scheme::Bearer, "api", &OAuthError::new(ErrorCode::InvalidRequest), None, None);
    assert_eq!((status, h.as_str()), (400, r#"Bearer realm="api""#));
}

#[test]
fn error_serialization_and_status() {
    let e = OAuthError::with(ErrorCode::InvalidGrant, "bad \"code\"\n\u{e9}\\");
    let j: serde_json::Value = serde_json::from_str(&e.to_json()).unwrap();
    assert_eq!(j["error"], "invalid_grant");
    let d = j["error_description"].as_str().unwrap();
    assert!(d.bytes().all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E)), "{d:?}");
    assert_eq!(ErrorCode::InvalidClient.http_status(), 401);
    assert_eq!(ErrorCode::InvalidGrant.http_status(), 400);
    assert_eq!(ErrorCode::InsufficientScope.http_status(), 403);
    assert_eq!(ErrorCode::TemporarilyUnavailable.http_status(), 503);
    for c in [ErrorCode::UseDpopNonce, ErrorCode::SlowDown, ErrorCode::InvalidProof, ErrorCode::LoginRequired] {
        assert_eq!(ErrorCode::parse(c.as_str()), Some(c));
    }
    assert_eq!(ErrorCode::parse("made_up"), None);
    assert_eq!(sanitize_description(&"x".repeat(1000)).len(), 256);
    let p = OAuthError::with(ErrorCode::AccessDenied, "no").state(Some("s")).to_params(Some("https://as"));
    assert_eq!(p.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["error", "error_description", "state", "iss"]);
    assert_eq!(OAuthError::from_json(&e.to_json()).unwrap().code, ErrorCode::InvalidGrant);
    assert!(OAuthError::from_json(r#"{"error":"nope"}"#).is_none());
    let _ = (b64::encode(""), Error::Decrypt);
}
