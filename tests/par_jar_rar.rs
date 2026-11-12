use authlas::jwa::Algorithm::*;
use authlas::jwk::Jwk;
use authlas::jwt::{self, Claims};
use authlas::oauth::error::ErrorCode;
use authlas::oauth::form::Params;
use authlas::oauth::par_jar::{self, ParStore, RequestObjectRules};
use authlas::oauth::rar_stepup::{self as rar, AuthRequirement, Detail};
use authlas::oauth::request::{self, ClientInfo, ServerPolicy};
use authlas::oauth::pkce;
use authlas::oauth::redirect::ClientKind;
use authlas::oauth::scope::Scope;
use authlas::b64;
use serde_json::json;

fn hs() -> Jwk { Jwk::parse(&json!({"kty": "oct", "k": b64::encode([5u8; 32])}).to_string()).unwrap() }
const NOW: u64 = 1_700_000_000;

fn client() -> ClientInfo {
    ClientInfo { client_id: "c1".into(), redirect_uris: vec!["https://app.example/cb".into()], kind: ClientKind::Web,
        allowed_scopes: Scope::parse("read write").unwrap(), response_types: vec!["code".into()] }
}
fn auth_body() -> String {
    let ch = pkce::s256_challenge(&"a".repeat(43)).unwrap();
    format!("response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=read&state=s&code_challenge={ch}&code_challenge_method=S256&client_secret=hush")
}

// ---------- PAR ----------

#[test]
fn par_push_redeem_once_end_to_end() {
    let store = ParStore::new();
    let body = auth_body();
    let (uri, exp) = store.push("c1", &Params::parse(&body).unwrap(), &body, Some(1000)).unwrap();
    assert!(uri.starts_with("urn:ietf:params:oauth:request_uri:") && exp == 60);
    let resp = par_jar::par_response_json(&uri, exp);
    assert_eq!(par_jar::parse_par_response(&resp).unwrap(), (uri.clone(), 60));
    // The browser only carries client_id + request_uri.
    let browser = par_jar::reference_query("c1", &uri);
    assert!(!browser.contains("code_challenge") && !browser.contains("scope"));
    let stored = store.redeem("c1", &uri, Some(1010)).unwrap();
    assert!(!stored.contains("client_secret"), "client credentials are not kept: {stored}");
    let req = request::validate(&stored, &client(), &ServerPolicy::default()).unwrap();
    assert_eq!(req.scope.to_string(), "read");
    // One use.
    assert_eq!(store.redeem("c1", &uri, Some(1011)).unwrap_err().code, ErrorCode::InvalidRequestUri);
}

#[test]
fn par_binding_and_expiry() {
    let store = ParStore::new();
    let body = auth_body();
    let p = Params::parse(&body).unwrap();
    let (uri, _) = store.push("c1", &p, &body, Some(1000)).unwrap();
    assert!(store.redeem("c2", &uri, Some(1001)).is_err(), "other client");
    assert!(store.redeem("c1", &uri, Some(1002)).is_err(), "the wrong-client attempt consumed it");
    let (uri, _) = store.push("c1", &p, &body, Some(1000)).unwrap();
    assert!(store.redeem("c1", &uri, Some(1060)).is_err(), "expired at 60 s");
    let (uri, _) = store.push("c1", &p, &body, Some(1000)).unwrap();
    assert!(store.redeem("c1", &uri, Some(1059)).is_ok());
    assert!(store.redeem("c1", "https://evil.example/x", Some(1)).is_err());
    assert!(store.redeem("c1", "urn:ietf:params:oauth:request_uri:guess", Some(1)).is_err());
}

#[test]
fn par_rejects_bad_pushes() {
    let store = ParStore::new();
    let with_uri = format!("{}&request_uri=urn%3Ax", auth_body());
    assert!(store.push("c1", &Params::parse(&with_uri).unwrap(), &with_uri, Some(1)).is_err(), "request_uri inside PAR");
    let other = auth_body().replace("client_id=c1", "client_id=c2");
    assert_eq!(store.push("c1", &Params::parse(&other).unwrap(), &other, Some(1)).unwrap_err().code, ErrorCode::InvalidClient);
    // client_id omitted from the body: filled in from the authenticated client.
    let no_id = auth_body().replace("client_id=c1&", "");
    let (u, _) = store.push("c1", &Params::parse(&no_id).unwrap(), &no_id, Some(1)).unwrap();
    assert!(store.redeem("c1", &u, Some(2)).unwrap().contains("client_id=c1"));
    assert!(par_jar::parse_par_response("{}").is_err());
    assert!(par_jar::parse_par_response(r#"{"request_uri":"urn:x","expires_in":"60"}"#).is_err());
    assert_ne!(par_jar::request_uri_fingerprint("a"), par_jar::request_uri_fingerprint("b"));
}

// ---------- JAR ----------

fn rules<'a>() -> RequestObjectRules<'a> {
    RequestObjectRules { algs: &[HS256], client_id: "c1", issuer: "https://as.example", now: None, max_lifetime: 600, require_typ: true }
}

#[test]
fn request_object_round_trip_and_query_cannot_override() {
    let obj = par_jar::build_request_object(HS256, &hs(), "c1", "https://as.example",
        &[("response_type", json!("code")), ("scope", json!("read")), ("redirect_uri", json!("https://app.example/cb")),
          ("code_challenge", json!(pkce::s256_challenge(&"a".repeat(43)).unwrap())), ("code_challenge_method", json!("S256")), ("state", json!("s")),
          ("authorization_details", json!([{"type": "payment"}]))], 300).unwrap();
    let q = par_jar::verify_request_object(&obj, &hs(), &rules()).unwrap();
    let p = Params::parse(&q).unwrap();
    assert_eq!(p.get("scope").unwrap(), Some("read"));
    assert_eq!(p.get("client_id").unwrap(), Some("c1"));
    assert!(!p.contains("iss") && !p.contains("aud") && !p.contains("exp") && !p.contains("jti"), "JWT claims are not request parameters: {q}");
    assert_eq!(p.get("authorization_details").unwrap(), Some(r#"[{"type":"payment"}]"#));
    request::validate(&q, &client(), &ServerPolicy::default()).unwrap();
}

#[test]
fn request_object_rejections() {
    let k = hs();
    let make = |c: Claims, typ: Option<&str>| jwt::sign(HS256, &k, &c, typ).unwrap();
    let base = |iss: &str, aud: &str| Claims::new().issuer(iss).audience(&[aud]).issued_at(authlas::jwt::unix_now()).expires_at(authlas::jwt::unix_now() + 300).set("scope", "read");
    let ok = make(base("c1", "https://as.example"), Some("oauth-authz-req+jwt"));
    par_jar::verify_request_object(&ok, &k, &rules()).unwrap();
    let cases = vec![
        ("wrong iss", make(base("c2", "https://as.example"), Some("oauth-authz-req+jwt"))),
        ("wrong aud", make(base("c1", "https://other.example"), Some("oauth-authz-req+jwt"))),
        ("wrong typ", make(base("c1", "https://as.example"), Some("JWT"))),
        ("no exp", make({ let mut c = base("c1", "https://as.example"); c.map.remove("exp"); c }, Some("oauth-authz-req+jwt"))),
        ("lifetime too long", make(base("c1", "https://as.example").expires_at(authlas::jwt::unix_now() + 5000), Some("oauth-authz-req+jwt"))),
        ("nested request_uri", make(base("c1", "https://as.example").set("request_uri", "urn:x"), Some("oauth-authz-req+jwt"))),
        ("client_id mismatch", make(base("c1", "https://as.example").set("client_id", "c2"), Some("oauth-authz-req+jwt"))),
        ("expired", make(base("c1", "https://as.example").expires_at(5).issued_at(1), Some("oauth-authz-req+jwt"))),
    ];
    for (label, tok) in cases {
        assert_eq!(par_jar::verify_request_object(&tok, &k, &rules()).unwrap_err().code, ErrorCode::InvalidRequestObject, "{label}");
    }
    let other = Jwk::parse(&json!({"kty": "oct", "k": b64::encode([6u8; 32])}).to_string()).unwrap();
    assert!(par_jar::verify_request_object(&ok, &other, &rules()).is_err(), "wrong key");
}

// ---------- RAR: RFC 9396 section 2 example ----------

const RFC9396_EXAMPLE: &str = r#"[
  {"type": "customer_information",
   "locations": ["https://example.com/customers"],
   "actions": ["read", "write"],
   "datatypes": ["contacts", "photos"]},
  {"type": "contacts", "actions": ["read"], "identifier": "dinesh"}
]"#;

#[test]
fn rar_parsing() {
    let d = rar::parse(RFC9396_EXAMPLE, &["customer_information", "contacts"]).unwrap();
    assert_eq!(d.len(), 2);
    assert_eq!((d[0].actions.clone(), d[0].datatypes.clone()), (vec!["read".to_string(), "write".to_string()], vec!["contacts".to_string(), "photos".to_string()]));
    assert_eq!(d[1].identifier.as_deref(), Some("dinesh"));
    // Unsupported type -> invalid_authorization_details.
    assert_eq!(rar::parse(RFC9396_EXAMPLE, &["contacts"]).unwrap_err().code, ErrorCode::InvalidAuthorizationDetails);
    for bad in ["", "{}", "[]", "[1]", r#"[{"actions":["x"]}]"#, r#"[{"type":""}]"#, r#"[{"type":"contacts","actions":"read"}]"#,
        r#"[{"type":"contacts","actions":[1]}]"#, r#"[{"type":"contacts","locations":["not a uri"]}]"#, r#"[{"type":"contacts","locations":["https://a.example/#f"]}]"#,
        r#"[{"type":"contacts","identifier":5}]"#, "not json"] {
        assert!(rar::parse(bad, &["contacts"]).is_err(), "{bad}");
    }
    let many = format!("[{}]", vec![r#"{"type":"contacts"}"#; 33].join(","));
    assert!(rar::parse(&many, &["contacts"]).is_err(), "more than 32 entries");
    assert!(rar::parse(&format!(r#"[{{"type":"contacts","note":"{}"}}]"#, "x".repeat(40_000)), &["contacts"]).is_err());
    let d2 = rar::parse(r#"[{"type":"contacts","custom":{"a":1}}]"#, &["contacts"]).unwrap();
    assert_eq!(d2[0].extra["custom"], json!({"a": 1}));
    let again = rar::parse(&rar::to_json(&d), &["customer_information", "contacts"]).unwrap();
    assert_eq!(again, d);
}

#[test]
fn rar_coverage_and_reduction() {
    let all = ["customer_information", "contacts"];
    let granted = rar::parse(RFC9396_EXAMPLE, &all).unwrap();
    let need = |s: &str| rar::parse(s, &all).unwrap().remove(0);
    assert!(granted[0].covers(&need(r#"[{"type":"customer_information","actions":["read"],"datatypes":["photos"]}]"#)));
    assert!(!granted[0].covers(&need(r#"[{"type":"customer_information","actions":["delete"]}]"#)));
    assert!(!granted[0].covers(&need(r#"[{"type":"contacts","actions":["read"]}]"#)), "different type");
    assert!(!granted[1].covers(&need(r#"[{"type":"contacts","actions":["read"],"identifier":"other"}]"#)));
    assert!(granted[1].covers(&need(r#"[{"type":"contacts","actions":["read"],"identifier":"dinesh"}]"#)));
    // A grant with an empty list covers nothing that asks for something in that field.
    let narrow = need(r#"[{"type":"contacts"}]"#);
    assert!(!narrow.covers(&need(r#"[{"type":"contacts","actions":["read"]}]"#)));
    // The user may reduce what was asked for, never widen it.
    let reduced = rar::parse(r#"[{"type":"customer_information","locations":["https://example.com/customers"],"actions":["read"],"datatypes":["contacts"]}]"#, &all).unwrap();
    assert!(rar::is_reduction(&granted, &reduced));
    let widened = rar::parse(r#"[{"type":"customer_information","locations":["https://example.com/customers"],"actions":["read","delete"],"datatypes":["contacts"]}]"#, &all).unwrap();
    assert!(!rar::is_reduction(&granted, &widened));
}

#[test]
fn rar_token_permits() {
    let all = ["customer_information", "contacts"];
    let c = Claims::new().set("authorization_details", serde_json::from_str::<serde_json::Value>(RFC9396_EXAMPLE).unwrap());
    let need = |s: &str| rar::parse(s, &all).unwrap().remove(0);
    rar::token_permits(&c, &need(r#"[{"type":"contacts","actions":["read"],"identifier":"dinesh"}]"#)).unwrap();
    let e = rar::token_permits(&c, &need(r#"[{"type":"contacts","actions":["write"],"identifier":"dinesh"}]"#)).unwrap_err();
    assert_eq!((e.code, e.status()), (ErrorCode::InsufficientScope, 403));
    assert!(rar::token_permits(&Claims::new(), &need(r#"[{"type":"contacts"}]"#)).is_err(), "no authorization_details claim");
    assert!(rar::token_permits(&Claims::new().set("authorization_details", "oops"), &need(r#"[{"type":"contacts"}]"#)).is_err());
}

// ---------- step-up ----------

#[test]
fn step_up_checks_and_challenge_round_trip() {
    let need = AuthRequirement { acr_values: vec!["urn:mace:incommon:iap:silver".into(), "urn:mace:incommon:iap:gold".into()], max_age: Some(300) };
    let good = Claims::new().set("acr", "urn:mace:incommon:iap:gold").set("auth_time", NOW - 100);
    rar::check_authentication(&good, &need, Some(NOW)).unwrap();
    for (label, c) in [
        ("weak acr", Claims::new().set("acr", "urn:mace:incommon:iap:bronze").set("auth_time", NOW - 10)),
        ("no acr", Claims::new().set("auth_time", NOW - 10)),
        ("stale", Claims::new().set("acr", "urn:mace:incommon:iap:gold").set("auth_time", NOW - 301)),
        ("no auth_time", Claims::new().set("acr", "urn:mace:incommon:iap:gold")),
        ("future auth_time", Claims::new().set("acr", "urn:mace:incommon:iap:gold").set("auth_time", NOW + 500)),
        ("acr wrong type", Claims::new().set("acr", 2).set("auth_time", NOW)),
    ] {
        let e = rar::check_authentication(&c, &need, Some(NOW)).unwrap_err();
        assert_eq!((e.code, e.status()), (ErrorCode::InsufficientUserAuthentication, 403), "{label}");
    }
    rar::check_authentication(&Claims::new(), &AuthRequirement::default(), Some(NOW)).unwrap();
    let h = rar::challenge("Bearer", &need, Some("api"));
    assert!(h.contains(r#"error="insufficient_user_authentication""#) && h.contains("max_age=300"), "{h}");
    let back = rar::parse_challenge(&h).unwrap();
    assert_eq!(back.max_age, Some(300));
    assert_eq!(back.acr_values, need.acr_values);
    assert!(rar::parse_challenge(r#"Bearer error="invalid_token""#).is_none());
    // Values cannot break out of the quoted string.
    let evil = AuthRequirement { acr_values: vec!["x\", error=\"pwn".into()], max_age: None };
    // Quotes and backslashes are stripped from values, so the injected text stays inside one quoted string.
    let h = rar::challenge("Bearer", &evil, None);
    assert_eq!(h.matches('"').count(), 6, "three quoted parameters, no extra quote from the value: {h}");
    assert!(h.contains(r#"acr_values="x,error=pwn""#), "{h}");
    let _ = Detail { kind: "x".into(), locations: vec![], actions: vec![], datatypes: vec![], identifier: None, privileges: vec![], extra: Default::default() };
}
