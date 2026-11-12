use authlas::jwa::Algorithm::*;
use authlas::jwk::Jwk;
use authlas::jwt::MemoryReplayCache;
use authlas::oauth::assertion::{self, Context, Kind, TrustedIssuer};
use authlas::oauth::client_auth::{self, Presented};
use authlas::oauth::form::Params;
use authlas::oauth::registration::{self as reg, hash_token, ClientStore, MemoryClientStore, Policy};
use authlas::oauth::scope::Scope;
use authlas::oauth::{request, ErrorCode};
use authlas::Error;
use serde_json::{json, Value};

const EP: &str = "https://as.example.com/register";
const PUBKEY: &str = r#"{"kty":"EC","crv":"P-256","x":"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ","y":"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8","kid":"k1"}"#;

fn policy() -> Policy {
    let mut p = Policy::new(EP);
    p.initial_access_token_hashes = vec![hash_token("iat-secret")];
    p.allowed_scopes = Scope::parse("read write").unwrap();
    p.default_scope = Scope::parse("read").unwrap();
    p.allowed_grant_types.extend(["client_credentials".to_string()]);
    p
}
fn pubkey() -> Value { serde_json::from_str(PUBKEY).unwrap() }
fn do_register(store: &MemoryClientStore, body: Value) -> Result<(authlas::oauth::registration::ClientRecord, Value), authlas::oauth::OAuthError> {
    reg::register(store, &body.to_string(), Some("iat-secret"), &policy(), Some(1000)).map(|(r, s)| (r, serde_json::from_str(&s).unwrap()))
}
fn web() -> Value { json!({"redirect_uris": ["https://app.example.com/cb"], "client_name": "App"}) }

// ---------- RFC 7591 ----------

#[test]
fn registers_with_defaults_and_returns_secret_once() {
    let store = MemoryClientStore::new();
    let (rec, resp) = do_register(&store, web()).unwrap();
    assert_eq!(resp["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(resp["grant_types"], json!(["authorization_code"]));
    assert_eq!(resp["response_types"], json!(["code"]));
    assert_eq!(resp["scope"], "read");
    assert_eq!(resp["client_secret_expires_at"], 0);
    assert_eq!(resp["client_id_issued_at"], 1000);
    assert_eq!(resp["registration_client_uri"], format!("{EP}/{}", rec.client_id));
    let secret = resp["client_secret"].as_str().unwrap();
    assert!(secret.len() >= 43, "256 bits of secret");
    assert!(resp["registration_access_token"].as_str().unwrap().len() >= 43);
    // Stored hashed, never plain.
    assert_eq!(rec.secret_hash.as_deref(), Some(hash_token(secret).as_slice()));
    assert!(rec.secret_plain.is_none());
    assert_ne!(rec.registration_token_hash, resp["registration_access_token"].as_str().unwrap().as_bytes());
    // The secret is not repeated on read.
    let read: Value = serde_json::from_str(&reg::read(&store, &rec.client_id, resp["registration_access_token"].as_str(), &policy()).unwrap()).unwrap();
    assert!(read.get("client_secret").is_none() && read.get("registration_access_token").is_none());
    // Two registrations never share ids or secrets.
    let (r2, resp2) = do_register(&store, web()).unwrap();
    assert_ne!(rec.client_id, r2.client_id);
    assert_ne!(resp["client_secret"], resp2["client_secret"]);
}

#[test]
fn registration_is_closed_unless_authorized() {
    let store = MemoryClientStore::new();
    let p = policy();
    for tok in [None, Some("wrong"), Some("")] {
        let e = reg::register(&store, &web().to_string(), tok, &p, None).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidToken, "{tok:?}");
    }
    let mut open = policy(); open.open = true;
    assert!(reg::register(&store, &web().to_string(), None, &open, None).is_ok());
    // No tokens configured and not open: nothing gets in, even an empty bearer.
    let none = Policy::new(EP);
    assert!(reg::register(&store, &web().to_string(), Some(""), &none, None).is_err());
}

#[test]
fn client_cannot_choose_server_owned_values() {
    let store = MemoryClientStore::new();
    let mut b = web();
    b["client_id"] = json!("admin"); b["client_secret"] = json!("known"); b["registration_access_token"] = json!("known");
    b["client_id_issued_at"] = json!(1); b["registration_client_uri"] = json!("https://evil.example/");
    let (rec, resp) = do_register(&store, b).unwrap();
    assert_ne!(rec.client_id, "admin");
    assert_ne!(resp["client_secret"], "known");
    assert_ne!(resp["registration_access_token"], "known");
    assert_eq!(resp["client_id_issued_at"], 1000);
    assert!(resp["registration_client_uri"].as_str().unwrap().starts_with(EP));
}

#[test]
fn forbidden_and_inconsistent_metadata() {
    let store = MemoryClientStore::new();
    let with = |k: &str, v: Value| { let mut b = web(); b[k] = v; do_register(&store, b) };
    let code = |r: Result<_, authlas::oauth::OAuthError>| r.map(|_: (_, Value)| ()).unwrap_err().code;
    assert_eq!(code(with("grant_types", json!(["implicit"]))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("grant_types", json!(["password"]))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("response_types", json!(["token"]))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("response_types", json!(["code token"]))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("grant_types", json!(["refresh_token"]))), ErrorCode::InvalidClientMetadata, "refresh without a grant that issues one");
    assert_eq!(code(with("grant_types", json!(["authorization_code", "authorization_code"]))), ErrorCode::InvalidClientMetadata, "duplicates");
    assert_eq!(code(with("grant_types", json!(["authorization_code", "urn:evil"]))), ErrorCode::InvalidClientMetadata, "not in the allow-list");
    assert_eq!(code(with("grant_types", json!([]))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("grant_types", json!("authorization_code"))), ErrorCode::InvalidClientMetadata, "wrong type");
    assert_eq!(code(with("token_endpoint_auth_method", json!("client_secret_jwt"))), ErrorCode::InvalidClientMetadata, "off by default");
    assert_eq!(code(with("token_endpoint_auth_method", json!("bogus"))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("token_endpoint_auth_method", json!("private_key_jwt"))), ErrorCode::InvalidClientMetadata, "needs keys");
    assert_eq!(code(with("scope", json!("admin"))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("application_type", json!("desktop"))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("contacts", json!(vec!["a@b"; 11]))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("client_name", json!("x\u{0}y"))), ErrorCode::InvalidClientMetadata, "control character");
    assert_eq!(code(with("client_uri", json!("http://insecure.example"))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("logo_uri", json!("javascript:alert(1)"))), ErrorCode::InvalidClientMetadata);
    assert_eq!(code(with("client_name#", json!("x"))), ErrorCode::InvalidClientMetadata, "empty language tag");
    // Public client cannot use client_credentials.
    let mut b = web(); b["token_endpoint_auth_method"] = json!("none"); b["grant_types"] = json!(["authorization_code", "client_credentials"]);
    assert_eq!(code(do_register(&store, b)), ErrorCode::InvalidClientMetadata);
    // A client_credentials client needs no redirect URIs and no response type.
    let ok = do_register(&store, json!({"grant_types": ["client_credentials"], "scope": "read"})).unwrap().1;
    assert_eq!(ok["response_types"], json!([]));
    // Authorization-code client without redirect URIs.
    assert_eq!(code(do_register(&store, json!({"client_name": "x"}))), ErrorCode::InvalidRedirectUri);
    // Oversized, non-object and duplicate-key bodies.
    assert!(reg::register(&store, &"x".repeat(70_000), Some("iat-secret"), &policy(), None).is_err());
    assert!(reg::register(&store, "[1]", Some("iat-secret"), &policy(), None).is_err());
    assert!(reg::register(&store, r#"{"redirect_uris":["https://a.example/cb"],"redirect_uris":["https://b.example/cb"]}"#, Some("iat-secret"), &policy(), None).is_err(), "duplicate member");
}

#[test]
fn redirect_uris_are_checked_like_everywhere_else() {
    let store = MemoryClientStore::new();
    for bad in ["http://app.example.com/cb", "https://app.example.com/cb#frag", "https:///nohost", "https://app.example.com\\@evil.example/", "javascript:alert(1)",
                "http://localhost:8080/cb", "https://user:pw@app.example.com/cb", "/relative"] {
        let e = do_register(&store, json!({"redirect_uris": [bad]})).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidRedirectUri, "{bad}");
    }
    assert_eq!(do_register(&store, json!({"redirect_uris": ["https://a.example/cb", "https://a.example/cb"]})).unwrap_err().code, ErrorCode::InvalidClientMetadata, "duplicate");
    // Native: loopback and private-use schemes are fine, but not for a web client.
    let native = json!({"application_type": "native", "redirect_uris": ["http://127.0.0.1/cb", "com.example.app:/cb"], "token_endpoint_auth_method": "none"});
    assert!(do_register(&store, native).is_ok());
    assert!(do_register(&store, json!({"redirect_uris": ["com.example.app:/cb"]})).is_err(), "private-use scheme on a web client");
    let mut no_native = policy(); no_native.allow_native = false;
    let n = json!({"application_type": "native", "redirect_uris": ["http://127.0.0.1/cb"], "token_endpoint_auth_method": "none"});
    assert!(reg::register(&store, &n.to_string(), Some("iat-secret"), &no_native, None).is_err());
}

#[test]
fn keys_and_mtls_metadata() {
    let store = MemoryClientStore::new();
    let pk = json!({"redirect_uris": ["https://app.example.com/cb"], "token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "ES256", "jwks": {"keys": [pubkey()]}});
    let (rec, resp) = do_register(&store, pk.clone()).unwrap();
    assert!(resp.get("client_secret").is_none(), "no secret for private_key_jwt");
    assert!(rec.secret_hash.is_none());
    let mut with = |f: &dyn Fn(&mut Value)| { let mut b = pk.clone(); f(&mut b); do_register(&store, b).map(|_| ()).unwrap_err().code };
    assert_eq!(with(&|b| b["jwks"]["keys"][0]["d"] = json!("secret")), ErrorCode::InvalidClientMetadata, "private key material");
    assert_eq!(with(&|b| b["jwks_uri"] = json!("https://c.example/jwks")), ErrorCode::InvalidClientMetadata, "jwks and jwks_uri together");
    assert_eq!(with(&|b| b["token_endpoint_auth_signing_alg"] = json!("none")), ErrorCode::InvalidClientMetadata);
    assert_eq!(with(&|b| b["token_endpoint_auth_signing_alg"] = json!("HS256")), ErrorCode::InvalidClientMetadata, "symmetric alg for private_key_jwt");
    assert_eq!(with(&|b| b["token_endpoint_auth_signing_alg"] = json!("RS256")), ErrorCode::InvalidClientMetadata, "not in the allow-list");
    assert_eq!(with(&|b| { b["jwks"] = json!({"keys": []}); }), ErrorCode::InvalidClientMetadata);
    assert_eq!(with(&|b| { b["token_endpoint_auth_signing_alg"] = Value::Null; }), ErrorCode::InvalidClientMetadata, "alg required");
    // jwks_uri: https only.
    let mut uri = pk.clone(); uri.as_object_mut().unwrap().remove("jwks"); uri["jwks_uri"] = json!("https://c.example/jwks");
    assert!(do_register(&store, uri.clone()).is_ok());
    uri["jwks_uri"] = json!("http://c.example/jwks");
    assert!(do_register(&store, uri).is_err());
    // tls_client_auth: exactly one subject member.
    let tls = |extra: Value| { let mut b = json!({"redirect_uris": ["https://app.example.com/cb"], "token_endpoint_auth_method": "tls_client_auth"}); for (k, v) in extra.as_object().unwrap() { b[k] = v.clone(); } do_register(&store, b).map(|_| ()) };
    assert!(tls(json!({"tls_client_auth_san_dns": "c.example.org"})).is_ok());
    assert!(tls(json!({})).is_err());
    assert!(tls(json!({"tls_client_auth_san_dns": "a", "tls_client_auth_subject_dn": "CN=a"})).is_err());
    assert!(tls(json!({"tls_client_auth_san_ip": "nope"})).is_err());
    assert!(do_register(&store, json!({"redirect_uris": ["https://app.example.com/cb"], "tls_client_auth_san_dns": "a"})).is_err(), "tls members without tls_client_auth");
}

#[test]
fn client_secret_jwt_when_enabled_keeps_a_usable_secret() {
    let store = MemoryClientStore::new();
    let mut p = policy(); p.allow_client_secret_jwt = true; p.allowed_signing_algs.push(HS256);
    let b = json!({"redirect_uris": ["https://app.example.com/cb"], "token_endpoint_auth_method": "client_secret_jwt", "token_endpoint_auth_signing_alg": "HS256"});
    let (rec, s) = reg::register(&store, &b.to_string(), Some("iat-secret"), &p, None).unwrap();
    let resp: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(rec.secret_plain.as_deref(), resp["client_secret"].as_str().map(str::as_bytes));
    // The record plugs into client authentication and a real assertion works.
    let k = Jwk::parse(&json!({"kty": "oct", "k": authlas::b64::encode(resp["client_secret"].as_str().unwrap())}).to_string()).unwrap();
    let a = client_auth::build_assertion(HS256, &k, &rec.client_id, "https://as.example.com/token", 60).unwrap();
    let reg_ = rec.registered(Some(&a)).unwrap();
    let got = client_auth::authenticate(&Presented::Assertion { client_id: None, assertion: a }, &reg_, "https://as.example.com/token", None, None, None).unwrap();
    assert_eq!(got, rec.client_id);
}

// ---------- the record drives the real endpoints ----------

#[test]
fn registered_client_authenticates_and_validates_authorization_requests() {
    let store = MemoryClientStore::new();
    let (rec, resp) = do_register(&store, web()).unwrap();
    let secret = resp["client_secret"].as_str().unwrap();
    let r = rec.registered(None).unwrap();
    let ok = client_auth::authenticate(&Presented::Basic { client_id: rec.client_id.clone(), secret: secret.into() }, &r, "https://as.example.com/token", None, None, None);
    assert_eq!(ok.unwrap(), rec.client_id);
    assert!(client_auth::authenticate(&Presented::Basic { client_id: rec.client_id.clone(), secret: "wrong".into() }, &r, "https://as.example.com/token", None, None, None).is_err());
    // Authorization endpoint accepts the registered redirect and scope, refuses others.
    let q = |ru: &str, scope: &str| format!("response_type=code&client_id={}&redirect_uri={ru}&scope={scope}&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", rec.client_id);
    let info = rec.client_info();
    assert!(request::validate(&q("https%3A%2F%2Fapp.example.com%2Fcb", "read"), &info, &Default::default()).is_ok());
    assert!(request::validate(&q("https%3A%2F%2Fevil.example%2Fcb", "read"), &info, &Default::default()).is_err());
    assert!(request::validate(&q("https%3A%2F%2Fapp.example.com%2Fcb", "write"), &info, &Default::default()).is_err(), "scope beyond the registration");
}

// ---------- RFC 7592 ----------

#[test]
fn management_requires_the_registration_token_and_does_not_leak_existence() {
    let store = MemoryClientStore::new();
    let (rec, resp) = do_register(&store, web()).unwrap();
    let tok = resp["registration_access_token"].as_str().unwrap();
    let p = policy();
    let wrong = reg::read(&store, &rec.client_id, Some("nope"), &p).unwrap_err();
    let unknown = reg::read(&store, "c_does_not_exist", Some(tok), &p).unwrap_err();
    let none = reg::read(&store, &rec.client_id, None, &p).unwrap_err();
    assert_eq!(wrong.code, ErrorCode::InvalidToken);
    assert_eq!(wrong, unknown, "wrong token and unknown client look the same");
    assert_eq!(wrong, none);
    // Another client's registration token does not open this client.
    let (other, oresp) = do_register(&store, web()).unwrap();
    assert!(reg::read(&store, &rec.client_id, oresp["registration_access_token"].as_str(), &p).is_err());
    assert!(reg::delete(&store, &rec.client_id, oresp["registration_access_token"].as_str()).is_err());
    assert!(store.get(&other.client_id).is_some());
}

#[test]
fn update_replaces_metadata_and_protects_server_owned_fields() {
    let store = MemoryClientStore::new();
    let (rec, resp) = do_register(&store, web()).unwrap();
    let tok = resp["registration_access_token"].as_str().unwrap();
    let secret = resp["client_secret"].as_str().unwrap();
    let p = policy();
    let upd = |b: Value| reg::update(&store, &rec.client_id, Some(tok), &b.to_string(), &p);
    let new = json!({"client_id": rec.client_id, "client_secret": secret, "redirect_uris": ["https://app.example.com/new"], "client_name": "Renamed", "scope": "read write"});
    let out: Value = serde_json::from_str(&upd(new.clone()).unwrap()).unwrap();
    assert_eq!(out["redirect_uris"], json!(["https://app.example.com/new"]));
    assert_eq!(out["scope"], "read write");
    assert!(out.get("client_secret").is_none(), "secret unchanged, not repeated");
    assert_eq!(store.get(&rec.client_id).unwrap().metadata.human["client_name"], "Renamed");
    // Replace semantics: omitted members go back to defaults.
    let out: Value = serde_json::from_str(&upd(json!({"client_id": rec.client_id, "redirect_uris": ["https://app.example.com/new"]})).unwrap()).unwrap();
    assert_eq!(out["scope"], "read");
    assert!(out.get("client_name").is_none());
    // Refusals.
    let mut bad = |f: &dyn Fn(&mut Value)| { let mut b = new.clone(); f(&mut b); upd(b).unwrap_err().code };
    assert_eq!(bad(&|b| { b.as_object_mut().unwrap().remove("client_id"); }), ErrorCode::InvalidClientMetadata, "client_id required");
    assert_eq!(bad(&|b| b["client_id"] = json!("other")), ErrorCode::InvalidClientMetadata, "client_id must match the URL");
    assert_eq!(bad(&|b| b["client_secret"] = json!("guess")), ErrorCode::InvalidClientMetadata, "client cannot pick a secret");
    assert_eq!(bad(&|b| b["registration_access_token"] = json!("mine")), ErrorCode::InvalidClientMetadata);
    assert_eq!(bad(&|b| b["client_id_issued_at"] = json!(5)), ErrorCode::InvalidClientMetadata);
    assert_eq!(bad(&|b| b["grant_types"] = json!(["implicit"])), ErrorCode::InvalidClientMetadata);
    // Failed updates left the stored client alone.
    assert_eq!(store.get(&rec.client_id).unwrap().metadata.redirect_uris, vec!["https://app.example.com/new"]);
    // Switching to a public client drops the secret; switching back issues a new one.
    let out: Value = serde_json::from_str(&upd(json!({"client_id": rec.client_id, "redirect_uris": ["https://app.example.com/new"], "token_endpoint_auth_method": "none"})).unwrap()).unwrap();
    assert!(out.get("client_secret").is_none() && store.get(&rec.client_id).unwrap().secret_hash.is_none());
    let out: Value = serde_json::from_str(&upd(json!({"client_id": rec.client_id, "redirect_uris": ["https://app.example.com/new"]})).unwrap()).unwrap();
    assert!(out["client_secret"].as_str().unwrap().len() >= 43);
    // Optional registration token rotation.
    let mut rot = policy(); rot.rotate_registration_token = true;
    let out: Value = serde_json::from_str(&reg::update(&store, &rec.client_id, Some(tok), &json!({"client_id": rec.client_id, "redirect_uris": ["https://app.example.com/new"], "client_secret": store.get(&rec.client_id).map(|_| out["client_secret"].as_str().unwrap().to_string()).unwrap()}).to_string(), &rot).unwrap()).unwrap();
    let newtok = out["registration_access_token"].as_str().unwrap();
    assert_ne!(newtok, tok);
    assert!(reg::read(&store, &rec.client_id, Some(tok), &p).is_err(), "old token is dead after rotation");
    assert!(reg::read(&store, &rec.client_id, Some(newtok), &p).is_ok());
}

#[test]
fn delete_removes_the_client() {
    let store = MemoryClientStore::new();
    let (rec, resp) = do_register(&store, web()).unwrap();
    let tok = resp["registration_access_token"].as_str().unwrap();
    reg::delete(&store, &rec.client_id, Some(tok)).unwrap();
    assert!(store.get(&rec.client_id).is_none());
    assert!(reg::read(&store, &rec.client_id, Some(tok), &policy()).is_err(), "token dies with the client");
    assert!(reg::delete(&store, &rec.client_id, Some(tok)).is_err());
}

// ---------- software statements ----------

fn ec() -> Option<Jwk> {
    match authlas::crypto::ec_generate("P-256") { Ok(k) => Some(k), Err(Error::Unsupported(m)) => { eprintln!("SKIP: {m}"); None }, Err(e) => panic!("{e}") }
}

#[test]
fn software_statements() {
    let Some(issuer_key) = ec() else { return };
    let mut p = policy();
    let mut k = issuer_key.public().unwrap(); k.kid = Some("v1".into());
    p.software_statement_keys = vec![k];
    let mut sk = issuer_key.clone(); sk.kid = Some("v1".into());
    let store = MemoryClientStore::new();
    let stmt = |claims: Value| authlas::jws::sign(ES256, &sk, &serde_json::Map::new(), claims.to_string().as_bytes()).unwrap();
    let body = |s: &str| json!({"redirect_uris": ["https://attacker.example/cb"], "software_statement": s}).to_string();
    // Claims in the statement override the plain members (RFC 7591 2.3).
    let s = stmt(json!({"redirect_uris": ["https://vendor.example/cb"], "software_id": "vendor-app", "client_name": "Vendor"}));
    let (rec, _) = reg::register(&store, &body(&s), Some("iat-secret"), &p, None).unwrap();
    assert_eq!(rec.metadata.redirect_uris, vec!["https://vendor.example/cb"]);
    assert_eq!(rec.metadata.software_id.as_deref(), Some("vendor-app"));
    // Unsigned by a trusted key, expired, wrong type, or accepted without keys configured.
    let other = ec().unwrap();
    let forged = authlas::jws::sign(ES256, &other, &serde_json::Map::new(), json!({"software_id": "x"}).to_string().as_bytes()).unwrap();
    assert_eq!(reg::register(&store, &body(&forged), Some("iat-secret"), &p, None).unwrap_err().code, ErrorCode::InvalidSoftwareStatement);
    let old = stmt(json!({"software_id": "x", "exp": 1000}));
    assert_eq!(reg::register(&store, &body(&old), Some("iat-secret"), &p, None).unwrap_err().code, ErrorCode::InvalidSoftwareStatement);
    assert_eq!(reg::register(&store, &body("not-a-jws"), Some("iat-secret"), &p, None).unwrap_err().code, ErrorCode::InvalidSoftwareStatement);
    assert_eq!(reg::register(&store, &body(&s), Some("iat-secret"), &policy(), None).unwrap_err().code, ErrorCode::UnapprovedSoftwareStatement);
    p.require_software_statement = true;
    assert_eq!(reg::register(&store, &web().to_string(), Some("iat-secret"), &p, None).unwrap_err().code, ErrorCode::InvalidSoftwareStatement);
    // A statement cannot smuggle server-owned values.
    p.require_software_statement = false;
    let sneaky = stmt(json!({"redirect_uris": ["https://vendor.example/cb"], "client_id": "admin", "client_secret": "known"}));
    let (r, _) = reg::register(&store, &body(&sneaky), Some("iat-secret"), &p, None).unwrap();
    assert_ne!(r.client_id, "admin");
}

// ---------- RFC 7523 JWT bearer grant ----------

const TOKEN_EP: &str = "https://as.example.com/token";
const ISS: &str = "https://as.example.com";

fn trusted(key: &Jwk) -> Vec<TrustedIssuer> {
    let mut k = key.public().unwrap(); k.kid = Some("a1".into());
    vec![TrustedIssuer::new("https://idp.example", vec![k], vec![ES256], Scope::parse("read write").unwrap())]
}
fn ctx<'a>(t: &'a [TrustedIssuer], r: Option<&'a MemoryReplayCache>) -> Context<'a> {
    Context { trusted: t, token_endpoint: TOKEN_EP, issuer: ISS, now: None, leeway: 5, replay: r.map(|x| x as &dyn authlas::jwt::ReplayCache) }
}
fn req(a: &str, scope: Option<&str>) -> assertion::Request {
    assertion::Request { kind: Kind::Jwt, assertion: a.into(), scope: scope.map(|s| Scope::parse(s).unwrap()), client_id: None }
}
fn mk(key: &Jwk, f: &dyn Fn(authlas::jwt::Claims) -> authlas::jwt::Claims) -> String {
    let mut k = key.clone(); k.kid = Some("a1".into());
    let now = authlas::jwt::unix_now();
    let c = authlas::jwt::Claims::new().issuer("https://idp.example").subject("alice").audience(&[TOKEN_EP]).issued_at(now).expires_at(now + 120).jti("j-1");
    authlas::jwt::sign(ES256, &k, &f(c), Some("JWT")).unwrap()
}

#[test]
fn request_parsing_and_building() {
    let body = assertion::request_body(Kind::Jwt, "a.b.c", Some(&Scope::parse("read").unwrap()));
    let r = assertion::parse_request(&Params::parse(&body).unwrap()).unwrap();
    assert_eq!((r.kind, r.assertion.as_str(), r.scope.unwrap().to_string()), (Kind::Jwt, "a.b.c", "read".to_string()));
    let p = |s: &str| assertion::parse_request(&Params::parse(s).unwrap());
    assert_eq!(p("grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&assertion=x").unwrap().kind, Kind::Saml2);
    assert_eq!(p("grant_type=password&assertion=x").unwrap_err().code, ErrorCode::UnsupportedGrantType);
    assert!(p("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer").is_err(), "assertion required");
    assert!(Params::parse("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=a&assertion=b").is_err(), "repeated assertion is stopped by the form parser");
    assert!(p(&format!("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={}", "a".repeat(20_000))).is_err());
}

#[test]
fn jwt_bearer_grant_accepts_a_good_assertion() {
    let Some(key) = ec() else { return };
    let t = trusted(&key);
    let g = assertion::verify_jwt(&req(&mk(&key, &|c| c), Some("read")), &ctx(&t, None)).unwrap();
    assert_eq!((g.subject.as_str(), g.assertion_issuer.as_str(), g.scope.to_string().as_str()), ("alice", "https://idp.example", "read"));
    // No scope requested: the issuer's maximum.
    assert_eq!(assertion::verify_jwt(&req(&mk(&key, &|c| c), None), &ctx(&t, None)).unwrap().scope.to_string(), "read write");
    // The issuer identifier is accepted as audience too (RFC 7523 3 item 3).
    let a = mk(&key, &|c| c.audience(&[ISS]));
    assert!(assertion::verify_jwt(&req(&a, None), &ctx(&t, None)).is_ok());
    // And the freshly built helper works end to end.
    let built = assertion::build_jwt(ES256, &{ let mut k = key.clone(); k.kid = Some("a1".into()); k }, "https://idp.example", "bob", TOKEN_EP, 60).unwrap();
    assert_eq!(assertion::verify_jwt(&req(&built, None), &ctx(&t, None)).unwrap().subject, "bob");
}

#[test]
fn jwt_bearer_grant_rejects_bad_assertions() {
    let Some(key) = ec() else { return };
    let other = ec().unwrap();
    let t = trusted(&key);
    let bad = |a: String, why: &str| {
        let e = assertion::verify_jwt(&req(&a, None), &ctx(&t, None)).expect_err(why);
        assert_eq!(e.code, ErrorCode::InvalidGrant, "{why}");
    };
    bad(mk(&other, &|c| c), "signed by a key that is not registered");
    bad(mk(&key, &|c| c.issuer("https://evil.example")), "unknown issuer");
    bad(mk(&key, &|c| c.audience(&["https://other.example/token"])), "wrong audience");
    bad(mk(&key, &|c| c.expires_at(authlas::jwt::unix_now() - 100)), "expired");
    bad(mk(&key, &|c| c.expires_at(authlas::jwt::unix_now() + 86_400)), "lives longer than the issuer's cap");
    bad(mk(&key, &|c| c.not_before(authlas::jwt::unix_now() + 3_600)), "not yet valid");
    bad(mk(&key, &|c| { let mut c = c; c.map.remove("sub"); c }), "no subject");
    bad(mk(&key, &|c| c.subject("")), "empty subject");
    bad(mk(&key, &|c| { let mut c = c; c.map.remove("jti"); c }), "no jti when required");
    bad(mk(&key, &|c| { let mut c = c; c.map.remove("exp"); c }), "no exp");
    bad("not-a-jwt".into(), "garbage");
    bad(String::new(), "empty");
    // Unknown issuer and bad signature are indistinguishable.
    let e1 = assertion::verify_jwt(&req(&mk(&key, &|c| c.issuer("https://evil.example")), None), &ctx(&t, None)).unwrap_err();
    let e2 = assertion::verify_jwt(&req(&mk(&other, &|c| c), None), &ctx(&t, None)).unwrap_err();
    assert_eq!(e1, e2);
    // Scope can narrow, never widen.
    let a = mk(&key, &|c| c);
    assert_eq!(assertion::verify_jwt(&req(&a, Some("admin")), &ctx(&t, None)).unwrap_err().code, ErrorCode::InvalidScope);
    assert_eq!(assertion::verify_jwt(&req(&a, Some("read admin")), &ctx(&t, None)).unwrap_err().code, ErrorCode::InvalidScope);
    // SAML request through the JWT verifier is refused.
    let mut r = req(&a, None); r.kind = Kind::Saml2;
    assert_eq!(assertion::verify_jwt(&r, &ctx(&t, None)).unwrap_err().code, ErrorCode::UnsupportedGrantType);
}

#[test]
fn jwt_bearer_replay_subject_and_algorithm_rules() {
    let Some(key) = ec() else { return };
    let mut t = trusted(&key);
    let cache = MemoryReplayCache::new();
    let a = mk(&key, &|c| c);
    assert!(assertion::verify_jwt(&req(&a, None), &ctx(&t, Some(&cache))).is_ok());
    assert!(assertion::verify_jwt(&req(&a, None), &ctx(&t, Some(&cache))).is_err(), "second use of the same jti");
    // A failed attempt does not burn the jti.
    let b = mk(&key, &|c| c.jti("j-2"));
    assert!(assertion::verify_jwt(&req(&b, Some("admin")), &ctx(&t, Some(&cache))).is_err());
    assert!(assertion::verify_jwt(&req(&b, Some("read")), &ctx(&t, Some(&cache))).is_ok(), "a request refused for its scope must not burn the assertion");
    // Subject allow-list.
    t[0].allowed_subjects = vec!["bob".into()];
    assert!(assertion::verify_jwt(&req(&mk(&key, &|c| c.jti("j-3")), None), &ctx(&t, None)).is_err());
    assert!(assertion::verify_jwt(&req(&mk(&key, &|c| c.subject("bob").jti("j-4")), None), &ctx(&t, None)).is_ok());
    t[0].allowed_subjects.clear();
    // jti optional when the issuer does not require it.
    t[0].require_jti = false;
    assert!(assertion::verify_jwt(&req(&mk(&key, &|c| { let mut c = c; c.map.remove("jti"); c }), None), &ctx(&t, None)).is_ok());
    // Algorithm allow-list: an assertion signed with an algorithm the issuer entry does not list is refused.
    t[0].algs = vec![PS256];
    assert!(assertion::verify_jwt(&req(&mk(&key, &|c| c.jti("j-5")), None), &ctx(&t, None)).is_err());
    // An issuer with no keys never verifies.
    t[0].keys.clear(); t[0].algs = vec![ES256];
    assert!(assertion::verify_jwt(&req(&mk(&key, &|c| c.jti("j-6")), None), &ctx(&t, None)).is_err());
}

struct FakeSaml(Result<assertion::VerifiedAssertion, String>);
impl assertion::AssertionVerifier for FakeSaml { fn verify(&self, _: &str) -> Result<assertion::VerifiedAssertion, String> { self.0.clone() } }

#[test]
fn saml_goes_through_the_plug_in_but_keeps_server_rules() {
    let now = authlas::jwt::unix_now();
    let t = vec![TrustedIssuer::new("https://saml-idp.example", vec![], vec![], Scope::parse("read").unwrap())];
    let good = |exp: u64| FakeSaml(Ok(assertion::VerifiedAssertion { issuer: "https://saml-idp.example".into(), subject: "alice".into(), expires_at: exp, id: "_id1".into() }));
    let r = assertion::Request { kind: Kind::Saml2, assertion: "<xml/>".into(), scope: None, client_id: None };
    let cache = MemoryReplayCache::new();
    let c = ctx(&t, Some(&cache));
    assert_eq!(assertion::verify_with(&r, &good(now + 100), &t, &c).unwrap().subject, "alice");
    assert!(assertion::verify_with(&r, &good(now + 100), &t, &c).is_err(), "assertion id replayed");
    let fresh = |id: &str, exp: u64| FakeSaml(Ok(assertion::VerifiedAssertion { issuer: "https://saml-idp.example".into(), subject: "alice".into(), expires_at: exp, id: id.into() }));
    assert!(assertion::verify_with(&r, &fresh("_2", now - 100), &t, &c).is_err(), "expired");
    assert!(assertion::verify_with(&r, &fresh("_3", now + 86_400), &t, &c).is_err(), "too long");
    assert!(assertion::verify_with(&r, &FakeSaml(Err("bad signature".into())), &t, &c).is_err());
    let evil = FakeSaml(Ok(assertion::VerifiedAssertion { issuer: "https://evil.example".into(), subject: "a".into(), expires_at: now + 10, id: "_4".into() }));
    assert!(assertion::verify_with(&r, &evil, &t, &c).is_err(), "issuer not in the registry");
    let mut wide = r.clone(); wide.scope = Some(Scope::parse("admin").unwrap());
    assert_eq!(assertion::verify_with(&wide, &fresh("_5", now + 10), &t, &c).unwrap_err().code, ErrorCode::InvalidScope);
}
