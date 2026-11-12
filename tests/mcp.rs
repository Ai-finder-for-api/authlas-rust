#![cfg(feature = "mcp")]
//! MCP authorization (spec 2025-11-25): client discovery and flow, resource-server checks, Client ID Metadata Documents.
use authlas::jwa::Algorithm::{self, *};
use authlas::jwk::Jwk;
use authlas::jwt::{self, Claims, MemoryReplayCache};
use authlas::mcp::*;
use authlas::oauth::at_jwt;
use authlas::oauth::error::{ErrorCode, OAuthError};
use authlas::oauth::introspection::Introspection;
use authlas::oauth::metadata::AsMetadata;
use authlas::oauth::scope::Scope;
use authlas::Error;
use serde_json::{json, Value};
use std::net::IpAddr;

const MCP: &str = "https://mcp.example.com/mcp";
const AS: &str = "https://auth.example.com";
const NOW: u64 = 1_800_000_000;

fn ec() -> Option<Jwk> {
    match authlas::crypto::ec_generate("P-256") { Ok(k) => Some(k), Err(Error::Unsupported(m)) => { eprintln!("SKIP: {m}"); None }, Err(e) => panic!("{e}") }
}
fn scope(s: &str) -> Scope { Scope::parse(s).unwrap() }

fn token(key: &Jwk, iss: &str, aud: &[&str], sc: &str, exp: u64) -> String {
    at_jwt::Issue { alg: ES256, key, issuer: iss, audience: aud, subject: "alice", client_id: "c1", scope: &scope(sc), lifetime: exp - NOW, now: Some(NOW), extra: &[], cnf: None }.sign().unwrap()
}

fn rs() -> ResourceServer {
    let mut r = ResourceServer::new(MCP, &[AS], &[ES256]).unwrap();
    r.scopes_supported = vec!["files:read".into(), "files:write".into()];
    r.challenge_scope = Some(scope("files:read"));
    r
}
fn keys_of(k: &Jwk) -> impl Fn(&str, Option<&str>) -> Option<Jwk> + '_ { move |_, _| Some(k.public().unwrap()) }

// ---------- canonical resource identifiers ----------

#[test]
fn canonical_resource_follows_the_spec_examples() {
    for (i, o) in [("https://mcp.example.com/mcp", "https://mcp.example.com/mcp"), ("https://mcp.example.com", "https://mcp.example.com"),
        ("https://mcp.example.com:8443", "https://mcp.example.com:8443"), ("https://mcp.example.com/server/mcp", "https://mcp.example.com/server/mcp"),
        ("HTTPS://MCP.Example.COM/mcp", "https://mcp.example.com/mcp"), ("https://mcp.example.com/", "https://mcp.example.com"),
        ("https://mcp.example.com:443/mcp", "https://mcp.example.com/mcp"), ("http://127.0.0.1:3000/mcp", "http://127.0.0.1:3000/mcp")] {
        assert_eq!(canonical_resource(i).unwrap(), o, "{i}");
    }
}

#[test]
fn canonical_resource_refuses_the_spec_invalid_examples_and_worse() {
    for bad in ["mcp.example.com", "https://mcp.example.com#fragment", "https://mcp.example.com/mcp?x=1", "http://mcp.example.com/mcp", "ftp://mcp.example.com",
        "https://user:pw@mcp.example.com/mcp", "https://mcp.example.com/a/../b", "https://mcp.example.com/a b", "https://mcp.example.com\\evil", "", "https:///mcp"] {
        assert!(canonical_resource(bad).is_err(), "{bad:?} must be refused");
    }
    assert!(resources_equal("HTTPS://MCP.example.com/mcp/", MCP));
    assert!(!resources_equal("https://mcp.example.com/other", MCP));
    assert!(!resources_equal("https://mcp.example.com.evil.net/mcp", MCP));
}

// ---------- discovery ----------

#[test]
fn resource_metadata_urls_try_path_specific_then_root() {
    assert_eq!(resource_metadata_urls("https://example.com/public/mcp").unwrap(),
        ["https://example.com/.well-known/oauth-protected-resource/public/mcp", "https://example.com/.well-known/oauth-protected-resource"]);
    assert_eq!(resource_metadata_urls("https://example.com").unwrap(), ["https://example.com/.well-known/oauth-protected-resource"]);
}

#[test]
fn as_discovery_follows_the_priority_order() {
    assert_eq!(as_discovery_urls("https://auth.example.com/tenant1").unwrap(), [
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
        "https://auth.example.com/.well-known/openid-configuration/tenant1",
        "https://auth.example.com/tenant1/.well-known/openid-configuration"]);
    assert_eq!(as_discovery_urls("https://auth.example.com").unwrap(), [
        "https://auth.example.com/.well-known/oauth-authorization-server", "https://auth.example.com/.well-known/openid-configuration"]);
}

#[test]
fn resource_metadata_must_name_the_server_and_list_an_authorization_server() {
    let ok = json!({"resource": MCP, "authorization_servers": [AS], "scopes_supported": ["files:read"]}).to_string();
    let md = parse_resource_metadata(&ok, MCP).unwrap();
    assert_eq!(select_authorization_server(&md, &[]).unwrap(), AS);
    // The document of another server, served from this URL (mix-up).
    let other = json!({"resource": "https://other.example.com/mcp", "authorization_servers": [AS]}).to_string();
    assert!(matches!(parse_resource_metadata(&other, MCP), Err(Error::Claim(_))));
    // MCP requires at least one authorization server.
    assert!(parse_resource_metadata(&json!({"resource": MCP, "authorization_servers": []}).to_string(), MCP).is_err());
    assert!(parse_resource_metadata(&json!({"resource": MCP}).to_string(), MCP).is_err());
    // Trailing slash and case differences are tolerated.
    assert!(parse_resource_metadata(&json!({"resource": "https://MCP.example.com/mcp/", "authorization_servers": [AS]}).to_string(), MCP).is_ok());
    // Client-side allow-list.
    assert!(select_authorization_server(&md, &["https://elsewhere.example"]).is_err());
    assert_eq!(select_authorization_server(&md, &[AS]).unwrap(), AS);
}

fn as_md(extra: Value) -> AsMetadata {
    let mut v = json!({"issuer": AS, "authorization_endpoint": format!("{AS}/authorize"), "token_endpoint": format!("{AS}/token"),
        "code_challenge_methods_supported": ["S256"], "authorization_response_iss_parameter_supported": true});
    for (k, x) in extra.as_object().cloned().unwrap_or_default() { v[k] = x; }
    AsMetadata::parse(&v.to_string(), AS).unwrap()
}

#[test]
fn clients_refuse_to_continue_without_pkce_support() {
    assert!(require_pkce(&as_md(json!({}))).is_ok());
    let mut none = as_md(json!({})); none.code_challenge_methods_supported.clear();
    assert!(matches!(require_pkce(&none), Err(Error::Claim(_))));
    assert!(Flow::new(&none, "c", "http://127.0.0.1:1/cb", MCP).is_err());
    let plain = as_md(json!({"code_challenge_methods_supported": ["plain"]}));
    assert!(require_pkce(&plain).is_err());
}

#[test]
fn registration_priority_is_preregistered_then_cimd_then_dcr_then_manual() {
    let cimd = as_md(json!({"client_id_metadata_document_supported": true, "registration_endpoint": format!("{AS}/register")}));
    let dcr = as_md(json!({"registration_endpoint": format!("{AS}/register")}));
    let none = as_md(json!({}));
    let url = Some("https://app.example/client.json");
    assert_eq!(choose_registration(true, &cimd, url), Registration::Preregistered);
    assert_eq!(choose_registration(false, &cimd, url), Registration::ClientIdMetadataDocument);
    assert_eq!(choose_registration(false, &cimd, None), Registration::Dynamic);
    assert_eq!(choose_registration(false, &dcr, url), Registration::Dynamic);
    assert_eq!(choose_registration(false, &none, url), Registration::Manual);
    assert!(supports_client_id_metadata(&cimd) && !supports_client_id_metadata(&dcr));
}

// ---------- WWW-Authenticate ----------

#[test]
fn parses_the_spec_example_challenge() {
    let h = r#"Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="files:read""#;
    let c = parse_challenges(h).unwrap();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].resource_metadata(), Some("https://mcp.example.com/.well-known/oauth-protected-resource"));
    assert_eq!(c[0].scope(), Some("files:read"));
    assert!(c[0].is_bearer());
}

#[test]
fn parses_the_insufficient_scope_example_and_multiple_challenges() {
    let h = "Bearer error=\"insufficient_scope\",\n scope=\"files:read files:write user:profile\",\n resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\",\n error_description=\"Additional file write permission required\"";
    let c = parse_challenges(&h.replace('\n', " ")).unwrap();
    assert_eq!(c[0].error(), Some("insufficient_scope"));
    assert_eq!(c[0].scope(), Some("files:read files:write user:profile"));
    assert_eq!(c[0].error_description(), Some("Additional file write permission required"));
    let two = parse_challenges(r#"Basic realm="x", Bearer scope="a b", resource_metadata="https://m/x""#).unwrap();
    assert_eq!(two.len(), 2);
    assert_eq!(bearer_challenge(&two).unwrap().scope(), Some("a b"));
    // Quoted strings with commas and escaped quotes.
    let q = parse_challenges(r#"Bearer error_description="a, b \"c\"", realm=mcp"#).unwrap();
    assert_eq!(q[0].error_description(), Some("a, b \"c\""));
    assert_eq!(q[0].param("realm"), Some("mcp"));
    // Parameter names are case-insensitive, the scheme too.
    assert_eq!(parse_challenges(r#"bearer SCOPE="x""#).unwrap()[0].scope(), Some("x"));
}

#[test]
fn hostile_challenges_are_errors_not_guesses() {
    // A repeated parameter must not be resolved by "first wins": an on-path party could pick the metadata URL.
    assert!(parse_challenges(r#"Bearer resource_metadata="https://good/x", resource_metadata="https://evil/x""#).is_err());
    assert!(parse_challenges(r#"Bearer scope="unterminated"#).is_err());
    assert!(parse_challenges("Bearer scope=\"a\x01b\"").is_err());
    assert!(parse_challenges(&format!("Bearer scope=\"{}\"", "a".repeat(9000))).is_err());
    assert!(parse_challenges("Bearer abc123==").is_err());
    assert!(parse_challenges(r#"Bearer scope="a\"#).is_err());
    let many = (0..40).map(|i| format!("p{i}=\"x\"")).collect::<Vec<_>>().join(", ");
    assert!(parse_challenges(&format!("Bearer {many}")).is_err());
    assert_eq!(parse_challenges("").unwrap().len(), 0);
}

#[test]
fn scope_selection_prefers_the_challenge_then_scopes_supported_then_nothing() {
    let md = parse_resource_metadata(&json!({"resource": MCP, "authorization_servers": [AS], "scopes_supported": ["a", "b"]}).to_string(), MCP).unwrap();
    let ch = parse_challenges(r#"Bearer scope="x y""#).unwrap();
    assert_eq!(select_scope(ch.first(), Some(&md)).unwrap().to_string(), "x y");
    // Not a subset of scopes_supported: still authoritative.
    assert_eq!(select_scope(None, Some(&md)).unwrap().to_string(), "a b");
    let bare = parse_challenges(r#"Bearer realm="m""#).unwrap();
    assert_eq!(select_scope(bare.first(), Some(&md)).unwrap().to_string(), "a b");
    let no_scopes = parse_resource_metadata(&json!({"resource": MCP, "authorization_servers": [AS]}).to_string(), MCP).unwrap();
    assert!(select_scope(None, Some(&no_scopes)).is_none());
    assert!(select_scope(None, None).is_none());
    // A challenge scope that does not parse is ignored rather than trusted.
    let junk = parse_challenges(r#"Bearer scope="a  b""#).unwrap();
    assert_eq!(select_scope(junk.first(), Some(&md)).unwrap().to_string(), "a b");
}

// ---------- client flow ----------

#[test]
fn flow_sends_resource_in_both_requests_with_pkce_s256() {
    let md = as_md(json!({}));
    let f = Flow::new(&md, "c1", "http://127.0.0.1:3000/cb", "HTTPS://MCP.example.com/mcp/").unwrap();
    assert_eq!(f.resource, MCP);
    let out = f.start(Some(&scope("files:read"))).unwrap();
    let q = url::Url::parse(&out.url).unwrap();
    let get = |k: &str| q.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.to_string());
    assert_eq!(get("resource").as_deref(), Some(MCP));
    assert_eq!(get("code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(get("response_type").as_deref(), Some("code"));
    assert_eq!(get("state").as_deref(), Some(out.state.as_str()));
    assert_eq!(get("scope").as_deref(), Some("files:read"));
    assert_eq!(out.url.matches("resource=").count(), 1);
    let body = f.token_request("the-code", &out.code_verifier);
    let p = authlas::oauth::form::Params::parse(&body).unwrap();
    assert_eq!(p.get("resource").unwrap(), Some(MCP));
    assert_eq!(p.get("code_verifier").unwrap(), Some(out.code_verifier.as_str()));
    assert_eq!(p.get("grant_type").unwrap(), Some("authorization_code"));
    let r = authlas::oauth::form::Params::parse(&f.refresh_request("rt", Some(&scope("a")))).unwrap();
    assert_eq!(r.get("resource").unwrap(), Some(MCP));
}

#[test]
fn flow_checks_state_and_issuer_on_the_way_back() {
    let md = as_md(json!({}));
    let f = Flow::new(&md, "c1", "http://127.0.0.1:3000/cb", MCP).unwrap();
    let ok = format!("code=abc&state=s1&iss={}", url::form_urlencoded::byte_serialize(AS.as_bytes()).collect::<String>());
    assert_eq!(f.parse_redirect(&ok, "s1").unwrap(), "abc");
    assert!(f.parse_redirect(&ok, "other").is_err(), "state mismatch");
    assert!(f.parse_redirect("code=abc&state=s1", "s1").is_err(), "iss is advertised, so a missing iss is a mix-up signal");
    assert!(f.parse_redirect("code=abc&state=s1&iss=https%3A%2F%2Fevil.example", "s1").is_err());
    // A server that does not advertise iss is not held to it.
    let md2 = as_md(json!({"authorization_response_iss_parameter_supported": false}));
    let f2 = Flow::new(&md2, "c1", "http://127.0.0.1:3000/cb", MCP).unwrap();
    assert_eq!(f2.parse_redirect("code=abc&state=s1", "s1").unwrap(), "abc");
}

#[test]
fn step_up_merges_scopes_and_stops_after_the_limit() {
    let mut t = StepUpTracker::new(2);
    let ch = parse_challenges(r#"Bearer error="insufficient_scope", scope="files:write", resource_metadata="https://m/x""#).unwrap();
    let granted = scope("files:read");
    let next = t.next_scope("op1", &granted, &ch[0]).unwrap();
    assert_eq!(next.to_string(), "files:read files:write", "granted scopes are kept");
    // The same operation keeps failing: second attempt allowed, third is a permanent failure.
    assert!(t.next_scope("op1", &granted, &ch[0]).is_ok());
    assert!(t.next_scope("op1", &granted, &ch[0]).is_err());
    // A different operation has its own budget.
    assert!(t.next_scope("op2", &granted, &ch[0]).is_ok());
    // Not an insufficient_scope challenge.
    let other = parse_challenges(r#"Bearer error="invalid_token""#).unwrap();
    assert!(t.next_scope("op3", &granted, &other[0]).is_err());
    // Nothing new asked for: no point re-running the flow.
    let same = parse_challenges(r#"Bearer error="insufficient_scope", scope="files:read""#).unwrap();
    assert!(t.next_scope("op4", &granted, &same[0]).is_err());
    let none = parse_challenges(r#"Bearer error="insufficient_scope""#).unwrap();
    assert!(t.next_scope("op5", &granted, &none[0]).is_err());
}

// ---------- resource server ----------

#[test]
fn resource_server_metadata_and_unauthenticated_challenge() {
    let r = rs();
    assert_eq!(r.metadata_url(), "https://mcp.example.com/.well-known/oauth-protected-resource/mcp");
    let md = parse_resource_metadata(&r.metadata_json(), MCP).unwrap();
    assert_eq!(md.authorization_servers, [AS]);
    assert_eq!(md.bearer_methods_supported, ["header"]);
    let d = r.unauthenticated();
    assert_eq!(d.status, 401);
    let c = &parse_challenges(&d.www_authenticate).unwrap()[0];
    assert_eq!(c.resource_metadata(), Some(r.metadata_url()));
    assert_eq!(c.scope(), Some("files:read"));
    assert_eq!(c.error(), None, "no error code when no credentials were sent (RFC 6750 3.1)");
    // Constructors refuse unusable setups.
    assert!(ResourceServer::new("http://mcp.example.com/mcp", &[AS], &[ES256]).is_err());
    assert!(ResourceServer::new(MCP, &[], &[ES256]).is_err());
    assert!(ResourceServer::new(MCP, &[AS], &[]).is_err());
    assert!(ResourceServer::new(MCP, &["http://auth.example.com"], &[ES256]).is_err());
}

#[test]
fn accepts_a_token_issued_for_this_server() {
    let Some(k) = ec() else { return };
    let r = rs();
    let t = token(&k, AS, &[MCP], "files:read", NOW + 300);
    let h = format!("Bearer {t}");
    let p = r.authenticate_jwt(&[&h], &keys_of(&k), None, Some(NOW + 10)).unwrap();
    assert_eq!(p.subject.as_deref(), Some("alice"));
    assert_eq!(p.client_id.as_deref(), Some("c1"));
    assert!(p.scope.contains("files:read"));
    assert!(r.authorize(&p, &["files:read"]).is_ok());
}

#[test]
fn rejects_tokens_for_other_audiences_the_confused_deputy_case() {
    let Some(k) = ec() else { return };
    let r = rs();
    for aud in [vec!["https://other.example.com/mcp"], vec!["https://mcp.example.com"], vec!["https://mcp.example.com/mcp/"], vec![AS]] {
        let t = token(&k, AS, &aud.iter().copied().collect::<Vec<_>>(), "files:read", NOW + 300);
        let d = r.authenticate_jwt(&[&format!("Bearer {t}")], &keys_of(&k), None, Some(NOW)).unwrap_err();
        assert_eq!(d.status, 401, "aud {aud:?}");
        assert_eq!(d.error.code, ErrorCode::InvalidToken);
        let c = &parse_challenges(&d.www_authenticate).unwrap()[0];
        assert_eq!(c.error(), Some("invalid_token"));
        assert_eq!(c.resource_metadata(), Some(r.metadata_url()));
    }
    // One of several audiences is enough.
    let t = token(&k, AS, &["https://other.example.com", MCP], "files:read", NOW + 300);
    assert!(r.authenticate_jwt(&[&format!("Bearer {t}")], &keys_of(&k), None, Some(NOW)).is_ok());
}

#[test]
fn rejects_untrusted_issuers_expired_and_forged_tokens() {
    let Some(k) = ec() else { return };
    let Some(evil) = ec() else { return };
    let r = rs();
    // Right audience, wrong issuer: the key lookup must not even be asked.
    let t = token(&k, "https://evil.example.com", &[MCP], "files:read", NOW + 300);
    let asked = std::cell::Cell::new(false);
    let spy = |_: &str, _: Option<&str>| { asked.set(true); Some(k.public().unwrap()) };
    assert!(r.authenticate_jwt(&[&format!("Bearer {t}")], &spy, None, Some(NOW)).is_err());
    assert!(!asked.get(), "keys must only be looked up for trusted issuers");
    // Expired.
    let old = token(&k, AS, &[MCP], "files:read", NOW + 10);
    assert!(r.authenticate_jwt(&[&format!("Bearer {old}")], &keys_of(&k), None, Some(NOW + 1000)).is_err());
    // Signed by someone else's key.
    let forged = token(&evil, AS, &[MCP], "files:read", NOW + 300);
    assert!(r.authenticate_jwt(&[&format!("Bearer {forged}")], &keys_of(&k), None, Some(NOW)).is_err());
    // No key for the issuer.
    assert!(r.authenticate_jwt(&[&format!("Bearer {}", token(&k, AS, &[MCP], "a", NOW + 300))], &|_, _| None, None, Some(NOW)).is_err());
    // An ID token or other JWT without typ at+jwt is not an access token.
    let c = Claims::new().issuer(AS).subject("alice").audience(&[MCP]).expires_at(NOW + 300).issued_at(NOW).jti("j").set("client_id", "c1");
    let plain = jwt::sign(ES256, &k, &c, Some("JWT")).unwrap();
    assert!(r.authenticate_jwt(&[&format!("Bearer {plain}")], &keys_of(&k), None, Some(NOW)).is_err());
}

#[test]
fn authorization_header_handling() {
    let Some(k) = ec() else { return };
    let r = rs();
    let t = token(&k, AS, &[MCP], "files:read", NOW + 300);
    assert_eq!(r.authenticate_jwt(&[], &keys_of(&k), None, Some(NOW)).unwrap_err().status, 401);
    let two = format!("Bearer {t}");
    let d = r.authenticate_jwt(&[&two, &two], &keys_of(&k), None, Some(NOW)).unwrap_err();
    assert_eq!(d.status, 400, "two Authorization headers: do not pick one");
    assert_eq!(r.authenticate_jwt(&["Basic Zm9vOmJhcg=="], &keys_of(&k), None, Some(NOW)).unwrap_err().status, 401);
    assert_eq!(r.authenticate_jwt(&["Bearer"], &keys_of(&k), None, Some(NOW)).unwrap_err().status, 401);
    assert_eq!(r.authenticate_jwt(&["Bearer a b"], &keys_of(&k), None, Some(NOW)).unwrap_err().status, 401);
    // Scheme is case-insensitive.
    assert!(r.authenticate_jwt(&[&format!("bearer {t}")], &keys_of(&k), None, Some(NOW)).is_ok());
    // A DPoP-scheme token is not accepted by a Bearer-only server.
    assert_eq!(r.authenticate_jwt(&[&format!("DPoP {t}")], &keys_of(&k), None, Some(NOW)).unwrap_err().status, 401);
}

#[test]
fn replayed_jti_is_refused_when_a_cache_is_supplied() {
    let Some(k) = ec() else { return };
    let r = rs();
    let cache = MemoryReplayCache::new();
    let h = format!("Bearer {}", token(&k, AS, &[MCP], "files:read", NOW + 300));
    assert!(r.authenticate_jwt(&[&h], &keys_of(&k), Some(&cache), Some(NOW)).is_ok());
    assert!(r.authenticate_jwt(&[&h], &keys_of(&k), Some(&cache), Some(NOW)).is_err());
}

#[test]
fn insufficient_scope_is_403_with_resource_metadata_and_the_scopes_to_ask_for() {
    let Some(k) = ec() else { return };
    let r = rs();
    let h = format!("Bearer {}", token(&k, AS, &[MCP], "files:read", NOW + 300));
    let p = r.authenticate_jwt(&[&h], &keys_of(&k), None, Some(NOW)).unwrap();
    let d = r.authorize(&p, &["files:write"]).unwrap_err();
    assert_eq!(d.status, 403);
    assert_eq!(d.error.code, ErrorCode::InsufficientScope);
    let c = &parse_challenges(&d.www_authenticate).unwrap()[0];
    assert_eq!(c.error(), Some("insufficient_scope"));
    assert_eq!(c.scope(), Some("files:read files:write"), "granted scopes stay in the request so the client does not lose them");
    assert_eq!(c.resource_metadata(), Some(r.metadata_url()));
    // The client side closes the loop.
    let mut t = StepUpTracker::new(3);
    assert_eq!(t.next_scope("call", &p.scope, c).unwrap().to_string(), "files:read files:write");
    // Minimal variant.
    let mut r2 = rs(); r2.include_granted_in_challenge = false;
    let d2 = r2.authorize(&p, &["files:write"]).unwrap_err();
    assert_eq!(parse_challenges(&d2.www_authenticate).unwrap()[0].scope(), Some("files:write"));
    assert!(r.authorize(&p, &[]).is_ok());
}

#[test]
fn opaque_tokens_through_introspection() {
    let r = rs();
    let good = |_: &str| -> Result<Introspection, OAuthError> {
        Ok(Introspection { active: true, scope: Some(scope("files:read")), client_id: Some("c1".into()), sub: Some("alice".into()), aud: vec![MCP.into()], iss: Some(AS.into()), exp: Some(NOW + 300), ..Default::default() })
    };
    let p = r.authenticate_introspection(&["Bearer opaque-token"], &good, Some(NOW)).unwrap();
    assert_eq!(p.subject.as_deref(), Some("alice"));
    let inactive = |_: &str| Ok(Introspection::inactive());
    assert_eq!(r.authenticate_introspection(&["Bearer x"], &inactive, Some(NOW)).unwrap_err().status, 401);
    let wrong_aud = |_: &str| Ok(Introspection { active: true, aud: vec!["https://other.example.com".into()], exp: Some(NOW + 300), ..Default::default() });
    assert_eq!(r.authenticate_introspection(&["Bearer x"], &wrong_aud, Some(NOW)).unwrap_err().status, 401);
    let no_aud = |_: &str| Ok(Introspection { active: true, exp: Some(NOW + 300), ..Default::default() });
    assert!(r.authenticate_introspection(&["Bearer x"], &no_aud, Some(NOW)).is_err(), "a response without aud proves nothing about this server");
    let evil_iss = |_: &str| Ok(Introspection { active: true, aud: vec![MCP.into()], iss: Some("https://evil.example".into()), exp: Some(NOW + 300), ..Default::default() });
    assert!(r.authenticate_introspection(&["Bearer x"], &evil_iss, Some(NOW)).is_err());
    let expired = |_: &str| Ok(Introspection { active: true, aud: vec![MCP.into()], exp: Some(NOW - 1000), ..Default::default() });
    assert!(r.authenticate_introspection(&["Bearer x"], &expired, Some(NOW)).is_err());
    // An introspection outage is the server's problem (503), not a reason to tell the client its token is bad.
    let down = |_: &str| Err(OAuthError::new(ErrorCode::TemporarilyUnavailable));
    assert_eq!(r.authenticate_introspection(&["Bearer x"], &down, Some(NOW)).unwrap_err().status, 503);
}

// ---------- SSRF ----------

#[test]
fn ssrf_check_refuses_internal_targets() {
    for bad in ["http://app.example.com/c.json", "https://localhost/c.json", "https://127.0.0.1/c.json", "https://[::1]/c.json", "https://10.0.0.5/c.json",
        "https://192.168.1.1/c.json", "https://172.16.0.1/c.json", "https://169.254.169.254/latest/meta-data", "https://[fe80::1]/c", "https://[fd00::1]/c",
        "https://0.0.0.0/c", "https://[::ffff:127.0.0.1]/c", "https://[::ffff:10.0.0.1]/c", "https://100.64.0.1/c", "https://metadata/c", "https://printer.local/c",
        "https://db.internal/c", "file:///etc/passwd", "gopher://x/", "https://user:pw@app.example.com/c", "https://app.example.com\\@evil/c", "https://[64:ff9b::7f00:1]/c",
        "https://[2002:7f00:1::]/c", "https://224.0.0.1/c", "https://localhost./c", "https://LOCALHOST/c"] {
        assert!(ssrf_check(bad).is_err(), "{bad} must be refused");
    }
    for ok in ["https://app.example.com/client.json", "https://8.8.8.8/c", "https://[2606:4700:4700::1111]/c", "https://app.example.com:8443/c"] {
        assert!(ssrf_check(ok).is_ok(), "{ok} must be allowed");
    }
}

#[test]
fn is_public_ip_classifies_reserved_ranges() {
    let no = ["0.0.0.0", "127.0.0.1", "10.1.2.3", "172.31.255.255", "192.168.0.1", "169.254.1.1", "100.64.0.1", "100.127.255.255", "198.18.0.1", "192.0.2.1",
        "203.0.113.9", "240.0.0.1", "255.255.255.255", "224.0.0.1", "::", "::1", "fc00::1", "fe80::1", "ff02::1", "::ffff:192.168.1.1", "2001:db8::1", "2001::1", "64:ff9b::a00:1"];
    let yes = ["8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"];
    for a in no { assert!(!is_public_ip(a.parse::<IpAddr>().unwrap()), "{a}"); }
    for a in yes { assert!(is_public_ip(a.parse::<IpAddr>().unwrap()), "{a}"); }
}

#[test]
fn cache_lifetime_never_caches_errors_or_no_store() {
    assert_eq!(cache_lifetime(404, Some("max-age=600")), 0);
    assert_eq!(cache_lifetime(500, None), 0);
    assert_eq!(cache_lifetime(200, Some("no-store")), 0);
    assert_eq!(cache_lifetime(200, Some("private, no-cache")), 0);
    assert_eq!(cache_lifetime(200, Some("max-age=0")), 0);
    assert_eq!(cache_lifetime(200, Some("max-age=3600")), 3600);
    assert_eq!(cache_lifetime(200, Some("max-age=5")), CACHE_MIN);
    assert_eq!(cache_lifetime(200, Some("max-age=99999999")), CACHE_MAX);
    assert_eq!(cache_lifetime(200, None), CACHE_DEFAULT);
    assert_eq!(cache_lifetime(200, Some("public")), CACHE_DEFAULT);
}

// ---------- Client ID Metadata Documents ----------

const CID: &str = "https://app.example.com/oauth/client-metadata.json";

fn doc(extra: Value) -> String {
    let mut v = json!({"client_id": CID, "client_name": "Example MCP Client", "client_uri": "https://app.example.com", "logo_uri": "https://app.example.com/logo.png",
        "redirect_uris": ["http://127.0.0.1:3000/callback", "https://app.example.com/cb"], "grant_types": ["authorization_code"], "response_types": ["code"],
        "token_endpoint_auth_method": "none"});
    for (k, x) in extra.as_object().cloned().unwrap_or_default() { if x.is_null() { v.as_object_mut().unwrap().remove(&k); } else { v[k] = x; } }
    v.to_string()
}

#[test]
fn the_spec_example_document_is_accepted() {
    let spec = r#"{"client_id": "https://app.example.com/oauth/client-metadata.json", "client_name": "Example MCP Client", "client_uri": "https://app.example.com",
        "logo_uri": "https://app.example.com/logo.png", "redirect_uris": ["http://127.0.0.1:3000/callback", "http://localhost:3000/callback"],
        "grant_types": ["authorization_code"], "response_types": ["code"], "token_endpoint_auth_method": "none"}"#;
    // localhost is refused by default (RFC 8252 8.3) and allowed by an explicit local policy.
    assert!(ClientIdDocument::parse(CID, spec, &CimdPolicy::default()).is_err());
    let d = ClientIdDocument::parse(CID, spec, &CimdPolicy { allow_localhost: true, ..Default::default() }).unwrap();
    assert_eq!(d.display_host, "app.example.com");
    assert!(d.localhost_only, "all redirect URIs are on this machine: warn on the consent screen");
    assert_eq!(d.redirect_uris.len(), 2);
    assert!(d.redirect_matches("http://127.0.0.1:3000/callback"));
    assert!(!d.redirect_matches("http://127.0.0.1:54321/callback"), "a port the client pinned in its document is compared exactly");
    assert!(d.redirect_matches("http://localhost:3000/callback"));
    assert!(!d.redirect_matches("http://localhost:3001/callback"), "localhost is compared exactly");
    assert!(!d.redirect_matches("http://127.0.0.1:3000/other"));
}

#[test]
fn a_portless_loopback_redirect_gets_the_rfc8252_flexible_port() {
    let d = ClientIdDocument::parse(CID, &doc(json!({"redirect_uris": ["http://127.0.0.1/callback"]})), &CimdPolicy::default()).unwrap();
    assert!(d.redirect_matches("http://127.0.0.1:54321/callback"));
    assert!(d.redirect_matches("http://127.0.0.1:1/callback"));
    assert!(!d.redirect_matches("http://127.0.0.1:54321/other"));
    assert!(!d.redirect_matches("https://127.0.0.1:54321/callback"));
    assert!(!d.redirect_matches("http://127.0.0.2:54321/callback"));
    assert!(d.localhost_only);
}

#[test]
fn document_with_a_web_redirect_is_not_localhost_only() {
    let d = ClientIdDocument::parse(CID, &doc(json!({})), &CimdPolicy::default()).unwrap();
    assert!(!d.localhost_only);
    let s = d.consent_summary();
    assert_eq!(s["host"], "app.example.com");
    assert_eq!(s["name"], "Example MCP Client");
    let info = d.client_info(scope("files:read"));
    assert_eq!(info.client_id, CID);
    assert!(info.allowed_scopes.contains("files:read"));
}

#[test]
fn client_id_must_equal_the_url_it_came_from() {
    assert!(matches!(ClientIdDocument::parse(CID, &doc(json!({"client_id": "https://app.example.com/other.json"})), &CimdPolicy::default()), Err(Error::Claim(_))));
    assert!(ClientIdDocument::parse(CID, &doc(json!({"client_id": null})), &CimdPolicy::default()).is_err());
    assert!(ClientIdDocument::parse(CID, &doc(json!({"client_id": "https://APP.example.com/oauth/client-metadata.json"})), &CimdPolicy::default()).is_err(), "simple string comparison");
}

#[test]
fn client_id_url_rules() {
    for bad in ["http://app.example.com/c.json", "https://app.example.com", "https://app.example.com/", "https://app.example.com/a/../c.json", "https://app.example.com/./c.json",
        "https://app.example.com/c.json#frag", "https://u:p@app.example.com/c.json", "app.example.com/c.json", "https://app.example.com/%2e%2e/c.json"] {
        assert!(check_client_id_url(bad).is_err(), "{bad}");
    }
    assert!(check_client_id_url("https://app.example.com:8443/c.json").is_ok());
    assert!(check_client_id_url("https://app.example.com/c.json?v=1").is_ok(), "a query is discouraged, not forbidden");
}

#[test]
fn shared_secret_methods_are_refused() {
    for m in ["client_secret_basic", "client_secret_post", "client_secret_jwt", "tls_client_auth"] {
        assert!(ClientIdDocument::parse(CID, &doc(json!({"token_endpoint_auth_method": m})), &CimdPolicy::default()).is_err(), "{m}");
    }
    assert!(ClientIdDocument::parse(CID, &doc(json!({"client_secret": "x"})), &CimdPolicy::default()).is_err());
    assert!(ClientIdDocument::parse(CID, &doc(json!({"client_secret_expires_at": 0})), &CimdPolicy::default()).is_err());
}

#[test]
fn private_key_jwt_needs_public_keys_only() {
    let Some(k) = ec() else { return };
    let public: Value = serde_json::from_str(&k.public().unwrap().to_json()).unwrap();
    let private: Value = serde_json::from_str(&k.to_json()).unwrap();
    let ok = ClientIdDocument::parse(CID, &doc(json!({"token_endpoint_auth_method": "private_key_jwt", "jwks": {"keys": [public]}})), &CimdPolicy::default()).unwrap();
    assert_eq!(ok.jwks.as_ref().unwrap().len(), 1);
    assert!(ClientIdDocument::parse(CID, &doc(json!({"token_endpoint_auth_method": "private_key_jwt", "jwks": {"keys": [private]}})), &CimdPolicy::default()).is_err(), "private key published");
    assert!(ClientIdDocument::parse(CID, &doc(json!({"token_endpoint_auth_method": "private_key_jwt"})), &CimdPolicy::default()).is_err(), "no keys");
    assert!(ClientIdDocument::parse(CID, &doc(json!({"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://app.example.com/jwks.json"})), &CimdPolicy::default()).is_ok());
    assert!(ClientIdDocument::parse(CID, &doc(json!({"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://169.254.169.254/jwks"})), &CimdPolicy::default()).is_err(), "jwks_uri is fetched too: SSRF");
    assert!(ClientIdDocument::parse(CID, &doc(json!({"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://app.example.com/jwks.json", "jwks": {"keys": [public]}})), &CimdPolicy::default()).is_err());
}

#[test]
fn document_content_rules() {
    let p = CimdPolicy::default();
    let bad = |extra: Value| ClientIdDocument::parse(CID, &doc(extra), &p).is_err();
    assert!(bad(json!({"client_name": null})));
    assert!(bad(json!({"client_name": "  "})));
    assert!(bad(json!({"client_name": "x".repeat(101)})));
    assert!(bad(json!({"client_name": "evil\u{0007}name"})));
    assert!(bad(json!({"redirect_uris": []})));
    assert!(bad(json!({"redirect_uris": null})));
    assert!(bad(json!({"redirect_uris": ["javascript:alert(1)"]})));
    assert!(bad(json!({"redirect_uris": ["http://evil.example/cb"]})));
    assert!(bad(json!({"redirect_uris": ["https://app.example.com/cb#frag"]})));
    assert!(bad(json!({"redirect_uris": ["https://app.example.com/cb", 5]})));
    assert!(bad(json!({"redirect_uris": (0..17).map(|i| format!("https://app.example.com/cb{i}")).collect::<Vec<_>>()})));
    assert!(bad(json!({"grant_types": ["implicit"]})));
    assert!(bad(json!({"grant_types": ["password"]})));
    assert!(bad(json!({"response_types": ["token"]})));
    assert!(bad(json!({"logo_uri": "http://app.example.com/logo.png"})));
    assert!(bad(json!({"client_uri": "javascript:alert(1)"})));
    assert!(bad(json!({"scope": "a  b"})));
    // Oversize and duplicate members.
    assert!(ClientIdDocument::parse(CID, &doc(json!({"padding": "x".repeat(6000)})), &p).is_err(), "5 KiB cap");
    let dup = format!(r#"{{"client_id": "{CID}", "client_id": "https://evil/x.json", "client_name": "n", "redirect_uris": ["https://app.example.com/cb"]}}"#);
    assert!(ClientIdDocument::parse(CID, &dup, &p).is_err());
    assert!(ClientIdDocument::parse(CID, "not json", &p).is_err());
    assert!(ClientIdDocument::parse(CID, "[]", &p).is_err());
}

#[test]
fn same_origin_redirect_policy() {
    let strict = CimdPolicy { require_same_origin_redirects: true, ..Default::default() };
    assert!(ClientIdDocument::parse(CID, &doc(json!({})), &strict).is_ok());
    assert!(ClientIdDocument::parse(CID, &doc(json!({"redirect_uris": ["https://evil.example/cb"]})), &strict).is_err());
    assert!(ClientIdDocument::parse(CID, &doc(json!({"redirect_uris": ["https://app.example.com.evil.net/cb"]})), &strict).is_err());
    assert!(ClientIdDocument::parse(CID, &doc(json!({"redirect_uris": ["https://evil.example/cb"]})), &CimdPolicy::default()).is_ok(), "off by default");
    // Native loopback stays allowed under the strict policy.
    assert!(ClientIdDocument::parse(CID, &doc(json!({"redirect_uris": ["http://127.0.0.1:8080/cb"]})), &strict).is_ok());
}

#[test]
fn a_document_cannot_grant_itself_scopes() {
    let d = ClientIdDocument::parse(CID, &doc(json!({"scope": "admin everything"})), &CimdPolicy::default()).unwrap();
    let info = d.client_info(scope("files:read"));
    assert!(!info.allowed_scopes.contains("admin"), "scopes come from server policy, never from the client's own metadata");
}

#[test]
fn full_authorization_request_with_a_cimd_client() {
    use authlas::oauth::request::{validate, ServerPolicy};
    let d = ClientIdDocument::parse(CID, &doc(json!({})), &CimdPolicy::default()).unwrap();
    let info = d.client_info(scope("files:read files:write"));
    let mut pol = ServerPolicy::default();
    pol.allowed_resources = vec![MCP.into()];
    pol.issuer = Some(AS.into());
    let q = format!("response_type=code&client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=files%3Aread&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource={}",
        url::form_urlencoded::byte_serialize(CID.as_bytes()).collect::<String>(), url::form_urlencoded::byte_serialize(MCP.as_bytes()).collect::<String>());
    let req = validate(&q, &info, &pol).expect("valid request");
    assert_eq!(req.resources, [MCP]);
    // A resource the server does not know is invalid_target.
    let bad = q.replace("mcp.example.com%2Fmcp", "evil.example.com%2Fmcp");
    assert_eq!(validate(&bad, &info, &pol).unwrap_err().error().code, ErrorCode::InvalidTarget);
    // A redirect URI that is not in the document is never redirected to.
    let hijack = q.replace("app.example.com%2Fcb", "evil.example.com%2Fcb");
    assert!(matches!(validate(&hijack, &info, &pol), Err(authlas::oauth::request::Failure::Direct(_))));
}

#[test]
fn advertising_cimd_support() {
    let mut md = as_md(json!({}));
    assert!(!supports_client_id_metadata(&md));
    advertise_client_id_metadata(&mut md);
    assert!(supports_client_id_metadata(&md));
    let again = AsMetadata::parse(&md.to_json(), AS).unwrap();
    assert!(supports_client_id_metadata(&again), "survives a round trip");
}

#[allow(dead_code)]
fn _uses(_: Algorithm) {}
