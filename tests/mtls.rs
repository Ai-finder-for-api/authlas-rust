use authlas::jwt::Claims;
use authlas::oauth::form::Params;
use authlas::oauth::metadata::AsMetadata;
use authlas::oauth::mtls::{self, ExpectedSubject, Registration};
use authlas::oauth::ErrorCode;
use authlas::jwk::Jwk;
use authlas::jwa::Hash;
use authlas::x509::{self, Certificate, San};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

fn vectors() -> Value { serde_json::from_str(include_str!("vectors/certs.json")).unwrap() }
fn cert(label: &str) -> Certificate {
    let v = vectors();
    Certificate::from_der(&STANDARD.decode(v[label]["der"].as_str().unwrap()).unwrap()).unwrap()
}
fn body(id: &str) -> Params { Params::from_pairs([("client_id", id)]).unwrap() }
const NOW: u64 = 1_800_000_000; // inside 2025..2035? no: 2027-01-15, inside the window
const DN: &str = "CN=client.example.org,O=Example\\, Inc.,C=US";

// ---------- certificate reader against independently produced certificates ----------

#[test]
fn reader_matches_python_cryptography_for_every_key_type() {
    let v = vectors();
    for label in ["ec256", "ec384", "ec521", "rsa2048", "ed25519", "expired", "future", "nosan", "escapes"] {
        let c = cert(label);
        assert_eq!(c.subject_rfc4514, v[label]["subject_rfc4514"].as_str().unwrap(), "{label} subject");
        assert_eq!(c.x5t_s256().unwrap(), v[label]["x5t_s256"].as_str().unwrap(), "{label} thumbprint");
        let want = Jwk::parse(&v[label]["jwk"].to_string()).unwrap();
        assert_eq!(c.public_jwk().unwrap(), want, "{label} jwk");
    }
}

#[test]
fn reader_extracts_all_san_types_and_validity() {
    let c = cert("ec256");
    assert!(c.sans.contains(&San::Dns("client.example.org".into())));
    assert!(c.sans.contains(&San::Dns("alt.example.org".into())));
    assert!(c.sans.contains(&San::Uri("https://client.example.org/id".into())));
    assert!(c.sans.contains(&San::Ip("192.0.2.7".parse().unwrap())));
    assert!(c.sans.contains(&San::Ip("2001:db8::1".parse().unwrap())));
    assert!(c.sans.contains(&San::Email("ops@example.org".into())));
    assert!(c.valid_at(NOW));
    assert!(!c.valid_at(1_000_000_000));
    assert!(cert("nosan").sans.is_empty());
    assert!(!cert("expired").valid_at(NOW));
    assert!(!cert("future").valid_at(NOW));
}

#[test]
fn reader_rejects_malformed_der() {
    let v = vectors();
    let der = STANDARD.decode(v["ec256"]["der"].as_str().unwrap()).unwrap();
    assert!(Certificate::from_der(&[]).is_err());
    assert!(Certificate::from_der(&der[..der.len() - 1]).is_err(), "truncated");
    let mut trailing = der.clone(); trailing.push(0);
    assert!(Certificate::from_der(&trailing).is_err(), "trailing byte");
    assert!(Certificate::from_der(&vec![0x30; 20000]).is_err(), "oversize");
    let mut wrong_tag = der.clone(); wrong_tag[0] = 0x31;
    assert!(Certificate::from_der(&wrong_tag).is_err());
    // Indefinite length.
    let mut indef = der.clone(); indef[1] = 0x80;
    assert!(Certificate::from_der(&indef).is_err());
    // Non-minimal length encoding of the outer SEQUENCE: 0x82 0x00 NN where the value fits in one byte of length.
    let mut nm = vec![0x30, 0x83, 0x00, 0x00];
    nm.extend_from_slice(&der[3..]);
    assert!(Certificate::from_der(&nm).is_err());
    // Fuzz-ish: flipping every byte never panics.
    for i in (0..der.len()).step_by(7) { let mut d = der.clone(); d[i] ^= 0xff; let _ = Certificate::from_der(&d); }
    // Random garbage of many shapes never panics.
    for n in 0..200usize { let g: Vec<u8> = (0..n).map(|i| (i * 31 + n) as u8).collect(); let _ = Certificate::from_der(&g); }
}

#[test]
fn forwarded_header_forms() {
    let v = vectors();
    let want = cert("ec256").x5t_s256().unwrap();
    let der_b64 = v["ec256"]["der"].as_str().unwrap();
    let pem = v["ec256"]["pem"].as_str().unwrap();
    assert_eq!(x509::from_forwarded_header(der_b64).unwrap().x5t_s256().unwrap(), want);
    assert_eq!(x509::from_forwarded_header(pem).unwrap().x5t_s256().unwrap(), want);
    let escaped: String = url::form_urlencoded::byte_serialize(pem.as_bytes()).collect::<String>().replace('+', "%20");
    assert_eq!(x509::from_forwarded_header(&escaped).unwrap().x5t_s256().unwrap(), want, "nginx $ssl_client_escaped_cert form");
    assert!(x509::from_forwarded_header("not a certificate").is_err());
    assert!(x509::from_forwarded_header(&format!("{pem}{pem}")).is_err(), "two certificates");
    assert!(x509::from_forwarded_header(&"A".repeat(200_000)).is_err());
}

// ---------- ExpectedSubject ----------

#[test]
fn registration_metadata_needs_exactly_one_subject_value() {
    use ExpectedSubject::*;
    assert_eq!(ExpectedSubject::from_metadata(Some("CN=x"), None, None, None, None).unwrap(), SubjectDn("CN=x".into()));
    assert_eq!(ExpectedSubject::from_metadata(None, Some("a.example"), None, None, None).unwrap(), SanDns("a.example".into()));
    assert_eq!(ExpectedSubject::from_metadata(None, None, None, Some("2001:db8::1"), None).unwrap(), SanIp("2001:db8::1".parse().unwrap()));
    assert!(ExpectedSubject::from_metadata(None, None, None, None, None).is_err(), "none");
    assert!(ExpectedSubject::from_metadata(Some("CN=x"), Some("a"), None, None, None).is_err(), "two");
    assert!(ExpectedSubject::from_metadata(Some(""), None, None, None, None).is_err(), "empty");
    assert!(ExpectedSubject::from_metadata(None, None, None, Some("not-an-ip"), None).is_err());
    assert_eq!(ExpectedSubject::from_metadata(None, Some("a"), None, None, Some("x@y")).unwrap_err().code, ErrorCode::InvalidClientMetadata);
}

// ---------- authentication ----------

fn pki(e: ExpectedSubject) -> Registration { Registration::Pki { client_id: "c1".into(), expected: e } }

#[test]
fn pki_authentication_by_each_subject_kind() {
    let c = cert("ec256");
    let ok = |e: ExpectedSubject| mtls::authenticate(&c, true, None, &body("c1"), &pki(e), Some(NOW));
    assert_eq!(ok(ExpectedSubject::SubjectDn(DN.into())).unwrap(), "c1");
    assert!(ok(ExpectedSubject::SubjectDn("CN=client.example.org,C=US".into())).is_err(), "partial DN");
    assert!(ok(ExpectedSubject::SubjectDn(DN.to_lowercase())).is_err(), "DN is compared exactly");
    assert!(ok(ExpectedSubject::SanDns("client.example.org".into())).is_ok());
    assert!(ok(ExpectedSubject::SanDns("CLIENT.EXAMPLE.ORG".into())).is_ok(), "DNS names are case-insensitive");
    assert!(ok(ExpectedSubject::SanDns("evil.example.org".into())).is_err());
    assert!(ok(ExpectedSubject::SanDns("*.example.org".into())).is_err(), "no wildcard matching");
    assert!(ok(ExpectedSubject::SanUri("https://client.example.org/id".into())).is_ok());
    assert!(ok(ExpectedSubject::SanUri("https://client.example.org/ID".into())).is_err(), "URIs are exact");
    assert!(ok(ExpectedSubject::SanIp("192.0.2.7".parse().unwrap())).is_ok());
    assert!(ok(ExpectedSubject::SanIp("2001:db8::1".parse().unwrap())).is_ok());
    assert!(ok(ExpectedSubject::SanIp("192.0.2.8".parse().unwrap())).is_err());
    assert!(ok(ExpectedSubject::SanEmail("ops@EXAMPLE.org".into())).is_ok(), "email domain is case-insensitive");
    assert!(ok(ExpectedSubject::SanEmail("OPS@example.org".into())).is_err(), "email local part is exact");
    // The escaped DN renders exactly as RFC 4514 requires.
    let e = cert("escapes");
    assert_eq!(mtls::authenticate(&e, true, None, &body("c1"), &pki(ExpectedSubject::SubjectDn("CN=\\#lead \\\"q\\\",O=A\\, B\\+C".into())), Some(NOW)).unwrap(), "c1");
}

#[test]
fn pki_requires_a_verified_chain_and_a_valid_time() {
    let c = cert("ec256");
    let reg = pki(ExpectedSubject::SanDns("client.example.org".into()));
    assert!(mtls::authenticate(&c, false, None, &body("c1"), &reg, Some(NOW)).is_err(), "the TLS layer did not validate the chain");
    assert!(mtls::authenticate(&c, true, None, &body("c1"), &reg, Some(1_000_000_000)).is_err(), "before notBefore");
    assert!(mtls::authenticate(&c, true, None, &body("c1"), &reg, Some(2_200_000_000)).is_err(), "after notAfter");
    let exp = cert("expired");
    let reg = pki(ExpectedSubject::SubjectDn("CN=old".into()));
    assert!(mtls::authenticate(&exp, true, None, &body("c1"), &reg, Some(NOW)).is_err(), "expired certificate");
}

#[test]
fn authentication_binds_to_the_client_id_and_stays_uniform() {
    let c = cert("ec256");
    let reg = pki(ExpectedSubject::SanDns("client.example.org".into()));
    let e1 = mtls::authenticate(&c, true, None, &body("someone-else"), &reg, Some(NOW)).unwrap_err();
    let e2 = mtls::authenticate(&cert("nosan"), true, None, &body("c1"), &reg, Some(NOW)).unwrap_err();
    assert_eq!(e1.code, ErrorCode::InvalidClient);
    assert_eq!(e1, e2, "wrong id and wrong certificate are indistinguishable");
    assert!(mtls::authenticate(&c, true, None, &Params::default(), &reg, Some(NOW)).is_err(), "client_id missing");
    assert!(mtls::authenticate(&c, true, None, &Params::parse("client_id=c1&client_id=c1").unwrap_or_default(), &reg, Some(NOW)).is_err());
}

#[test]
fn mtls_cannot_be_combined_with_another_client_authentication() {
    let c = cert("ec256");
    let reg = pki(ExpectedSubject::SanDns("client.example.org".into()));
    assert_eq!(mtls::authenticate(&c, true, Some("Basic YzE6eA=="), &body("c1"), &reg, Some(NOW)).unwrap_err().code, ErrorCode::InvalidRequest);
    for extra in ["client_secret", "client_assertion", "client_assertion_type"] {
        let p = Params::from_pairs([("client_id", "c1"), (extra, "x")]).unwrap();
        assert_eq!(mtls::authenticate(&c, true, None, &p, &reg, Some(NOW)).unwrap_err().code, ErrorCode::InvalidRequest, "{extra}");
    }
}

#[test]
fn self_signed_authentication_uses_key_equality_not_the_chain() {
    let c = cert("ec256");
    let right = c.public_jwk().unwrap();
    let other = cert("ec384").public_jwk().unwrap();
    let reg = |keys: Vec<Jwk>| Registration::SelfSigned { client_id: "c1".into(), keys };
    // chain_verified = false is fine here: self-signed certificates have no trusted chain.
    assert!(mtls::authenticate(&c, false, None, &body("c1"), &reg(vec![right.clone()]), Some(NOW)).is_ok());
    assert!(mtls::authenticate(&c, false, None, &body("c1"), &reg(vec![other.clone(), right.clone()]), Some(NOW)).is_ok(), "key rotation: several keys");
    assert!(mtls::authenticate(&c, false, None, &body("c1"), &reg(vec![other]), Some(NOW)).is_err(), "different key");
    assert!(mtls::authenticate(&c, false, None, &body("c1"), &reg(vec![]), Some(NOW)).is_err(), "no registered key never authenticates");
    // A private registered key still compares by its public part.
    assert!(mtls::authenticate(&cert("expired"), false, None, &body("c1"), &reg(vec![cert("expired").public_jwk().unwrap()]), Some(NOW)).is_err(), "expired still refused");
    assert_eq!(mtls::SELF_SIGNED_TLS_CLIENT_AUTH, reg(vec![]).method());
}

// ---------- certificate-bound access tokens ----------

#[test]
fn bound_token_must_match_the_connection_certificate() {
    let c = cert("ec256");
    let token = Claims::new().set("cnf", mtls::cnf_for(&c).unwrap());
    assert!(mtls::check_binding(&token, &c).is_ok());
    assert_eq!(mtls::check_binding(&token, &cert("ec384")).unwrap_err().code, ErrorCode::InvalidToken, "stolen token on another certificate");
    assert!(mtls::check_binding(&Claims::new(), &c).is_err(), "unbound token");
    assert!(mtls::check_binding(&Claims::new().set("cnf", json!({"jkt": "abc"})), &c).is_err(), "bound to a DPoP key, not a certificate");
    assert!(mtls::check_binding(&Claims::new().set("cnf", json!({"x5t#S256": 5})), &c).is_err());
    assert!(mtls::same_certificate(&c.x5t_s256().unwrap(), &c));
    assert!(!mtls::same_certificate(&c.x5t_s256().unwrap(), &cert("rsa2048")));
    // The thumbprint is the SHA-256 of the DER, matching an independent computation.
    let der = STANDARD.decode(vectors()["ec256"]["der"].as_str().unwrap()).unwrap();
    assert_eq!(c.x5t_s256().unwrap(), authlas::b64::encode(authlas::crypto::digest(Hash::Sha256, &der).unwrap()));
}

// ---------- metadata ----------

#[test]
fn endpoint_aliases() {
    let mut m = AsMetadata::secure_defaults("https://as.example.com", "https://as.example.com");
    m.revocation_endpoint = Some("https://as.example.com/revoke".into());
    assert_eq!(mtls::endpoint(&m, "token_endpoint", false).unwrap(), "https://as.example.com/token");
    assert!(mtls::endpoint(&m, "token_endpoint", true).is_err(), "aliases required but absent: never fall back to the plain endpoint");
    mtls::advertise(&mut m, &[("token_endpoint", "https://mtls.as.example.com/token"), ("revocation_endpoint", "http://mtls.as.example.com/revoke")]);
    assert!(m.tls_client_certificate_bound_access_tokens);
    for method in ["tls_client_auth", "self_signed_tls_client_auth"] { assert!(m.token_endpoint_auth_methods_supported.iter().any(|x| x == method)); }
    assert_eq!(mtls::endpoint(&m, "token_endpoint", true).unwrap(), "https://mtls.as.example.com/token");
    assert!(mtls::endpoint(&m, "revocation_endpoint", true).is_err(), "alias must use https");
    assert!(mtls::endpoint(&m, "userinfo_endpoint", true).is_err(), "alias not listed");
    assert!(mtls::endpoint(&m, "bogus", false).is_err());
    // Survives a JSON round trip.
    let back = AsMetadata::parse(&m.to_json(), "https://as.example.com").unwrap();
    assert_eq!(mtls::endpoint(&back, "token_endpoint", true).unwrap(), "https://mtls.as.example.com/token");
}
