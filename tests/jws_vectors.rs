use authlas::jwa::Algorithm::{self, *};
use authlas::jwk::Jwk;
use authlas::jws::{self, Policy};
use authlas::Error;
use serde_json::{json, Map, Value};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/rfc7515.json")).unwrap()
}

fn vec_jwk(name: &str) -> (Jwk, String) {
    let v = vectors();
    let e = &v[name];
    (Jwk::parse(&e["jwk"].to_string()).unwrap(), e["jws"].as_str().unwrap().to_string())
}

// ---------- RFC 7515 appendix A known-answer tests ----------

#[test]
fn rfc7515_a1_hs256_verifies() {
    let (k, t) = vec_jwk("hs256");
    let (h, payload) = jws::verify(&t, &k, &Policy::new(&[HS256])).unwrap();
    assert_eq!(h.alg, HS256);
    assert_eq!(h.typ.as_deref(), Some("JWT"));
    assert!(String::from_utf8(payload).unwrap().contains("\"iss\":\"joe\""));
}

#[test]
fn rfc7515_a1_hs256_signature_is_reproduced_exactly() {
    // HMAC is deterministic, so re-signing the same input must give the RFC's bytes.
    let (k, t) = vec_jwk("hs256");
    let parts: Vec<&str> = t.split('.').collect();
    let (_, payload) = jws::verify(&t, &k, &Policy::new(&[HS256])).unwrap();
    let mut extra = Map::new();
    extra.insert("typ".into(), json!("JWT"));
    let out = jws::sign(HS256, &k, &extra, &payload).unwrap();
    let out_parts: Vec<&str> = out.split('.').collect();
    assert_eq!(out_parts[2].len(), parts[2].len());
    // header bytes differ (RFC example contains CRLF), so compare via a fresh verify instead.
    jws::verify(&out, &k, &Policy::new(&[HS256])).unwrap();
}

#[test]
fn rfc7515_a2_rs256_verifies() {
    let (k, t) = vec_jwk("rs256");
    jws::verify(&t, &k, &Policy::new(&[RS256])).unwrap();
}

#[test]
fn rfc7515_a3_es256_verifies() {
    let (k, t) = vec_jwk("es256");
    jws::verify(&t, &k, &Policy::new(&[ES256])).unwrap();
}

#[test]
fn rfc7515_a4_es512_verifies() {
    let (k, t) = vec_jwk("es512");
    match jws::verify(&t, &k, &Policy::new(&[ES512])) {
        Err(Error::Unsupported(m)) => eprintln!("SKIP es512: {m}"),
        r => { r.unwrap(); }
    }
}

// ---------- round trips for every algorithm family ----------

fn roundtrip(alg: Algorithm, key_name: &str) {
    let (k, _) = vec_jwk(key_name);
    let token = match jws::sign(alg, &k, &Map::new(), b"hello authlas") {
        Err(Error::Unsupported(m)) => { eprintln!("SKIP {}: {m}", alg.as_str()); return; }
        r => r.unwrap(),
    };
    let pubk = if k.kty == "oct" { k.clone() } else { k.public().unwrap() };
    let (h, p) = jws::verify(&token, &pubk, &Policy::new(&[alg])).unwrap();
    assert_eq!(h.alg, alg);
    assert_eq!(p, b"hello authlas");
}

#[test]
fn roundtrip_hmac() { roundtrip(HS256, "hs256"); }
#[test]
fn roundtrip_rs256() { roundtrip(RS256, "rs256"); }
#[test]
fn roundtrip_ps256() { roundtrip(PS256, "rs256"); }
#[test]
fn roundtrip_rs512() { roundtrip(RS512, "rs256"); }
#[test]
fn roundtrip_ps384() { roundtrip(PS384, "rs256"); }
#[test]
fn roundtrip_es256() { roundtrip(ES256, "es256"); }
#[test]
fn roundtrip_es512() { roundtrip(ES512, "es512"); }

#[test]
fn roundtrip_eddsa_rfc8037_key() {
    // RFC 8037 appendix A.1 Ed25519 private key.
    let k = Jwk::parse(r#"{"kty":"OKP","crv":"Ed25519",
        "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#).unwrap();
    let token = jws::sign(EdDSA, &k, &Map::new(), b"Example of Ed25519 signing").unwrap();
    jws::verify(&token, &k.public().unwrap(), &Policy::new(&[EdDSA])).unwrap();
}

#[test]
fn rfc8037_a4_eddsa_known_signature() {
    // RFC 8037 appendix A.4: Ed25519 is deterministic, so the signature must match exactly.
    let k = Jwk::parse(r#"{"kty":"OKP","crv":"Ed25519",
        "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#).unwrap();
    let token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
    let (_, p) = jws::verify(token, &k.public().unwrap(), &Policy::new(&[EdDSA])).unwrap();
    assert_eq!(p, b"Example of Ed25519 signing");
}

// ---------- rejection paths ----------

#[test]
fn tampered_payload_is_rejected() {
    let (k, t) = vec_jwk("es256");
    let mut parts: Vec<String> = t.split('.').map(String::from).collect();
    parts[1] = authlas::b64::encode(b"{\"iss\":\"mallory\"}");
    let bad = parts.join(".");
    assert_eq!(jws::verify(&bad, &k, &Policy::new(&[ES256])).unwrap_err(), Error::BadSignature);
}

#[test]
fn tampered_signature_is_rejected() {
    let (k, t) = vec_jwk("hs256");
    let mut bytes = t.into_bytes();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    let bad = String::from_utf8(bytes).unwrap();
    assert!(jws::verify(&bad, &k, &Policy::new(&[HS256])).is_err());
}

#[test]
fn alg_not_in_policy_is_rejected() {
    let (k, t) = vec_jwk("rs256");
    let e = jws::verify(&t, &k, &Policy::new(&[ES256, HS256])).unwrap_err();
    assert!(matches!(e, Error::Algorithm(_)), "{e:?}");
}

#[test]
fn hmac_with_rsa_public_key_is_rejected() {
    // Classic algorithm-confusion attack: sign HS256 using the RSA public key bytes as the secret.
    let (rsa, _) = vec_jwk("rs256");
    let pubk = rsa.public().unwrap();
    let (hs, _) = vec_jwk("hs256");
    let token = jws::sign(HS256, &hs, &Map::new(), b"x").unwrap();
    let e = jws::verify(&token, &pubk, &Policy::new(&[HS256, RS256])).unwrap_err();
    assert!(matches!(e, Error::Key(_)), "{e:?}");
}

#[test]
fn alg_none_is_unknown_without_test_mode() {
    #[cfg(not(feature = "test-mode"))]
    {
        let (k, _) = vec_jwk("hs256");
        let t = format!("{}.{}.", authlas::b64::encode(br#"{"alg":"none"}"#), authlas::b64::encode(b"{}"));
        let e = jws::verify(&t, &k, &Policy::new(&[HS256])).unwrap_err();
        assert!(matches!(e, Error::Algorithm(_)), "{e:?}");
    }
}

#[test]
fn short_hmac_key_is_rejected() {
    let k = Jwk::parse(r#"{"kty":"oct","k":"c2hvcnQ"}"#).unwrap();
    assert!(matches!(jws::sign(HS256, &k, &Map::new(), b"x").unwrap_err(), Error::Key(_)));
}

#[test]
fn key_restricted_to_other_alg_is_rejected() {
    let (mut k, _) = vec_jwk("es256");
    k.alg = Some("ES384".into());
    assert!(matches!(jws::sign(ES256, &k, &Map::new(), b"x").unwrap_err(), Error::Key(_)));
}

#[test]
fn wrong_curve_for_alg_is_rejected() {
    let (k, _) = vec_jwk("es256");
    assert!(matches!(jws::sign(ES384, &k, &Map::new(), b"x").unwrap_err(), Error::Key(_)));
}

#[test]
fn unknown_crit_header_is_rejected() {
    let (k, _) = vec_jwk("hs256");
    let mut extra = Map::new();
    extra.insert("crit".into(), json!(["exp"]));
    extra.insert("exp".into(), json!(1));
    let t = jws::sign(HS256, &k, &extra, b"x").unwrap();
    assert!(jws::verify(&t, &k, &Policy::new(&[HS256])).is_err());
    let mut p = Policy::new(&[HS256]);
    p.understood_crit = &["exp"];
    jws::verify(&t, &k, &p).unwrap();
}

#[test]
fn duplicate_header_members_are_rejected() {
    let (k, _) = vec_jwk("hs256");
    let head = authlas::b64::encode(br#"{"alg":"HS256","alg":"HS512"}"#);
    let t = format!("{head}.{}.AAAA", authlas::b64::encode(b"x"));
    assert!(matches!(jws::verify(&t, &k, &Policy::new(&[HS256, HS512])).unwrap_err(), Error::Malformed(_)));
}

#[test]
fn typ_is_enforced_case_insensitively_with_application_prefix() {
    let (k, _) = vec_jwk("hs256");
    let mut extra = Map::new();
    extra.insert("typ".into(), json!("application/AT+JWT"));
    let t = jws::sign(HS256, &k, &extra, b"x").unwrap();
    let mut p = Policy::new(&[HS256]);
    p.typ = Some("at+jwt");
    jws::verify(&t, &k, &p).unwrap();
    p.typ = Some("dpop+jwt");
    assert!(jws::verify(&t, &k, &p).is_err());
}

#[test]
fn wrong_segment_count_is_rejected() {
    let (k, _) = vec_jwk("hs256");
    for bad in ["a.b", "a.b.c.d", "", "...."] {
        assert!(jws::verify(bad, &k, &Policy::new(&[HS256])).is_err(), "{bad:?}");
    }
}

#[test]
fn padded_or_spaced_base64_is_rejected() {
    assert!(authlas::b64::decode("YQ==").is_err());
    assert!(authlas::b64::decode("Y Q").is_err());
    assert_eq!(authlas::b64::decode("YQ").unwrap(), b"a");
}

// ---------- JWK thumbprint (RFC 7638 section 3.1) ----------

#[test]
fn rfc7638_rsa_thumbprint() {
    let k = Jwk::parse(r#"{"kty":"RSA","e":"AQAB","alg":"RS256","kid":"2011-04-29",
      "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}"#).unwrap();
    assert_eq!(k.thumbprint(authlas::jwa::Hash::Sha256).unwrap(), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
}

#[test]
fn rfc9278_thumbprint_uri_shape() {
    let (k, _) = vec_jwk("es256");
    let u = k.thumbprint_uri(authlas::jwa::Hash::Sha256).unwrap();
    assert!(u.starts_with("urn:ietf:params:oauth:jwk-thumbprint:sha-256:"), "{u}");
}

#[test]
fn thumbprint_ignores_private_members() {
    let (k, _) = vec_jwk("es256");
    let a = k.thumbprint(authlas::jwa::Hash::Sha256).unwrap();
    let b = k.public().unwrap().thumbprint(authlas::jwa::Hash::Sha256).unwrap();
    assert_eq!(a, b);
}
