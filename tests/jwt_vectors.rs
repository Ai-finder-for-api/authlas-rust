use authlas::jwa::Algorithm::{self, *};
use authlas::jwe::{self, Enc, KeyAlg};
use authlas::jwk::Jwk;
use authlas::jwt::{self, Claims, MemoryReplayCache, Validation};
use authlas::{b64, Error};
use serde_json::{json, Map, Value};

const ISS: &str = "https://as.example";
const AUD: &str = "https://rs.example";
const NOW: u64 = 1_700_000_000;
const ALGS: &[Algorithm] = &[HS256];

fn hs_key() -> Jwk {
    Jwk::parse(&json!({"kty": "oct", "kid": "k1", "k": b64::encode([0x42u8; 32])}).to_string()).unwrap()
}

fn good_claims() -> Claims {
    Claims::new().issuer(ISS).subject("alice").audience(&[AUD]).issued_at(NOW - 10).expires_at(NOW + 600).jti("id-1")
}

fn val() -> Validation<'static> {
    let mut v = Validation::new(ALGS, ISS, AUD);
    v.now = Some(NOW);
    v
}

fn claim_err(c: Claims, v: &Validation<'_>) -> String {
    let t = jwt::sign(HS256, &hs_key(), &c, None).unwrap();
    match jwt::verify(&t, &hs_key(), v) {
        Err(Error::Claim(m)) => m,
        other => panic!("expected a claim error, got {other:?}"),
    }
}

#[test]
fn valid_token_round_trips() {
    let t = jwt::sign(HS256, &hs_key(), &good_claims(), None).unwrap();
    let (h, c) = jwt::verify(&t, &hs_key(), &val()).unwrap();
    assert_eq!(h.typ.as_deref(), Some("JWT"));
    assert_eq!(h.kid.as_deref(), Some("k1"));
    assert_eq!(c.str_claim("sub").unwrap(), Some("alice"));
}

#[test]
fn rfc7515_a1_token_is_checked_against_its_real_claims() {
    // RFC 7515 A.1 payload: {"iss":"joe","exp":1300819380,...}. No aud, so the audience check must refuse it.
    let v: Value = serde_json::from_str(include_str!("vectors/rfc7515.json")).unwrap();
    let k = Jwk::parse(&v["hs256"]["jwk"].to_string()).unwrap();
    let t = v["hs256"]["jws"].as_str().unwrap();
    let mut val = Validation::new(ALGS, "joe", AUD);
    val.now = Some(1_300_819_000);
    assert_eq!(match jwt::verify(t, &k, &val) { Err(Error::Claim(m)) => m, o => panic!("{o:?}") }, "aud is missing");
    let c = jwt::peek_claims_unverified(t).unwrap();
    assert_eq!(c.date("exp").unwrap(), Some(1_300_819_380));
    assert_eq!(c.str_claim("iss").unwrap(), Some("joe"));
    // Direct claim check shows exp is enforced at the RFC's value.
    let mut with_aud = c.clone();
    with_aud = with_aud.audience(&[AUD]);
    val.now = Some(1_300_819_380 + 31);
    assert_eq!(val.check(&with_aud).unwrap_err(), Error::Claim("token has expired".into()));
    val.now = Some(1_300_819_380 - 1);
    val.check(&with_aud).unwrap();
}

#[test]
fn exp_boundary_is_exclusive_and_leeway_applies() {
    let mut v = val();
    v.leeway = 0;
    let c = good_claims().expires_at(NOW);
    assert_eq!(v.check(&c).unwrap_err(), Error::Claim("token has expired".into()), "now == exp is expired");
    v.now = Some(NOW - 1);
    v.check(&c).unwrap();
    v.leeway = 5;
    v.now = Some(NOW + 4);
    v.check(&c).unwrap();
    v.now = Some(NOW + 5);
    assert!(v.check(&c).is_err());
}

#[test]
fn leeway_is_capped() {
    let mut v = val();
    v.leeway = u64::MAX;
    let c = good_claims().expires_at(NOW - 301);
    assert!(v.check(&c).is_err(), "a huge leeway must not turn expiry off");
}

#[test]
fn nbf_and_iat_in_the_future_are_rejected() {
    let mut v = val();
    v.leeway = 0;
    assert_eq!(claim_err(good_claims().not_before(NOW + 60), &v), "token is not valid yet");
    assert_eq!(claim_err(good_claims().issued_at(NOW + 60), &v), "iat is in the future");
    v.leeway = 30;
    v.check(&good_claims().not_before(NOW + 20)).unwrap();
}

#[test]
fn issuer_audience_and_exp_are_mandatory() {
    let v = val();
    assert_eq!(claim_err(Claims::new().audience(&[AUD]).expires_at(NOW + 5), &v), "iss is missing");
    assert_eq!(claim_err(good_claims().issuer("https://evil.example"), &v), "iss does not match");
    assert_eq!(claim_err(Claims::new().issuer(ISS).expires_at(NOW + 5), &v), "aud is missing");
    assert_eq!(claim_err(good_claims().audience(&["https://other.example"]), &v), "aud does not include this recipient");
    let mut no_exp = good_claims();
    no_exp.map.remove("exp");
    assert_eq!(claim_err(no_exp, &v), "exp is missing");
}

#[test]
fn issuer_must_match_exactly() {
    let v = val();
    for bad in ["https://as.example/", "HTTPS://AS.EXAMPLE", "https://as.example ", "https://as.example.evil"] {
        assert_eq!(claim_err(good_claims().issuer(bad), &v), "iss does not match", "{bad:?}");
    }
}

#[test]
fn audience_array_and_substring_rules() {
    let v = val();
    let ok = good_claims().audience(&["a", AUD, "b"]);
    v.check(&ok).unwrap();
    // A prefix or superstring of the audience is not the audience.
    assert!(v.check(&good_claims().audience(&["https://rs.example/api"])).is_err());
    assert!(v.check(&good_claims().audience(&["https://rs.exampl"])).is_err());
    assert!(v.check(&good_claims().audience(&[])).is_err());
}

#[test]
fn claims_of_the_wrong_type_are_errors_not_ignored() {
    let v = val();
    assert!(v.check(&good_claims().set("aud", 5)).is_err());
    assert!(v.check(&good_claims().set("aud", json!(["ok", 5]))).is_err());
    assert!(v.check(&good_claims().set("iss", json!(["x"]))).is_err());
    assert!(v.check(&good_claims().set("exp", "soon")).is_err());
    assert!(v.check(&good_claims().set("nbf", "yesterday")).is_err());
    assert!(v.check(&good_claims().set("sub", 7)).is_err());
}

#[test]
fn numeric_dates_are_range_checked() {
    let v = val();
    assert!(v.check(&good_claims().set("exp", -1)).is_err());
    assert!(v.check(&good_claims().set("exp", 1e300)).is_err());
    // Fractions are legal and floored.
    v.check(&good_claims().set("exp", (NOW + 600) as f64 + 0.9)).unwrap();
}

#[test]
fn max_age_and_required_claims() {
    let mut v = val();
    v.max_age = Some(60);
    v.leeway = 0;
    v.check(&good_claims()).unwrap();
    assert_eq!(claim_err(good_claims().issued_at(NOW - 61), &v), "token is older than max_age");
    let mut no_iat = good_claims();
    no_iat.map.remove("iat");
    assert_eq!(claim_err(no_iat, &v), "iat is required when max_age is set");
    let mut v = val();
    v.require = &["sub", "scope"];
    assert_eq!(claim_err(good_claims(), &v), "scope is missing");
    v.check(&good_claims().set("scope", "read")).unwrap();
}

#[test]
fn replayed_jti_is_rejected_once_and_expires() {
    let cache = MemoryReplayCache::new();
    let mut v = val();
    v.replay = Some(&cache);
    v.check(&good_claims()).unwrap();
    assert_eq!(v.check(&good_claims()).unwrap_err(), Error::Claim("token was already used".into()));
    v.check(&good_claims().jti("id-2")).unwrap();
    assert_eq!(cache.len(), 2);
    // After exp + leeway the entry is dropped.
    v.now = Some(NOW + 10_000);
    v.check(&good_claims().expires_at(NOW + 20_000).jti("id-3")).unwrap();
    assert_eq!(cache.len(), 1);
    // A token without jti cannot be replay-checked, so it is refused.
    let mut none = good_claims();
    none.map.remove("jti");
    assert!(v.check(&none).is_err());
}

#[test]
fn same_jti_from_another_issuer_is_not_a_replay() {
    let cache = MemoryReplayCache::new();
    let mut a = val();
    a.replay = Some(&cache);
    a.check(&good_claims()).unwrap();
    let mut b = Validation::new(ALGS, "https://other-as.example", AUD);
    b.now = Some(NOW);
    b.replay = Some(&cache);
    b.check(&good_claims().issuer("https://other-as.example")).unwrap();
}

#[test]
fn failed_validation_does_not_burn_the_jti() {
    let cache = MemoryReplayCache::new();
    let mut v = val();
    v.replay = Some(&cache);
    assert!(v.check(&good_claims().issuer("https://evil.example")).is_err());
    assert!(cache.is_empty(), "a rejected token must not poison the cache");
    v.check(&good_claims()).unwrap();
}

#[test]
fn typ_is_enforced_for_cross_token_confusion() {
    let t = jwt::sign(HS256, &hs_key(), &good_claims(), Some("at+jwt")).unwrap();
    let mut v = val();
    v.typ = Some("at+jwt");
    jwt::verify(&t, &hs_key(), &v).unwrap();
    v.typ = Some("JWT");
    assert!(jwt::verify(&t, &hs_key(), &v).is_err());
    let plain = jwt::sign(HS256, &hs_key(), &good_claims(), None).unwrap();
    v.typ = Some("at+jwt");
    assert!(jwt::verify(&plain, &hs_key(), &v).is_err());
}

#[test]
fn algorithm_allow_list_and_wrong_key_are_enforced() {
    let t = jwt::sign(HS256, &hs_key(), &good_claims(), None).unwrap();
    let mut v = val();
    v.algs = &[HS384];
    assert!(matches!(jwt::verify(&t, &hs_key(), &v), Err(Error::Algorithm(_))));
    let other = Jwk::parse(&json!({"kty": "oct", "k": b64::encode([0x43u8; 32])}).to_string()).unwrap();
    assert_eq!(jwt::verify(&t, &other, &val()).unwrap_err(), Error::BadSignature);
}

#[test]
fn signature_is_checked_before_claims_are_trusted() {
    // Forge: valid-looking claims with a bad signature must be BadSignature, not a claim error or success.
    let t = jwt::sign(HS256, &hs_key(), &good_claims(), None).unwrap();
    let p: Vec<&str> = t.split('.').collect();
    let evil = Claims::new().issuer(ISS).audience(&[AUD]).expires_at(NOW + 99999).subject("admin");
    let forged = format!("{}.{}.{}", p[0], b64::encode(evil.to_bytes()), p[2]);
    assert_eq!(jwt::verify(&forged, &hs_key(), &val()).unwrap_err(), Error::BadSignature);
}

#[test]
fn payload_that_is_not_an_object_is_refused() {
    let t = authlas::jws::sign(HS256, &hs_key(), &Map::new(), b"[1,2]").unwrap();
    assert!(matches!(jwt::verify(&t, &hs_key(), &val()), Err(Error::Claim(_))));
    let t = authlas::jws::sign(HS256, &hs_key(), &Map::new(), br#"{"iss":"a","iss":"b"}"#).unwrap();
    assert!(matches!(jwt::verify(&t, &hs_key(), &val()), Err(Error::Claim(_))), "duplicate claim names");
}

#[test]
fn header_key_pointers_are_never_followed() {
    // RFC 8725 3.? : jku/jwk/x5u/x5c in the header must not influence which key verifies.
    let k = hs_key();
    let mut h = Map::new();
    h.insert("jku".into(), json!("https://evil.example/keys"));
    h.insert("jwk".into(), json!({"kty": "oct", "k": b64::encode([1u8; 32])}));
    let t = authlas::jws::sign(HS256, &k, &h, &good_claims().to_bytes()).unwrap();
    jwt::verify(&t, &k, &val()).unwrap();
    let evil = Jwk::parse(&json!({"kty": "oct", "k": b64::encode([1u8; 32])}).to_string()).unwrap();
    assert_eq!(jwt::verify(&t, &evil, &val()).unwrap_err(), Error::BadSignature);
}

#[test]
fn cnf_jkt_binds_to_a_key() {
    let dpop = Jwk::parse(&json!({"kty": "EC", "crv": "P-256",
        "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs", "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}).to_string()).unwrap();
    let c = good_claims().confirm_jkt(&dpop).unwrap();
    let cnf = c.cnf().unwrap().unwrap();
    assert!(cnf.matches_key(&dpop).unwrap());
    let other = Jwk::parse(&json!({"kty": "oct", "k": "AAAA"}).to_string()).unwrap();
    assert!(!cnf.matches_key(&other).unwrap());
    // The public form of a private key has the same thumbprint.
    assert!(cnf.matches_key(&dpop.public().unwrap()).unwrap());
}

#[test]
fn cnf_jwk_must_be_public_and_x5t_matches() {
    let sk = match authlas::crypto::ec_generate("P-256") {
        Ok(k) => k,
        Err(Error::Unsupported(m)) => { eprintln!("SKIP: {m}"); return; }
        Err(e) => panic!("{e}"),
    };
    assert!(good_claims().confirm_jwk(&sk).is_err());
    let c = good_claims().confirm_jwk(&sk.public().unwrap()).unwrap();
    assert!(c.cnf().unwrap().unwrap().matches_key(&sk).unwrap());
    // A private key smuggled into cnf by someone else is rejected on read.
    let leaked = good_claims().set("cnf", json!({"jwk": serde_json::to_value(&sk).unwrap()}));
    assert!(leaked.cnf().is_err());
    let x = good_claims().confirm_x5t_s256("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2");
    let cnf = x.cnf().unwrap().unwrap();
    assert!(cnf.matches_x5t_s256("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"));
    assert!(!cnf.matches_x5t_s256("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg3"));
    assert!(good_claims().set("cnf", json!({})).cnf().is_err());
    assert!(good_claims().set("cnf", "x").cnf().is_err());
    assert!(good_claims().cnf().unwrap().is_none());
}

#[test]
fn nested_jwt_sign_then_encrypt() {
    let enc_key = Jwk::parse(&json!({"kty": "oct", "k": b64::encode([9u8; 32])}).to_string()).unwrap();
    let inner = jwt::sign(HS256, &hs_key(), &good_claims(), None).unwrap();
    let outer = jwt::encrypt_nested(&inner, KeyAlg::Dir, Enc::A256Gcm, &enc_key).unwrap();
    let pol = jwe::Policy::new(&[KeyAlg::Dir], &[Enc::A256Gcm]);
    let (_, c) = jwt::decrypt_nested(&outer, &enc_key, &pol, &hs_key(), &val()).unwrap();
    assert_eq!(c.str_claim("sub").unwrap(), Some("alice"));
    // Inner claims are still validated.
    let mut v = val();
    v.audience = "someone-else";
    assert!(matches!(jwt::decrypt_nested(&outer, &enc_key, &pol, &hs_key(), &v), Err(Error::Claim(_))));
    // A JWE without cty=JWT is not treated as a nested JWT.
    let no_cty = jwe::encrypt(KeyAlg::Dir, Enc::A256Gcm, &enc_key, &Map::new(), inner.as_bytes()).unwrap();
    assert!(matches!(jwt::decrypt_nested(&no_cty, &enc_key, &pol, &hs_key(), &val()), Err(Error::Malformed(_))));
}

#[test]
fn peek_requires_a_three_part_token() {
    assert!(jwt::peek_claims_unverified("a.b").is_err());
    assert!(jwt::peek_claims_unverified("a.b.c.d").is_err());
}
