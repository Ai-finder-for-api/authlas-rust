use authlas::jwa::Algorithm::*;
use authlas::jwk::Jwk;
use authlas::jws;
use authlas::jwt::{Claims, MemoryReplayCache};
use authlas::oauth::dpop::{self, Expect, NonceSource, ProofBuilder};
use authlas::oauth::error::ErrorCode;
use authlas::{b64, crypto, Error};
use serde_json::{json, Map, Value};

fn vector() -> Value { serde_json::from_str(include_str!("vectors/rfc9449.json")).unwrap() }

fn expect<'a>(method: &'a str, url: &'a str) -> Expect<'a> {
    Expect { algs: &[ES256, EdDSA, RS256, PS256], method, url, access_token: None, nonce: None, now: None, leeway: 0, replay: None }
}

/// A key pair for tests. The qscrypt backend cannot generate EC keys, so use Ed25519 material built by hand there.
fn key_pair() -> Option<(Jwk, authlas::jwa::Algorithm)> {
    match crypto::ec_generate("P-256") {
        Ok(k) => Some((k, ES256)),
        Err(Error::Unsupported(m)) => { eprintln!("SKIP: {m}"); None }
        Err(e) => panic!("{e}"),
    }
}

fn code(e: authlas::oauth::OAuthError) -> ErrorCode { e.code }

#[test]
fn rfc9449_section_7_proof_verifies() {
    let v = vector();
    let proof = v["proof"].as_str().unwrap();
    let tok = v["access_token"].as_str().unwrap();
    let mut e = expect("GET", "https://resource.example.org/protectedresource");
    e.now = Some(1562262618 + 5);
    e.access_token = Some(tok);
    let ok = dpop::verify_proof(proof, &e).expect("the RFC's own example must verify");
    assert_eq!(ok.jkt, v["jkt"].as_str().unwrap());
    assert_eq!(ok.claims.str_claim("jti").unwrap(), Some("e1j3V_bKic8-LAEB"));
    assert_eq!(dpop::access_token_hash(tok).unwrap(), "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
}

#[test]
fn rfc9449_proof_is_rejected_when_anything_differs() {
    let v = vector();
    let proof = v["proof"].as_str().unwrap();
    let tok = v["access_token"].as_str().unwrap();
    let base = |f: &dyn Fn(&mut Expect)| {
        let mut e = expect("GET", "https://resource.example.org/protectedresource");
        e.now = Some(1562262618 + 5);
        e.access_token = Some(tok);
        f(&mut e);
        dpop::verify_proof(proof, &e)
    };
    assert_eq!(code(base(&|e| e.method = "POST").unwrap_err()), ErrorCode::InvalidDpopProof);
    assert!(base(&|e| e.url = "https://resource.example.org/other").is_err());
    assert!(base(&|e| e.url = "https://evil.example.org/protectedresource").is_err());
    assert!(base(&|e| e.access_token = Some("a-different-token")).is_err(), "ath must bind the token");
    assert!(base(&|e| e.access_token = None).is_ok(), "no token expected at the token endpoint");
    assert!(base(&|e| e.now = Some(1562262618 + 301)).is_err(), "too old");
    assert!(base(&|e| e.now = Some(1562262618 - 120)).is_err(), "from the future");
    assert!(base(&|e| e.algs = &[EdDSA]).is_err(), "algorithm not accepted by the server");
    assert_eq!(code(base(&|e| e.nonce = Some("n-123")).unwrap_err()), ErrorCode::UseDpopNonce);
}

#[test]
fn htu_ignores_query_and_fragment_and_default_port() {
    assert_eq!(dpop::normalize_htu("HTTPS://Resource.Example.org:443/p?x=1#f").unwrap(), "https://resource.example.org/p");
    assert_eq!(dpop::normalize_htu("https://r.example/p/").unwrap(), "https://r.example/p/");
    assert_ne!(dpop::normalize_htu("https://r.example/p").unwrap(), dpop::normalize_htu("https://r.example/p/").unwrap());
    assert!(dpop::normalize_htu("ftp://r.example/p").is_none());
    assert!(dpop::normalize_htu("not a url").is_none());
}

#[test]
fn built_proofs_round_trip_and_carry_the_expected_members() {
    let Some((k, alg)) = key_pair() else { return };
    let tok = "access-token-xyz";
    let proof = ProofBuilder { alg, key: &k, method: "post", url: "https://rs.example/api?q=1", access_token: Some(tok), nonce: Some("srv-nonce") }.build().unwrap();
    let h = jws::peek_header(&proof).unwrap();
    assert_eq!(h.typ.as_deref(), Some("dpop+jwt"));
    let jwk = h.raw.get("jwk").unwrap();
    assert!(jwk.get("d").is_none(), "the private key must never be in the header");
    let mut e = expect("POST", "https://rs.example/api");
    e.access_token = Some(tok);
    e.nonce = Some("srv-nonce");
    let v = dpop::verify_proof(&proof, &e).unwrap();
    assert_eq!(v.jkt, k.public().unwrap().thumbprint(authlas::jwa::Hash::Sha256).unwrap());
    // Wrong nonce -> use_dpop_nonce so the client can retry.
    e.nonce = Some("other");
    assert_eq!(code(dpop::verify_proof(&proof, &e).unwrap_err()), ErrorCode::UseDpopNonce);
}

#[test]
fn builder_refuses_unsafe_inputs() {
    let hs = Jwk::parse(&json!({"kty": "oct", "k": b64::encode([1u8; 32])}).to_string()).unwrap();
    assert!(ProofBuilder { alg: HS256, key: &hs, method: "GET", url: "https://a.example/", access_token: None, nonce: None }.build().is_err());
    let Some((k, alg)) = key_pair() else { return };
    assert!(ProofBuilder { alg, key: &k.public().unwrap(), method: "GET", url: "https://a.example/", access_token: None, nonce: None }.build().is_err(), "public key cannot sign");
    assert!(ProofBuilder { alg, key: &k, method: "GET", url: "ftp://a.example/", access_token: None, nonce: None }.build().is_err());
}

/// Signs a hand-made proof so each header/claim defect can be tested alone.
fn forge(k: &Jwk, alg: authlas::jwa::Algorithm, edit_h: impl FnOnce(&mut Map<String, Value>), edit_c: impl FnOnce(&mut Claims)) -> String {
    let mut c = Claims::new().jti("j1").set("htm", "GET").set("htu", "https://rs.example/api").issued_at(authlas::jwt::unix_now());
    edit_c(&mut c);
    let mut h = Map::new();
    h.insert("typ".into(), json!("dpop+jwt"));
    h.insert("jwk".into(), serde_json::from_str(&k.public().unwrap().to_json()).unwrap());
    edit_h(&mut h);
    jws::sign(alg, k, &h, &c.to_bytes()).unwrap()
}

#[test]
fn each_defect_is_rejected() {
    let Some((k, alg)) = key_pair() else { return };
    let e = expect("GET", "https://rs.example/api");
    dpop::verify_proof(&forge(&k, alg, |_| {}, |_| {}), &e).expect("baseline");
    let cases: Vec<(&str, String)> = vec![
        ("wrong typ", forge(&k, alg, |h| { h.insert("typ".into(), json!("JWT")); }, |_| {})),
        ("no typ", forge(&k, alg, |h| { h.remove("typ"); }, |_| {})),
        ("no jwk", forge(&k, alg, |h| { h.remove("jwk"); }, |_| {})),
        ("jku", forge(&k, alg, |h| { h.insert("jku".into(), json!("https://evil/keys")); }, |_| {})),
        ("x5c", forge(&k, alg, |h| { h.insert("x5c".into(), json!(["AAAA"])); }, |_| {})),
        ("private jwk in header", forge(&k, alg, |h| { h.insert("jwk".into(), serde_json::from_str(&k.to_json()).unwrap()); }, |_| {})),
        ("jwk is a different key", {
            let other = crypto::ec_generate("P-256").unwrap();
            forge(&k, alg, |h| { h.insert("jwk".into(), serde_json::from_str(&other.public().unwrap().to_json()).unwrap()); }, |_| {})
        }),
        ("no jti", forge(&k, alg, |_| {}, |c| { c.map.remove("jti"); })),
        ("no htm", forge(&k, alg, |_| {}, |c| { c.map.remove("htm"); })),
        ("no htu", forge(&k, alg, |_| {}, |c| { c.map.remove("htu"); })),
        ("no iat", forge(&k, alg, |_| {}, |c| { c.map.remove("iat"); })),
        ("htm lower case", forge(&k, alg, |_| {}, |c| { c.map.insert("htm".into(), json!("get")); })),
        ("htu typed wrong", forge(&k, alg, |_| {}, |c| { c.map.insert("htu".into(), json!(5)); })),
        ("iat as string", forge(&k, alg, |_| {}, |c| { c.map.insert("iat".into(), json!("now")); })),
    ];
    for (label, p) in cases {
        let r = dpop::verify_proof(&p, &e);
        assert!(matches!(&r, Err(x) if x.code == ErrorCode::InvalidDpopProof), "{label}: {r:?}");
    }
}

#[test]
fn symmetric_and_none_proofs_are_refused() {
    let hs = Jwk::parse(&json!({"kty": "oct", "k": b64::encode([1u8; 32])}).to_string()).unwrap();
    let mut h = Map::new();
    h.insert("typ".into(), json!("dpop+jwt"));
    h.insert("jwk".into(), json!({"kty": "oct", "k": b64::encode([1u8; 32])}));
    let c = Claims::new().jti("j").set("htm", "GET").set("htu", "https://rs.example/api").issued_at(authlas::jwt::unix_now());
    let p = jws::sign(HS256, &hs, &h, &c.to_bytes()).unwrap();
    let mut e = expect("GET", "https://rs.example/api");
    e.algs = &[HS256, ES256];
    assert!(dpop::verify_proof(&p, &e).is_err(), "HS256 proof with the secret in the header must fail even if the server list is careless");
    assert!(dpop::verify_proof("a.b", &e).is_err());
    assert!(dpop::verify_proof("", &e).is_err());
    assert!(dpop::verify_proof("e30.e30.", &e).is_err());
}

#[test]
fn proof_replay_is_detected_and_rejection_does_not_burn_the_jti() {
    let Some((k, alg)) = key_pair() else { return };
    let cache = MemoryReplayCache::new();
    let mut e = expect("GET", "https://rs.example/api");
    e.replay = Some(&cache);
    let p = forge(&k, alg, |_| {}, |_| {});
    dpop::verify_proof(&p, &e).unwrap();
    assert!(dpop::verify_proof(&p, &e).is_err(), "same proof twice");
    // A proof rejected for another reason must not poison the cache.
    let cache2 = MemoryReplayCache::new();
    let mut wrong = expect("POST", "https://rs.example/api");
    wrong.replay = Some(&cache2);
    assert!(dpop::verify_proof(&p, &wrong).is_err());
    assert!(cache2.is_empty());
    // Same jti from a different key is a different proof.
    let k2 = crypto::ec_generate("P-256").unwrap();
    dpop::verify_proof(&forge(&k2, ES256, |_| {}, |_| {}), &e).unwrap();
}

#[test]
fn token_binding_checks() {
    let Some((k, alg)) = key_pair() else { return };
    let proof = forge(&k, alg, |_| {}, |_| {});
    let v = dpop::verify_proof(&proof, &expect("GET", "https://rs.example/api")).unwrap();
    let bound = Claims::new().confirm_jkt(&k.public().unwrap()).unwrap();
    dpop::check_binding(&bound, &v).unwrap();
    let other = crypto::ec_generate("P-256").unwrap();
    let wrong = Claims::new().confirm_jkt(&other.public().unwrap()).unwrap();
    assert_eq!(code(dpop::check_binding(&wrong, &v).unwrap_err()), ErrorCode::InvalidToken);
    // A bearer token (no cnf) presented with DPoP is not bound, so it is refused.
    assert!(dpop::check_binding(&Claims::new(), &v).is_err());
    // cnf with only x5t#S256 is not a DPoP binding.
    assert!(dpop::check_binding(&Claims::new().confirm_x5t_s256("abc"), &v).is_err());
    dpop::check_dpop_jkt(&v.jkt, &v).unwrap();
    assert!(dpop::check_dpop_jkt("AAAA", &v).is_err());
}

#[test]
fn stateless_nonces() {
    let n = NonceSource::new(&[7u8; 32], 60).unwrap();
    let a = n.issue(Some(1000)).unwrap();
    assert!(n.is_valid(&a, Some(1000)));
    assert!(n.is_valid(&a, Some(1060)));
    assert!(!n.is_valid(&a, Some(1061)), "expired");
    assert!(!n.is_valid(&a, Some(900)), "from the future");
    let other = NonceSource::new(&[8u8; 32], 60).unwrap();
    assert!(!other.is_valid(&a, Some(1000)), "other secret");
    // Moving the timestamp forward must break the MAC.
    let (t, m) = a.split_once('.').unwrap();
    let mut ts = b64::decode(t).unwrap();
    *ts.last_mut().unwrap() ^= 0x10;
    assert!(!n.is_valid(&format!("{}.{m}", b64::encode(ts)), Some(1040)));
    for bad in ["", ".", "a.b", "a", "....", "AAAA.AAAA"] { assert!(!n.is_valid(bad, Some(1000)), "{bad:?}"); }
    assert!(NonceSource::new(&[7u8; 31], 60).is_err(), "short secrets are refused");
    let (status, h) = dpop::nonce_challenge(&a);
    assert_eq!((status, h[0].0), (400, "DPoP-Nonce"));
}
