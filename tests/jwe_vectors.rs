//! JWE tests. Runs against whichever backend is active.
//! Vectors: RFC 7520 (JOSE cookbook) section 5, RFC 3394 section 4, RFC 6070-style PBKDF2 checked against Python.
//! An operation the active backend does not implement is reported as SKIP (Error::Unsupported), never as a pass.
use authlas::{crypto, jwe::{self, Enc, KeyAlg, Policy}, jwk::Jwk, Error};
use serde_json::{json, Map, Value};

const ALL_ALG: &[KeyAlg] = &[
    KeyAlg::Dir, KeyAlg::A128Kw, KeyAlg::A192Kw, KeyAlg::A256Kw, KeyAlg::A128GcmKw, KeyAlg::A192GcmKw, KeyAlg::A256GcmKw,
    KeyAlg::RsaOaep, KeyAlg::RsaOaep256, KeyAlg::RsaOaep384, KeyAlg::RsaOaep512,
    KeyAlg::EcdhEs, KeyAlg::EcdhEsA128Kw, KeyAlg::EcdhEsA192Kw, KeyAlg::EcdhEsA256Kw,
    KeyAlg::Pbes2Hs256A128Kw, KeyAlg::Pbes2Hs384A192Kw, KeyAlg::Pbes2Hs512A256Kw,
];
const ALL_ENC: &[Enc] = &[Enc::A128CbcHs256, Enc::A192CbcHs384, Enc::A256CbcHs512, Enc::A128Gcm, Enc::A192Gcm, Enc::A256Gcm];

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/rfc7520_jwe.json")).unwrap()
}

fn all_policy() -> Policy<'static> {
    let mut p = Policy::new(ALL_ALG, ALL_ENC);
    p.pbes2_min_iter = 1;
    p
}

/// Returns None (and prints SKIP) if the backend cannot do the operation.
fn skip<T>(name: &str, r: Result<T, Error>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(Error::Unsupported(m)) => { eprintln!("SKIP {name}: {m}"); None }
        Err(e) => panic!("{name}: {e}"),
    }
}

fn oct(bytes: &[u8]) -> Jwk {
    Jwk::parse(&json!({"kty": "oct", "k": authlas::b64::encode(bytes)}).to_string()).unwrap()
}

fn plaintext() -> Vec<u8> {
    vectors()["plaintext"].as_str().unwrap().as_bytes().to_vec()
}

fn cookbook(name: &str) {
    let v = vectors();
    let c = &v[name];
    let key: Jwk = if name == "pbes2" {
        oct(c["password"].as_str().unwrap().as_bytes())
    } else {
        serde_json::from_value(c["key"].clone()).unwrap()
    };
    let r = jwe::decrypt(c["jwe"].as_str().unwrap(), &key, &all_policy());
    if let Some((_, pt)) = skip(name, r) {
        if name == "pbes2" {
            // RFC 7520 5.3 encrypts the JWK Set from Figure 95, not the Frodo quote.
            let got: Value = serde_json::from_slice(&pt).unwrap();
            assert_eq!(got, c["plaintext_json"], "pbes2: JWK Set mismatch");
        } else {
            assert_eq!(pt, plaintext(), "{name}: plaintext mismatch");
        }
    }
}

#[test] fn rfc7520_5_2_rsa_oaep_a256gcm() { cookbook("rsa_oaep_gcm"); }
#[test] fn rfc7520_5_3_pbes2_hs512_a256kw_a128cbc_hs256() { cookbook("pbes2"); }
#[test] fn rfc7520_5_4_ecdh_es_a128kw_p384_a128gcm() { cookbook("ecdh_kw"); }
#[test] fn rfc7520_5_5_ecdh_es_p256_a128cbc_hs256() { cookbook("ecdh_es"); }
#[test] fn rfc7520_5_6_dir_a128gcm() { cookbook("dir_gcm"); }
#[test] fn rfc7520_5_7_a256gcmkw_a128cbc_hs256() { cookbook("aesgcmkw_cbc"); }
#[test] fn rfc7520_5_8_a128kw_a128gcm() { cookbook("a128kw_gcm"); }

#[test]
fn rfc3394_4_6_key_wrap_vector() {
    let kek = hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    let data = hex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    let want = hex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");
    if let Some(w) = skip("kw wrap", crypto::aes_kw_wrap(&kek, &data)) {
        assert_eq!(w, want);
        assert_eq!(crypto::aes_kw_unwrap(&kek, &w).unwrap(), data);
        let mut bad = w.clone();
        bad[9] ^= 1;
        assert!(matches!(crypto::aes_kw_unwrap(&kek, &bad), Err(Error::Decrypt)));
    }
}

#[test]
fn pbkdf2_matches_reference() {
    // Reference: Python hashlib.pbkdf2_hmac(<hash>, b"password", b"NaCl", 1000, 40)
    let cases = [
        (authlas::jwa::Hash::Sha256, "67dbcc78548a75328f6890125bec2c59876e8de2e4c92c99b201872a760e2aec07f928a3644f7638"),
        (authlas::jwa::Hash::Sha384, "47776ec4520d3e79ac411e5b41e962c7f166aff3c1598c9bfdaecf6c484f60f2dff20f261b066298"),
        (authlas::jwa::Hash::Sha512, "6d3d85ab0b2085ce9b31b6737517900170be315ba6ed538e6f924b3588c66e9763210c9873672c55"),
    ];
    for (h, want) in cases {
        if let Some(a) = skip("pbkdf2", crypto::pbkdf2(h, b"password", b"NaCl", 1000, 40)) {
            assert_eq!(a, hex(want), "{h:?}");
        }
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn key_for(alg: KeyAlg, enc: Enc) -> Option<(Jwk, Jwk)> {
    // (key used to encrypt, key used to decrypt)
    use KeyAlg::*;
    let rnd = |n: usize| { let mut v = vec![0u8; n]; crypto::random(&mut v).unwrap(); v };
    Some(match alg {
        Dir => { let k = oct(&rnd(enc.cek_len())); (k.clone(), k) }
        A128Kw | A128GcmKw => { let k = oct(&rnd(16)); (k.clone(), k) }
        A192Kw | A192GcmKw => { let k = oct(&rnd(24)); (k.clone(), k) }
        A256Kw | A256GcmKw => { let k = oct(&rnd(32)); (k.clone(), k) }
        Pbes2Hs256A128Kw | Pbes2Hs384A192Kw | Pbes2Hs512A256Kw => { let k = oct(b"correct horse battery staple"); (k.clone(), k) }
        RsaOaep | RsaOaep256 | RsaOaep384 | RsaOaep512 => {
            let v = vectors();
            let sk: Jwk = serde_json::from_value(v["rsa_oaep_gcm"]["key"].clone()).unwrap();
            (sk.public().unwrap(), sk)
        }
        EcdhEs | EcdhEsA128Kw | EcdhEsA192Kw | EcdhEsA256Kw => {
            let sk = skip("ec_generate", crypto::ec_generate("P-256"))?;
            (sk.public().unwrap(), sk)
        }
        _ => return None,
    })
}

#[test]
fn round_trip_every_alg_with_every_enc() {
    let msg = b"round trip \xe2\x9c\x93 payload".to_vec();
    let mut done = 0;
    for &alg in ALL_ALG {
        for &enc in ALL_ENC {
            let Some((ek, dk)) = key_for(alg, enc) else { continue };
            let mut extra = Map::new();
            if matches!(alg, KeyAlg::Pbes2Hs256A128Kw | KeyAlg::Pbes2Hs384A192Kw | KeyAlg::Pbes2Hs512A256Kw) { extra.insert("p2c".into(), json!(1000)); }
            let name = format!("{}/{}", alg.as_str(), enc.as_str());
            let Some(tok) = skip(&name, jwe::encrypt(alg, enc, &ek, &extra, &msg)) else { continue };
            assert_eq!(tok.split('.').count(), 5, "{name}");
            let (h, pt) = jwe::decrypt(&tok, &dk, &all_policy()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(pt, msg, "{name}");
            assert_eq!((h.alg, h.enc), (alg, enc), "{name}");
            done += 1;
        }
    }
    assert!(done > 0, "no combination ran on this backend");
    eprintln!("round-tripped {done} alg/enc combinations on backend {}", crypto::backend_name());
}

#[test]
fn ecdh_es_on_every_curve() {
    for crv in ["P-256", "P-384", "P-521", "X25519"] {
        let Some(sk) = skip(crv, crypto::ec_generate(crv)) else { continue };
        let Some(tok) = skip(crv, jwe::encrypt(KeyAlg::EcdhEsA256Kw, Enc::A256Gcm, &sk.public().unwrap(), &Map::new(), b"x")) else { continue };
        assert_eq!(jwe::decrypt(&tok, &sk, &all_policy()).unwrap().1, b"x", "{crv}");
    }
}

#[test]
fn ecdh_apu_apv_are_bound_into_the_key() {
    let Some(sk) = skip("gen", crypto::ec_generate("P-256")) else { return };
    let mut extra = Map::new();
    extra.insert("apu".into(), json!(authlas::b64::encode("Alice")));
    extra.insert("apv".into(), json!(authlas::b64::encode("Bob")));
    let Some(tok) = skip("ecdh", jwe::encrypt(KeyAlg::EcdhEs, Enc::A128Gcm, &sk.public().unwrap(), &extra, b"bound")) else { return };
    assert_eq!(jwe::decrypt(&tok, &sk, &all_policy()).unwrap().1, b"bound");
    // Swap apv in the protected header: the derived key changes, so decryption must fail.
    let parts: Vec<&str> = tok.split('.').collect();
    let mut h: Map<String, Value> = serde_json::from_slice(&authlas::b64::decode(parts[0]).unwrap()).unwrap();
    h.insert("apv".into(), json!(authlas::b64::encode("Mallory")));
    let forged = format!("{}.{}.{}.{}.{}", authlas::b64::encode(serde_json::to_vec(&h).unwrap()), parts[1], parts[2], parts[3], parts[4]);
    assert!(matches!(jwe::decrypt(&forged, &sk, &all_policy()), Err(Error::Decrypt)));
}

fn good_token() -> (String, Jwk) {
    let k = oct(&[7u8; 32]);
    (jwe::encrypt(KeyAlg::A256Kw, Enc::A256Gcm, &k, &Map::new(), b"secret").unwrap(), k)
}

#[test]
fn every_segment_tamper_gives_the_same_error() {
    let (tok, k) = good_token();
    let parts: Vec<String> = tok.split('.').map(String::from).collect();
    for i in 0..5 {
        let mut p = parts.clone();
        if i == 0 {
            // Header is AAD: adding a harmless member must invalidate the tag, not the JSON.
            p[0] = with_header(&tok, |h| { h.insert("x".into(), json!(1)); }).split('.').next().unwrap().to_string();
        } else {
            let mut raw = authlas::b64::decode(&p[i]).unwrap();
            if raw.is_empty() { continue; }
            let last = raw.len() - 1;
            raw[last] ^= 1;
            p[i] = authlas::b64::encode(raw);
        }
        let r = jwe::decrypt(&p.join("."), &k, &all_policy());
        assert!(matches!(r, Err(Error::Decrypt)), "segment {i} tamper gave {r:?}");
    }
}

#[test]
fn cbc_hmac_tamper_and_truncation_are_rejected() {
    let k = oct(&[9u8; 64]);
    let tok = jwe::encrypt(KeyAlg::Dir, Enc::A256CbcHs512, &k, &Map::new(), b"cbc-hmac payload").unwrap();
    let p: Vec<&str> = tok.split('.').collect();
    let mut ct = authlas::b64::decode(p[3]).unwrap();
    ct.truncate(ct.len() - 16);
    let t = format!("{}.{}.{}.{}.{}", p[0], p[1], p[2], authlas::b64::encode(ct), p[4]);
    assert!(matches!(jwe::decrypt(&t, &k, &all_policy()), Err(Error::Decrypt)));
    let mut tag = authlas::b64::decode(p[4]).unwrap();
    tag.truncate(tag.len() - 1);
    let t = format!("{}.{}.{}.{}.{}", p[0], p[1], p[2], p[3], authlas::b64::encode(tag));
    assert!(matches!(jwe::decrypt(&t, &k, &all_policy()), Err(Error::Decrypt)));
}

#[test]
fn wrong_key_is_a_plain_decrypt_error() {
    let (tok, _) = good_token();
    let other = oct(&[8u8; 32]);
    assert!(matches!(jwe::decrypt(&tok, &other, &all_policy()), Err(Error::Decrypt)));
}

#[test]
fn policy_is_enforced() {
    let (tok, k) = good_token();
    let only_dir = Policy::new(&[KeyAlg::Dir], ALL_ENC);
    assert!(matches!(jwe::decrypt(&tok, &k, &only_dir), Err(Error::Algorithm(_))));
    let only_cbc = Policy::new(ALL_ALG, &[Enc::A128CbcHs256]);
    assert!(matches!(jwe::decrypt(&tok, &k, &only_cbc), Err(Error::Algorithm(_))));
}

fn with_header(tok: &str, f: impl FnOnce(&mut Map<String, Value>)) -> String {
    let p: Vec<&str> = tok.split('.').collect();
    let mut h: Map<String, Value> = serde_json::from_slice(&authlas::b64::decode(p[0]).unwrap()).unwrap();
    f(&mut h);
    format!("{}.{}.{}.{}.{}", authlas::b64::encode(serde_json::to_vec(&h).unwrap()), p[1], p[2], p[3], p[4])
}

#[test]
fn zip_rsa1_5_and_unknown_crit_are_rejected() {
    let (tok, k) = good_token();
    let z = with_header(&tok, |h| { h.insert("zip".into(), json!("DEF")); });
    assert!(matches!(jwe::decrypt(&z, &k, &all_policy()), Err(Error::Malformed(_))));
    let r = with_header(&tok, |h| { h.insert("alg".into(), json!("RSA1_5")); });
    assert!(matches!(jwe::decrypt(&r, &k, &all_policy()), Err(Error::Algorithm(_))));
    let c = with_header(&tok, |h| { h.insert("crit".into(), json!(["exp"])); h.insert("exp".into(), json!(1)); });
    assert!(matches!(jwe::decrypt(&c, &k, &all_policy()), Err(Error::Malformed(_))));
}

#[test]
fn malformed_tokens_are_rejected() {
    let k = oct(&[1u8; 32]);
    for t in ["", "a.b.c.d", "a.b.c.d.e.f", "....", "!!!.b.c.d.e"] {
        assert!(jwe::decrypt(t, &k, &all_policy()).is_err(), "{t:?}");
    }
    let mut tiny = all_policy();
    tiny.max_token_len = 10;
    assert!(matches!(jwe::decrypt("aaaaaaaaaa.b.c.d.e", &k, &tiny), Err(Error::Malformed(_))));
}

#[test]
fn pbes2_iteration_count_is_bounded() {
    let k = oct(b"pw");
    let mut extra = Map::new();
    extra.insert("p2c".into(), json!(1000));
    let Some(tok) = skip("pbes2", jwe::encrypt(KeyAlg::Pbes2Hs256A128Kw, Enc::A128Gcm, &k, &extra, b"x")) else { return };
    let evil = with_header(&tok, |h| { h.insert("p2c".into(), json!(2_000_000_000u64)); });
    let pol = Policy::new(ALL_ALG, ALL_ENC);
    assert!(matches!(jwe::decrypt(&evil, &k, &pol), Err(Error::Key(_))), "huge p2c must be refused before any hashing");
    let weak = with_header(&tok, |h| { h.insert("p2c".into(), json!(1)); });
    assert!(matches!(jwe::decrypt(&weak, &k, &pol), Err(Error::Key(_))));
}

#[test]
fn key_use_and_ops_are_enforced() {
    let mut k = oct(&[7u8; 32]);
    k.use_ = Some("sig".into());
    assert!(matches!(jwe::encrypt(KeyAlg::Dir, Enc::A256Gcm, &k, &Map::new(), b"x"), Err(Error::Key(_))));
    let mut k = oct(&[7u8; 32]);
    k.key_ops = Some(vec!["sign".into()]);
    assert!(matches!(jwe::encrypt(KeyAlg::Dir, Enc::A256Gcm, &k, &Map::new(), b"x"), Err(Error::Key(_))));
}

#[test]
fn wrong_dir_key_length_is_a_key_error_not_a_panic() {
    let k = oct(&[7u8; 20]);
    assert!(matches!(jwe::encrypt(KeyAlg::Dir, Enc::A256Gcm, &k, &Map::new(), b"x"), Err(Error::Key(_))));
}

#[test]
fn ecdh_rejects_epk_on_another_curve_and_private_epk() {
    let Some(sk) = skip("gen", crypto::ec_generate("P-256")) else { return };
    let Some(tok) = skip("ecdh", jwe::encrypt(KeyAlg::EcdhEs, Enc::A128Gcm, &sk.public().unwrap(), &Map::new(), b"x")) else { return };
    let Some(other) = skip("gen", crypto::ec_generate("P-384")) else { return };
    let swapped = with_header(&tok, |h| { h.insert("epk".into(), serde_json::to_value(other.public().unwrap()).unwrap()); });
    assert!(matches!(jwe::decrypt(&swapped, &sk, &all_policy()), Err(Error::Key(_))));
    let leaked = with_header(&tok, |h| { h.insert("epk".into(), serde_json::to_value(&other).unwrap()); });
    assert!(matches!(jwe::decrypt(&leaked, &sk, &all_policy()), Err(Error::Malformed(_))));
}

#[test]
fn ecdh_rejects_a_point_that_is_not_on_the_curve() {
    let Some(sk) = skip("gen", crypto::ec_generate("P-256")) else { return };
    let Some(tok) = skip("ecdh", jwe::encrypt(KeyAlg::EcdhEs, Enc::A128Gcm, &sk.public().unwrap(), &Map::new(), b"x")) else { return };
    let forged = with_header(&tok, |h| {
        let epk = h.get_mut("epk").unwrap().as_object_mut().unwrap();
        let y = authlas::b64::decode(epk["y"].as_str().unwrap()).unwrap();
        let mut y2 = y.clone();
        y2[31] ^= 1; // moves the point off the curve
        epk.insert("y".into(), json!(authlas::b64::encode(y2)));
    });
    let r = jwe::decrypt(&forged, &sk, &all_policy());
    assert!(matches!(r, Err(Error::Key(_))), "invalid-curve point must be refused, got {r:?}");
}

#[test]
fn caller_cannot_inject_protected_members() {
    let k = oct(&[7u8; 32]);
    for banned in ["zip", "epk", "iv", "tag"] {
        let mut extra = Map::new();
        extra.insert(banned.into(), json!("x"));
        assert!(jwe::encrypt(KeyAlg::Dir, Enc::A256Gcm, &k, &extra, b"x").is_err(), "{banned}");
    }
}

#[test]
fn nothing_secret_appears_in_error_text() {
    let (tok, _) = good_token();
    let e = jwe::decrypt(&tok, &oct(&[8u8; 32]), &all_policy()).unwrap_err();
    assert_eq!(e.to_string(), "decryption failed");
}
