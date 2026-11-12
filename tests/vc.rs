#![cfg(feature = "vc")]
//! Token Status List, SD-JWT VC, and Type Metadata. Vectors in tests/vectors/ were extracted from the drafts
//! (status-list-21 appendix C, sd-jwt-vc-26 figures 7, 8 and 10).
use authlas::jwa::Algorithm::{self, *};
use authlas::jwk::{Jwk, JwkSet};
use authlas::sdjwt::{self, path, KeyBindingPolicy, Presentation};
use authlas::sdjwt_vc::type_metadata::{self as tm, PathComp, Sd};
use authlas::sdjwt_vc::*;
use authlas::status_list::*;
use authlas::Error;
use serde_json::{json, Map, Value};

const NOW: u64 = 1_800_000_000;

fn ec() -> Option<Jwk> {
    match authlas::crypto::ec_generate("P-256") { Ok(k) => Some(k), Err(Error::Unsupported(m)) => { eprintln!("SKIP: {m}"); None }, Err(e) => panic!("{e}") }
}
fn vectors(name: &str) -> Value {
    let p = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap()
}
fn obj(v: Value) -> Map<String, Value> { v.as_object().unwrap().clone() }

// =====================================================================================================================
// Status list: draft vectors
// =====================================================================================================================

#[test]
fn small_examples_from_section_4() {
    for v in vectors("status_list_small.json").as_array().unwrap() {
        let bits = v["bits"].as_u64().unwrap() as u8;
        let want: Vec<u8> = v["bytes"].as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
        let list = StatusList::from_json(&json!({"bits": bits, "lst": v["lst"]}), DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(list.as_bytes(), want.as_slice(), "bits={bits}: decompressed bytes");
    }
    // 1-bit example: statuses 1,0,0,1,1,1,0,1 / 1,1,0,0,0,1,0,1.
    let l1 = StatusList::from_json(&json!({"bits":1,"lst":"eNrbuRgAAhcBXQ"}), 1024).unwrap();
    let got: Vec<u8> = (0..16).map(|i| l1.get(i).unwrap()).collect();
    assert_eq!(got, [1,0,0,1,1,1,0,1, 1,1,0,0,0,1,0,1]);
    // 2-bit example: 01 10 00 11 00 01 00 01 01 10 11 11.
    let l2 = StatusList::from_json(&json!({"bits":2,"lst":"eNo76fITAAPfAgc"}), 1024).unwrap();
    let got: Vec<u8> = (0..12).map(|i| l2.get(i).unwrap()).collect();
    assert_eq!(got, [1,2,0,3,0,1,0,1,1,2,3,3]);
}

#[test]
fn appendix_c_vectors_decode_to_exactly_the_listed_statuses() {
    for v in vectors("status_list.json").as_array().unwrap() {
        let bits = v["bits"].as_u64().unwrap() as u8;
        let list = StatusList::from_json(&json!({"bits": bits, "lst": v["lst"]}), DEFAULT_MAX_BYTES).unwrap();
        assert!(list.len() >= 1 << 20, "bits={bits}: 2^20 entries");
        let set: std::collections::BTreeMap<usize, u8> = v["set"].as_object().unwrap().iter().map(|(k, x)| (k.parse().unwrap(), x.as_u64().unwrap() as u8)).collect();
        assert!(!set.is_empty());
        for (i, want) in &set { assert_eq!(list.get(*i), Some(*want), "bits={bits} idx={i}"); }
        // Everything else is 0 (VALID).
        let mut nonzero = 0;
        for i in 0..(1 << 20) { if list.get(i) != Some(0) { nonzero += 1; assert!(set.contains_key(&i), "bits={bits}: unexpected status at {i}"); } }
        assert_eq!(nonzero, set.values().filter(|v| **v != 0).count());
    }
}

#[test]
fn encoding_is_canonical_for_the_draft_examples() {
    // Re-encoding the small examples gives the draft's exact `lst` strings (zlib, best compression).
    let mut l = StatusList::new(1, 16).unwrap();
    for (i, v) in [1,0,0,1,1,1,0,1, 1,1,0,0,0,1,0,1].iter().enumerate() { l.set(i, *v).unwrap(); }
    assert_eq!(l.as_bytes(), [0xb9, 0xa3]);
    assert_eq!(l.to_json()["lst"], "eNrbuRgAAhcBXQ");
    let mut l2 = StatusList::new(2, 12).unwrap();
    for (i, v) in [1,2,0,3,0,1,0,1,1,2,3,3].iter().enumerate() { l2.set(i, *v).unwrap(); }
    assert_eq!(l2.as_bytes(), [0xc9, 0x44, 0xf9]);
    assert_eq!(l2.to_json()["lst"], "eNo76fITAAPfAgc");
}

#[test]
fn list_get_set_for_every_width() {
    for bits in [1u8, 2, 4, 8] {
        let modulus: u16 = 1 << bits;
        let mut l = StatusList::new(bits, 100).unwrap();
        for i in 0..100usize { l.set(i, (i as u16 % modulus) as u8).unwrap(); }
        for i in 0..100usize { assert_eq!(l.get(i), Some((i as u16 % modulus) as u8), "bits={bits} i={i}"); }
        // Neighbours are untouched by a write.
        let max = (modulus - 1) as u8;
        let before: Vec<_> = (0..100).map(|i| l.get(i).unwrap()).collect();
        l.set(37, max).unwrap();
        for i in 0..100 { if i != 37 { assert_eq!(l.get(i).unwrap(), before[i], "bits={bits}: write at 37 changed {i}"); } }
        assert_eq!(l.get(37), Some(max));
        if bits < 8 { assert!(l.set(5, max + 1).is_err(), "bits={bits}: a value that does not fit must be refused"); }
        assert_eq!(l.get(l.len()), None);
        assert!(l.set(l.len(), 0).is_err());
        assert_eq!(l.get(usize::MAX), None);
    }
    assert!(StatusList::new(3, 8).is_err() && StatusList::new(0, 8).is_err() && StatusList::new(16, 8).is_err());
    assert!(StatusList::new(1, 0).is_err());
    assert!(StatusList::new(1, usize::MAX).is_err());
}

#[test]
fn hostile_status_lists() {
    let enc = |bytes: &[u8]| authlas::b64::encode(miniz_oxide::deflate::compress_to_vec_zlib(bytes, 9));
    // A zip bomb: 64 MiB of zeros compresses to ~64 KiB and must not be inflated.
    let bomb = enc(&vec![0u8; 64 * 1024 * 1024]);
    assert!(bomb.len() < MAX_ENCODED);
    assert!(StatusList::from_json(&json!({"bits": 1, "lst": bomb}), DEFAULT_MAX_BYTES).is_err());
    // The same list is fine with a bigger cap, so the failure above was the cap.
    assert!(StatusList::from_json(&json!({"bits": 1, "lst": enc(&vec![0u8; 1024])}), 2048).is_ok());
    assert!(StatusList::from_json(&json!({"bits": 1, "lst": enc(&vec![0u8; 4096])}), 2048).is_err());
    for bad in [json!({"bits": 3, "lst": "eNrbuRgAAhcBXQ"}), json!({"bits": "1", "lst": "eNrbuRgAAhcBXQ"}), json!({"lst": "eNrbuRgAAhcBXQ"}), json!({"bits": 1}),
        json!({"bits": 1, "lst": ""}), json!({"bits": 1, "lst": "!!!"}), json!({"bits": 1, "lst": authlas::b64::encode(b"not zlib")}), json!("x"), json!({"bits": 1, "lst": 5}),
        json!({"bits": 1, "lst": enc(b"")})] {
        assert!(StatusList::from_json(&bad, 1024).is_err(), "{bad}");
    }
}

// =====================================================================================================================
// Status list: token
// =====================================================================================================================

const SL_URI: &str = "https://example.com/statuslists/1";

fn list_with(revoked: &[usize]) -> StatusList {
    let mut l = StatusList::new(2, 1000).unwrap();
    for i in revoked { l.set(*i, INVALID).unwrap(); }
    l.set(9, SUSPENDED).unwrap();
    l
}
fn tpol<'a>(algs: &'a [Algorithm]) -> TokenPolicy<'a> { let mut p = TokenPolicy::new(algs, SL_URI); p.now = Some(NOW + 10); p }

#[test]
fn status_token_round_trip() {
    let Some(k) = ec() else { return };
    let l = list_with(&[3, 4]);
    let mut i = StatusListTokenIssue::new(ES256, &k, SL_URI, &l); i.now = Some(NOW); i.issuer = Some("https://example.com");
    let t = i.sign().unwrap();
    let h = authlas::jws::peek_header(&t).unwrap();
    assert_eq!(h.typ.as_deref(), Some("statuslist+jwt"));
    let algs = [ES256];
    let v = verify_token(&t, &k.public().unwrap(), &tpol(&algs)).unwrap();
    assert_eq!(v.status(3).unwrap(), INVALID);
    assert_eq!(v.status(9).unwrap(), SUSPENDED);
    assert_eq!(v.status(0).unwrap(), VALID);
    assert_eq!(v.ttl, Some(3600));
    assert!(ensure_accepted(v.status(0).unwrap(), &[VALID]).is_ok());
    assert!(ensure_accepted(v.status(3).unwrap(), &[VALID]).is_err());
    assert!(ensure_accepted(v.status(9).unwrap(), &[VALID]).is_err());
    assert!(ensure_accepted(v.status(9).unwrap(), &[VALID, SUSPENDED]).is_ok());
    // Out of range is an error, not VALID.
    assert!(v.status(999_999).is_err());
    assert!(v.status(u64::MAX).is_err());
}

#[test]
fn status_token_from_the_draft_verifies_structurally() {
    // The draft's example token is signed with a key the draft does not publish, so only the claims can be checked here.
    let t = vectors("status_list_token.json")["token"].as_str().unwrap().to_string();
    let h = authlas::jws::peek_header(&t).unwrap();
    assert_eq!(h.typ.as_deref(), Some("statuslist+jwt"));
    assert_eq!(h.kid.as_deref(), Some("12"));
    let c = authlas::jwt::peek_claims_unverified(&t).unwrap();
    assert_eq!(c.str_claim("sub").unwrap(), Some(SL_URI));
    let l = StatusList::from_json(&c.map["status_list"], 1024).unwrap();
    assert_eq!(l.get(0), Some(1));
    // With some other key it must fail.
    let Some(k) = ec() else { return };
    assert!(verify_token(&t, &k.public().unwrap(), &tpol(&[ES256])).is_err());
}

#[test]
fn status_token_checks() {
    let Some(k) = ec() else { return };
    let Some(evil) = ec() else { return };
    let pk = k.public().unwrap();
    let l = list_with(&[1]);
    let mk = |f: &dyn Fn(&mut StatusListTokenIssue)| { let mut i = StatusListTokenIssue::new(ES256, &k, SL_URI, &l); i.now = Some(NOW); f(&mut i); i.sign().unwrap() };
    let algs = [ES256];
    let good = mk(&|_| {});
    assert!(verify_token(&good, &pk, &tpol(&algs)).is_ok());
    // Wrong key / alg.
    assert!(verify_token(&good, &evil.public().unwrap(), &tpol(&algs)).is_err());
    assert!(verify_token(&good, &pk, &tpol(&[RS256])).is_err());
    // sub must equal the reference uri: a list for another token must not answer for this one.
    let other = mk(&|i| i.uri = "https://example.com/statuslists/2");
    assert!(matches!(verify_token(&other, &pk, &tpol(&algs)), Err(Error::Claim(_))));
    // Expired (exp is checked with the policy clock).
    let mut p = tpol(&algs); p.now = Some(NOW + 86_400 + 31);
    assert!(verify_token(&good, &pk, &p).is_err());
    p.now = Some(NOW + 86_400 - 1); p.leeway = 0;
    assert!(verify_token(&good, &pk, &p).is_ok());
    // iat in the future.
    let mut p = tpol(&algs); p.now = Some(NOW - 1000);
    assert!(verify_token(&good, &pk, &p).is_err());
    // Local freshness policy.
    let mut p = tpol(&algs); p.max_age = Some(5); p.leeway = 0;
    assert!(verify_token(&good, &pk, &p).is_err());
    // Pinned status issuer.
    let named = mk(&|i| i.issuer = Some("https://status.example.com"));
    let mut p = tpol(&algs); p.issuer = Some("https://status.example.com");
    assert!(verify_token(&named, &pk, &p).is_ok());
    p.issuer = Some("https://other.example.com");
    assert!(verify_token(&named, &pk, &p).is_err());
    assert!(verify_token(&good, &pk, &p).is_err(), "pinned issuer but token names none");
    // exp required.
    let no_exp = mk(&|i| i.lifetime = None);
    assert!(verify_token(&no_exp, &pk, &tpol(&algs)).is_ok());
    let mut p = tpol(&algs); p.require_exp = true;
    assert!(verify_token(&no_exp, &pk, &p).is_err());
    // Wrong typ: an ordinary JWT with a status_list claim is not a status list token.
    let c = authlas::jwt::Claims::new().subject(SL_URI).issued_at(NOW).set("status_list", l.to_json());
    let plain = authlas::jwt::sign(ES256, &k, &c, Some("JWT")).unwrap();
    assert!(verify_token(&plain, &pk, &tpol(&algs)).is_err());
    let no_typ = authlas::jwt::sign(ES256, &k, &c, None).unwrap();
    assert!(verify_token(&no_typ, &pk, &tpol(&algs)).is_err());
    // Issuer-side validation.
    let mut bad = StatusListTokenIssue::new(ES256, &k, SL_URI, &l); bad.ttl = Some(0);
    assert!(bad.sign().is_err());
    assert!(StatusListTokenIssue::new(ES256, &k, "not a uri", &l).sign().is_err());
}

#[test]
fn status_token_mac_is_opt_in() {
    let hk = Jwk::parse(r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#).unwrap();
    let l = list_with(&[]);
    let c = authlas::jwt::Claims::new().subject(SL_URI).issued_at(NOW).expires_at(NOW + 1000).set("status_list", l.to_json());
    let t = authlas::jwt::sign(HS256, &hk, &c, Some("statuslist+jwt")).unwrap();
    let mut p = TokenPolicy::new(&[HS256], SL_URI); p.now = Some(NOW);
    assert!(verify_token(&t, &hk, &p).is_err(), "MACs are refused unless the policy allows them");
    p.allow_mac = true;
    assert!(verify_token(&t, &hk, &p).is_ok());
    let Some(k) = ec() else { return };
    assert!(StatusListTokenIssue::new(HS256, &hk, SL_URI, &l).sign().is_err());
    let _ = k;
}

#[test]
fn ttl_and_exp_shape_the_refresh_time() {
    let Some(k) = ec() else { return };
    let l = list_with(&[]);
    let mk = |ttl: Option<u64>, life: Option<u64>| { let mut i = StatusListTokenIssue::new(ES256, &k, SL_URI, &l); i.now = Some(NOW); i.ttl = ttl; i.lifetime = life; verify_token(&i.sign().unwrap(), &k.public().unwrap(), &tpol(&[ES256])).unwrap() };
    let b = RefreshBounds::default();
    assert_eq!(mk(Some(600), Some(86_400)).refresh_at(NOW, b), NOW + 600);
    assert_eq!(mk(Some(1), Some(86_400)).refresh_at(NOW, b), NOW + 60, "a ttl of 1 second must not make clients hammer the server");
    assert_eq!(mk(Some(31_536_000), None).refresh_at(NOW, b), NOW + 86_400, "nor keep a list for a year");
    assert_eq!(mk(None, None).refresh_at(NOW, b), NOW + 3600);
    assert_eq!(mk(Some(7200), Some(300)).refresh_at(NOW, b), NOW + 300, "never later than exp");
}

#[test]
fn status_reference_in_claims() {
    let r = StatusReference::new(412, SL_URI).unwrap();
    let c = obj(json!({"status": r.to_claim()}));
    assert_eq!(StatusReference::from_claims(&c).unwrap(), Some(r));
    assert_eq!(StatusReference::from_claims(&obj(json!({}))).unwrap(), None);
    assert_eq!(StatusReference::from_claims(&obj(json!({"status": {"other_mechanism": {}}}))).unwrap(), None);
    for bad in [json!({"status": []}), json!({"status": {}}), json!({"status": {"status_list": 5}}), json!({"status": {"status_list": {"idx": -1, "uri": SL_URI}}}),
        json!({"status": {"status_list": {"idx": "0", "uri": SL_URI}}}), json!({"status": {"status_list": {"idx": 0}}}), json!({"status": {"status_list": {"idx": 0, "uri": "nope"}}}),
        json!({"status": {"status_list": {"idx": 1.5, "uri": SL_URI}}}), json!({"status": {"status_list": {"idx": 0, "uri": "https://x/a b"}}})] {
        assert!(StatusReference::from_claims(&obj(bad.clone())).is_err(), "{bad}");
    }
}

// =====================================================================================================================
// SD-JWT: shape (the new facts the verifier records)
// =====================================================================================================================

#[test]
fn draft_example_figures_verify_and_report_shape() {
    let v = vectors("sdjwt_vc.json");
    // The draft's signing key is not published, so check structure with the unverified path: split, count disclosures.
    let issued = v["issued"].as_str().unwrap();
    let p = sdjwt::split(issued).unwrap();
    assert_eq!(p.disclosures.len(), 9, "figure 7 has nine disclosures");
    assert!(p.kb_jwt.is_none());
    let pres = sdjwt::split(v["presented_kb"].as_str().unwrap()).unwrap();
    assert_eq!(pres.disclosures.len(), 2);
    assert!(pres.kb_jwt.is_some(), "figure 8 carries a key-binding JWT");
    let no_kb = sdjwt::split(v["presented"].as_str().unwrap()).unwrap();
    assert_eq!(no_kb.disclosures.len(), 2);
    assert!(no_kb.kb_jwt.is_none());
    let (name, value) = sdjwt::describe(pres.disclosures[0]).unwrap();
    assert_eq!(name.as_deref(), Some("is_over_65"));
    assert_eq!(value, json!(true));
    // The header is the renamed typ.
    assert_eq!(authlas::jws::peek_header(p.jwt).unwrap().typ.as_deref(), Some("dc+sd-jwt"));
}

// =====================================================================================================================
// SD-JWT VC
// =====================================================================================================================

const ISS: &str = "https://issuer.example.com";
const VCT: &str = "https://credentials.example.com/identity_credential";
const AUD: &str = "https://verifier.example.org";

fn claims() -> Map<String, Value> {
    obj(json!({"given_name": "John", "family_name": "Doe", "email": "johndoe@example.com", "address": {"street_address": "123 Main St", "locality": "Anytown", "country": "US"},
        "birthdate": "1940-01-01", "is_over_18": true, "nationalities": ["US", "DE"]}))
}
fn pol<'a>(algs: &'a [Algorithm], may: &'a dyn Fn(&str, &str) -> bool) -> VcPolicy<'a> { let mut p = VcPolicy::new(algs, may); p.now = Some(NOW + 10); p }
fn allow_all(_: &str, _: &str) -> bool { true }

fn issue_vc<'a>(k: &'a Jwk, holder: &'a Jwk, hide: &[&str], f: impl FnOnce(&mut VcIssue<'a>)) -> sdjwt::Issued {
    let mut v = VcIssue::new(ES256, k, ISS, VCT); v.now = Some(NOW); v.holder_key = Some(holder);
    f(&mut v);
    v.issue(&claims(), &hide.iter().map(|p| path(p)).collect::<Vec<_>>()).unwrap()
}
fn keyfn(k: &Jwk) -> impl Fn(&str, Option<&str>, Algorithm) -> Option<Jwk> + '_ { move |_, _, _| Some(k.public().unwrap()) }

#[test]
fn issue_and_verify_a_credential() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    let issued = issue_vc(&k, &hp, &["given_name", "family_name", "email", "address", "birthdate", "is_over_18", "nationalities/1"], |v| v.decoys = 2);
    assert_eq!(authlas::jws::peek_header(issued.compact.split('~').next().unwrap()).unwrap().typ.as_deref(), Some("dc+sd-jwt"));
    let algs = [ES256];
    let may = |iss: &str, vct: &str| iss == ISS && vct == VCT;
    let vc = verify(&issued.compact, &keyfn(&k), &pol(&algs, &may)).unwrap();
    assert_eq!(vc.issuer, ISS);
    assert_eq!(vc.vct, VCT);
    assert_eq!(vc.claims["given_name"], "John");
    assert_eq!(vc.claims["nationalities"], json!(["US", "DE"]));
    assert!(vc.claims.contains_key("cnf") && !vc.claims.contains_key("_sd"));
    assert!(vc.is_of_type(VCT) && !vc.is_of_type("urn:other:type"));
}

#[test]
fn registered_claims_cannot_be_hidden_when_issuing() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    // The issuer side refuses to hide them.
    for name in ["vct", "iss", "exp", "status", "aka_vcts", "cnf", "nbf"] {
        let mut v = VcIssue::new(ES256, &k, ISS, VCT); v.holder_key = Some(&hp);
        assert!(v.issue(&claims(), &[path(name)]).is_err(), "{name}");
    }
    // And refuses claims that would collide with what it sets itself.
    for name in ["iss", "vct", "exp", "iat", "cnf", "status", "aka_vcts", "_sd", "_sd_alg"] {
        let mut c = claims(); c.insert(name.into(), json!("x"));
        assert!(VcIssue::new(ES256, &k, ISS, VCT).issue(&c, &[]).is_err(), "{name}");
    }
}

#[test]
fn verifier_rejects_a_credential_where_a_registered_claim_came_through_a_disclosure() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    // A rogue issuer (or a bug) uses the raw SD-JWT issuer to hide `status` and `exp`.
    let mut c = claims();
    c.insert("iss".into(), json!(ISS)); c.insert("vct".into(), json!(VCT)); c.insert("exp".into(), json!(NOW + 1000));
    c.insert("status".into(), StatusReference::new(1, SL_URI).unwrap().to_claim());
    for hidden in ["exp", "status"] {
        let i = sdjwt::Issuer { alg: ES256, key: &k, hash: authlas::jwa::Hash::Sha256, decoys: 0, holder_key: Some(&hp), typ: "dc+sd-jwt" };
        let issued = i.issue(&c, &[path(hidden)]).unwrap();
        let algs = [ES256];
        let mut p = pol(&algs, &allow_all); p.require_exp = false;
        assert!(matches!(verify(&issued.compact, &keyfn(&k), &p), Err(Error::Claim(_))), "{hidden} hidden by the issuer must be refused");
    }
}

#[test]
fn issuer_authorisation_comes_before_key_lookup() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    let issued = issue_vc(&k, &hp, &["email"], |_| {});
    let algs = [ES256];
    let asked = std::cell::Cell::new(false);
    let spy = |_: &str, _: Option<&str>, _: Algorithm| { asked.set(true); Some(k.public().unwrap()) };
    // An issuer that is not authorised for this type: refused, key never requested (so no SSRF on its behalf either).
    let deny = |_: &str, _: &str| false;
    assert!(verify(&issued.compact, &spy, &pol(&algs, &deny)).is_err());
    assert!(!asked.get());
    // Authorised for a different type only.
    let other = |iss: &str, vct: &str| iss == ISS && vct == "https://credentials.example.com/other";
    assert!(verify(&issued.compact, &spy, &pol(&algs, &other)).is_err());
    assert!(!asked.get());
    let ok = |iss: &str, vct: &str| iss == ISS && vct == VCT;
    assert!(verify(&issued.compact, &spy, &pol(&algs, &ok)).is_ok());
    assert!(asked.get());
}

#[test]
fn aka_vcts_matching_is_not_authorisation() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    let issued = issue_vc(&k, &hp, &[], |v| v.aka_vcts = &["urn:example:eudi:pid"]);
    let algs = [ES256];
    // The verifier asked for the general type. The credential qualifies by aka_vcts...
    let mut p = pol(&algs, &allow_all); p.accept_types = &["urn:example:eudi:pid"];
    let vc = verify(&issued.compact, &keyfn(&k), &p).unwrap();
    assert!(vc.is_of_type("urn:example:eudi:pid"));
    assert_eq!(vc.aka_vcts, ["urn:example:eudi:pid"]);
    // ...but the authorisation callback sees only the issuer and the credential's own vct, so claiming a famous type does not help.
    let seen = std::cell::RefCell::new(vec![]);
    let may = |iss: &str, vct: &str| { seen.borrow_mut().push((iss.to_string(), vct.to_string())); iss == ISS && vct == VCT };
    assert!(verify(&issued.compact, &keyfn(&k), &pol(&algs, &may)).is_ok());
    assert_eq!(seen.borrow()[0], (ISS.to_string(), VCT.to_string()));
    // Not an accepted type.
    let mut p = pol(&algs, &allow_all); p.accept_types = &["urn:example:something:else"];
    assert!(verify(&issued.compact, &keyfn(&k), &p).is_err());
}

#[test]
fn aka_vcts_and_vct_syntax() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    for bad in ["identity", "has space:x", "", "a\u{7}b:c"] { assert!(check_type_name(bad).is_err(), "{bad:?}"); }
    for ok in ["https://credentials.example.com/identity_credential", "urn:example:eudi:pid:aendgard:1", "com.example.identity"] { assert!(check_type_name(ok).is_ok(), "{ok}"); }
    let mut v = VcIssue::new(ES256, &k, ISS, VCT); v.holder_key = Some(&hp);
    v.aka_vcts = &[VCT];
    assert!(v.issue(&claims(), &[]).is_err(), "aka_vcts must not contain vct");
    v.aka_vcts = &["plainword"];
    assert!(v.issue(&claims(), &[]).is_err());
    assert!(VcIssue::new(ES256, &k, ISS, "plainword").issue(&claims(), &[]).is_err());
}

#[test]
fn header_typ_rules() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    let mut c = claims();
    c.insert("iss".into(), json!(ISS)); c.insert("vct".into(), json!(VCT)); c.insert("exp".into(), json!(NOW + 1000));
    let algs = [ES256];
    for (typ, legacy, ok) in [("dc+sd-jwt", false, true), ("vc+sd-jwt", false, false), ("vc+sd-jwt", true, true), ("JWT", true, false), ("example+sd-jwt", true, false)] {
        let i = sdjwt::Issuer { alg: ES256, key: &k, hash: authlas::jwa::Hash::Sha256, decoys: 0, holder_key: Some(&hp), typ };
        let issued = i.issue(&c, &[path("email")]).unwrap_or_else(|_| i.issue(&{ let mut c = c.clone(); c.insert("email".into(), json!("a@b.c")); c }, &[path("email")]).unwrap());
        let mut p = pol(&algs, &allow_all); p.accept_legacy_typ = legacy;
        assert_eq!(verify(&issued.compact, &keyfn(&k), &p).is_ok(), ok, "typ={typ} legacy={legacy}");
    }
}

#[test]
fn key_binding_and_presentation() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    // The key-binding JWT is stamped with the wall clock by the holder helper, so this test runs on the real clock throughout.
    let issued = issue_vc(&k, &hp, &["given_name", "email", "address"], |v| v.now = None);
    let pres = Presentation { sd_jwt: &issued.compact, reveal: &[0, 2] }.build().unwrap();
    let with_kb = Presentation::with_key_binding(&pres, authlas::jwa::Hash::Sha256, ES256, &h, AUD, "nonce-1").unwrap();
    let algs = [ES256]; let kbalgs = [ES256];
    let kb = |nonce: &'static str, aud: &'static str| KeyBindingPolicy { algs: &kbalgs, audience: aud, nonce, max_age: 300 };
    let mut p = pol(&algs, &allow_all);
    p.now = None;
    // Not required: both forms pass.
    assert!(verify(&pres, &keyfn(&k), &p).is_ok());
    // Required: a presentation without it fails, with it passes, wrong nonce/aud fail.
    p.key_binding = Some(kb("nonce-1", AUD));
    assert!(verify(&pres, &keyfn(&k), &p).is_err());
    assert!(verify(&with_kb, &keyfn(&k), &p).unwrap().key_binding_verified);
    p.key_binding = Some(kb("nonce-2", AUD));
    assert!(verify(&with_kb, &keyfn(&k), &p).is_err());
    p.key_binding = Some(kb("nonce-1", "https://evil.example"));
    assert!(verify(&with_kb, &keyfn(&k), &p).is_err());
    // Signed by a key that is not the one in cnf.
    let Some(other) = ec() else { return };
    let stolen = Presentation::with_key_binding(&pres, authlas::jwa::Hash::Sha256, ES256, &other, AUD, "nonce-1").unwrap();
    p.key_binding = Some(kb("nonce-1", AUD));
    assert!(verify(&stolen, &keyfn(&k), &p).is_err());
}

#[test]
fn credential_policy_checks() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    let algs = [ES256];
    // Expired.
    let issued = issue_vc(&k, &hp, &[], |v| v.lifetime = Some(100));
    let mut p = pol(&algs, &allow_all); p.now = Some(NOW + 1000);
    assert!(verify(&issued.compact, &keyfn(&k), &p).is_err());
    // No exp: refused by default, allowed on request.
    let forever = issue_vc(&k, &hp, &[], |v| v.lifetime = None);
    assert!(verify(&forever.compact, &keyfn(&k), &pol(&algs, &allow_all)).is_err());
    let mut p = pol(&algs, &allow_all); p.require_exp = false;
    assert!(verify(&forever.compact, &keyfn(&k), &p).is_ok());
    // Status reference required / surfaced.
    let r = StatusReference::new(7, SL_URI).unwrap();
    let with_status = issue_vc(&k, &hp, &[], |v| v.status = Some(&r));
    let mut p = pol(&algs, &allow_all); p.require_status = true;
    assert_eq!(verify(&with_status.compact, &keyfn(&k), &p).unwrap().status, Some(r.clone()));
    assert!(verify(&issue_vc(&k, &hp, &[], |_| {}).compact, &keyfn(&k), &p).is_err());
    // Wrong key.
    let Some(evil) = ec() else { return };
    assert!(verify(&with_status.compact, &keyfn(&evil), &pol(&algs, &allow_all)).is_err());
    // iss that is not an https identifier cannot be used for key discovery.
    let mut v = VcIssue::new(ES256, &k, "http://issuer.example.com", VCT); v.now = Some(NOW);
    let bad = v.issue(&claims(), &[]).unwrap();
    assert!(verify(&bad.compact, &keyfn(&k), &pol(&algs, &allow_all)).is_err());
}

#[test]
fn end_to_end_with_status_list() {
    let (Some(k), Some(h), Some(sk)) = (ec(), ec(), ec()) else { return };
    let hp = h.public().unwrap();
    let mut list = StatusList::new(2, 100).unwrap();
    let r_ok = StatusReference::new(5, SL_URI).unwrap();
    let r_revoked = StatusReference::new(6, SL_URI).unwrap();
    list.set(6, INVALID).unwrap();
    let mut ti = StatusListTokenIssue::new(ES256, &sk, SL_URI, &list); ti.now = Some(NOW);
    let token = ti.sign().unwrap();
    let algs = [ES256];
    for (r, accepted) in [(&r_ok, true), (&r_revoked, false)] {
        let issued = issue_vc(&k, &hp, &["email"], |v| v.status = Some(r));
        let vc = verify(&issued.compact, &keyfn(&k), &pol(&algs, &allow_all)).unwrap();
        let reference = vc.status.clone().unwrap();
        let slt = verify_token(&token, &sk.public().unwrap(), &tpol(&algs).with_uri(&reference.uri)).unwrap();
        let st = slt.status(reference.idx).unwrap();
        assert_eq!(ensure_accepted(st, &[VALID]).is_ok(), accepted);
    }
    // A reference to another list's URI cannot be satisfied by this token.
    let other = StatusReference::new(5, "https://example.com/statuslists/9").unwrap();
    assert!(verify_token(&token, &sk.public().unwrap(), &TokenPolicy { now: Some(NOW + 1), ..TokenPolicy::new(&algs, &other.uri) }).is_err());
}

// =====================================================================================================================
// Issuer metadata
// =====================================================================================================================

#[test]
fn issuer_metadata_urls() {
    assert_eq!(issuer_metadata_url("https://example.com").unwrap(), "https://example.com/.well-known/jwt-vc-issuer");
    assert_eq!(issuer_metadata_url("https://example.com/").unwrap(), "https://example.com/.well-known/jwt-vc-issuer");
    assert_eq!(issuer_metadata_url("https://example.com/tenant/1234").unwrap(), "https://example.com/.well-known/jwt-vc-issuer/tenant/1234");
    assert_eq!(issuer_metadata_url("https://example.com/tenant/1234/").unwrap(), "https://example.com/.well-known/jwt-vc-issuer/tenant/1234");
    assert_eq!(issuer_metadata_url("https://example.com:8443/t").unwrap(), "https://example.com:8443/.well-known/jwt-vc-issuer/t");
    for bad in ["http://example.com", "https://example.com?x=1", "https://example.com/a#f", "https://example.com/a/../b", "https://u:p@example.com", "https:///x", "example.com", "https://example.com/a b", "https://example.com/%2e%2e/x"] {
        assert!(issuer_metadata_url(bad).is_err(), "{bad}");
    }
}

#[test]
fn issuer_metadata_documents() {
    let Some(k) = ec() else { return };
    let pk: Value = serde_json::from_str(&k.public().unwrap().to_json()).unwrap();
    let inline = json!({"issuer": ISS, "jwks": {"keys": [pk]}}).to_string();
    let m = IssuerMetadata::parse(&inline, ISS).unwrap();
    assert!(matches!(m.keys, IssuerKeys::Inline(ref s) if s.keys.len() == 1));
    let uri = json!({"issuer": ISS, "jwks_uri": "https://jwt-vc-issuer.example.com/my_public_keys.jwks"}).to_string();
    assert!(matches!(IssuerMetadata::parse(&uri, ISS).unwrap().keys, IssuerKeys::Uri(_)));
    // 4.3: the document must name the issuer the credential names.
    assert!(matches!(IssuerMetadata::parse(&inline, "https://other.example.com"), Err(Error::Claim(_))));
    for bad in [json!({"issuer": ISS}), json!({"issuer": ISS, "jwks": {"keys": [pk]}, "jwks_uri": "https://a.example.com/k"}), json!({"issuer": ISS, "jwks_uri": "https://169.254.169.254/k"}),
        json!({"issuer": ISS, "jwks_uri": "http://a.example.com/k"}), json!({"issuer": ISS, "jwks": {"keys": []}}), json!({"jwks": {"keys": [pk]}}), json!({"issuer": ISS, "jwks_uri": 5}),
        json!({"issuer": ISS, "jwks": {"keys": [serde_json::from_str::<Value>(&k.to_json()).unwrap()]}})] {
        assert!(IssuerMetadata::parse(&bad.to_string(), ISS).is_err(), "{bad}");
    }
    assert!(IssuerMetadata::parse(&format!("{{\"issuer\":\"{ISS}\",\"issuer\":\"https://evil.example.com\",\"jwks\":{{\"keys\":[]}}}}"), ISS).is_err(), "duplicate member");
    assert!(IssuerMetadata::parse(&format!("{{\"issuer\":\"{ISS}\",\"padding\":\"{}\"}}", "x".repeat(300_000)), ISS).is_err());
}

// =====================================================================================================================
// Type metadata
// =====================================================================================================================

fn docs(list: Vec<(&'static str, Value)>) -> impl Fn(&str) -> Option<Vec<u8>> {
    move |r: &str| list.iter().find(|(k, _)| *k == r).map(|(_, v)| serde_json::to_vec(v).unwrap())
}
const T_BASE: &str = "https://credentials.example.com/base";
const T_CHILD: &str = "https://credentials.example.com/child";
const T_URN: &str = "urn:example:eudi:pid";

#[test]
fn type_metadata_parse_and_integrity() {
    let doc = json!({"vct": T_BASE, "name": "Base", "claims": [{"path": ["given_name"], "mandatory": true, "sd": "always", "display": [{"locale": "en", "label": "Given name"}]},
        {"path": ["nationalities", null]}, {"path": ["degrees", 0, "type"]}]});
    let bytes = serde_json::to_vec(&doc).unwrap();
    let t = tm::TypeMetadata::parse(&bytes, T_BASE).unwrap();
    assert_eq!(t.claims.len(), 3);
    assert_eq!(t.claims[0].sd, Some(Sd::Always));
    assert_eq!(t.claims[1].path, [PathComp::Key("nationalities".into()), PathComp::All]);
    assert_eq!(t.claims[2].path[1], PathComp::Index(0));
    // The document must name the type it was fetched for.
    assert!(matches!(tm::TypeMetadata::parse(&bytes, T_CHILD), Err(Error::Claim(_))));
    for bad in [json!({"vct": T_BASE, "claims": [{"path": []}]}), json!({"vct": T_BASE, "claims": [{"path": [true]}]}), json!({"vct": T_BASE, "claims": [{"path": [-1]}]}),
        json!({"vct": T_BASE, "claims": [{"path": ["a"], "sd": "sometimes"}]}), json!({"vct": T_BASE, "claims": [{"path": ["a"], "mandatory": "yes"}]}), json!({"vct": T_BASE, "claims": [{}]}),
        json!({"vct": T_BASE, "claims": {}}), json!({"vct": T_BASE, "display": {}}), json!({"name": "x"}), json!({"vct": T_BASE, "extends#integrity": "sha256-AAAA"}), json!({"vct": 5})] {
        assert!(tm::TypeMetadata::parse(&serde_json::to_vec(&bad).unwrap(), T_BASE).is_err(), "{bad}");
    }
    assert!(tm::TypeMetadata::parse(&vec![b' '; tm::MAX_DOC_BYTES + 1], T_BASE).is_err());
    // Unknown properties are ignored.
    assert!(tm::TypeMetadata::parse(&serde_json::to_vec(&json!({"vct": T_BASE, "x-future": {"a": 1}})).unwrap(), T_BASE).is_ok());

    // Integrity (section 6).
    let good = tm::integrity_for(&bytes).unwrap();
    assert!(tm::check_integrity(&bytes, &good).is_ok());
    assert!(tm::check_integrity(b"tampered", &good).is_err());
    assert!(tm::check_integrity(&bytes, "md5-AAAA").is_err(), "no supported algorithm");
    assert!(tm::check_integrity(&bytes, "").is_err());
    // Strongest wins: a correct sha256 next to a wrong sha512 fails, because sha512 is the one that counts.
    let wrong512 = format!("sha512-{}", "A".repeat(86) + "==");
    assert!(tm::check_integrity(&bytes, &format!("{good} {wrong512}")).is_err());
    // Several of the strongest: any may match.
    let d256 = good.clone();
    assert!(tm::check_integrity(&bytes, &format!("{d256} sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")).is_ok());
    // A single bit flipped in the digest.
    let mut flipped = good.clone().into_bytes(); let n = flipped.len() - 3; flipped[n] = if flipped[n] == b'A' { b'B' } else { b'A' };
    assert!(tm::check_integrity(&bytes, std::str::from_utf8(&flipped).unwrap()).is_err());
}

#[test]
fn resolve_extends_chain_with_inheritance() {
    let base = json!({"vct": T_BASE, "name": "Base", "display": [{"locale": "en", "name": "Base"}],
        "claims": [{"path": ["given_name"], "mandatory": true, "sd": "allowed", "display": [{"locale": "en", "label": "Given name"}]}, {"path": ["email"], "sd": "always"}, {"path": ["country"], "sd": "never"}]});
    let child = json!({"vct": T_CHILD, "extends": T_BASE, "display": [{"locale": "en", "name": "Child"}],
        "claims": [{"path": ["given_name"], "sd": "always"}, {"path": ["birthdate"], "mandatory": true}, {"path": ["email"], "display": [{"locale": "de", "label": "E-Mail"}]}]});
    let r = tm::resolve(T_CHILD, None, &docs(vec![(T_CHILD, child), (T_BASE, base)])).unwrap();
    assert_eq!(r.chain, [T_CHILD, T_BASE]);
    let by = |p: &str| r.claims.iter().find(|c| c.path == [PathComp::Key(p.into())]).unwrap().clone();
    assert_eq!(by("given_name").sd, Some(Sd::Always), "child tightens allowed to always");
    assert!(by("given_name").is_mandatory(), "inherited");
    assert!(by("given_name").display.is_some(), "inherited display survives when the child sets none");
    assert_eq!(by("email").sd, Some(Sd::Always));
    assert_eq!(by("email").display.as_ref().unwrap()[0]["locale"], "de", "display is replaced, not merged");
    assert!(by("birthdate").is_mandatory());
    assert_eq!(by("country").sd, Some(Sd::Never));
    assert_eq!(r.display.as_ref().unwrap()[0]["name"], "Child", "the child's own display wins (5.5.2)");
}

#[test]
fn extending_may_not_loosen() {
    let base = json!({"vct": T_BASE, "claims": [{"path": ["a"], "sd": "always"}, {"path": ["b"], "sd": "never"}, {"path": ["c"], "mandatory": true}]});
    for child_claim in [json!({"path": ["a"], "sd": "never"}), json!({"path": ["a"], "sd": "allowed"}), json!({"path": ["b"], "sd": "always"}), json!({"path": ["c"], "mandatory": false})] {
        let child = json!({"vct": T_CHILD, "extends": T_BASE, "claims": [child_claim]});
        assert!(tm::resolve(T_CHILD, None, &docs(vec![(T_CHILD, child), (T_BASE, base.clone())])).is_err(), "{child_claim}");
    }
    // Restating the same value is fine.
    let child = json!({"vct": T_CHILD, "extends": T_BASE, "claims": [{"path": ["a"], "sd": "always"}, {"path": ["c"], "mandatory": true}]});
    assert!(tm::resolve(T_CHILD, None, &docs(vec![(T_CHILD, child), (T_BASE, base)])).is_ok());
}

#[test]
fn resolve_refuses_cycles_long_chains_and_bad_sources() {
    // A -> B -> A
    let a = json!({"vct": "https://t.example.com/a", "extends": "https://t.example.com/b"});
    let b = json!({"vct": "https://t.example.com/b", "extends": "https://t.example.com/a"});
    assert!(matches!(tm::resolve("https://t.example.com/a", None, &docs(vec![("https://t.example.com/a", a), ("https://t.example.com/b", b)])), Err(Error::Claim(_))));
    // Self reference.
    let s = json!({"vct": "https://t.example.com/s", "extends": "https://t.example.com/s"});
    assert!(tm::resolve("https://t.example.com/s", None, &docs(vec![("https://t.example.com/s", s)])).is_err());
    // A chain longer than the limit.
    let names: Vec<String> = (0..12).map(|i| format!("https://t.example.com/t{i}")).collect();
    let leaked: Vec<(&'static str, Value)> = names.iter().enumerate().map(|(i, n)| {
        let name: &'static str = Box::leak(n.clone().into_boxed_str());
        let mut d = json!({"vct": n}); if i + 1 < names.len() { d["extends"] = json!(names[i + 1]); }
        (name, d)
    }).collect();
    assert!(tm::resolve(&names[0], None, &docs(leaked)).is_err());
    // Not retrievable.
    assert!(tm::resolve(T_BASE, None, &|_| None).is_err());
    // http is never fetched; internal https targets are refused before `fetch` is called.
    let called = std::cell::Cell::new(false);
    let spy = |_: &str| { called.set(true); None };
    assert!(tm::resolve("http://credentials.example.com/x", None, &spy).is_err());
    assert!(tm::resolve("https://169.254.169.254/latest", None, &spy).is_err());
    assert!(tm::resolve("https://localhost/x", None, &spy).is_err());
    assert!(!called.get());
    // A URN goes to the registry callback.
    let urn = json!({"vct": T_URN, "claims": [{"path": ["given_name"], "mandatory": true}]});
    assert!(tm::resolve(T_URN, None, &docs(vec![(T_URN, urn)])).is_ok());
    // A registry that answers with the wrong type is not believed.
    let wrong = json!({"vct": "urn:example:other"});
    assert!(tm::resolve(T_URN, None, &docs(vec![(T_URN, wrong)])).is_err());
}

#[test]
fn resolve_checks_integrity_of_each_document() {
    let base = json!({"vct": T_BASE, "claims": [{"path": ["a"]}]});
    let base_bytes = serde_json::to_vec(&base).unwrap();
    let child = json!({"vct": T_CHILD, "extends": T_BASE, "extends#integrity": tm::integrity_for(&base_bytes).unwrap()});
    let child_bytes = serde_json::to_vec(&child).unwrap();
    let fetch = docs(vec![(T_CHILD, child.clone()), (T_BASE, base.clone())]);
    assert!(tm::resolve(T_CHILD, Some(&tm::integrity_for(&child_bytes).unwrap()), &fetch).is_ok());
    // vct#integrity that does not match.
    assert!(tm::resolve(T_CHILD, Some(&tm::integrity_for(b"something else").unwrap()), &fetch).is_err());
    // The parent has been swapped for something else.
    let swapped = docs(vec![(T_CHILD, child), (T_BASE, json!({"vct": T_BASE, "claims": [{"path": ["a"], "mandatory": true}]}))]);
    assert!(tm::resolve(T_CHILD, None, &swapped).is_err(), "extends#integrity catches the swap");
}

// ---------- claim metadata validation (5.6) ----------

fn vc_with(k: &Jwk, h: &Jwk, hide: &[&str], extra: Value) -> VerifiedVc {
    let mut c = claims();
    for (key, v) in extra.as_object().cloned().unwrap_or_default() { c.insert(key, v); }
    let mut v = VcIssue::new(ES256, k, ISS, VCT); v.now = Some(NOW); v.holder_key = Some(h);
    let issued = v.issue(&c, &hide.iter().map(|p| path(p)).collect::<Vec<_>>()).unwrap();
    // A holder that discloses everything it was given.
    verify(&issued.compact, &keyfn(k), &pol(&[ES256], &allow_all)).unwrap()
}
fn meta(claims: Value) -> Vec<tm::ClaimMeta> { tm::TypeMetadata::parse(&serde_json::to_vec(&json!({"vct": T_BASE, "claims": claims})).unwrap(), T_BASE).unwrap().claims }

#[test]
fn claim_metadata_sd_rules() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    let vc = vc_with(&k, &hp, &["given_name", "address", "nationalities/0"], json!({}));
    // always: the claim must have arrived through a disclosure.
    assert!(tm::validate(&meta(json!([{"path": ["given_name"], "sd": "always"}])), &vc.shape, true).is_ok());
    assert!(tm::validate(&meta(json!([{"path": ["family_name"], "sd": "always"}])), &vc.shape, true).is_err(), "family_name was issued in the clear");
    // never: a disclosed claim violates it.
    assert!(tm::validate(&meta(json!([{"path": ["family_name"], "sd": "never"}])), &vc.shape, true).is_ok());
    assert!(tm::validate(&meta(json!([{"path": ["given_name"], "sd": "never"}])), &vc.shape, true).is_err());
    // allowed: anything goes.
    assert!(tm::validate(&meta(json!([{"path": ["given_name"], "sd": "allowed"}, {"path": ["family_name"]}])), &vc.shape, true).is_ok());
    // Nested: address is disclosable as a whole; its children are not disclosable on their own ("not selectively disclosable solely
    // because an ancestor is").
    assert!(tm::validate(&meta(json!([{"path": ["address"], "sd": "always"}])), &vc.shape, true).is_ok());
    assert!(tm::validate(&meta(json!([{"path": ["address", "locality"], "sd": "always"}])), &vc.shape, true).is_err());
    assert!(tm::validate(&meta(json!([{"path": ["address", "locality"], "sd": "never"}])), &vc.shape, true).is_ok());
    // Array elements: element 0 is hidden-able, element 1 is plain; null selects all.
    assert!(tm::validate(&meta(json!([{"path": ["nationalities", 0], "sd": "always"}])), &vc.shape, true).is_ok());
    assert!(tm::validate(&meta(json!([{"path": ["nationalities", 1], "sd": "never"}])), &vc.shape, true).is_ok());
    assert!(tm::validate(&meta(json!([{"path": ["nationalities", null], "sd": "always"}])), &vc.shape, true).is_err(), "element 1 is not disclosable");
    assert!(tm::validate(&meta(json!([{"path": ["nationalities", null], "sd": "never"}])), &vc.shape, true).is_err(), "element 0 is disclosable");
}

#[test]
fn claim_metadata_mandatory_rules() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    let vc = vc_with(&k, &hp, &["given_name", "email"], json!({}));
    assert!(tm::validate(&meta(json!([{"path": ["family_name"], "mandatory": true}])), &vc.shape, true).is_ok());
    assert!(tm::validate(&meta(json!([{"path": ["shoe_size"], "mandatory": true}])), &vc.shape, true).is_err(), "a holder with everything sees it is missing");
    assert!(tm::validate(&meta(json!([{"path": ["shoe_size"]}])), &vc.shape, true).is_ok(), "optional");
    assert!(tm::validate(&meta(json!([{"path": ["address", "postal_code"], "mandatory": true}])), &vc.shape, true).is_err(), "missing nested claim");
    assert!(tm::validate(&meta(json!([{"path": ["nationalities", 5], "mandatory": true}])), &vc.shape, true).is_err(), "missing index");
    assert!(tm::validate(&meta(json!([{"path": ["nationalities", null], "mandatory": true}])), &vc.shape, true).is_ok());
}

#[test]
fn a_verifier_cannot_call_a_withheld_claim_missing() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    // Build a presentation that withholds `email`.
    let mut v = VcIssue::new(ES256, &k, ISS, VCT); v.now = Some(NOW); v.holder_key = Some(&hp);
    let issued = v.issue(&claims(), &[path("email"), path("given_name"), path("nationalities/0")]).unwrap();
    let pres = Presentation { sd_jwt: &issued.compact, reveal: &[] }.build().unwrap();
    let vc = verify(&pres, &keyfn(&k), &pol(&[ES256], &allow_all)).unwrap();
    assert!(!vc.claims.contains_key("email"));
    // email is mandatory and sd:allowed. A verifier must not conclude the issuer left it out.
    assert!(tm::validate(&meta(json!([{"path": ["email"], "mandatory": true}])), &vc.shape, false).is_ok());
    // The holder, who has every disclosure, can tell.
    assert!(tm::validate(&meta(json!([{"path": ["shoe_size"], "mandatory": true}])), &vc.shape, true).is_err());
    // But a claim that is mandatory and sd:never cannot have been withheld, so its absence is conclusive.
    assert!(tm::validate(&meta(json!([{"path": ["shoe_size"], "mandatory": true, "sd": "never"}])), &vc.shape, false).is_err());
    // An undisclosed array element keeps its place: element 0 is hidden, element 1 is visible and indexes count the hidden one.
    assert_eq!(vc.claims["nationalities"], json!(["DE"]));
    assert!(tm::validate(&meta(json!([{"path": ["nationalities", 1], "sd": "never"}])), &vc.shape, false).is_ok(), "index 1 is DE, as issued");
    assert!(tm::validate(&meta(json!([{"path": ["nationalities", 0], "sd": "always"}])), &vc.shape, false).is_ok(), "a hidden element is selectively disclosable");
    // Deeper components below a hidden element select nothing.
    assert!(tm::validate(&meta(json!([{"path": ["nationalities", 0, "x"], "mandatory": true, "sd": "never"}])), &vc.shape, false).is_ok());
}

#[test]
fn claim_path_type_errors() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    let vc = vc_with(&k, &hp, &[], json!({}));
    // String component on an array, index on an object, null on an object: processing aborts and the credential is rejected.
    for p in [json!(["nationalities", "x"]), json!(["address", 0]), json!(["address", null]), json!(["given_name", "x"]), json!(["given_name", 0])] {
        assert!(tm::validate(&meta(json!([{"path": p}])), &vc.shape, true).is_err(), "{p}");
    }
}

#[test]
fn check_credential_runs_the_whole_of_5_7() {
    let (Some(k), Some(h)) = (ec(), ec()) else { return };
    let hp = h.public().unwrap();
    let issued = { let mut v = VcIssue::new(ES256, &k, ISS, VCT); v.now = Some(NOW); v.holder_key = Some(&hp); v.issue(&claims(), &[path("given_name")]).unwrap() };
    let vc = verify(&issued.compact, &keyfn(&k), &pol(&[ES256], &allow_all)).unwrap();
    let ok = json!({"vct": VCT, "claims": [{"path": ["given_name"], "sd": "always", "mandatory": true, "display": [{"locale": "en", "label": "Given name"}]}, {"path": ["family_name"], "sd": "never"}]});
    let r = tm::check_credential(&vc, None, &docs(vec![(VCT, ok)]), false).unwrap();
    assert_eq!(tm::claim_labels(&r, "en")["given_name"], "Given name");
    // Metadata that cannot be retrieved: the credential is rejected when the policy requires metadata.
    assert!(tm::check_credential(&vc, None, &|_| None, false).is_err());
    // Metadata the credential violates.
    let strict = json!({"vct": VCT, "claims": [{"path": ["given_name"], "sd": "never"}]});
    assert!(tm::check_credential(&vc, None, &docs(vec![(VCT, strict)]), false).is_err());
    // Labels never carry control characters into a UI.
    let evil = json!({"vct": VCT, "claims": [{"path": ["given_name"], "display": [{"locale": "en", "label": "Name\u{0007}\u{001b}[31m"}]}]});
    let r = tm::check_credential(&vc, None, &docs(vec![(VCT, evil)]), false).unwrap();
    assert!(!tm::claim_labels(&r, "en")["given_name"].as_str().unwrap().chars().any(char::is_control));
}

#[test]
fn jwk_set_used_with_issuer_metadata() {
    let (Some(a), Some(b)) = (ec(), ec()) else { return };
    let mk = |k: &Jwk, kid: &str| { let mut p = k.public().unwrap(); p.kid = Some(kid.into()); p };
    let doc = json!({"issuer": ISS, "jwks": {"keys": [serde_json::from_str::<Value>(&mk(&a, "k1").to_json()).unwrap(), serde_json::from_str::<Value>(&mk(&b, "k2").to_json()).unwrap()]}});
    let IssuerKeys::Inline(set) = IssuerMetadata::parse(&doc.to_string(), ISS).unwrap().keys else { panic!() };
    let mut sk = b.clone(); sk.kid = Some("k2".into());
    let mut v = VcIssue::new(ES256, &sk, ISS, VCT); v.now = Some(NOW);
    let issued = v.issue(&claims(), &[]).unwrap();
    let keys = |_: &str, kid: Option<&str>, alg: Algorithm| set.select(kid, alg).ok().cloned();
    assert!(verify(&issued.compact, &keys, &pol(&[ES256], &allow_all)).is_ok());
    // A credential signed by k1 but claiming kid k2 fails on the signature.
    let mut fk = a.clone(); fk.kid = Some("k2".into());
    let forged = VcIssue { key: &fk, ..VcIssue::new(ES256, &fk, ISS, VCT) };
    let mut forged = forged; forged.now = Some(NOW);
    assert!(verify(&forged.issue(&claims(), &[]).unwrap().compact, &keys, &pol(&[ES256], &allow_all)).is_err());
}

trait WithUri<'a> { fn with_uri(self, uri: &'a str) -> Self; }
impl<'a> WithUri<'a> for TokenPolicy<'a> { fn with_uri(mut self, uri: &'a str) -> Self { self.uri = uri; self } }
