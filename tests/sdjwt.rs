use authlas::jwa::{Algorithm::*, Hash};
use authlas::jwk::Jwk;
use authlas::sdjwt::{self, path, Issuer, KeyBindingPolicy, Presentation, VerifyPolicy};
use authlas::{b64, Error};
use serde_json::{json, Map, Value};

fn vector() -> Value { serde_json::from_str(include_str!("vectors/rfc9901.json")).unwrap() }
fn jwk(v: &Value) -> Jwk { Jwk::parse(&v.to_string()).unwrap() }

fn policy<'a>(kb: Option<KeyBindingPolicy<'a>>) -> VerifyPolicy<'a> {
    VerifyPolicy { algs: &[ES256], issuer: "https://issuer.example.com", hashes: &[Hash::Sha256, Hash::Sha384, Hash::Sha512], key_binding: kb,
        audience: None, typ: None, now: Some(1_748_537_244 + 10), leeway: 0, require: &[] }
}
fn kb_policy<'a>() -> KeyBindingPolicy<'a> {
    KeyBindingPolicy { algs: &[ES256], audience: "https://verifier.example.org", nonce: "1234567890", max_age: 300 }
}

// ---------- RFC 9901 section 5 vectors ----------

#[test]
fn rfc9901_disclosure_digest() {
    let v = vector();
    let d = v["family_name_disclosure"].as_str().unwrap();
    assert_eq!(sdjwt::disclosure_digest(d, Hash::Sha256).unwrap(), v["family_name_digest"].as_str().unwrap());
    assert_eq!(sdjwt::describe(d).unwrap(), (Some("family_name".to_string()), json!("Doe")));
}

#[test]
fn rfc9901_issued_sd_jwt_verifies_and_discloses_everything() {
    let v = vector();
    let r = sdjwt::verify(v["issued"].as_str().unwrap(), &jwk(&v["issuer_pub"]), &{ let mut p = policy(None); p.now = Some(1_700_000_000); p }).unwrap();
    let c = &r.claims;
    assert_eq!(c["given_name"], "John");
    assert_eq!(c["family_name"], "Doe");
    assert_eq!(c["email"], "johndoe@example.com");
    assert_eq!(c["phone_number_verified"], true);
    assert_eq!(c["address"]["locality"], "Anytown");
    assert_eq!(c["birthdate"], "1940-01-01");
    assert_eq!(c["nationalities"], json!(["US", "DE"]));
    assert!(!c.contains_key("_sd") && !c.contains_key("_sd_alg"));
    assert!(!r.key_binding_verified);
    assert_eq!(r.header.typ.as_deref(), Some("example+sd-jwt"));
}

#[test]
fn rfc9901_presentation_with_key_binding_verifies() {
    let v = vector();
    let r = sdjwt::verify(v["presentation"].as_str().unwrap(), &jwk(&v["issuer_pub"]), &policy(Some(kb_policy()))).expect("the RFC's own presentation");
    assert!(r.key_binding_verified);
    // Exactly the disclosed claims; the hidden ones are absent, one nationality was withheld.
    assert_eq!(r.claims["family_name"], "Doe");
    assert_eq!(r.claims["given_name"], "John");
    assert_eq!(r.claims["nationalities"], json!(["US"]));
    for hidden in ["email", "phone_number", "birthdate", "updated_at"] { assert!(!r.claims.contains_key(hidden), "{hidden}"); }
}

#[test]
fn rfc9901_presentation_fails_when_any_binding_input_differs() {
    let v = vector();
    let pres = v["presentation"].as_str().unwrap();
    let key = jwk(&v["issuer_pub"]);
    let try_with = |f: &dyn Fn(&mut KeyBindingPolicy)| { let mut k = kb_policy(); f(&mut k); sdjwt::verify(pres, &key, &policy(Some(k))) };
    assert!(try_with(&|k| k.nonce = "other").is_err(), "nonce");
    assert!(try_with(&|k| k.audience = "https://evil.example").is_err(), "aud");
    assert!(try_with(&|_| {}).is_ok());
    let mut stale = policy(Some(kb_policy())); stale.now = Some(1_748_537_244 + 1000);
    assert!(sdjwt::verify(pres, &key, &stale).is_err(), "key binding too old");
    let mut future = policy(Some(kb_policy())); future.now = Some(1_748_537_244 - 1000);
    assert!(sdjwt::verify(pres, &key, &future).is_err(), "key binding from the future");
    let mut wrong_iss = policy(Some(kb_policy())); wrong_iss.issuer = "https://evil.example";
    assert!(sdjwt::verify(pres, &key, &wrong_iss).is_err(), "issuer");
    // Adding or removing a disclosure after binding breaks sd_hash.
    let parts: Vec<&str> = pres.split('~').collect();
    let dropped = format!("{}~{}~{}~{}", parts[0], parts[1], parts[2], parts[parts.len() - 1]);
    assert!(sdjwt::verify(&dropped, &key, &policy(Some(kb_policy()))).is_err(), "dropped disclosure");
    let extra = format!("{}~{}~{}~{}~{}~{}~{}", parts[0], parts[1], parts[2], parts[3], parts[4], v["family_name_disclosure"].as_str().unwrap(), parts[5]);
    assert!(sdjwt::verify(&extra, &key, &policy(Some(kb_policy()))).is_err(), "added disclosure");
    // Wrong issuer key.
    let other = Jwk::parse(&json!({"kty":"EC","crv":"P-256","x":"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc","y":"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}).to_string()).unwrap();
    assert_eq!(sdjwt::verify(pres, &other, &policy(Some(kb_policy()))).unwrap_err(), Error::BadSignature);
}

#[test]
fn key_binding_requirement_is_the_verifiers_decision() {
    let v = vector();
    let key = jwk(&v["issuer_pub"]);
    let pres = v["presentation"].as_str().unwrap();
    // Required but missing: the holder dropped the KB-JWT.
    let no_kb: String = pres.rsplit_once('~').map(|(a, _)| format!("{a}~")).unwrap();
    assert!(sdjwt::verify(&no_kb, &key, &policy(Some(kb_policy()))).is_err());
    // Not required: both forms are accepted and key binding is reported as not verified for the bare form.
    assert!(!sdjwt::verify(&no_kb, &key, &policy(None)).unwrap().key_binding_verified);
    assert!(!sdjwt::verify(pres, &key, &policy(None)).unwrap().key_binding_verified, "a KB-JWT is not trusted when the policy did not ask for it");
}

// ---------- issuance round trip ----------

fn ec() -> Option<Jwk> {
    match authlas::crypto::ec_generate("P-256") { Ok(k) => Some(k), Err(Error::Unsupported(m)) => { eprintln!("SKIP: {m}"); None }, Err(e) => panic!("{e}") }
}

fn claims() -> Map<String, Value> {
    json!({"iss": "https://issuer.example.com", "sub": "user_42", "iat": 1_748_537_000u64, "exp": 1_883_000_000u64,
        "given_name": "John", "family_name": "Doe", "address": {"street": "123 Main", "country": "US"},
        "nationalities": ["US", "DE", "FR"]}).as_object().unwrap().clone()
}

fn issue(isk: &Jwk, holder: Option<&Jwk>, hide: &[&str], decoys: usize) -> sdjwt::Issued {
    Issuer { alg: ES256, key: isk, hash: Hash::Sha256, decoys, holder_key: holder, typ: "example+sd-jwt" }
        .issue(&claims(), &hide.iter().map(|p| path(p)).collect::<Vec<_>>()).unwrap()
}

#[test]
fn issue_hold_present_verify() {
    let (Some(isk), Some(hsk)) = (ec(), ec()) else { return };
    let issued = issue(&isk, Some(&hsk.public().unwrap()), &["given_name", "family_name", "address/street", "address", "nationalities/1"], 3);
    assert_eq!(issued.disclosures.len(), 5);
    let pubk = isk.public().unwrap();
    // The issuer JWT payload shows nothing that was hidden.
    let payload = String::from_utf8(b64::decode(issued.compact.split('.').nth(1).unwrap()).unwrap()).unwrap();
    for secret in ["John", "Doe", "123 Main"] { assert!(!payload.contains(secret), "{secret} leaked"); }
    // Holder reveals only family_name.
    let idx = issued.disclosures.iter().position(|d| sdjwt::describe(d).unwrap().0.as_deref() == Some("family_name")).unwrap();
    let pres = Presentation { sd_jwt: &issued.compact, reveal: &[idx] }.build().unwrap();
    let with_kb = Presentation::with_key_binding(&pres, Hash::Sha256, ES256, &hsk, "https://verifier.example.org", "n-1").unwrap();
    let mut p = policy(Some(KeyBindingPolicy { algs: &[ES256], audience: "https://verifier.example.org", nonce: "n-1", max_age: 60 }));
    p.now = None;
    let r = sdjwt::verify(&with_kb, &pubk, &p).unwrap();
    assert_eq!(r.claims["family_name"], "Doe");
    assert!(!r.claims.contains_key("given_name") && !r.claims.contains_key("address"));
    assert_eq!(r.claims["nationalities"], json!(["US", "FR"]), "the hidden element is removed, not nulled");
    assert!(r.key_binding_verified);
    // Revealing a nested claim requires its parent: with only the child, the verifier sees nothing of it.
    let street = issued.disclosures.iter().position(|d| sdjwt::describe(d).unwrap().0.as_deref() == Some("street")).unwrap();
    let only_child = Presentation { sd_jwt: &issued.compact, reveal: &[street] }.build().unwrap();
    assert!(sdjwt::verify(&only_child, &pubk, &{ let mut p = policy(None); p.now = None; p }).is_err(), "a disclosure whose parent is hidden is unreferenced");
    // Everything.
    let all: Vec<usize> = (0..issued.disclosures.len()).collect();
    let full = Presentation { sd_jwt: &issued.compact, reveal: &all }.build().unwrap();
    let r = sdjwt::verify(&full, &pubk, &{ let mut p = policy(None); p.now = None; p }).unwrap();
    assert_eq!(r.claims["address"], json!({"street": "123 Main", "country": "US"}));
    assert_eq!(r.claims["nationalities"], json!(["US", "DE", "FR"]));
    assert_eq!(r.claims["given_name"], "John");
}

#[test]
fn decoys_and_sorting_hide_the_count() {
    let Some(isk) = ec() else { return };
    let a = issue(&isk, None, &["given_name"], 0);
    let b = issue(&isk, None, &["given_name"], 5);
    let n = |t: &str| serde_json::from_slice::<Value>(&b64::decode(t.split('.').nth(1).unwrap()).unwrap()).unwrap()["_sd"].as_array().unwrap().len();
    assert_eq!((n(&a.compact), n(&b.compact)), (1, 6));
    let sd = serde_json::from_slice::<Value>(&b64::decode(b.compact.split('.').nth(1).unwrap()).unwrap()).unwrap()["_sd"].clone();
    let list: Vec<&str> = sd.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    assert!(list.windows(2).all(|w| w[0] <= w[1]), "digests are sorted so position reveals nothing");
    // Decoys verify fine: they have no disclosure and are ignored.
    let mut p = policy(None); p.now = None;
    sdjwt::verify(&b.compact, &isk.public().unwrap(), &p).unwrap();
}

#[test]
fn salts_are_random() {
    let Some(isk) = ec() else { return };
    let a = issue(&isk, None, &["given_name"], 0);
    let b = issue(&isk, None, &["given_name"], 0);
    assert_ne!(a.disclosures[0], b.disclosures[0], "same claim, different salt");
}

// ---------- hostile inputs ----------

fn hand_made(isk: &Jwk, payload: Value, disclosures: &[Value]) -> String {
    let jws = authlas::jws::sign(ES256, isk, &Map::new(), payload.to_string().as_bytes()).unwrap();
    let mut s = format!("{jws}~");
    for d in disclosures { s.push_str(&b64::encode(d.to_string())); s.push('~'); }
    s
}
fn dg(d: &Value) -> String { sdjwt::disclosure_digest(&b64::encode(d.to_string()), Hash::Sha256).unwrap() }
fn base(extra: Value) -> Value {
    let mut b = json!({"iss": "https://issuer.example.com", "exp": 1_883_000_000u64, "iat": 1_748_537_000u64});
    for (k, v) in extra.as_object().unwrap() { b[k] = v.clone(); }
    b
}

#[test]
fn spec_must_reject_cases() {
    let Some(isk) = ec() else { return };
    let pubk = isk.public().unwrap();
    let mut pol = policy(None); pol.now = None;
    let ok_d = json!(["salt1", "name", "Alice"]);
    // sanity: well-formed passes
    let good = hand_made(&isk, base(json!({"_sd": [dg(&ok_d)]})), &[ok_d.clone()]);
    assert_eq!(sdjwt::verify(&good, &pubk, &pol).unwrap().claims["name"], "Alice");
    let reject = |label: &str, s: String| assert!(sdjwt::verify(&s, &pubk, &pol).is_err(), "{label}");
    // Digest used twice.
    reject("digest twice in _sd", hand_made(&isk, base(json!({"_sd": [dg(&ok_d), dg(&ok_d)]})), &[ok_d.clone()]));
    reject("digest in two places", hand_made(&isk, base(json!({"_sd": [dg(&ok_d)], "other": {"_sd": [dg(&ok_d)]}})), &[ok_d.clone()]));
    // Disclosure that nothing refers to.
    reject("unreferenced disclosure", hand_made(&isk, base(json!({})), &[ok_d.clone()]));
    // Same disclosure sent twice.
    reject("duplicate disclosure", hand_made(&isk, base(json!({"_sd": [dg(&ok_d)]})), &[ok_d.clone(), ok_d.clone()]));
    // Claim name collides with a plaintext claim.
    let clash = json!(["s", "iss", "https://evil.example"]);
    reject("name already exists", hand_made(&isk, base(json!({"_sd": [dg(&clash)]})), &[clash]));
    // Two disclosures for the same name.
    let (n1, n2) = (json!(["s1", "x", 1]), json!(["s2", "x", 2]));
    reject("same name twice", hand_made(&isk, base(json!({"_sd": [dg(&n1), dg(&n2)]})), &[n1, n2]));
    // Reserved names.
    for bad in ["_sd", "..."] {
        let d = json!(["s", bad, "x"]);
        reject(bad, hand_made(&isk, base(json!({"_sd": [dg(&d)]})), &[d]));
    }
    // Wrong shapes.
    let two = json!(["s", "v"]); // array-shaped in an object
    reject("object disclosure with 2 elements", hand_made(&isk, base(json!({"_sd": [dg(&two)]})), &[two]));
    let three = json!(["s", "n", "v"]); // object-shaped in an array
    reject("array disclosure with 3 elements", hand_made(&isk, base(json!({"list": [{"...": dg(&three)}]})), &[three]));
    let not_arr = json!({"a": 1});
    reject("disclosure is an object", hand_made(&isk, base(json!({"_sd": [dg(&not_arr)]})), &[not_arr]));
    let num_name = json!(["s", 7, "v"]);
    reject("name not a string", hand_made(&isk, base(json!({"_sd": [dg(&num_name)]})), &[num_name]));
    reject("_sd not an array", hand_made(&isk, base(json!({"_sd": "oops"})), &[]));
    reject("_sd entries not strings", hand_made(&isk, base(json!({"_sd": [5]})), &[]));
    reject("... not a string", hand_made(&isk, base(json!({"list": [{"...": 5}]})), &[]));
    // Garbage disclosure bytes.
    reject("not base64", format!("{}~!!!~", good.split('~').next().unwrap()));
    reject("not json", format!("{}~{}~", good.split('~').next().unwrap(), b64::encode("not json")));
    // Missing trailing tilde / empty disclosure.
    reject("no trailing tilde", good.trim_end_matches('~').to_string());
    reject("empty disclosure", format!("{}~~", good.split('~').next().unwrap()));
    // A decoy-style digest with no disclosure is fine, and so is an array element whose disclosure was withheld.
    let withheld = hand_made(&isk, base(json!({"list": ["a", {"...": "dGVzdA"}, "b"]})), &[]);
    assert_eq!(sdjwt::verify(&withheld, &pubk, &pol).unwrap().claims["list"], json!(["a", "b"]));
    // Nested recursion: a disclosure revealing a value that itself contains _sd.
    let inner = json!(["s2", "city", "Paris"]);
    let outer = json!(["s1", "address", {"_sd": [dg(&inner)]}]);
    let nested = hand_made(&isk, base(json!({"_sd": [dg(&outer)]})), &[outer.clone(), inner.clone()]);
    assert_eq!(sdjwt::verify(&nested, &pubk, &pol).unwrap().claims["address"], json!({"city": "Paris"}));
    // The same digest referenced at two levels (top-level _sd and again inside a disclosed value) is refused.
    let twice = json!(["s1", "address", {"_sd": [dg(&inner)]}]);
    reject("digest at two levels", hand_made(&isk, base(json!({"_sd": [dg(&twice), dg(&inner)]})), &[twice, inner.clone()]));
}

#[test]
fn hash_algorithm_policy() {
    let Some(isk) = ec() else { return };
    let pubk = isk.public().unwrap();
    let d = json!(["s", "n", "v"]);
    let md5 = hand_made(&isk, base(json!({"_sd_alg": "md5", "_sd": ["x"]})), &[]);
    let mut pol = policy(None); pol.now = None;
    assert!(sdjwt::verify(&md5, &pubk, &pol).is_err(), "unknown/weak _sd_alg");
    assert!(sdjwt::verify(&hand_made(&isk, base(json!({"_sd_alg": 5})), &[]), &pubk, &pol).is_err());
    // sha-512 is understood; policy can still restrict.
    let dg512 = sdjwt::disclosure_digest(&b64::encode(d.to_string()), Hash::Sha512).unwrap();
    let s512 = hand_made(&isk, base(json!({"_sd_alg": "sha-512", "_sd": [dg512]})), &[d.clone()]);
    assert_eq!(sdjwt::verify(&s512, &pubk, &pol).unwrap().claims["n"], "v");
    pol.hashes = &[Hash::Sha256];
    assert!(matches!(sdjwt::verify(&s512, &pubk, &pol), Err(Error::Algorithm(_))));
}

#[test]
fn issuer_jwt_is_validated_as_a_jwt() {
    let Some(isk) = ec() else { return };
    let pubk = isk.public().unwrap();
    let mut pol = policy(None);
    pol.now = Some(1_900_000_000);
    let expired = hand_made(&isk, base(json!({})), &[]);
    assert!(matches!(sdjwt::verify(&expired, &pubk, &pol), Err(Error::Claim(_))), "exp in the past");
    pol.now = None;
    let wrong_iss = hand_made(&isk, json!({"iss": "https://evil.example", "exp": 1_883_000_000u64}), &[]);
    assert!(sdjwt::verify(&wrong_iss, &pubk, &pol).is_err());
    let no_exp = hand_made(&isk, json!({"iss": "https://issuer.example.com"}), &[]);
    assert!(sdjwt::verify(&no_exp, &pubk, &pol).is_ok(), "exp optional unless required");
    pol.require = &["exp"];
    assert!(sdjwt::verify(&no_exp, &pubk, &pol).is_err(), "verifier can require exp");
    // typ pinning.
    pol.require = &[];
    pol.typ = Some("dc+sd-jwt");
    assert!(sdjwt::verify(&hand_made(&isk, base(json!({})), &[]), &pubk, &pol).is_err(), "no typ");
}

#[test]
fn key_binding_needs_a_cnf_and_a_correct_key() {
    let (Some(isk), Some(hsk), Some(other)) = (ec(), ec(), ec()) else { return };
    let pubk = isk.public().unwrap();
    let mk = |holder: Option<&Jwk>| {
        let i = issue(&isk, holder, &["given_name"], 0);
        Presentation { sd_jwt: &i.compact, reveal: &[0] }.build().unwrap()
    };
    let pol = |nonce| { let mut p = policy(Some(KeyBindingPolicy { algs: &[ES256], audience: "v", nonce, max_age: 60 })); p.now = None; p };
    // No cnf in the credential: key binding cannot be satisfied.
    let pres = mk(None);
    let kb = Presentation::with_key_binding(&pres, Hash::Sha256, ES256, &hsk, "v", "n").unwrap();
    assert!(sdjwt::verify(&kb, &pubk, &pol("n")).is_err());
    // Signed by a key other than the one in cnf.
    let pres = mk(Some(&hsk.public().unwrap()));
    let forged = Presentation::with_key_binding(&pres, Hash::Sha256, ES256, &other, "v", "n").unwrap();
    assert_eq!(sdjwt::verify(&forged, &pubk, &pol("n")).unwrap_err(), Error::BadSignature);
    // The right key works; a replay with another nonce does not.
    let good = Presentation::with_key_binding(&pres, Hash::Sha256, ES256, &hsk, "v", "n").unwrap();
    assert!(sdjwt::verify(&good, &pubk, &pol("n")).unwrap().key_binding_verified);
    assert!(sdjwt::verify(&good, &pubk, &pol("n2")).is_err());
    // A holder never accepts a presentation that already has a KB-JWT, and cannot bind a private key into cnf.
    assert!(Presentation { sd_jwt: &good, reveal: &[] }.build().is_err());
    assert!(Issuer { alg: ES256, key: &isk, hash: Hash::Sha256, decoys: 0, holder_key: Some(&hsk), typ: "t" }.issue(&claims(), &[]).is_err());
}

#[test]
fn issuer_input_validation() {
    let Some(isk) = ec() else { return };
    let i = |hide: &[&str]| Issuer { alg: ES256, key: &isk, hash: Hash::Sha256, decoys: 0, holder_key: None, typ: "t" }
        .issue(&claims(), &hide.iter().map(|p| path(p)).collect::<Vec<_>>());
    assert!(i(&["nope"]).is_err());
    assert!(i(&["address/nope"]).is_err());
    assert!(i(&["nationalities/9"]).is_err());
    assert!(i(&["given_name/x"]).is_err());
    assert!(i(&[""]).is_err());
    let mut c = claims();
    c.insert("_sd".into(), json!("x"));
    assert!(Issuer { alg: ES256, key: &isk, hash: Hash::Sha256, decoys: 0, holder_key: None, typ: "t" }.issue(&c, &[path("_sd")]).is_err(), "reserved name cannot be hidden");
    // Plain issuance with nothing hidden carries no _sd_alg and needs no disclosures.
    let plain = i(&[]).unwrap();
    assert!(plain.disclosures.is_empty() && plain.compact.ends_with('~'));
}
