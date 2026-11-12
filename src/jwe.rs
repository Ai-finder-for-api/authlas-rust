//! JSON Web Encryption, compact serialization (RFC 7516, algorithms from RFC 7518 and RFC 8037).
//!
//! Supported `alg`: dir, A128KW/A192KW/A256KW, A128GCMKW/A192GCMKW/A256GCMKW, RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384, RSA-OAEP-512,
//! ECDH-ES, ECDH-ES+A128KW/A192KW/A256KW (P-256, P-384, P-521, X25519), PBES2-HS256/384/512+A128KW/A192KW/A256KW.
//! Supported `enc`: A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, A256GCM.
//!
//! Deliberately not supported:
//!  * `RSA1_5` (PKCS#1 v1.5 key transport): Bleichenbacher-style oracle, RFC 8725 section 3.2 says do not use it.
//!  * `zip` (compression): decompression bombs and compression side channels. A token with `zip` is rejected.
//!  * Multi-recipient / JSON serializations (a later item).
//!
//! Failure behaviour: every decryption failure returns the same `Error::Decrypt`. When the key cannot be
//! unwrapped, a random CEK of the right length is used instead, so that wrapping errors and tag errors
//! cost the same and look the same (RFC 7516 section 11.5).
use crate::{b64, crypto::{self, AeadAlg, OaepHash}, error::{Error, Result}, json, jwa::Hash, jwk::Jwk};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyAlg {
    Dir,
    A128Kw, A192Kw, A256Kw,
    A128GcmKw, A192GcmKw, A256GcmKw,
    RsaOaep, RsaOaep256, RsaOaep384, RsaOaep512,
    EcdhEs, EcdhEsA128Kw, EcdhEsA192Kw, EcdhEsA256Kw,
    Pbes2Hs256A128Kw, Pbes2Hs384A192Kw, Pbes2Hs512A256Kw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Enc { A128CbcHs256, A192CbcHs384, A256CbcHs512, A128Gcm, A192Gcm, A256Gcm }

impl KeyAlg {
    pub fn as_str(self) -> &'static str {
        use KeyAlg::*;
        match self {
            Dir => "dir", A128Kw => "A128KW", A192Kw => "A192KW", A256Kw => "A256KW",
            A128GcmKw => "A128GCMKW", A192GcmKw => "A192GCMKW", A256GcmKw => "A256GCMKW",
            RsaOaep => "RSA-OAEP", RsaOaep256 => "RSA-OAEP-256", RsaOaep384 => "RSA-OAEP-384", RsaOaep512 => "RSA-OAEP-512",
            EcdhEs => "ECDH-ES", EcdhEsA128Kw => "ECDH-ES+A128KW", EcdhEsA192Kw => "ECDH-ES+A192KW", EcdhEsA256Kw => "ECDH-ES+A256KW",
            Pbes2Hs256A128Kw => "PBES2-HS256+A128KW", Pbes2Hs384A192Kw => "PBES2-HS384+A192KW", Pbes2Hs512A256Kw => "PBES2-HS512+A256KW",
        }
    }
}

impl std::str::FromStr for KeyAlg {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        use KeyAlg::*;
        Ok(match s {
            "dir" => Dir, "A128KW" => A128Kw, "A192KW" => A192Kw, "A256KW" => A256Kw,
            "A128GCMKW" => A128GcmKw, "A192GCMKW" => A192GcmKw, "A256GCMKW" => A256GcmKw,
            "RSA-OAEP" => RsaOaep, "RSA-OAEP-256" => RsaOaep256, "RSA-OAEP-384" => RsaOaep384, "RSA-OAEP-512" => RsaOaep512,
            "ECDH-ES" => EcdhEs, "ECDH-ES+A128KW" => EcdhEsA128Kw, "ECDH-ES+A192KW" => EcdhEsA192Kw, "ECDH-ES+A256KW" => EcdhEsA256Kw,
            "PBES2-HS256+A128KW" => Pbes2Hs256A128Kw, "PBES2-HS384+A192KW" => Pbes2Hs384A192Kw, "PBES2-HS512+A256KW" => Pbes2Hs512A256Kw,
            "RSA1_5" => return Err(Error::Algorithm("RSA1_5 is not supported (Bleichenbacher oracle, RFC 8725 3.2)".into())),
            other => return Err(Error::Algorithm(format!("unsupported JWE alg {other:?}"))),
        })
    }
}

impl Enc {
    pub fn as_str(self) -> &'static str {
        match self {
            Enc::A128CbcHs256 => "A128CBC-HS256", Enc::A192CbcHs384 => "A192CBC-HS384", Enc::A256CbcHs512 => "A256CBC-HS512",
            Enc::A128Gcm => "A128GCM", Enc::A192Gcm => "A192GCM", Enc::A256Gcm => "A256GCM",
        }
    }
    /// Content encryption key length in bytes.
    pub fn cek_len(self) -> usize {
        match self { Enc::A128CbcHs256 => 32, Enc::A192CbcHs384 => 48, Enc::A256CbcHs512 => 64, Enc::A128Gcm => 16, Enc::A192Gcm => 24, Enc::A256Gcm => 32 }
    }
    fn iv_len(self) -> usize { match self { Enc::A128CbcHs256 | Enc::A192CbcHs384 | Enc::A256CbcHs512 => 16, _ => 12 } }
}

impl std::str::FromStr for Enc {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "A128CBC-HS256" => Enc::A128CbcHs256, "A192CBC-HS384" => Enc::A192CbcHs384, "A256CBC-HS512" => Enc::A256CbcHs512,
            "A128GCM" => Enc::A128Gcm, "A192GCM" => Enc::A192Gcm, "A256GCM" => Enc::A256Gcm,
            other => return Err(Error::Algorithm(format!("unsupported JWE enc {other:?}"))),
        })
    }
}

/// Decryption policy. There is no permissive default.
#[derive(Debug, Clone)]
pub struct Policy<'a> {
    pub allowed_alg: &'a [KeyAlg],
    pub allowed_enc: &'a [Enc],
    pub understood_crit: &'a [&'a str],
    /// Accepted PBES2 iteration count range (guards against both weak keys and CPU exhaustion).
    pub pbes2_min_iter: u32,
    pub pbes2_max_iter: u32,
    /// Maximum compact token length in bytes.
    pub max_token_len: usize,
}

impl<'a> Policy<'a> {
    pub fn new(allowed_alg: &'a [KeyAlg], allowed_enc: &'a [Enc]) -> Self {
        Policy { allowed_alg, allowed_enc, understood_crit: &[], pbes2_min_iter: 1000, pbes2_max_iter: 1_000_000, max_token_len: 256 * 1024 }
    }
}

/// Parsed protected header.
#[derive(Debug, Clone)]
pub struct Header {
    pub alg: KeyAlg,
    pub enc: Enc,
    pub kid: Option<String>,
    pub raw: Map<String, Value>,
}

fn hash_for_pbes(a: KeyAlg) -> (Hash, usize) {
    match a { KeyAlg::Pbes2Hs256A128Kw => (Hash::Sha256, 16), KeyAlg::Pbes2Hs384A192Kw => (Hash::Sha384, 24), _ => (Hash::Sha512, 32) }
}
fn oaep_hash(a: KeyAlg) -> OaepHash {
    match a { KeyAlg::RsaOaep => OaepHash::Sha1, KeyAlg::RsaOaep256 => OaepHash::Sha256, KeyAlg::RsaOaep384 => OaepHash::Sha384, _ => OaepHash::Sha512 }
}
fn kw_len(a: KeyAlg) -> usize {
    match a { KeyAlg::A128Kw | KeyAlg::A128GcmKw | KeyAlg::EcdhEsA128Kw => 16, KeyAlg::A192Kw | KeyAlg::A192GcmKw | KeyAlg::EcdhEsA192Kw => 24, _ => 32 }
}
fn is_ecdh(a: KeyAlg) -> bool { matches!(a, KeyAlg::EcdhEs | KeyAlg::EcdhEsA128Kw | KeyAlg::EcdhEsA192Kw | KeyAlg::EcdhEsA256Kw) }
fn is_gcmkw(a: KeyAlg) -> bool { matches!(a, KeyAlg::A128GcmKw | KeyAlg::A192GcmKw | KeyAlg::A256GcmKw) }
fn gcmkw_alg(a: KeyAlg) -> AeadAlg { match a { KeyAlg::A128GcmKw => AeadAlg::A128Gcm, KeyAlg::A192GcmKw => AeadAlg::A192Gcm, _ => AeadAlg::A256Gcm } }
fn is_rsa(a: KeyAlg) -> bool { matches!(a, KeyAlg::RsaOaep | KeyAlg::RsaOaep256 | KeyAlg::RsaOaep384 | KeyAlg::RsaOaep512) }

/// NIST SP 800-56A Concat KDF with SHA-256, as profiled by RFC 7518 section 4.6.2.
fn concat_kdf(z: &[u8], alg_id: &str, apu: &[u8], apv: &[u8], key_bits: u32, out_len: usize) -> Result<Vec<u8>> {
    let lp = |d: &[u8]| { let mut v = (d.len() as u32).to_be_bytes().to_vec(); v.extend_from_slice(d); v };
    let mut other = lp(alg_id.as_bytes());
    other.extend(lp(apu));
    other.extend(lp(apv));
    other.extend(key_bits.to_be_bytes());
    let mut out = Vec::new();
    let mut ctr = 1u32;
    while out.len() < out_len {
        let mut input = ctr.to_be_bytes().to_vec();
        input.extend_from_slice(z);
        input.extend_from_slice(&other);
        out.extend(crypto::digest(Hash::Sha256, &input)?);
        ctr += 1;
    }
    out.truncate(out_len);
    Ok(out)
}

fn aes_gcm_alg(e: Enc) -> AeadAlg { match e { Enc::A128Gcm => AeadAlg::A128Gcm, Enc::A192Gcm => AeadAlg::A192Gcm, _ => AeadAlg::A256Gcm } }

/// Content encryption. Returns (ciphertext, tag).
fn content_encrypt(enc: Enc, cek: &[u8], iv: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if cek.len() != enc.cek_len() { return Err(Error::Key("wrong CEK length for enc".into())); }
    match enc {
        Enc::A128Gcm | Enc::A192Gcm | Enc::A256Gcm => crypto::aead_seal(aes_gcm_alg(enc), cek, iv, aad, pt),
        _ => {
            let (mac_key, enc_key) = cek.split_at(cek.len() / 2);
            let ct = crypto::cbc_encrypt(enc_key, iv, pt)?;
            let tag = cbc_tag(enc, mac_key, aad, iv, &ct)?;
            Ok((ct, tag))
        }
    }
}

fn cbc_tag(enc: Enc, mac_key: &[u8], aad: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let h = match enc { Enc::A128CbcHs256 => Hash::Sha256, Enc::A192CbcHs384 => Hash::Sha384, _ => Hash::Sha512 };
    let mut m = aad.to_vec();
    m.extend_from_slice(iv);
    m.extend_from_slice(ct);
    m.extend_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    let mut t = crypto::hmac(h, mac_key, &m)?;
    t.truncate(mac_key.len());
    Ok(t)
}

/// Backend availability problems (library missing, hash pin mismatch, operation unsupported) do not
/// depend on the attacker's input, so they are reported as what they are. Everything else is `Decrypt`.
fn scrub(e: Error) -> Error {
    match e { Error::Crypto(_) | Error::Unsupported(_) => e, _ => Error::Decrypt }
}

fn content_decrypt(enc: Enc, cek: &[u8], iv: &[u8], aad: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    if cek.len() != enc.cek_len() || iv.len() != enc.iv_len() { return Err(Error::Decrypt); }
    match enc {
        Enc::A128Gcm | Enc::A192Gcm | Enc::A256Gcm => crypto::aead_open(aes_gcm_alg(enc), cek, iv, aad, ct, tag).map_err(scrub),
        _ => {
            let (mac_key, enc_key) = cek.split_at(cek.len() / 2);
            let want = cbc_tag(enc, mac_key, aad, iv, ct).map_err(scrub)?;
            if !crypto::ct_eq(&want, tag) { return Err(Error::Decrypt); }
            crypto::cbc_decrypt(enc_key, iv, ct).map_err(scrub)
        }
    }
}

fn rand(n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    crypto::random(&mut v)?;
    Ok(v)
}

fn str_member<'a>(h: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>> {
    match h.get(k) { None => Ok(None), Some(Value::String(s)) => Ok(Some(s)), Some(_) => Err(Error::Malformed(format!("{k} must be a string"))) }
}

fn oct_key(k: &Jwk) -> Result<Vec<u8>> {
    if k.kty != "oct" { return Err(Error::Key("this alg needs an oct key".into())); }
    k.req("k")
}

fn check_key_use(k: &Jwk, op: &str) -> Result<()> {
    if let Some(u) = &k.use_ { if u != "enc" { return Err(Error::Key(format!("key use is {u:?}, not \"enc\""))); } }
    if let Some(ops) = &k.key_ops {
        let ok = ops.iter().any(|o| o == op || (op == "encrypt" && o == "wrapKey") || (op == "decrypt" && o == "unwrapKey")
            || o == "deriveKey" || o == "deriveBits");
        if !ok { return Err(Error::Key(format!("key_ops does not permit {op:?}"))); }
    }
    Ok(())
}

/// Produces (cek, encrypted_key) for encryption; may add members (epk, p2c, p2s) to the header.
fn wrap_cek(alg: KeyAlg, enc: Enc, key: &Jwk, hdr: &mut Map<String, Value>) -> Result<(Vec<u8>, Vec<u8>)> {
    match alg {
        KeyAlg::Dir => {
            let k = oct_key(key)?;
            if k.len() != enc.cek_len() { return Err(Error::Key(format!("dir key must be {} bytes for {}", enc.cek_len(), enc.as_str()))); }
            Ok((k, Vec::new()))
        }
        KeyAlg::A128Kw | KeyAlg::A192Kw | KeyAlg::A256Kw => {
            let kek = oct_key(key)?;
            if kek.len() != kw_len(alg) { return Err(Error::Key(format!("{} needs a {}-byte key", alg.as_str(), kw_len(alg)))); }
            let cek = rand(enc.cek_len())?;
            let ek = crypto::aes_kw_wrap(&kek, &cek)?;
            Ok((cek, ek))
        }
        a if is_gcmkw(a) => {
            let kek = oct_key(key)?;
            if kek.len() != kw_len(a) { return Err(Error::Key(format!("{} needs a {}-byte key", a.as_str(), kw_len(a)))); }
            let iv = rand(crypto::GCM_IV_LEN)?;
            let cek = rand(enc.cek_len())?;
            // RFC 7518 4.7: the wrapped key is the AES-GCM ciphertext with an empty AAD; iv and tag go in the header.
            let (ek, tag) = crypto::aead_seal(gcmkw_alg(a), &kek, &iv, &[], &cek)?;
            hdr.insert("iv".into(), Value::String(b64::encode(&iv)));
            hdr.insert("tag".into(), Value::String(b64::encode(&tag)));
            Ok((cek, ek))
        }
        a if is_rsa(a) => {
            let cek = rand(enc.cek_len())?;
            let ek = crypto::rsa_oaep_encrypt(oaep_hash(a), key, &cek)?;
            Ok((cek, ek))
        }
        a if is_ecdh(a) => {
            let (crv, _) = crypto::check_agreement_key(key)?;
            let eph = crypto::ec_generate(&crv)?;
            let z = crypto::ecdh(&eph, &key.public()?)?;
            let epk = eph.public()?;
            hdr.insert("epk".into(), serde_json::to_value(&epk)?);
            let apu = str_member(hdr, "apu")?.map(b64::decode).transpose()?.unwrap_or_default();
            let apv = str_member(hdr, "apv")?.map(b64::decode).transpose()?.unwrap_or_default();
            if a == KeyAlg::EcdhEs {
                let cek = concat_kdf(&z, enc.as_str(), &apu, &apv, (enc.cek_len() * 8) as u32, enc.cek_len())?;
                Ok((cek, Vec::new()))
            } else {
                let n = kw_len(a);
                let kek = concat_kdf(&z, a.as_str(), &apu, &apv, (n * 8) as u32, n)?;
                let cek = rand(enc.cek_len())?;
                let ek = crypto::aes_kw_wrap(&kek, &cek)?;
                Ok((cek, ek))
            }
        }
        a => {
            // PBES2
            let pw = oct_key(key)?;
            let (h, n) = hash_for_pbes(a);
            let p2c = match hdr.get("p2c") {
                Some(v) => v.as_u64().ok_or_else(|| Error::Malformed("p2c must be an integer".into()))? as u32,
                None => 600_000,
            };
            let p2s_raw = match str_member(hdr, "p2s")? { Some(s) => b64::decode(s)?, None => rand(16)? };
            if p2s_raw.len() < 8 { return Err(Error::Key("p2s must be at least 8 bytes".into())); }
            hdr.insert("p2c".into(), json!(p2c));
            hdr.insert("p2s".into(), Value::String(b64::encode(&p2s_raw)));
            let mut salt = a.as_str().as_bytes().to_vec();
            salt.push(0);
            salt.extend_from_slice(&p2s_raw);
            let kek = crypto::pbkdf2(h, &pw, &salt, p2c, n)?;
            let cek = rand(enc.cek_len())?;
            let ek = crypto::aes_kw_wrap(&kek, &cek)?;
            Ok((cek, ek))
        }
    }
}

/// Encrypts `plaintext` to a compact JWE. `extra` members (kid, apu, apv, p2c, ...) are merged into the
/// protected header; `alg` and `enc` always come from the arguments.
pub fn encrypt(alg: KeyAlg, enc: Enc, key: &Jwk, extra: &Map<String, Value>, plaintext: &[u8]) -> Result<String> {
    check_key_use(key, "encrypt")?;
    let mut hdr = extra.clone();
    for banned in ["zip", "epk", "iv", "tag"] {
        if hdr.contains_key(banned) { return Err(Error::Malformed(format!("{banned:?} cannot be set by the caller"))); }
    }
    hdr.insert("alg".into(), Value::String(alg.as_str().into()));
    hdr.insert("enc".into(), Value::String(enc.as_str().into()));
    if let Some(kid) = &key.kid { hdr.entry("kid").or_insert_with(|| Value::String(kid.clone())); }
    let (cek, ek) = wrap_cek(alg, enc, key, &mut hdr)?;
    let h64 = b64::encode(serde_json::to_vec(&hdr)?);
    let iv = rand(enc.iv_len())?;
    let (ct, tag) = content_encrypt(enc, &cek, &iv, h64.as_bytes(), plaintext)?;
    Ok(format!("{h64}.{}.{}.{}.{}", b64::encode(ek), b64::encode(&iv), b64::encode(ct), b64::encode(tag)))
}

fn split5(t: &str) -> Result<[&str; 5]> {
    let p: Vec<&str> = t.split('.').collect();
    p.try_into().map_err(|_| Error::Malformed("compact JWE must have exactly five segments".into()))
}

fn parse_header(h64: &str) -> Result<Header> {
    let raw = json::parse_object(&b64::decode(h64)?)?;
    let alg = str_member(&raw, "alg")?.ok_or_else(|| Error::Malformed("missing alg".into()))?.parse::<KeyAlg>()?;
    let enc = str_member(&raw, "enc")?.ok_or_else(|| Error::Malformed("missing enc".into()))?.parse::<Enc>()?;
    let kid = str_member(&raw, "kid")?.map(String::from);
    Ok(Header { alg, enc, kid, raw })
}

/// Decodes the header without decrypting (to pick a key by `kid`). Never trust the result.
pub fn peek_header(token: &str) -> Result<Header> {
    parse_header(split5(token)?[0])
}

/// Recovers the CEK. If unwrapping fails for a reason an attacker could cause (bad wrap, bad OAEP
/// padding, wrong CEK length), a random CEK is returned instead (RFC 7516 section 11.5), so the
/// failure shows up later as an ordinary tag mismatch.
fn unwrap_cek(h: &Header, key: &Jwk, ek: &[u8], pol: &Policy<'_>) -> Result<Vec<u8>> {
    let enc = h.enc;
    let real: Result<Vec<u8>> = (|| match h.alg {
        KeyAlg::Dir => {
            if !ek.is_empty() { return Err(Error::Decrypt); }
            let k = oct_key(key)?;
            if k.len() != enc.cek_len() { return Err(Error::Key("dir key has the wrong length for enc".into())); }
            Ok(k)
        }
        KeyAlg::A128Kw | KeyAlg::A192Kw | KeyAlg::A256Kw => {
            let kek = oct_key(key)?;
            if kek.len() != kw_len(h.alg) { return Err(Error::Key("key length does not match alg".into())); }
            crypto::aes_kw_unwrap(&kek, ek)
        }
        a if is_gcmkw(a) => {
            let kek = oct_key(key)?;
            if kek.len() != kw_len(a) { return Err(Error::Key("key length does not match alg".into())); }
            let iv = b64::decode(str_member(&h.raw, "iv")?.ok_or_else(|| Error::Malformed("missing iv".into()))?)?;
            let tag = b64::decode(str_member(&h.raw, "tag")?.ok_or_else(|| Error::Malformed("missing tag".into()))?)?;
            if iv.len() != crypto::GCM_IV_LEN || tag.len() != crypto::GCM_TAG_LEN { return Err(Error::Malformed("iv/tag have the wrong length".into())); }
            crypto::aead_open(gcmkw_alg(a), &kek, &iv, &[], ek, &tag)
        }
        a if is_rsa(a) => crypto::rsa_oaep_decrypt(oaep_hash(a), key, ek),
        a if is_ecdh(a) => {
            let epk: Jwk = serde_json::from_value(h.raw.get("epk").cloned().ok_or_else(|| Error::Malformed("missing epk".into()))?)
                .map_err(|e| Error::Malformed(format!("epk: {e}")))?;
            if epk.d.is_some() || epk.k.is_some() { return Err(Error::Malformed("epk must be a public key".into())); }
            let (mine, _) = crypto::check_agreement_key(key)?;
            let (theirs, _) = crypto::check_agreement_key(&epk)?;
            if mine != theirs { return Err(Error::Key("epk is on a different curve than the recipient key".into())); }
            let z = crypto::ecdh(key, &epk)?;
            let apu = str_member(&h.raw, "apu")?.map(b64::decode).transpose()?.unwrap_or_default();
            let apv = str_member(&h.raw, "apv")?.map(b64::decode).transpose()?.unwrap_or_default();
            if a == KeyAlg::EcdhEs {
                if !ek.is_empty() { return Err(Error::Decrypt); }
                concat_kdf(&z, enc.as_str(), &apu, &apv, (enc.cek_len() * 8) as u32, enc.cek_len())
            } else {
                let n = kw_len(a);
                let kek = concat_kdf(&z, a.as_str(), &apu, &apv, (n * 8) as u32, n)?;
                crypto::aes_kw_unwrap(&kek, ek)
            }
        }
        a => {
            let pw = oct_key(key)?;
            let (hh, n) = hash_for_pbes(a);
            let p2c = h.raw.get("p2c").and_then(Value::as_u64).ok_or_else(|| Error::Malformed("missing or invalid p2c".into()))?;
            if p2c < pol.pbes2_min_iter as u64 || p2c > pol.pbes2_max_iter as u64 {
                return Err(Error::Key(format!("p2c {p2c} outside the allowed range {}..={}", pol.pbes2_min_iter, pol.pbes2_max_iter)));
            }
            let p2s = b64::decode(str_member(&h.raw, "p2s")?.ok_or_else(|| Error::Malformed("missing p2s".into()))?)?;
            if p2s.len() < 8 { return Err(Error::Malformed("p2s shorter than 8 bytes".into())); }
            let mut salt = a.as_str().as_bytes().to_vec();
            salt.push(0);
            salt.extend_from_slice(&p2s);
            let kek = crypto::pbkdf2(hh, &pw, &salt, p2c as u32, n)?;
            crypto::aes_kw_unwrap(&kek, ek)
        }
    })();
    match real {
        Ok(cek) if cek.len() == enc.cek_len() => Ok(cek),
        // Problems with the caller's key, the policy or the backend do not depend on the attacker's bytes
        // (backends map bad wraps and bad padding to `Decrypt`), so they are reported as they are.
        Err(e @ (Error::Key(_) | Error::Unsupported(_) | Error::Malformed(_) | Error::Crypto(_))) => Err(e),
        // Everything else looks like a bad tag from the outside.
        _ => rand(enc.cek_len()),
    }
}

/// Decrypts a compact JWE.
pub fn decrypt(token: &str, key: &Jwk, policy: &Policy<'_>) -> Result<(Header, Vec<u8>)> {
    if token.len() > policy.max_token_len { return Err(Error::Malformed("token too large".into())); }
    let [h64, ek64, iv64, ct64, tag64] = split5(token)?;
    let header = parse_header(h64)?;
    if !policy.allowed_alg.contains(&header.alg) { return Err(Error::Algorithm(format!("alg {} is not allowed by policy", header.alg.as_str()))); }
    if !policy.allowed_enc.contains(&header.enc) { return Err(Error::Algorithm(format!("enc {} is not allowed by policy", header.enc.as_str()))); }
    if header.raw.contains_key("zip") { return Err(Error::Malformed("compressed JWE (zip) is not accepted".into())); }
    if let Some(crit) = header.raw.get("crit") {
        let list = crit.as_array().filter(|a| !a.is_empty()).ok_or_else(|| Error::Malformed("crit must be a non-empty array".into()))?;
        for c in list {
            let name = c.as_str().ok_or_else(|| Error::Malformed("crit entries must be strings".into()))?;
            if !policy.understood_crit.contains(&name) { return Err(Error::Malformed(format!("unsupported critical header {name:?}"))); }
            if !header.raw.contains_key(name) { return Err(Error::Malformed(format!("critical header {name:?} is missing"))); }
        }
    }
    check_key_use(key, "decrypt")?;
    let (ek, iv, ct, tag) = (b64::decode(ek64)?, b64::decode(iv64)?, b64::decode(ct64)?, b64::decode(tag64)?);
    let cek = unwrap_cek(&header, key, &ek, policy)?;
    let pt = content_decrypt(header.enc, &cek, &iv, h64.as_bytes(), &ct, &tag)?;
    Ok((header, pt))
}
