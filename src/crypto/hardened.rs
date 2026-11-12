//! The `hardened` backend: Authlas' own composition layer.
//!
//! It contains no primitives of its own. It runs each operation through every other backend that
//! is compiled in and only returns a result when at least two independent implementations took
//! part and agree. That removes a whole class of failures that no single library can rule out
//! about itself: a miscompiled or buggy primitive, a wrong curve check, a divergent edge case.
//!
//! Rules:
//!  * `Error::Unsupported` from a backend means "abstain". Fewer than [`QUORUM`] participants
//!    means the operation is refused, never answered by one implementation alone.
//!  * Deterministic outputs (digest, MAC, AEAD, CBC, key wrap, PBKDF2, ECDH, decryption) must be
//!    byte-identical across participants. Any difference is `Error::Crypto("backends disagree")`.
//!  * Verification must give the same verdict everywhere. One "valid" against one "invalid" is an error.
//!  * Signatures are produced by one backend (the private key is not spread to every library) and
//!    then verified through the quorum, which also catches fault-injected signatures.
//!  * Random bytes are the XOR of every backend's RNG output: as strong as the best source, and a
//!    failing source fails the call.
//!  * RSA decryption skips the `rustcrypto` backend (its RSA private operation is not constant time,
//!    RUSTSEC-2023-0071), which would otherwise make the whole call leak timing.
//!  * RSA-OAEP *encryption* uses a single backend: with only a public key there is nothing to
//!    cross-check against, and a bad ciphertext is undecryptable rather than insecure.
use super::{ct_eq, AeadAlg, OaepHash};
use crate::error::{Error, Result};
use crate::jwa::{Algorithm, Hash};
use crate::jwk::Jwk;

/// Minimum number of independent implementations that must take part in an operation.
pub const QUORUM: usize = 2;

macro_rules! fanout {
    ($f:ident($($a:expr),*)) => {{
        let mut r: Vec<(&'static str, Result<_>)> = Vec::new();
        #[cfg(feature = "backend-awslc")] r.push(("awslc", super::awslc::$f($($a),*)));
        #[cfg(feature = "backend-openssl")] r.push(("openssl", super::openssl_backend::$f($($a),*)));
        #[cfg(feature = "backend-qscrypt")] r.push(("qscrypt", super::qscrypt::$f($($a),*)));
        #[cfg(feature = "backend-rustcrypto")] r.push(("rustcrypto", super::rustcrypto::$f($($a),*)));
        r
    }};
}

/// Same, without the pure-Rust RSA implementation (see the module notes).
macro_rules! fanout_no_rustcrypto {
    ($f:ident($($a:expr),*)) => {{
        let mut r: Vec<(&'static str, Result<_>)> = Vec::new();
        #[cfg(feature = "backend-awslc")] r.push(("awslc", super::awslc::$f($($a),*)));
        #[cfg(feature = "backend-openssl")] r.push(("openssl", super::openssl_backend::$f($($a),*)));
        #[cfg(feature = "backend-qscrypt")] r.push(("qscrypt", super::qscrypt::$f($($a),*)));
        r
    }};
}

fn abstains(e: &Error) -> bool {
    matches!(e, Error::Unsupported(_))
}

fn disagree(op: &str, detail: &str) -> Error {
    Error::Crypto(format!("hardened: backends disagree on {op} ({detail})"))
}

/// Core agreement rule over byte outputs.
fn agree(op: &str, results: Vec<(&'static str, Result<Vec<u8>>)>) -> Result<Vec<u8>> {
    let mut oks: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let mut errs: Vec<(&'static str, Error)> = Vec::new();
    let mut abstained = 0usize;
    for (name, r) in results {
        match r {
            Ok(v) => oks.push((name, v)),
            Err(e) if abstains(&e) => abstained += 1,
            Err(e) => errs.push((name, e)),
        }
    }
    let participants = oks.len() + errs.len();
    if participants < QUORUM {
        return Err(Error::Unsupported(format!(
            "hardened: {op} needs {QUORUM} independent backends, only {participants} could take part ({abstained} abstained)")));
    }
    match (oks.is_empty(), errs.is_empty()) {
        (false, true) => {
            let (first_name, first) = &oks[0];
            for (name, v) in &oks[1..] {
                if !ct_eq(first, v) {
                    return Err(disagree(op, &format!("{first_name} vs {name}")));
                }
            }
            Ok(oks.swap_remove(0).1)
        }
        (true, false) => Err(errs.swap_remove(0).1),
        _ => {
            let who: Vec<&str> = oks.iter().map(|(n, _)| *n).chain(errs.iter().map(|(n, _)| *n)).collect();
            Err(disagree(op, &format!("some accepted, some rejected: {}", who.join(","))))
        }
    }
}

fn agree_unit(op: &str, results: Vec<(&'static str, Result<()>)>) -> Result<()> {
    agree(op, results.into_iter().map(|(n, r)| (n, r.map(|_| Vec::new()))).collect()).map(|_| ())
}

fn pack(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(&(p.len() as u64).to_be_bytes());
        v.extend_from_slice(p);
    }
    v
}

fn unpack2(b: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let l1 = u64::from_be_bytes(b[..8].try_into().unwrap()) as usize;
    let first = b[8..8 + l1].to_vec();
    let rest = &b[8 + l1..];
    let l2 = u64::from_be_bytes(rest[..8].try_into().unwrap()) as usize;
    (first, rest[8..8 + l2].to_vec())
}

pub fn digest(h: Hash, data: &[u8]) -> Result<Vec<u8>> {
    agree("digest", fanout!(digest(h, data)))
}

pub fn hmac(h: Hash, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    agree("hmac", fanout!(hmac(h, key, data)))
}

/// XOR of every backend's output. Needs [`QUORUM`] sources, and any failing source fails the call.
pub fn random(buf: &mut [u8]) -> Result<()> {
    let mut acc = vec![0u8; buf.len()];
    let mut sources = 0usize;
    macro_rules! mix { ($m:path) => {{
        let mut t = vec![0u8; buf.len()];
        $m(&mut t)?;
        for (a, b) in acc.iter_mut().zip(&t) { *a ^= b; }
        sources += 1;
    }}}
    #[cfg(feature = "backend-awslc")] mix!(super::awslc::random);
    #[cfg(feature = "backend-openssl")] mix!(super::openssl_backend::random);
    #[cfg(feature = "backend-qscrypt")] mix!(super::qscrypt::random);
    #[cfg(feature = "backend-rustcrypto")] mix!(super::rustcrypto::random);
    if sources < QUORUM {
        return Err(Error::Unsupported(format!("hardened: random needs {QUORUM} entropy sources, have {sources}")));
    }
    buf.copy_from_slice(&acc);
    Ok(())
}

pub fn verify(alg: Algorithm, k: &Jwk, data: &[u8], sig: &[u8]) -> Result<()> {
    agree_unit("verify", fanout!(verify(alg, k, data, sig)))
}

/// One backend signs (so the private key is not copied into every library), then the whole quorum verifies.
pub fn sign(alg: Algorithm, k: &Jwk, data: &[u8]) -> Result<Vec<u8>> {
    let mut sig: Option<Vec<u8>> = None;
    let mut err: Option<Error> = None;
    macro_rules! try_sign { ($m:path) => {
        if sig.is_none() {
            match $m(alg, k, data) {
                Ok(s) => sig = Some(s),
                Err(e) if abstains(&e) => {}
                Err(e) => { if err.is_none() { err = Some(e); } }
            }
        }
    }}
    #[cfg(feature = "backend-awslc")] try_sign!(super::awslc::sign);
    #[cfg(feature = "backend-openssl")] try_sign!(super::openssl_backend::sign);
    #[cfg(feature = "backend-qscrypt")] try_sign!(super::qscrypt::sign);
    #[cfg(feature = "backend-rustcrypto")] try_sign!(super::rustcrypto::sign);
    let sig = match sig {
        Some(s) => s,
        None => return Err(err.unwrap_or_else(|| Error::Unsupported(format!("hardened: no backend can sign with {}", alg.as_str())))),
    };
    let pubk = k.public()?;
    verify(alg, &pubk, data, &sig).map_err(|e| match e {
        Error::BadSignature => Error::Crypto("hardened: freshly made signature failed quorum verification (fault?)".into()),
        other => other,
    })?;
    Ok(sig)
}

pub fn aead_seal(alg: AeadAlg, key: &[u8], iv: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let r = fanout!(aead_seal(alg, key, iv, aad, pt))
        .into_iter().map(|(n, r)| (n, r.map(|(c, t)| pack(&[&c, &t])))).collect();
    Ok(unpack2(&agree("aead_seal", r)?))
}

pub fn aead_open(alg: AeadAlg, key: &[u8], iv: &[u8], aad: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    agree("aead_open", fanout!(aead_open(alg, key, iv, aad, ct, tag)))
}

pub fn cbc_encrypt(key: &[u8], iv: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    agree("cbc_encrypt", fanout!(cbc_encrypt(key, iv, pt)))
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    agree("cbc_decrypt", fanout!(cbc_decrypt(key, iv, ct)))
}

pub fn aes_kw_wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    agree("aes_kw_wrap", fanout!(aes_kw_wrap(kek, key)))
}

pub fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    agree("aes_kw_unwrap", fanout!(aes_kw_unwrap(kek, wrapped)))
}

pub fn pbkdf2(h: Hash, password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Result<Vec<u8>> {
    agree("pbkdf2", fanout!(pbkdf2(h, password, salt, iterations, out_len)))
}

pub fn ecdh(private: &Jwk, public: &Jwk) -> Result<Vec<u8>> {
    agree("ecdh", fanout!(ecdh(private, public)))
}

pub fn rsa_oaep_decrypt(h: OaepHash, k: &Jwk, ct: &[u8]) -> Result<Vec<u8>> {
    agree("rsa_oaep_decrypt", fanout_no_rustcrypto!(rsa_oaep_decrypt(h, k, ct)))
}

/// Single backend by design (see the module notes).
pub fn rsa_oaep_encrypt(h: OaepHash, k: &Jwk, msg: &[u8]) -> Result<Vec<u8>> {
    let mut err: Option<Error> = None;
    macro_rules! attempt { ($m:path) => {
        match $m(h, k, msg) {
            Ok(c) => return Ok(c),
            Err(e) if abstains(&e) => {}
            Err(e) => { if err.is_none() { err = Some(e); } }
        }
    }}
    #[cfg(feature = "backend-awslc")] attempt!(super::awslc::rsa_oaep_encrypt);
    #[cfg(feature = "backend-openssl")] attempt!(super::openssl_backend::rsa_oaep_encrypt);
    #[cfg(feature = "backend-qscrypt")] attempt!(super::qscrypt::rsa_oaep_encrypt);
    #[cfg(feature = "backend-rustcrypto")] attempt!(super::rustcrypto::rsa_oaep_encrypt);
    Err(err.unwrap_or_else(|| Error::Unsupported("hardened: no backend can do this RSA-OAEP encryption".into())))
}

/// Generates a key pair with one backend, then proves the private and public halves belong together
/// by running ECDH both ways through the quorum and requiring identical secrets.
pub fn ec_generate(crv: &str) -> Result<Jwk> {
    let mut made: Option<Jwk> = None;
    let mut err: Option<Error> = None;
    macro_rules! gen { ($m:path) => {
        if made.is_none() {
            match $m(crv) {
                Ok(k) => made = Some(k),
                Err(e) if abstains(&e) => {}
                Err(e) => { if err.is_none() { err = Some(e); } }
            }
        }
    }}
    #[cfg(feature = "backend-awslc")] gen!(super::awslc::ec_generate);
    #[cfg(feature = "backend-openssl")] gen!(super::openssl_backend::ec_generate);
    #[cfg(feature = "backend-qscrypt")] gen!(super::qscrypt::ec_generate);
    #[cfg(feature = "backend-rustcrypto")] gen!(super::rustcrypto::ec_generate);
    let a = match made {
        Some(k) => k,
        None => return Err(err.unwrap_or_else(|| Error::Unsupported(format!("hardened: no backend can generate {crv} keys")))),
    };
    // Self-consistency: a second, independent key must agree with this one in both directions.
    let b = ec_generate_once(crv)?;
    let ab = ecdh(&a, &b.public()?)?;
    let ba = ecdh(&b, &a.public()?)?;
    if !ct_eq(&ab, &ba) {
        return Err(Error::Crypto("hardened: generated key pair failed the ECDH consistency check".into()));
    }
    Ok(a)
}

fn ec_generate_once(crv: &str) -> Result<Jwk> {
    #[cfg(feature = "backend-openssl")] { match super::openssl_backend::ec_generate(crv) { Err(e) if abstains(&e) => {}, r => return r } }
    #[cfg(feature = "backend-awslc")] { match super::awslc::ec_generate(crv) { Err(e) if abstains(&e) => {}, r => return r } }
    #[cfg(feature = "backend-rustcrypto")] { match super::rustcrypto::ec_generate(crv) { Err(e) if abstains(&e) => {}, r => return r } }
    #[cfg(feature = "backend-qscrypt")] { match super::qscrypt::ec_generate(crv) { Err(e) if abstains(&e) => {}, r => return r } }
    Err(Error::Unsupported(format!("hardened: no backend can generate {crv} keys")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(n: &'static str, v: &[u8]) -> (&'static str, Result<Vec<u8>>) { (n, Ok(v.to_vec())) }
    fn unsup(n: &'static str) -> (&'static str, Result<Vec<u8>>) { (n, Err(Error::Unsupported("x".into()))) }

    #[test]
    fn identical_outputs_pass() {
        assert_eq!(agree("t", vec![ok("a", b"1"), ok("b", b"1"), unsup("c")]).unwrap(), b"1");
    }
    #[test]
    fn one_flipped_byte_is_caught() {
        let e = agree("t", vec![ok("a", b"12"), ok("b", b"13")]).unwrap_err();
        assert!(e.to_string().contains("disagree"), "{e}");
    }
    #[test]
    fn a_single_participant_is_refused() {
        let e = agree("t", vec![ok("a", b"1"), unsup("b"), unsup("c")]).unwrap_err();
        assert!(matches!(e, Error::Unsupported(_)), "{e}");
    }
    #[test]
    fn accept_versus_reject_is_caught() {
        let e = agree("t", vec![ok("a", b"1"), ("b", Err(Error::BadSignature))]).unwrap_err();
        assert!(e.to_string().contains("some accepted, some rejected"), "{e}");
    }
    #[test]
    fn unanimous_rejection_keeps_the_error() {
        let e = agree("t", vec![("a", Err(Error::BadSignature)), ("b", Err(Error::BadSignature))]).unwrap_err();
        assert!(matches!(e, Error::BadSignature));
    }
    #[test]
    fn pack_round_trips() {
        let p = pack(&[b"cipher", b"tag"]);
        assert_eq!(unpack2(&p), (b"cipher".to_vec(), b"tag".to_vec()));
    }
}
