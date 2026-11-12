//! Crypto backends.
//!
//! Every backend module exposes the same free functions. Cargo features decide which backends
//! are compiled, `build.rs` (driven by `crypto_backends=...`) decides which one is active.
//!
//! | backend      | what it is                                                              |
//! |--------------|-------------------------------------------------------------------------|
//! | `awslc`      | aws-lc-rs (default)                                                     |
//! | `openssl`    | system/vcpkg OpenSSL                                                    |
//! | `rustcrypto` | pure-Rust RustCrypto crates                                             |
//! | `qscrypt`    | qs_crypt (quantum-suite) loaded from a DLL/.so, SHA-256 pinned          |
//! | `hardened`   | Authlas' own: every operation runs through 2+ backends, fails closed    |
//!
//! Required surface of a backend module (all `pub fn`):
//! `digest, hmac, random, sign, verify, aead_seal, aead_open, cbc_encrypt, cbc_decrypt,
//!  rsa_oaep_encrypt, rsa_oaep_decrypt, ec_generate, ecdh, aes_kw_wrap, aes_kw_unwrap, pbkdf2`.
use crate::error::{Error, Result};
use crate::jwa::Hash;
use crate::jwk::Jwk;

#[cfg(feature = "backend-awslc")]
pub mod awslc;
#[cfg(feature = "backend-openssl")]
pub mod openssl_backend;
#[cfg(feature = "backend-rustcrypto")]
pub mod rustcrypto;
#[cfg(feature = "backend-qscrypt")]
pub mod qscrypt;
#[cfg(feature = "backend-hardened")]
pub mod hardened;

#[cfg(authlas_active = "awslc")]
pub use awslc::*;
#[cfg(authlas_active = "openssl")]
pub use openssl_backend::*;
#[cfg(authlas_active = "rustcrypto")]
pub use rustcrypto::*;
#[cfg(authlas_active = "qscrypt")]
pub use qscrypt::*;
#[cfg(authlas_active = "hardened")]
pub use hardened::*;

/// Name of the active backend.
pub fn backend_name() -> &'static str {
    env!("AUTHLAS_ACTIVE_BACKEND")
}

/// Comma-separated list of every backend compiled into this build.
pub fn compiled_backends() -> &'static str {
    env!("AUTHLAS_COMPILED_BACKENDS")
}

/// AES-GCM key sizes used by JWE (RFC 7518 section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlg { A128Gcm, A192Gcm, A256Gcm }

impl AeadAlg {
    pub fn key_len(self) -> usize {
        match self { AeadAlg::A128Gcm => 16, AeadAlg::A192Gcm => 24, AeadAlg::A256Gcm => 32 }
    }
}

/// Hash used by RSA-OAEP. SHA-1 exists only because "RSA-OAEP" in RFC 7518 is defined with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OaepHash { Sha1, Sha256, Sha384, Sha512 }

pub const GCM_IV_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;

/// Constant-time byte comparison. Length differences are not hidden (lengths are public).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    std::hint::black_box(acc) == 0
}

/// Validates that the key's curve matches what the algorithm requires.
pub(crate) fn check_ec(alg: crate::jwa::Algorithm, k: &Jwk) -> Result<()> {
    if k.kty != "EC" {
        return Err(Error::Key(format!("{} needs an EC key", alg.as_str())));
    }
    let want = alg.curve().ok_or_else(|| Error::Algorithm("not an ECDSA alg".into()))?;
    if k.crv.as_deref() != Some(want) {
        return Err(Error::Key(format!("{} needs curve {want}", alg.as_str())));
    }
    Ok(())
}

pub(crate) fn check_okp(k: &Jwk) -> Result<()> {
    if k.kty != "OKP" || k.crv.as_deref() != Some("Ed25519") {
        return Err(Error::Key("EdDSA needs an OKP/Ed25519 key".into()));
    }
    Ok(())
}

/// RFC 7518 section 3.3: RSA keys must be at least 2048 bits.
pub(crate) fn check_rsa(k: &Jwk) -> Result<(Vec<u8>, Vec<u8>)> {
    if k.kty != "RSA" {
        return Err(Error::Key("RSA algorithm needs an RSA key".into()));
    }
    let n = k.req("n")?;
    let e = k.req("e")?;
    let n_trim: &[u8] = {
        let i = n.iter().position(|b| *b != 0).unwrap_or(n.len());
        &n[i..]
    };
    if n_trim.len() * 8 < 2048 {
        return Err(Error::Key("RSA modulus shorter than 2048 bits".into()));
    }
    Ok((n, e))
}

/// Size in bytes of the field elements / scalars of a key-agreement curve.
pub(crate) fn curve_len(crv: &str) -> Result<usize> {
    match crv {
        "P-256" | "X25519" => Ok(32),
        "P-384" => Ok(48),
        "P-521" => Ok(66),
        other => Err(Error::Key(format!("unsupported curve {other:?} for key agreement"))),
    }
}

/// Builds the JWK for a freshly generated key-agreement key.
pub(crate) fn ec_jwk(crv: &str, d: &[u8], x: &[u8], y: Option<&[u8]>) -> Jwk {
    use crate::b64::encode;
    let mut k = Jwk::default();
    k.kty = if crv == "X25519" { "OKP".into() } else { "EC".into() };
    k.crv = Some(crv.into());
    k.d = Some(encode(d));
    k.x = Some(encode(x));
    k.y = y.map(encode);
    k
}

/// Checks a key-agreement JWK and returns (curve, scalar-or-coordinate length).
pub(crate) fn check_agreement_key(k: &Jwk) -> Result<(String, usize)> {
    let crv = k.crv.clone().ok_or_else(|| Error::Key("missing crv".into()))?;
    let n = curve_len(&crv)?;
    match (k.kty.as_str(), crv.as_str()) {
        ("EC", "P-256" | "P-384" | "P-521") | ("OKP", "X25519") => Ok((crv, n)),
        _ => Err(Error::Key(format!("kty {} cannot do key agreement on {crv}", k.kty))),
    }
}

pub(crate) fn unsupported<T>(backend: &str, what: &str) -> Result<T> {
    Err(Error::Unsupported(format!("{what} (backend {backend})")))
}

pub(crate) fn hash_of(h: OaepHash) -> Option<Hash> {
    match h {
        OaepHash::Sha1 => None,
        OaepHash::Sha256 => Some(Hash::Sha256),
        OaepHash::Sha384 => Some(Hash::Sha384),
        OaepHash::Sha512 => Some(Hash::Sha512),
    }
}

// ---------------------------------------------------------------------------------------------
// Shared algorithms built on a backend's own primitives. They are tested against the RFC vectors.
// ---------------------------------------------------------------------------------------------

/// AES Key Wrap (RFC 3394) on top of a single-block AES encryptor.
pub(crate) fn kw_wrap_with(enc: &dyn Fn(&[u8; 16]) -> Result<[u8; 16]>, key: &[u8]) -> Result<Vec<u8>> {
    if key.len() < 16 || key.len() % 8 != 0 {
        return Err(Error::Key("key to wrap must be a multiple of 8 bytes, at least 16".into()));
    }
    let n = key.len() / 8;
    let mut a = [0xA6u8; 8];
    let mut r: Vec<[u8; 8]> = key.chunks(8).map(|c| c.try_into().unwrap()).collect();
    for j in 0..6u64 {
        for i in 0..n {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(&r[i]);
            let o = enc(&b)?;
            let t = (n as u64) * j + (i as u64) + 1;
            a.copy_from_slice(&o[..8]);
            for (k, byte) in t.to_be_bytes().iter().enumerate() { a[k] ^= byte; }
            r[i].copy_from_slice(&o[8..]);
        }
    }
    let mut out = a.to_vec();
    for blk in r { out.extend_from_slice(&blk); }
    Ok(out)
}

/// AES Key Unwrap (RFC 3394). The integrity value is compared in constant time.
pub(crate) fn kw_unwrap_with(dec: &dyn Fn(&[u8; 16]) -> Result<[u8; 16]>, wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
        return Err(Error::Decrypt);
    }
    let n = wrapped.len() / 8 - 1;
    let mut a: [u8; 8] = wrapped[..8].try_into().unwrap();
    let mut r: Vec<[u8; 8]> = wrapped[8..].chunks(8).map(|c| c.try_into().unwrap()).collect();
    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = (n as u64) * j + (i as u64) + 1;
            let mut b = [0u8; 16];
            let mut ax = a;
            for (k, byte) in t.to_be_bytes().iter().enumerate() { ax[k] ^= byte; }
            b[..8].copy_from_slice(&ax);
            b[8..].copy_from_slice(&r[i]);
            let o = dec(&b)?;
            a.copy_from_slice(&o[..8]);
            r[i].copy_from_slice(&o[8..]);
        }
    }
    if !ct_eq(&a, &[0xA6u8; 8]) {
        return Err(Error::Decrypt);
    }
    Ok(r.concat())
}

/// PBKDF2 (RFC 8018) over any HMAC function.
pub(crate) fn pbkdf2_with(
    mac: &dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>>,
    hash_len: usize,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Result<Vec<u8>> {
    if iterations == 0 || out_len == 0 {
        return Err(Error::Key("pbkdf2: iterations and length must be non-zero".into()));
    }
    let _ = password;
    let mut out = Vec::with_capacity(out_len);
    let mut block = 1u32;
    while out.len() < out_len {
        let mut first = salt.to_vec();
        first.extend_from_slice(&block.to_be_bytes());
        let mut u = mac(password, &first)?;
        let mut t = u.clone();
        for _ in 1..iterations {
            u = mac(password, &u)?;
            for (a, b) in t.iter_mut().zip(&u) { *a ^= b; }
        }
        debug_assert_eq!(t.len(), hash_len);
        out.extend_from_slice(&t);
        block += 1;
    }
    out.truncate(out_len);
    Ok(out)
}

/// PKCS#7 padding.
pub(crate) fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad = 16 - (data.len() % 16);
    let mut v = data.to_vec();
    v.extend(std::iter::repeat(pad as u8).take(pad));
    v
}

/// PKCS#7 unpadding with no early exit on the pad value. Returns `Error::Decrypt` for bad padding.
/// The caller must have authenticated the ciphertext first (JWE does: HMAC-then-decrypt).
pub(crate) fn pkcs7_unpad(mut data: Vec<u8>) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(Error::Decrypt);
    }
    let pad = *data.last().unwrap() as usize;
    let mut bad = (pad == 0) as u8 | (pad > 16) as u8;
    for i in 0..16usize {
        let in_pad = (i < pad) as u8;
        bad |= in_pad & (data[data.len() - 1 - i] != pad as u8) as u8;
    }
    if std::hint::black_box(bad) != 0 {
        return Err(Error::Decrypt);
    }
    data.truncate(data.len() - pad);
    Ok(data)
}
