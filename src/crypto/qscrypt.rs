//! qs_crypt backend (quantum-suite). Loads `qs_crypt.dll` / `libqs_crypt.so` at run time.
//!
//! Why a run-time load and not a link: the library is a separate product with its own release
//! cycle, and Authlas must not silently run against a build it was not tested with.
//!
//! * Location: `AUTHLAS_QSCRYPT_PATH` (full path), else `qs_crypt.dll` next to the executable.
//! * Integrity: if `AUTHLAS_QSCRYPT_SHA256` is set, the file must match it before it is loaded.
//!   Without it the library still loads, but `qscrypt_status()` reports `pinned: false`.
//! * Version: the library must report 0.2.x and export every symbol used here, or loading fails.
//!
//! What qs_crypt does not have, this backend refuses with `Error::Unsupported` rather than falling
//! back to something else: ECDSA P-384/P-521, ECDH on NIST curves, SHA-1 OAEP, AES-192-GCM.
//! (The `hardened` backend routes those operations to another implementation.)
//!
//! Known limit: AES here is table-based (cache-timing exposure on shared hardware). ChaCha20 is
//! unaffected. RSA decryption blinds and uses CRT when the JWK carries p and q.
use super::{check_agreement_key, check_ec, check_okp, check_rsa, ec_jwk, unsupported, AeadAlg, OaepHash};
use crate::error::{Error, Result};
use crate::jwa::{Algorithm, Hash};
use crate::jwk::Jwk;
use libloading::{Library, Symbol};
use std::{env, ffi::c_void, fs, os::raw::c_int, path::PathBuf, sync::OnceLock};

#[repr(C)] #[derive(Clone, Copy)] struct Slice { data: *const u8, length: u64 }
#[repr(C)] struct Buffer { data: *mut u8, length: u64 }
#[repr(C)] struct Digest { data: [u8; 64], length: u64 }

const ALG_SHA2_256: u32 = 0x0200;
const ALG_SHA2_384: u32 = 0x0201;
const ALG_SHA2_512: u32 = 0x0202;
const ALG_HMAC_256: u32 = 0x0300;
const ALG_HMAC_384: u32 = 0x0302;
const ALG_HMAC_512: u32 = 0x0301;
const ALG_AES_128_GCM: u32 = 0x0100;
const ALG_AES_256_GCM: u32 = 0x0101;

struct Api {
    _lib: Library,
    init: unsafe extern "C" fn() -> c_int,
    version: unsafe extern "C" fn(*mut u32, *mut u32, *mut u32),
    random: unsafe extern "C" fn(*mut u8, u64) -> c_int,
    hash: unsafe extern "C" fn(u32, Slice, *mut Digest) -> c_int,
    mac: unsafe extern "C" fn(u32, Slice, Slice, *mut Digest) -> c_int,
    aead_enc: unsafe extern "C" fn(u32, Slice, Slice, Slice, Slice, *mut u8, *mut Digest) -> c_int,
    aead_dec: unsafe extern "C" fn(u32, Slice, Slice, Slice, Slice, Slice, *mut u8) -> c_int,
    cbc_enc: unsafe extern "C" fn(Slice, *const u8, Slice, *mut u8, *mut u64) -> c_int,
    cbc_dec: unsafe extern "C" fn(Slice, *const u8, Slice, *mut u8, *mut u64) -> c_int,
    kw_wrap: unsafe extern "C" fn(Slice, Slice, *mut u8) -> c_int,
    kw_unwrap: unsafe extern "C" fn(Slice, Slice, *mut u8) -> c_int,
    pbkdf2: unsafe extern "C" fn(u32, Slice, Slice, u32, *mut u8, u64) -> c_int,
    ed_sign: unsafe extern "C" fn(*const u8, *const u8, u64, *mut u8) -> c_int,
    ed_verify: unsafe extern "C" fn(*const u8, *const u8, u64, *const u8) -> c_int,
    p256_sign: unsafe extern "C" fn(*const u8, Slice, *mut u8) -> c_int,
    p256_verify: unsafe extern "C" fn(*const u8, Slice, *const u8) -> c_int,
    x_keygen: unsafe extern "C" fn(*mut u8, *mut u8) -> c_int,
    x_shared: unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> c_int,
    rsa_pub_create: unsafe extern "C" fn(Slice, Slice, *mut *mut c_void) -> c_int,
    rsa_priv_create_crt: unsafe extern "C" fn(Slice, Slice, Slice, Slice, Slice, *mut *mut c_void) -> c_int,
    rsa_pub_destroy: unsafe extern "C" fn(*mut c_void),
    rsa_priv_destroy: unsafe extern "C" fn(*mut c_void),
    pkcs1_sign: unsafe extern "C" fn(*const c_void, u32, Slice, *mut Buffer) -> c_int,
    pkcs1_verify: unsafe extern "C" fn(*const c_void, u32, Slice, Slice) -> c_int,
    pss_sign: unsafe extern "C" fn(*const c_void, u32, Slice, *mut Buffer) -> c_int,
    pss_verify: unsafe extern "C" fn(*const c_void, u32, Slice, Slice) -> c_int,
    oaep_enc: unsafe extern "C" fn(*const c_void, u32, Slice, *mut Buffer) -> c_int,
    oaep_dec: unsafe extern "C" fn(*const c_void, u32, Slice, *mut Buffer) -> c_int,
}
unsafe impl Send for Api {}
unsafe impl Sync for Api {}

/// What `qscrypt_status` reports.
#[derive(Debug, Clone)]
pub struct Status { pub path: String, pub version: (u32, u32, u32), pub pinned: bool }

static API: OnceLock<std::result::Result<(Api, Status), String>> = OnceLock::new();

fn sha256_file(bytes: &[u8]) -> String {
    use std::fmt::Write;
    // Hash with qs_crypt itself would prove nothing; use a tiny local SHA-256 over the DLL bytes.
    let d = sha256(bytes);
    let mut s = String::new();
    for b in d { let _ = write!(s, "{b:02x}"); }
    s
}

fn locate() -> std::result::Result<PathBuf, String> {
    if let Some(p) = env::var_os("AUTHLAS_QSCRYPT_PATH") { return Ok(PathBuf::from(p)); }
    let name = if cfg!(windows) { "qs_crypt.dll" } else if cfg!(target_os = "macos") { "libqs_crypt.dylib" } else { "libqs_crypt.so" };
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let beside = exe.parent().map(|d| d.join(name));
    match beside { Some(p) if p.is_file() => Ok(p), _ => Err(format!("{name} not found; set AUTHLAS_QSCRYPT_PATH")) }
}

macro_rules! sym {
    ($lib:expr, $name:literal, $ty:ty) => {{
        let s: Symbol<$ty> = unsafe { $lib.get($name) }.map_err(|e| format!("missing export {}: {e}", String::from_utf8_lossy($name)))?;
        *s
    }};
}

fn load() -> std::result::Result<(Api, Status), String> {
    let path = locate()?;
    let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let actual = sha256_file(&bytes);
    let pinned = match env::var("AUTHLAS_QSCRYPT_SHA256") {
        Ok(want) => {
            if !want.trim().eq_ignore_ascii_case(&actual) {
                return Err(format!("qs_crypt hash mismatch: expected {}, file is {actual}", want.trim()));
            }
            true
        }
        Err(_) => false,
    };
    let lib = unsafe { Library::new(&path) }.map_err(|e| e.to_string())?;
    let api = Api {
        init: sym!(lib, b"qsc_init", unsafe extern "C" fn() -> c_int),
        version: sym!(lib, b"qsc_version", unsafe extern "C" fn(*mut u32, *mut u32, *mut u32)),
        random: sym!(lib, b"qsc_random_bytes", unsafe extern "C" fn(*mut u8, u64) -> c_int),
        hash: sym!(lib, b"qsc_hash", unsafe extern "C" fn(u32, Slice, *mut Digest) -> c_int),
        mac: sym!(lib, b"qsc_mac", unsafe extern "C" fn(u32, Slice, Slice, *mut Digest) -> c_int),
        aead_enc: sym!(lib, b"qsc_aead_encrypt", unsafe extern "C" fn(u32, Slice, Slice, Slice, Slice, *mut u8, *mut Digest) -> c_int),
        aead_dec: sym!(lib, b"qsc_aead_decrypt", unsafe extern "C" fn(u32, Slice, Slice, Slice, Slice, Slice, *mut u8) -> c_int),
        cbc_enc: sym!(lib, b"qsc_aes_cbc_encrypt", unsafe extern "C" fn(Slice, *const u8, Slice, *mut u8, *mut u64) -> c_int),
        cbc_dec: sym!(lib, b"qsc_aes_cbc_decrypt", unsafe extern "C" fn(Slice, *const u8, Slice, *mut u8, *mut u64) -> c_int),
        kw_wrap: sym!(lib, b"qsc_aes_kw_wrap", unsafe extern "C" fn(Slice, Slice, *mut u8) -> c_int),
        kw_unwrap: sym!(lib, b"qsc_aes_kw_unwrap", unsafe extern "C" fn(Slice, Slice, *mut u8) -> c_int),
        pbkdf2: sym!(lib, b"qsc_pbkdf2", unsafe extern "C" fn(u32, Slice, Slice, u32, *mut u8, u64) -> c_int),
        ed_sign: sym!(lib, b"qsc_ed25519_sign", unsafe extern "C" fn(*const u8, *const u8, u64, *mut u8) -> c_int),
        ed_verify: sym!(lib, b"qsc_ed25519_verify", unsafe extern "C" fn(*const u8, *const u8, u64, *const u8) -> c_int),
        p256_sign: sym!(lib, b"qsc_ecdsa_p256_sign", unsafe extern "C" fn(*const u8, Slice, *mut u8) -> c_int),
        p256_verify: sym!(lib, b"qsc_ecdsa_p256_verify", unsafe extern "C" fn(*const u8, Slice, *const u8) -> c_int),
        x_keygen: sym!(lib, b"qsc_x25519_keygen", unsafe extern "C" fn(*mut u8, *mut u8) -> c_int),
        x_shared: sym!(lib, b"qsc_x25519_shared", unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> c_int),
        rsa_pub_create: sym!(lib, b"qsc_rsa_public_create", unsafe extern "C" fn(Slice, Slice, *mut *mut c_void) -> c_int),
        rsa_priv_create_crt: sym!(lib, b"qsc_rsa_private_create_crt", unsafe extern "C" fn(Slice, Slice, Slice, Slice, Slice, *mut *mut c_void) -> c_int),
        rsa_pub_destroy: sym!(lib, b"qsc_rsa_public_destroy", unsafe extern "C" fn(*mut c_void)),
        rsa_priv_destroy: sym!(lib, b"qsc_rsa_private_destroy", unsafe extern "C" fn(*mut c_void)),
        pkcs1_sign: sym!(lib, b"qsc_rsa_pkcs1_sign", unsafe extern "C" fn(*const c_void, u32, Slice, *mut Buffer) -> c_int),
        pkcs1_verify: sym!(lib, b"qsc_rsa_pkcs1_verify", unsafe extern "C" fn(*const c_void, u32, Slice, Slice) -> c_int),
        pss_sign: sym!(lib, b"qsc_rsa_pss_sign_ex", unsafe extern "C" fn(*const c_void, u32, Slice, *mut Buffer) -> c_int),
        pss_verify: sym!(lib, b"qsc_rsa_pss_verify_ex", unsafe extern "C" fn(*const c_void, u32, Slice, Slice) -> c_int),
        oaep_enc: sym!(lib, b"qsc_rsa_oaep_encrypt_ex", unsafe extern "C" fn(*const c_void, u32, Slice, *mut Buffer) -> c_int),
        oaep_dec: sym!(lib, b"qsc_rsa_oaep_decrypt_ex", unsafe extern "C" fn(*const c_void, u32, Slice, *mut Buffer) -> c_int),
        _lib: lib,
    };
    let (mut a, mut b, mut c) = (0u32, 0u32, 0u32);
    unsafe { (api.version)(&mut a, &mut b, &mut c) };
    if (a, b) != (0, 2) { return Err(format!("qs_crypt {a}.{b}.{c} is not the tested 0.2.x line")); }
    let rc = unsafe { (api.init)() };
    if rc != 0 { return Err(format!("qsc_init failed: {rc}")); }
    Ok((api, Status { path: path.display().to_string(), version: (a, b, c), pinned }))
}

fn api() -> Result<&'static Api> {
    match API.get_or_init(load) {
        Ok((a, _)) => Ok(a),
        Err(m) => Err(Error::Crypto(format!("qs_crypt backend unavailable: {m}"))),
    }
}

/// Loads the library now (instead of on first use) and reports where it came from.
pub fn qscrypt_status() -> Result<Status> {
    api()?;
    match API.get() { Some(Ok((_, s))) => Ok(s.clone()), _ => Err(Error::Crypto("qs_crypt not loaded".into())) }
}

fn sl(b: &[u8]) -> Slice { Slice { data: if b.is_empty() { std::ptr::NonNull::<u8>::dangling().as_ptr() } else { b.as_ptr() }, length: b.len() as u64 } }
fn ok(rc: c_int, what: &str) -> Result<()> { if rc == 0 { Ok(()) } else { Err(Error::Crypto(format!("qs_crypt {what} failed (code {rc})"))) } }

// ---- SHA-256 for the integrity check only (the library must not vouch for itself) ----
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    let mut h: [u32; 8] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let mut m = data.to_vec();
    m.push(0x80);
    while m.len() % 64 != 56 { m.push(0); }
    m.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for ch in m.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 { w[i] = u32::from_be_bytes(ch[4 * i..4 * i + 4].try_into().unwrap()); }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let chv = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(chv).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let mj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(mj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 { h[i] = h[i].wrapping_add(v[i]); }
    }
    let mut out = [0u8; 32];
    for i in 0..8 { out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

fn hash_id(h: Hash) -> u32 { match h { Hash::Sha256 => ALG_SHA2_256, Hash::Sha384 => ALG_SHA2_384, Hash::Sha512 => ALG_SHA2_512 } }
fn hmac_id(h: Hash) -> u32 { match h { Hash::Sha256 => ALG_HMAC_256, Hash::Sha384 => ALG_HMAC_384, Hash::Sha512 => ALG_HMAC_512 } }

pub fn digest(h: Hash, data: &[u8]) -> Result<Vec<u8>> {
    let a = api()?;
    let mut d = Digest { data: [0; 64], length: 0 };
    ok(unsafe { (a.hash)(hash_id(h), sl(data), &mut d) }, "hash")?;
    Ok(d.data[..d.length as usize].to_vec())
}

pub fn hmac(h: Hash, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let a = api()?;
    if key.is_empty() { return Err(Error::Key("empty HMAC key".into())); }
    let mut d = Digest { data: [0; 64], length: 0 };
    ok(unsafe { (a.mac)(hmac_id(h), sl(key), sl(data), &mut d) }, "mac")?;
    Ok(d.data[..d.length as usize].to_vec())
}

pub fn random(buf: &mut [u8]) -> Result<()> {
    let a = api()?;
    if buf.is_empty() { return Ok(()); }
    ok(unsafe { (a.random)(buf.as_mut_ptr(), buf.len() as u64) }, "random")
}

// ---- RSA handles with guaranteed destruction ----
struct RsaPub(*mut c_void, &'static Api);
impl Drop for RsaPub { fn drop(&mut self) { unsafe { (self.1.rsa_pub_destroy)(self.0) } } }
struct RsaPriv(*mut c_void, &'static Api);
impl Drop for RsaPriv { fn drop(&mut self) { unsafe { (self.1.rsa_priv_destroy)(self.0) } } }

fn rsa_pub(k: &Jwk) -> Result<RsaPub> {
    let a = api()?;
    let (n, e) = check_rsa(k)?;
    let mut h = std::ptr::null_mut();
    ok(unsafe { (a.rsa_pub_create)(sl(&n), sl(&e), &mut h) }, "rsa public import").map_err(|_| Error::Key("RSA public key rejected (qs_crypt supports 2048/3072/4096-bit)".into()))?;
    Ok(RsaPub(h, a))
}

fn rsa_priv(k: &Jwk) -> Result<RsaPriv> {
    let a = api()?;
    let (n, e) = check_rsa(k)?;
    let (d, p, q) = (k.req("d")?, k.req("p")?, k.req("q")?);
    let mut h = std::ptr::null_mut();
    ok(unsafe { (a.rsa_priv_create_crt)(sl(&n), sl(&e), sl(&d), sl(&p), sl(&q), &mut h) }, "rsa private import")
        .map_err(|_| Error::Key("RSA private key rejected (needs consistent n, e, d, p, q at 2048/3072/4096 bits)".into()))?;
    Ok(RsaPriv(h, a))
}

fn rsa_out<F: FnOnce(&mut Buffer) -> c_int>(cap: usize, f: F, what: &str) -> Result<Vec<u8>> {
    let mut v = vec![0u8; cap];
    let mut b = Buffer { data: v.as_mut_ptr(), length: cap as u64 };
    ok(f(&mut b), what)?;
    v.truncate(b.length as usize);
    Ok(v)
}

pub fn sign(alg: Algorithm, k: &Jwk, data: &[u8]) -> Result<Vec<u8>> {
    use Algorithm::*;
    let a = api()?;
    match alg {
        ES256 => {
            check_ec(alg, k)?;
            let mut sig = [0u8; 64];
            ok(unsafe { (a.p256_sign)(k.coord("d", 32)?.as_ptr(), sl(data), sig.as_mut_ptr()) }, "ecdsa sign")?;
            Ok(sig.to_vec())
        }
        ES384 | ES512 => { check_ec(alg, k)?; unsupported("qscrypt", "ECDSA P-384/P-521") }
        EdDSA => {
            check_okp(k)?;
            let mut sig = [0u8; 64];
            ok(unsafe { (a.ed_sign)(k.coord("d", 32)?.as_ptr(), data.as_ptr(), data.len() as u64, sig.as_mut_ptr()) }, "ed25519 sign")?;
            Ok(sig.to_vec())
        }
        RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => {
            let key = rsa_priv(k)?;
            let hid = hash_id(alg.hash().unwrap());
            let cap = check_rsa(k)?.0.len().max(512);
            let f = if matches!(alg, RS256 | RS384 | RS512) { a.pkcs1_sign } else { a.pss_sign };
            rsa_out(cap, |b| unsafe { f(key.0, hid, sl(data), b) }, "rsa sign")
        }
        _ => Err(Error::Algorithm(format!("{} is not a signature algorithm for this backend", alg.as_str()))),
    }
}

pub fn verify(alg: Algorithm, k: &Jwk, data: &[u8], sig: &[u8]) -> Result<()> {
    use Algorithm::*;
    let a = api()?;
    let bad = |rc: c_int| if rc == 0 { Ok(()) } else { Err(Error::BadSignature) };
    match alg {
        ES256 => {
            check_ec(alg, k)?;
            if sig.len() != 64 { return Err(Error::BadSignature); }
            let mut pt = [0u8; 65];
            pt[0] = 4;
            pt[1..33].copy_from_slice(&k.coord("x", 32)?);
            pt[33..].copy_from_slice(&k.coord("y", 32)?);
            bad(unsafe { (a.p256_verify)(pt.as_ptr(), sl(data), sig.as_ptr()) })
        }
        ES384 | ES512 => { check_ec(alg, k)?; unsupported("qscrypt", "ECDSA P-384/P-521") }
        EdDSA => {
            check_okp(k)?;
            if sig.len() != 64 { return Err(Error::BadSignature); }
            bad(unsafe { (a.ed_verify)(k.coord("x", 32)?.as_ptr(), data.as_ptr(), data.len() as u64, sig.as_ptr()) })
        }
        RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => {
            let key = rsa_pub(k)?;
            let hid = hash_id(alg.hash().unwrap());
            let f = if matches!(alg, RS256 | RS384 | RS512) { a.pkcs1_verify } else { a.pss_verify };
            bad(unsafe { f(key.0, hid, sl(data), sl(sig)) })
        }
        _ => Err(Error::Algorithm(format!("{} is not a signature algorithm for this backend", alg.as_str()))),
    }
}

pub fn aead_seal(alg: AeadAlg, key: &[u8], iv: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let a = api()?;
    let id = match alg { AeadAlg::A128Gcm => ALG_AES_128_GCM, AeadAlg::A256Gcm => ALG_AES_256_GCM,
        AeadAlg::A192Gcm => return unsupported("qscrypt", "AES-192-GCM") };
    if key.len() != alg.key_len() || iv.len() != super::GCM_IV_LEN {
        return Err(Error::Key("AES-GCM needs a matching key length and a 12-byte IV".into()));
    }
    let mut ct = vec![0u8; pt.len()];
    let mut tag = Digest { data: [0; 64], length: 0 };
    ok(unsafe { (a.aead_enc)(id, sl(key), sl(iv), sl(aad), sl(pt), ct.as_mut_ptr(), &mut tag) }, "aead seal")?;
    Ok((ct, tag.data[..tag.length as usize].to_vec()))
}

pub fn aead_open(alg: AeadAlg, key: &[u8], iv: &[u8], aad: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    let a = api()?;
    let id = match alg { AeadAlg::A128Gcm => ALG_AES_128_GCM, AeadAlg::A256Gcm => ALG_AES_256_GCM,
        AeadAlg::A192Gcm => return unsupported("qscrypt", "AES-192-GCM") };
    if key.len() != alg.key_len() || iv.len() != super::GCM_IV_LEN {
        return Err(Error::Key("AES-GCM needs a matching key length and a 12-byte IV".into()));
    }
    if tag.len() != super::GCM_TAG_LEN { return Err(Error::Decrypt); }
    let mut pt = vec![0u8; ct.len()];
    let rc = unsafe { (a.aead_dec)(id, sl(key), sl(iv), sl(aad), sl(ct), sl(tag), pt.as_mut_ptr()) };
    if rc != 0 { return Err(Error::Decrypt); }
    Ok(pt)
}

pub fn cbc_encrypt(key: &[u8], iv: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let a = api()?;
    if iv.len() != 16 { return Err(Error::Key("CBC IV must be 16 bytes".into())); }
    let mut out = vec![0u8; (pt.len() / 16 + 1) * 16];
    let mut n = 0u64;
    ok(unsafe { (a.cbc_enc)(sl(key), iv.as_ptr(), sl(pt), out.as_mut_ptr(), &mut n) }, "cbc encrypt").map_err(|_| Error::Key("bad AES key or IV".into()))?;
    out.truncate(n as usize);
    Ok(out)
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let a = api()?;
    if iv.len() != 16 { return Err(Error::Key("CBC IV must be 16 bytes".into())); }
    if ct.is_empty() || ct.len() % 16 != 0 { return Err(Error::Decrypt); }
    let mut out = vec![0u8; ct.len()];
    let mut n = 0u64;
    let rc = unsafe { (a.cbc_dec)(sl(key), iv.as_ptr(), sl(ct), out.as_mut_ptr(), &mut n) };
    if rc != 0 { return Err(Error::Decrypt); }
    out.truncate(n as usize);
    Ok(out)
}

pub fn aes_kw_wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let a = api()?;
    if key.len() < 16 || key.len() % 8 != 0 { return Err(Error::Key("key to wrap must be a multiple of 8 bytes, at least 16".into())); }
    let mut out = vec![0u8; key.len() + 8];
    ok(unsafe { (a.kw_wrap)(sl(kek), sl(key), out.as_mut_ptr()) }, "key wrap").map_err(|_| Error::Key("bad AES key".into()))?;
    Ok(out)
}

pub fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    let a = api()?;
    if wrapped.len() < 24 || wrapped.len() % 8 != 0 { return Err(Error::Decrypt); }
    let mut out = vec![0u8; wrapped.len() - 8];
    if unsafe { (a.kw_unwrap)(sl(kek), sl(wrapped), out.as_mut_ptr()) } != 0 { return Err(Error::Decrypt); }
    Ok(out)
}

pub fn pbkdf2(h: Hash, password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Result<Vec<u8>> {
    let a = api()?;
    if iterations == 0 || out_len == 0 { return Err(Error::Key("pbkdf2: iterations and length must be non-zero".into())); }
    let mut out = vec![0u8; out_len];
    ok(unsafe { (a.pbkdf2)(hmac_id(h), sl(password), sl(salt), iterations, out.as_mut_ptr(), out_len as u64) }, "pbkdf2")?;
    Ok(out)
}

pub fn rsa_oaep_encrypt(h: OaepHash, k: &Jwk, msg: &[u8]) -> Result<Vec<u8>> {
    let a = api()?;
    let hh = super::hash_of(h).ok_or_else(|| Error::Unsupported("RSA-OAEP with SHA-1 (backend qscrypt)".into()))?;
    let key = rsa_pub(k)?;
    let cap = check_rsa(k)?.0.len().max(512);
    rsa_out(cap, |b| unsafe { (a.oaep_enc)(key.0, hash_id(hh), sl(msg), b) }, "oaep encrypt")
}

pub fn rsa_oaep_decrypt(h: OaepHash, k: &Jwk, ct: &[u8]) -> Result<Vec<u8>> {
    let a = api()?;
    let hh = super::hash_of(h).ok_or_else(|| Error::Unsupported("RSA-OAEP with SHA-1 (backend qscrypt)".into()))?;
    let key = rsa_priv(k)?;
    let cap = ct.len().max(512);
    rsa_out(cap, |b| unsafe { (a.oaep_dec)(key.0, hash_id(hh), sl(ct), b) }, "oaep decrypt").map_err(|_| Error::Decrypt)
}

pub fn ec_generate(crv: &str) -> Result<Jwk> {
    let a = api()?;
    if crv != "X25519" { return unsupported("qscrypt", "EC key generation on NIST curves"); }
    let (mut d, mut x) = ([0u8; 32], [0u8; 32]);
    ok(unsafe { (a.x_keygen)(d.as_mut_ptr(), x.as_mut_ptr()) }, "x25519 keygen")?;
    Ok(ec_jwk(crv, &d, &x, None))
}

pub fn ecdh(private: &Jwk, public: &Jwk) -> Result<Vec<u8>> {
    let a = api()?;
    let (crv, _) = check_agreement_key(private)?;
    let (pcrv, _) = check_agreement_key(public)?;
    if crv != pcrv { return Err(Error::Key("ECDH keys are on different curves".into())); }
    if crv != "X25519" { return unsupported("qscrypt", "ECDH on NIST curves"); }
    let mut out = [0u8; 32];
    ok(unsafe { (a.x_shared)(private.coord("d", 32)?.as_ptr(), public.coord("x", 32)?.as_ptr(), out.as_mut_ptr()) }, "x25519 shared")
        .map_err(|_| Error::Key("X25519 peer key has small order".into()))?;
    Ok(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_sha256_matches_fips_vector() {
        let d = sha256(b"abc");
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let big = vec![0x61u8; 1_000_000];
        let hex: String = sha256(&big).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }
}
