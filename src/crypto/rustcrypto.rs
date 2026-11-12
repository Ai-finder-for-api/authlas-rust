use crate::error::{Error, Result};
use crate::jwa::{Algorithm, Hash};
use crate::jwk::Jwk;
use super::{check_ec, check_okp, check_rsa};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};

pub fn digest(h: Hash, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match h {
        Hash::Sha256 => Sha256::digest(data).to_vec(),
        Hash::Sha384 => Sha384::digest(data).to_vec(),
        Hash::Sha512 => Sha512::digest(data).to_vec(),
    })
}

pub fn hmac(h: Hash, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    macro_rules! go { ($d:ty) => {{
        let mut m = <Hmac<$d> as Mac>::new_from_slice(key).map_err(|e| Error::Key(e.to_string()))?;
        m.update(data);
        Ok(m.finalize().into_bytes().to_vec())
    }}}
    match h { Hash::Sha256 => go!(Sha256), Hash::Sha384 => go!(Sha384), Hash::Sha512 => go!(Sha512) }
}

pub fn random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| Error::Crypto(format!("entropy: {e}")))
}

fn ec_pub_sec1(k: &Jwk, size: usize) -> Result<Vec<u8>> {
    let mut v = vec![0x04];
    v.extend(k.coord("x", size)?);
    v.extend(k.coord("y", size)?);
    Ok(v)
}

macro_rules! ecdsa_impl {
    ($sign:ident, $verify:ident, $curve:ident, $size:expr) => {
        fn $sign(k: &Jwk, data: &[u8]) -> Result<Vec<u8>> {
            use $curve::ecdsa::{signature::Signer, Signature, SigningKey};
            let sk = SigningKey::from_slice(&k.coord("d", $size)?).map_err(|e| Error::Key(e.to_string()))?;
            let sig: Signature = sk.try_sign(data).map_err(|e| Error::Crypto(e.to_string()))?;
            Ok(sig.to_bytes().to_vec())
        }
        fn $verify(k: &Jwk, data: &[u8], sig: &[u8]) -> Result<()> {
            use $curve::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(&ec_pub_sec1(k, $size)?).map_err(|e| Error::Key(e.to_string()))?;
            let s = Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
            vk.verify(data, &s).map_err(|_| Error::BadSignature)
        }
    };
}
ecdsa_impl!(sign_p256, verify_p256, p256, 32);
ecdsa_impl!(sign_p384, verify_p384, p384, 48);
ecdsa_impl!(sign_p521, verify_p521, p521, 66);

fn rsa_public(k: &Jwk) -> Result<rsa::RsaPublicKey> {
    let (n, e) = check_rsa(k)?;
    rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(&n), rsa::BigUint::from_bytes_be(&e))
        .map_err(|e| Error::Key(e.to_string()))
}

fn rsa_private(k: &Jwk) -> Result<rsa::RsaPrivateKey> {
    let (n, e) = check_rsa(k)?;
    let d = k.req("d")?;
    let (p, q) = (k.req("p")?, k.req("q")?);
    let key = rsa::RsaPrivateKey::from_components(
        rsa::BigUint::from_bytes_be(&n),
        rsa::BigUint::from_bytes_be(&e),
        rsa::BigUint::from_bytes_be(&d),
        vec![rsa::BigUint::from_bytes_be(&p), rsa::BigUint::from_bytes_be(&q)],
    )
    .map_err(|e| Error::Key(e.to_string()))?;
    key.validate().map_err(|e| Error::Key(e.to_string()))?;
    Ok(key)
}

pub fn sign(alg: Algorithm, k: &Jwk, data: &[u8]) -> Result<Vec<u8>> {
    use Algorithm::*;
    use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer};
    match alg {
        ES256 => { check_ec(alg, k)?; sign_p256(k, data) }
        ES384 => { check_ec(alg, k)?; sign_p384(k, data) }
        ES512 => { check_ec(alg, k)?; sign_p521(k, data) }
        EdDSA => {
            check_okp(k)?;
            let sk = ed25519_dalek::SigningKey::from_bytes(
                &k.coord("d", 32)?.try_into().map_err(|_| Error::Key("bad d".into()))?);
            Ok(sk.sign(data).to_bytes().to_vec())
        }
        RS256 => Ok(rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_private(k)?).sign(data).to_vec()),
        RS384 => Ok(rsa::pkcs1v15::SigningKey::<Sha384>::new(rsa_private(k)?).sign(data).to_vec()),
        RS512 => Ok(rsa::pkcs1v15::SigningKey::<Sha512>::new(rsa_private(k)?).sign(data).to_vec()),
        PS256 => Ok(rsa::pss::BlindedSigningKey::<Sha256>::new(rsa_private(k)?).sign_with_rng(&mut rand_core::OsRng, data).to_vec()),
        PS384 => Ok(rsa::pss::BlindedSigningKey::<Sha384>::new(rsa_private(k)?).sign_with_rng(&mut rand_core::OsRng, data).to_vec()),
        PS512 => Ok(rsa::pss::BlindedSigningKey::<Sha512>::new(rsa_private(k)?).sign_with_rng(&mut rand_core::OsRng, data).to_vec()),
        _ => Err(Error::Algorithm(format!("{} is not a signature algorithm for this backend", alg.as_str()))),
    }
}

pub fn verify(alg: Algorithm, k: &Jwk, data: &[u8], sig: &[u8]) -> Result<()> {
    use Algorithm::*;
    use rsa::signature::Verifier;
    let bad = |_| Error::BadSignature;
    match alg {
        ES256 => { check_ec(alg, k)?; verify_p256(k, data, sig) }
        ES384 => { check_ec(alg, k)?; verify_p384(k, data, sig) }
        ES512 => { check_ec(alg, k)?; verify_p521(k, data, sig) }
        EdDSA => {
            check_okp(k)?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(
                &k.coord("x", 32)?.try_into().map_err(|_| Error::Key("bad x".into()))?)
                .map_err(|e| Error::Key(e.to_string()))?;
            let s = ed25519_dalek::Signature::from_slice(sig).map_err(bad)?;
            vk.verify_strict(data, &s).map_err(bad)
        }
        RS256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_public(k)?).verify(data, &rsa::pkcs1v15::Signature::try_from(sig).map_err(bad)?).map_err(bad),
        RS384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(rsa_public(k)?).verify(data, &rsa::pkcs1v15::Signature::try_from(sig).map_err(bad)?).map_err(bad),
        RS512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(rsa_public(k)?).verify(data, &rsa::pkcs1v15::Signature::try_from(sig).map_err(bad)?).map_err(bad),
        PS256 => rsa::pss::VerifyingKey::<Sha256>::new(rsa_public(k)?).verify(data, &rsa::pss::Signature::try_from(sig).map_err(bad)?).map_err(bad),
        PS384 => rsa::pss::VerifyingKey::<Sha384>::new(rsa_public(k)?).verify(data, &rsa::pss::Signature::try_from(sig).map_err(bad)?).map_err(bad),
        PS512 => rsa::pss::VerifyingKey::<Sha512>::new(rsa_public(k)?).verify(data, &rsa::pss::Signature::try_from(sig).map_err(bad)?).map_err(bad),
        _ => Err(Error::Algorithm(format!("{} is not a signature algorithm for this backend", alg.as_str()))),
    }
}

// ======================= JWE / key agreement / KDF additions =======================
use super::{ec_jwk, check_agreement_key, pkcs7_pad, pkcs7_unpad, AeadAlg, OaepHash};

pub fn aead_seal(alg: AeadAlg, key: &[u8], iv: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use aes_gcm::{aead::{consts::U12, generic_array::GenericArray, AeadInPlace, KeyInit}, aes::Aes192, Aes128Gcm, Aes256Gcm, AesGcm};
    type Aes192Gcm = AesGcm<Aes192, U12>;
    if key.len() != alg.key_len() || iv.len() != super::GCM_IV_LEN {
        return Err(Error::Key("AES-GCM needs a matching key length and a 12-byte IV".into()));
    }
    let mut buf = pt.to_vec();
    macro_rules! go { ($c:ty) => {{
        let c = <$c>::new(GenericArray::from_slice(key));
        let tag = c.encrypt_in_place_detached(GenericArray::from_slice(iv), aad, &mut buf)
            .map_err(|_| Error::Crypto("aead seal".into()))?;
        tag.to_vec()
    }}}
    let tag = match alg { AeadAlg::A128Gcm => go!(Aes128Gcm), AeadAlg::A192Gcm => go!(Aes192Gcm), AeadAlg::A256Gcm => go!(Aes256Gcm) };
    Ok((buf, tag))
}

pub fn aead_open(alg: AeadAlg, key: &[u8], iv: &[u8], aad: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::{consts::U12, generic_array::GenericArray, AeadInPlace, KeyInit}, aes::Aes192, Aes128Gcm, Aes256Gcm, AesGcm};
    type Aes192Gcm = AesGcm<Aes192, U12>;
    if key.len() != alg.key_len() || iv.len() != super::GCM_IV_LEN {
        return Err(Error::Key("AES-GCM needs a matching key length and a 12-byte IV".into()));
    }
    if tag.len() != super::GCM_TAG_LEN { return Err(Error::Decrypt); }
    let mut buf = ct.to_vec();
    macro_rules! go { ($c:ty) => {{
        let c = <$c>::new(GenericArray::from_slice(key));
        c.decrypt_in_place_detached(GenericArray::from_slice(iv), aad, &mut buf, GenericArray::from_slice(tag))
            .map_err(|_| Error::Decrypt)?;
    }}}
    match alg { AeadAlg::A128Gcm => go!(Aes128Gcm), AeadAlg::A192Gcm => go!(Aes192Gcm), AeadAlg::A256Gcm => go!(Aes256Gcm) }
    Ok(buf)
}

/// AES-CBC with PKCS#7 padding. JWE authenticates with HMAC before calling `cbc_decrypt`.
pub fn cbc_encrypt(key: &[u8], iv: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
    let data = pkcs7_pad(pt);
    macro_rules! go { ($a:ty) => {
        cbc::Encryptor::<$a>::new_from_slices(key, iv).map_err(|e| Error::Key(e.to_string()))?
            .encrypt_padded_vec_mut::<NoPadding>(&data)
    }}
    Ok(match key.len() { 16 => go!(aes::Aes128), 24 => go!(aes::Aes192), 32 => go!(aes::Aes256),
        _ => return Err(Error::Key("AES key must be 16, 24 or 32 bytes".into())) })
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    if ct.is_empty() || ct.len() % 16 != 0 { return Err(Error::Decrypt); }
    macro_rules! go { ($a:ty) => {
        cbc::Decryptor::<$a>::new_from_slices(key, iv).map_err(|e| Error::Key(e.to_string()))?
            .decrypt_padded_vec_mut::<NoPadding>(ct).map_err(|_| Error::Decrypt)?
    }}
    let raw = match key.len() { 16 => go!(aes::Aes128), 24 => go!(aes::Aes192), 32 => go!(aes::Aes256),
        _ => return Err(Error::Key("AES key must be 16, 24 or 32 bytes".into())) };
    pkcs7_unpad(raw)
}

pub fn rsa_oaep_encrypt(h: OaepHash, k: &Jwk, msg: &[u8]) -> Result<Vec<u8>> {
    let pubk = rsa_public(k)?;
    let mut rng = rand_core::OsRng;
    let r = match h {
        OaepHash::Sha1 => pubk.encrypt(&mut rng, rsa::Oaep::new::<sha1::Sha1>(), msg),
        OaepHash::Sha256 => pubk.encrypt(&mut rng, rsa::Oaep::new::<Sha256>(), msg),
        OaepHash::Sha384 => pubk.encrypt(&mut rng, rsa::Oaep::new::<Sha384>(), msg),
        OaepHash::Sha512 => pubk.encrypt(&mut rng, rsa::Oaep::new::<Sha512>(), msg),
    };
    r.map_err(|e| Error::Crypto(e.to_string()))
}

/// Note: the `rsa` crate's private-key operation is not constant time (RUSTSEC-2023-0071, "Marvin").
/// Prefer another backend for RSA decryption on a network-facing server.
pub fn rsa_oaep_decrypt(h: OaepHash, k: &Jwk, ct: &[u8]) -> Result<Vec<u8>> {
    let privk = rsa_private(k)?;
    let r = match h {
        OaepHash::Sha1 => privk.decrypt(rsa::Oaep::new::<sha1::Sha1>(), ct),
        OaepHash::Sha256 => privk.decrypt(rsa::Oaep::new::<Sha256>(), ct),
        OaepHash::Sha384 => privk.decrypt(rsa::Oaep::new::<Sha384>(), ct),
        OaepHash::Sha512 => privk.decrypt(rsa::Oaep::new::<Sha512>(), ct),
    };
    r.map_err(|_| Error::Decrypt)
}

pub fn ec_generate(crv: &str) -> Result<Jwk> {
    macro_rules! nist { ($c:ident) => {{
        use $c::elliptic_curve::sec1::ToEncodedPoint;
        let sk = $c::SecretKey::random(&mut rand_core::OsRng);
        let pt = sk.public_key().to_encoded_point(false);
        ec_jwk(crv, &sk.to_bytes(), pt.x().unwrap(), pt.y().map(|y| y.as_slice()))
    }}}
    Ok(match crv {
        "P-256" => nist!(p256),
        "P-384" => nist!(p384),
        "P-521" => nist!(p521),
        "X25519" => {
            let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
            let pk = x25519_dalek::PublicKey::from(&sk);
            ec_jwk(crv, &sk.to_bytes(), pk.as_bytes(), None)
        }
        other => return Err(Error::Key(format!("cannot generate {other:?} keys"))),
    })
}

/// ECDH. Validates that the peer point is on the curve; X25519 rejects low-order points.
pub fn ecdh(private: &Jwk, public: &Jwk) -> Result<Vec<u8>> {
    let (crv, n) = check_agreement_key(private)?;
    let (pcrv, _) = check_agreement_key(public)?;
    if crv != pcrv { return Err(Error::Key("ECDH keys are on different curves".into())); }
    let d = private.coord("d", n)?;
    macro_rules! nist { ($c:ident) => {{
        use $c::elliptic_curve::sec1::FromEncodedPoint;
        let sk = $c::SecretKey::from_slice(&d).map_err(|e| Error::Key(e.to_string()))?;
        let (x, y) = (public.coord("x", n)?, public.coord("y", n)?);
        let pt = $c::EncodedPoint::from_affine_coordinates($c::FieldBytes::from_slice(&x), $c::FieldBytes::from_slice(&y), false);
        let pk = Option::<$c::PublicKey>::from($c::PublicKey::from_encoded_point(&pt))
            .ok_or_else(|| Error::Key("peer public key is not on the curve".into()))?;
        $c::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine()).raw_secret_bytes().to_vec()
    }}}
    Ok(match crv.as_str() {
        "P-256" => nist!(p256),
        "P-384" => nist!(p384),
        "P-521" => nist!(p521),
        _ => {
            let sk = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(d.as_slice()).unwrap());
            let pk = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(public.coord("x", 32)?.as_slice()).unwrap());
            let ss = sk.diffie_hellman(&pk);
            if !ss.was_contributory() { return Err(Error::Key("X25519 peer key has small order".into())); }
            ss.as_bytes().to_vec()
        }
    })
}

pub fn aes_kw_wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    macro_rules! go { ($a:ty) => {{
        let c = <$a>::new_from_slice(kek).map_err(|e| Error::Key(e.to_string()))?;
        super::kw_wrap_with(&|b: &[u8; 16]| { let mut g = GenericArray::clone_from_slice(b); c.encrypt_block(&mut g); Ok(g.into()) }, key)
    }}}
    match kek.len() { 16 => go!(aes::Aes128), 24 => go!(aes::Aes192), 32 => go!(aes::Aes256),
        _ => Err(Error::Key("AES key must be 16, 24 or 32 bytes".into())) }
}

pub fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
    macro_rules! go { ($a:ty) => {{
        let c = <$a>::new_from_slice(kek).map_err(|e| Error::Key(e.to_string()))?;
        super::kw_unwrap_with(&|b: &[u8; 16]| { let mut g = GenericArray::clone_from_slice(b); c.decrypt_block(&mut g); Ok(g.into()) }, wrapped)
    }}}
    match kek.len() { 16 => go!(aes::Aes128), 24 => go!(aes::Aes192), 32 => go!(aes::Aes256),
        _ => Err(Error::Key("AES key must be 16, 24 or 32 bytes".into())) }
}

pub fn pbkdf2(h: Hash, password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Result<Vec<u8>> {
    super::pbkdf2_with(&|k, d| hmac(h, k, d), h.output_len(), password, salt, iterations, out_len)
}
