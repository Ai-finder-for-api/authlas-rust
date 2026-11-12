use crate::error::{Error, Result};
use crate::jwa::{Algorithm, Hash};
use crate::jwk::Jwk;
use super::{check_ec, check_okp, check_rsa};
use aws_lc_rs::{digest as d, hmac as h, rand::{SecureRandom, SystemRandom}, rsa::PublicKeyComponents,
    signature::{self as sg, EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair, UnparsedPublicKey}};

fn dig(x: Hash) -> &'static d::Algorithm {
    match x { Hash::Sha256 => &d::SHA256, Hash::Sha384 => &d::SHA384, Hash::Sha512 => &d::SHA512 }
}

pub fn digest(x: Hash, data: &[u8]) -> Result<Vec<u8>> { Ok(d::digest(dig(x), data).as_ref().to_vec()) }

pub fn hmac(x: Hash, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let a = match x { Hash::Sha256 => h::HMAC_SHA256, Hash::Sha384 => h::HMAC_SHA384, Hash::Sha512 => h::HMAC_SHA512 };
    Ok(h::sign(&h::Key::new(a, key), data).as_ref().to_vec())
}

pub fn random(buf: &mut [u8]) -> Result<()> {
    SystemRandom::new().fill(buf).map_err(|_| Error::Crypto("entropy failure".into()))
}

fn ec_n(alg: Algorithm) -> usize { match alg { Algorithm::ES256 => 32, Algorithm::ES384 => 48, _ => 66 } }

fn sec1(k: &Jwk, n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0x04];
    v.extend(k.coord("x", n)?);
    v.extend(k.coord("y", n)?);
    Ok(v)
}

// ---- minimal DER writer for PKCS#1 RSAPrivateKey ----
fn der_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 { out.push(n as u8); }
    else { let b = n.to_be_bytes(); let i = b.iter().position(|x| *x != 0).unwrap(); out.push(0x80 | (b.len() - i) as u8); out.extend(&b[i..]); }
}
fn der_int(out: &mut Vec<u8>, be: &[u8]) {
    let i = be.iter().position(|x| *x != 0).unwrap_or(be.len().saturating_sub(1));
    let t = &be[i..];
    out.push(0x02);
    let pad = t.first().map_or(false, |b| b & 0x80 != 0);
    der_len(out, t.len() + pad as usize);
    if pad { out.push(0); }
    out.extend(t);
}
fn rsa_der(k: &Jwk) -> Result<Vec<u8>> {
    let (n, e) = check_rsa(k)?;
    let mut body = Vec::new();
    der_int(&mut body, &[0]);
    der_int(&mut body, &n);
    der_int(&mut body, &e);
    for m in ["d", "p", "q", "dp", "dq", "qi"] { der_int(&mut body, &k.req(m)?); }
    let mut out = vec![0x30];
    der_len(&mut out, body.len());
    out.extend(body);
    Ok(out)
}

fn ec_pair(alg: Algorithm, k: &Jwk) -> Result<EcdsaKeyPair> {
    let a = match alg {
        Algorithm::ES256 => &sg::ECDSA_P256_SHA256_FIXED_SIGNING,
        Algorithm::ES384 => &sg::ECDSA_P384_SHA384_FIXED_SIGNING,
        _ => &sg::ECDSA_P521_SHA512_FIXED_SIGNING,
    };
    let n = ec_n(alg);
    EcdsaKeyPair::from_private_key_and_public_key(a, &k.coord("d", n)?, &sec1(k, n)?)
        .map_err(|x| Error::Key(x.to_string()))
}

pub fn sign(alg: Algorithm, k: &Jwk, data: &[u8]) -> Result<Vec<u8>> {
    use Algorithm::*;
    let rng = SystemRandom::new();
    match alg {
        ES256 | ES384 | ES512 => {
            check_ec(alg, k)?;
            Ok(ec_pair(alg, k)?.sign(&rng, data).map_err(|x| Error::Crypto(x.to_string()))?.as_ref().to_vec())
        }
        EdDSA => {
            check_okp(k)?;
            let kp = Ed25519KeyPair::from_seed_and_public_key(&k.coord("d", 32)?, &k.coord("x", 32)?)
                .map_err(|x| Error::Key(x.to_string()))?;
            Ok(kp.sign(data).as_ref().to_vec())
        }
        RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => {
            let kp = RsaKeyPair::from_der(&rsa_der(k)?).map_err(|x| Error::Key(x.to_string()))?;
            let padding: &'static dyn sg::RsaEncoding = match alg {
                RS256 => &sg::RSA_PKCS1_SHA256, RS384 => &sg::RSA_PKCS1_SHA384, RS512 => &sg::RSA_PKCS1_SHA512,
                PS256 => &sg::RSA_PSS_SHA256, PS384 => &sg::RSA_PSS_SHA384, _ => &sg::RSA_PSS_SHA512,
            };
            let mut sig = vec![0u8; kp.public_modulus_len()];
            kp.sign(padding, &rng, data, &mut sig).map_err(|x| Error::Crypto(x.to_string()))?;
            Ok(sig)
        }
        _ => Err(Error::Algorithm(format!("{} is not a signature algorithm for this backend", alg.as_str()))),
    }
}

pub fn verify(alg: Algorithm, k: &Jwk, data: &[u8], sig: &[u8]) -> Result<()> {
    use Algorithm::*;
    let bad = |_| Error::BadSignature;
    match alg {
        ES256 | ES384 | ES512 => {
            check_ec(alg, k)?;
            let a: &'static dyn sg::VerificationAlgorithm = match alg {
                ES256 => &sg::ECDSA_P256_SHA256_FIXED, ES384 => &sg::ECDSA_P384_SHA384_FIXED, _ => &sg::ECDSA_P521_SHA512_FIXED,
            };
            UnparsedPublicKey::new(a, sec1(k, ec_n(alg))?).verify(data, sig).map_err(bad)
        }
        EdDSA => {
            check_okp(k)?;
            UnparsedPublicKey::new(&sg::ED25519, k.coord("x", 32)?).verify(data, sig).map_err(bad)
        }
        RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => {
            let (n, e) = check_rsa(k)?;
            let a: &'static sg::RsaParameters = match alg {
                RS256 => &sg::RSA_PKCS1_2048_8192_SHA256, RS384 => &sg::RSA_PKCS1_2048_8192_SHA384, RS512 => &sg::RSA_PKCS1_2048_8192_SHA512,
                PS256 => &sg::RSA_PSS_2048_8192_SHA256, PS384 => &sg::RSA_PSS_2048_8192_SHA384, _ => &sg::RSA_PSS_2048_8192_SHA512,
            };
            PublicKeyComponents { n, e }.verify(a, data, sig).map_err(bad)
        }
        _ => Err(Error::Algorithm(format!("{} is not a signature algorithm for this backend", alg.as_str()))),
    }
}

// ======================= JWE / key agreement / KDF additions =======================
use super::{check_agreement_key, ec_jwk, pkcs7_pad, pkcs7_unpad, AeadAlg, OaepHash};
use aws_lc_rs::{aead as ae, agreement as ag, cipher as ci, encoding::{AsBigEndian, EcPrivateKeyBin, EcPublicKeyUncompressedBin},
    iv::FixedLength, rsa::{OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey, OAEP_SHA1_MGF1SHA1,
    OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512, OaepAlgorithm}};

pub fn aead_seal(alg: AeadAlg, key: &[u8], iv: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let a = match alg { AeadAlg::A128Gcm => &ae::AES_128_GCM, AeadAlg::A192Gcm => &ae::AES_192_GCM, AeadAlg::A256Gcm => &ae::AES_256_GCM };
    if key.len() != alg.key_len() || iv.len() != super::GCM_IV_LEN {
        return Err(Error::Key("AES-GCM needs a matching key length and a 12-byte IV".into()));
    }
    let k = ae::LessSafeKey::new(ae::UnboundKey::new(a, key).map_err(|_| Error::Key("aes-gcm key".into()))?);
    let nonce = ae::Nonce::try_assume_unique_for_key(iv).map_err(|_| Error::Key("iv".into()))?;
    let mut buf = pt.to_vec();
    let tag = k.seal_in_place_separate_tag(nonce, ae::Aad::from(aad), &mut buf).map_err(|_| Error::Crypto("aead seal".into()))?;
    Ok((buf, tag.as_ref().to_vec()))
}

pub fn aead_open(alg: AeadAlg, key: &[u8], iv: &[u8], aad: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    let a = match alg { AeadAlg::A128Gcm => &ae::AES_128_GCM, AeadAlg::A192Gcm => &ae::AES_192_GCM, AeadAlg::A256Gcm => &ae::AES_256_GCM };
    if key.len() != alg.key_len() || iv.len() != super::GCM_IV_LEN {
        return Err(Error::Key("AES-GCM needs a matching key length and a 12-byte IV".into()));
    }
    if tag.len() != super::GCM_TAG_LEN { return Err(Error::Decrypt); }
    let k = ae::LessSafeKey::new(ae::UnboundKey::new(a, key).map_err(|_| Error::Key("aes-gcm key".into()))?);
    let nonce = ae::Nonce::try_assume_unique_for_key(iv).map_err(|_| Error::Key("iv".into()))?;
    let mut buf = ct.to_vec();
    buf.extend_from_slice(tag);
    let n = k.open_in_place(nonce, ae::Aad::from(aad), &mut buf).map_err(|_| Error::Decrypt)?.len();
    buf.truncate(n);
    Ok(buf)
}

fn cipher_alg(key: &[u8]) -> Result<&'static ci::Algorithm> {
    match key.len() { 16 => Ok(&ci::AES_128), 24 => Ok(&ci::AES_192), 32 => Ok(&ci::AES_256),
        _ => Err(Error::Key("AES key must be 16, 24 or 32 bytes".into())) }
}

fn iv16(iv: &[u8]) -> Result<[u8; 16]> { iv.try_into().map_err(|_| Error::Key("CBC IV must be 16 bytes".into())) }

/// AES-CBC with PKCS#7 padding. JWE authenticates with HMAC before calling `cbc_decrypt`.
pub fn cbc_encrypt(key: &[u8], iv: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let k = ci::EncryptingKey::cbc(ci::UnboundCipherKey::new(cipher_alg(key)?, key).map_err(|_| Error::Key("aes key".into()))?)
        .map_err(|_| Error::Key("cbc".into()))?;
    let mut buf = pkcs7_pad(pt);
    k.less_safe_encrypt(&mut buf, ci::EncryptionContext::Iv128(FixedLength::from(iv16(iv)?))).map_err(|_| Error::Crypto("cbc".into()))?;
    Ok(buf)
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    if ct.is_empty() || ct.len() % 16 != 0 { return Err(Error::Decrypt); }
    let k = ci::DecryptingKey::cbc(ci::UnboundCipherKey::new(cipher_alg(key)?, key).map_err(|_| Error::Key("aes key".into()))?)
        .map_err(|_| Error::Key("cbc".into()))?;
    let mut buf = ct.to_vec();
    let n = k.decrypt(&mut buf, ci::DecryptionContext::Iv128(FixedLength::from(iv16(iv)?))).map_err(|_| Error::Decrypt)?.len();
    buf.truncate(n);
    pkcs7_unpad(buf)
}

fn ecb_block(key: &[u8], encrypt: bool, b: &[u8; 16]) -> Result<[u8; 16]> {
    let uk = ci::UnboundCipherKey::new(cipher_alg(key)?, key).map_err(|_| Error::Key("aes key".into()))?;
    let mut buf = b.to_vec();
    if encrypt {
        ci::EncryptingKey::ecb(uk).map_err(|_| Error::Key("ecb".into()))?
            .less_safe_encrypt(&mut buf, ci::EncryptionContext::None).map_err(|_| Error::Crypto("ecb".into()))?;
    } else {
        ci::DecryptingKey::ecb(uk).map_err(|_| Error::Key("ecb".into()))?
            .decrypt(&mut buf, ci::DecryptionContext::None).map_err(|_| Error::Crypto("ecb".into()))?;
    }
    buf.try_into().map_err(|_| Error::Crypto("ecb length".into()))
}

pub fn aes_kw_wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    cipher_alg(kek)?;
    super::kw_wrap_with(&|b| ecb_block(kek, true, b), key)
}

pub fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    cipher_alg(kek)?;
    super::kw_unwrap_with(&|b| ecb_block(kek, false, b), wrapped)
}

pub fn pbkdf2(h: Hash, password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Result<Vec<u8>> {
    super::pbkdf2_with(&|k, d| hmac(h, k, d), h.output_len(), password, salt, iterations, out_len)
}

// ---- RSA-OAEP: build the DER wrappers aws-lc-rs wants (SPKI for public, PKCS#8 for private) ----
fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    der_len(&mut v, body.len());
    v.extend_from_slice(body);
    v
}
const RSA_ALG_ID: [u8; 15] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];

fn rsa_spki(k: &Jwk) -> Result<Vec<u8>> {
    let (n, e) = check_rsa(k)?;
    let mut seq = Vec::new();
    der_int(&mut seq, &n);
    der_int(&mut seq, &e);
    let rsapub = der_tlv(0x30, &seq);
    let mut bits = vec![0u8];
    bits.extend(rsapub);
    let mut body = RSA_ALG_ID.to_vec();
    body.extend(der_tlv(0x03, &bits));
    Ok(der_tlv(0x30, &body))
}

fn rsa_pkcs8(k: &Jwk) -> Result<Vec<u8>> {
    let pkcs1 = rsa_der(k)?;
    let mut body = Vec::new();
    der_int(&mut body, &[0]);
    body.extend_from_slice(&RSA_ALG_ID);
    body.extend(der_tlv(0x04, &pkcs1));
    Ok(der_tlv(0x30, &body))
}

fn oaep_alg(h: OaepHash) -> &'static OaepAlgorithm {
    match h { OaepHash::Sha1 => &OAEP_SHA1_MGF1SHA1, OaepHash::Sha256 => &OAEP_SHA256_MGF1SHA256,
        OaepHash::Sha384 => &OAEP_SHA384_MGF1SHA384, OaepHash::Sha512 => &OAEP_SHA512_MGF1SHA512 }
}

pub fn rsa_oaep_encrypt(h: OaepHash, k: &Jwk, msg: &[u8]) -> Result<Vec<u8>> {
    let pk = PublicEncryptingKey::from_der(&rsa_spki(k)?).map_err(|e| Error::Key(e.to_string()))?;
    let size = pk.key_size_bytes();
    let key = OaepPublicEncryptingKey::new(pk).map_err(|_| Error::Key("oaep key".into()))?;
    let mut out = vec![0u8; size];
    let n = key.encrypt(oaep_alg(h), msg, &mut out, None).map_err(|_| Error::Crypto("oaep encrypt".into()))?.len();
    out.truncate(n);
    Ok(out)
}

pub fn rsa_oaep_decrypt(h: OaepHash, k: &Jwk, ct: &[u8]) -> Result<Vec<u8>> {
    let sk = PrivateDecryptingKey::from_pkcs8(&rsa_pkcs8(k)?).map_err(|e| Error::Key(e.to_string()))?;
    let key = OaepPrivateDecryptingKey::new(sk).map_err(|_| Error::Key("oaep key".into()))?;
    let mut out = vec![0u8; key.min_output_size()];
    let n = key.decrypt(oaep_alg(h), ct, &mut out, None).map_err(|_| Error::Decrypt)?.len();
    out.truncate(n);
    Ok(out)
}

fn ag_alg(crv: &str) -> Result<&'static ag::Algorithm> {
    match crv { "P-256" => Ok(&ag::ECDH_P256), "P-384" => Ok(&ag::ECDH_P384), "P-521" => Ok(&ag::ECDH_P521), "X25519" => Ok(&ag::X25519),
        other => Err(Error::Key(format!("unsupported curve {other:?}"))) }
}

pub fn ec_generate(crv: &str) -> Result<Jwk> {
    let sk = ag::PrivateKey::generate(ag_alg(crv)?).map_err(|_| Error::Crypto("keygen".into()))?;
    let pk = sk.compute_public_key().map_err(|_| Error::Crypto("public key".into()))?;
    if crv == "X25519" {
        let seed: aws_lc_rs::encoding::Curve25519SeedBin = sk.as_be_bytes().map_err(|_| Error::Crypto("export".into()))?;
        return Ok(ec_jwk(crv, seed.as_ref(), pk.as_ref(), None));
    }
    let d: EcPrivateKeyBin = sk.as_be_bytes().map_err(|_| Error::Crypto("export".into()))?;
    let pu: EcPublicKeyUncompressedBin = pk.as_be_bytes().map_err(|_| Error::Crypto("export".into()))?;
    let n = super::curve_len(crv)?;
    let p = pu.as_ref();
    if p.len() != 1 + 2 * n || p[0] != 4 { return Err(Error::Crypto("unexpected point encoding".into())); }
    Ok(ec_jwk(crv, d.as_ref(), &p[1..1 + n], Some(&p[1 + n..])))
}

/// ECDH. aws-lc validates that the peer point is on the curve; X25519 rejects an all-zero result.
pub fn ecdh(private: &Jwk, public: &Jwk) -> Result<Vec<u8>> {
    let (crv, n) = check_agreement_key(private)?;
    let (pcrv, _) = check_agreement_key(public)?;
    if crv != pcrv { return Err(Error::Key("ECDH keys are on different curves".into())); }
    let alg = ag_alg(&crv)?;
    let sk = ag::PrivateKey::from_private_key(alg, &private.coord("d", n)?).map_err(|e| Error::Key(e.to_string()))?;
    let peer = if crv == "X25519" { public.coord("x", 32)? } else { let mut v = vec![4u8]; v.extend(public.coord("x", n)?); v.extend(public.coord("y", n)?); v };
    ag::agree(&sk, ag::UnparsedPublicKey::new(alg, peer), Error::Key("ECDH failed: invalid peer key".into()),
        |s| if s.iter().all(|b| *b == 0) { Err(Error::Key("ECDH produced an all-zero secret".into())) } else { Ok(s.to_vec()) })
}
