use crate::error::{Error, Result};
use crate::jwa::{Algorithm, Hash};
use crate::jwk::Jwk;
use super::{check_ec, check_okp, check_rsa};
use openssl::{bn::{BigNum, BigNumContext}, ec::{EcGroup, EcKey, EcPoint}, ecdsa::EcdsaSig,
    hash::MessageDigest, nid::Nid, pkey::{Id, PKey, Private, Public}, rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer, Verifier}};

fn e<T: std::fmt::Display>(x: T) -> Error { Error::Crypto(x.to_string()) }
fn md(h: Hash) -> MessageDigest {
    match h { Hash::Sha256 => MessageDigest::sha256(), Hash::Sha384 => MessageDigest::sha384(), Hash::Sha512 => MessageDigest::sha512() }
}
fn bn(b: &[u8]) -> Result<BigNum> { BigNum::from_slice(b).map_err(e) }

pub fn digest(h: Hash, data: &[u8]) -> Result<Vec<u8>> {
    openssl::hash::hash(md(h), data).map(|d| d.to_vec()).map_err(e)
}

pub fn hmac(h: Hash, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let k = PKey::hmac(key).map_err(e)?;
    let mut s = Signer::new(md(h), &k).map_err(e)?;
    s.update(data).map_err(e)?;
    s.sign_to_vec().map_err(e)
}

pub fn random(buf: &mut [u8]) -> Result<()> {
    openssl::rand::rand_bytes(buf).map_err(e)
}

fn group(alg: Algorithm) -> Result<EcGroup> {
    EcGroup::from_curve_name(match alg {
        Algorithm::ES256 => Nid::X9_62_PRIME256V1,
        Algorithm::ES384 => Nid::SECP384R1,
        _ => Nid::SECP521R1,
    }).map_err(e)
}
fn ec_size(alg: Algorithm) -> usize {
    match alg { Algorithm::ES256 => 32, Algorithm::ES384 => 48, _ => 66 }
}

fn ec_public(alg: Algorithm, k: &Jwk) -> Result<EcKey<Public>> {
    let g = group(alg)?;
    let n = ec_size(alg);
    let (x, y) = (bn(&k.coord("x", n)?)?, bn(&k.coord("y", n)?)?);
    EcKey::from_public_key_affine_coordinates(&g, &x, &y).map_err(|x| Error::Key(x.to_string()))
}

fn ec_private(alg: Algorithm, k: &Jwk) -> Result<EcKey<Private>> {
    let g = group(alg)?;
    let n = ec_size(alg);
    let mut ctx = BigNumContext::new().map_err(e)?;
    let mut pt = EcPoint::new(&g).map_err(e)?;
    let (x, y) = (bn(&k.coord("x", n)?)?, bn(&k.coord("y", n)?)?);
    pt.set_affine_coordinates_gfp(&g, &x, &y, &mut ctx).map_err(|x| Error::Key(x.to_string()))?;
    let d = bn(&k.coord("d", n)?)?;
    let key = EcKey::from_private_components(&g, &d, &pt).map_err(|x| Error::Key(x.to_string()))?;
    key.check_key().map_err(|x| Error::Key(x.to_string()))?;
    Ok(key)
}

fn rsa_public(k: &Jwk) -> Result<Rsa<Public>> {
    let (n, ex) = check_rsa(k)?;
    Rsa::from_public_components(bn(&n)?, bn(&ex)?).map_err(|x| Error::Key(x.to_string()))
}

fn rsa_private(k: &Jwk) -> Result<Rsa<Private>> {
    let (n, ex) = check_rsa(k)?;
    let r = Rsa::from_private_components(bn(&n)?, bn(&ex)?, bn(&k.req("d")?)?, bn(&k.req("p")?)?,
        bn(&k.req("q")?)?, bn(&k.req("dp")?)?, bn(&k.req("dq")?)?, bn(&k.req("qi")?)?)
        .map_err(|x| Error::Key(x.to_string()))?;
    r.check_key().map_err(|x| Error::Key(x.to_string()))?;
    Ok(r)
}


pub fn sign(alg: Algorithm, k: &Jwk, data: &[u8]) -> Result<Vec<u8>> {
    use Algorithm::*;
    match alg {
        ES256 | ES384 | ES512 => {
            check_ec(alg, k)?;
            let key = ec_private(alg, k)?;
            let h = digest(alg.hash().unwrap(), data)?;
            let sig = EcdsaSig::sign(&h, &key).map_err(e)?;
            let n = ec_size(alg) as i32;
            let mut out = sig.r().to_vec_padded(n).map_err(e)?;
            out.extend(sig.s().to_vec_padded(n).map_err(e)?);
            Ok(out)
        }
        EdDSA => {
            check_okp(k)?;
            let pk = PKey::private_key_from_raw_bytes(&k.coord("d", 32)?, Id::ED25519).map_err(|x| Error::Key(x.to_string()))?;
            let mut s = Signer::new_without_digest(&pk).map_err(e)?;
            s.sign_oneshot_to_vec(data).map_err(e)
        }
        RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => {
            let pk = PKey::from_rsa(rsa_private(k)?).map_err(e)?;
            let h = md(alg.hash().unwrap());
            let mut s = Signer::new(h, &pk).map_err(e)?;
            if matches!(alg, PS256 | PS384 | PS512) {
                s.set_rsa_padding(Padding::PKCS1_PSS).map_err(e)?;
                s.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH).map_err(e)?;
                s.set_rsa_mgf1_md(h).map_err(e)?;
            } else {
                s.set_rsa_padding(Padding::PKCS1).map_err(e)?;
            }
            s.update(data).map_err(e)?;
            s.sign_to_vec().map_err(e)
        }
        _ => Err(Error::Algorithm(format!("{} is not a signature algorithm for this backend", alg.as_str()))),
    }
}

pub fn verify(alg: Algorithm, k: &Jwk, data: &[u8], sig: &[u8]) -> Result<()> {
    use Algorithm::*;
    let ok = |b: bool| if b { Ok(()) } else { Err(Error::BadSignature) };
    match alg {
        ES256 | ES384 | ES512 => {
            check_ec(alg, k)?;
            let n = ec_size(alg);
            if sig.len() != 2 * n { return Err(Error::BadSignature); }
            let key = ec_public(alg, k)?;
            let r = bn(&sig[..n])?;
            let s = bn(&sig[n..])?;
            let es = EcdsaSig::from_private_components(r, s).map_err(e)?;
            ok(es.verify(&digest(alg.hash().unwrap(), data)?, &key).map_err(e)?)
        }
        EdDSA => {
            check_okp(k)?;
            let pk = PKey::public_key_from_raw_bytes(&k.coord("x", 32)?, Id::ED25519).map_err(|x| Error::Key(x.to_string()))?;
            let mut v = Verifier::new_without_digest(&pk).map_err(e)?;
            ok(v.verify_oneshot(sig, data).unwrap_or(false))
        }
        RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => {
            let pk = PKey::from_rsa(rsa_public(k)?).map_err(e)?;
            let h = md(alg.hash().unwrap());
            let mut v = Verifier::new(h, &pk).map_err(e)?;
            if matches!(alg, PS256 | PS384 | PS512) {
                v.set_rsa_padding(Padding::PKCS1_PSS).map_err(e)?;
                v.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH).map_err(e)?;
                v.set_rsa_mgf1_md(h).map_err(e)?;
            } else {
                v.set_rsa_padding(Padding::PKCS1).map_err(e)?;
            }
            v.update(data).map_err(e)?;
            ok(v.verify(sig).unwrap_or(false))
        }
        _ => Err(Error::Algorithm(format!("{} is not a signature algorithm for this backend", alg.as_str()))),
    }
}

// ======================= JWE / key agreement / KDF additions =======================
use super::{check_agreement_key, curve_len, ec_jwk, pkcs7_pad, pkcs7_unpad, AeadAlg, OaepHash};
use openssl::{aes::{unwrap_key, wrap_key, AesKey}, derive::Deriver, pkcs5::pbkdf2_hmac,
    pkey_ctx::PkeyCtx, symm::{decrypt_aead, encrypt_aead, Cipher, Crypter, Mode}};

fn gcm_cipher(a: AeadAlg) -> Cipher {
    match a { AeadAlg::A128Gcm => Cipher::aes_128_gcm(), AeadAlg::A192Gcm => Cipher::aes_192_gcm(), AeadAlg::A256Gcm => Cipher::aes_256_gcm() }
}

pub fn aead_seal(alg: AeadAlg, key: &[u8], iv: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if key.len() != alg.key_len() || iv.len() != super::GCM_IV_LEN {
        return Err(Error::Key("AES-GCM needs a matching key length and a 12-byte IV".into()));
    }
    let mut tag = [0u8; super::GCM_TAG_LEN];
    let ct = encrypt_aead(gcm_cipher(alg), key, Some(iv), aad, pt, &mut tag).map_err(e)?;
    Ok((ct, tag.to_vec()))
}

pub fn aead_open(alg: AeadAlg, key: &[u8], iv: &[u8], aad: &[u8], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    if key.len() != alg.key_len() || iv.len() != super::GCM_IV_LEN {
        return Err(Error::Key("AES-GCM needs a matching key length and a 12-byte IV".into()));
    }
    if tag.len() != super::GCM_TAG_LEN { return Err(Error::Decrypt); }
    decrypt_aead(gcm_cipher(alg), key, Some(iv), aad, ct, tag).map_err(|_| Error::Decrypt)
}

fn cbc_cipher(key: &[u8]) -> Result<Cipher> {
    match key.len() { 16 => Ok(Cipher::aes_128_cbc()), 24 => Ok(Cipher::aes_192_cbc()), 32 => Ok(Cipher::aes_256_cbc()),
        _ => Err(Error::Key("AES key must be 16, 24 or 32 bytes".into())) }
}

fn cbc_raw(mode: Mode, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != 16 { return Err(Error::Key("CBC IV must be 16 bytes".into())); }
    let c = cbc_cipher(key)?;
    let mut cr = Crypter::new(c, mode, key, Some(iv)).map_err(e)?;
    cr.pad(false);
    let mut out = vec![0u8; data.len() + c.block_size()];
    let n = cr.update(data, &mut out).map_err(e)?;
    let m = cr.finalize(&mut out[n..]).map_err(e)?;
    out.truncate(n + m);
    Ok(out)
}

/// AES-CBC with PKCS#7 padding. JWE authenticates with HMAC before calling `cbc_decrypt`.
pub fn cbc_encrypt(key: &[u8], iv: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    cbc_raw(Mode::Encrypt, key, iv, &pkcs7_pad(pt))
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    if ct.is_empty() || ct.len() % 16 != 0 { return Err(Error::Decrypt); }
    pkcs7_unpad(cbc_raw(Mode::Decrypt, key, iv, ct)?)
}

pub fn aes_kw_wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() < 16 || key.len() % 8 != 0 { return Err(Error::Key("key to wrap must be a multiple of 8 bytes, at least 16".into())); }
    let k = AesKey::new_encrypt(kek).map_err(|_| Error::Key("bad AES key".into()))?;
    let mut out = vec![0u8; key.len() + 8];
    let n = wrap_key(&k, None, &mut out, key).map_err(|_| Error::Crypto("key wrap".into()))?;
    out.truncate(n);
    Ok(out)
}

pub fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < 24 || wrapped.len() % 8 != 0 { return Err(Error::Decrypt); }
    let k = AesKey::new_decrypt(kek).map_err(|_| Error::Key("bad AES key".into()))?;
    let mut out = vec![0u8; wrapped.len() - 8];
    let n = unwrap_key(&k, None, &mut out, wrapped).map_err(|_| Error::Decrypt)?;
    out.truncate(n);
    Ok(out)
}

pub fn pbkdf2(h: Hash, password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Result<Vec<u8>> {
    if iterations == 0 || out_len == 0 { return Err(Error::Key("pbkdf2: iterations and length must be non-zero".into())); }
    let mut out = vec![0u8; out_len];
    pbkdf2_hmac(password, salt, iterations as usize, md(h), &mut out).map_err(e)?;
    Ok(out)
}

fn oaep_md(h: OaepHash) -> &'static openssl::md::MdRef {
    match h { OaepHash::Sha1 => openssl::md::Md::sha1(), OaepHash::Sha256 => openssl::md::Md::sha256(),
        OaepHash::Sha384 => openssl::md::Md::sha384(), OaepHash::Sha512 => openssl::md::Md::sha512() }
}

pub fn rsa_oaep_encrypt(h: OaepHash, k: &Jwk, msg: &[u8]) -> Result<Vec<u8>> {
    let pk = PKey::from_rsa(rsa_public(k)?).map_err(e)?;
    let mut ctx = PkeyCtx::new(&pk).map_err(e)?;
    ctx.encrypt_init().map_err(e)?;
    ctx.set_rsa_padding(Padding::PKCS1_OAEP).map_err(e)?;
    ctx.set_rsa_oaep_md(oaep_md(h)).map_err(e)?;
    ctx.set_rsa_mgf1_md(oaep_md(h)).map_err(e)?;
    let mut out = Vec::new();
    ctx.encrypt_to_vec(msg, &mut out).map_err(e)?;
    Ok(out)
}

pub fn rsa_oaep_decrypt(h: OaepHash, k: &Jwk, ct: &[u8]) -> Result<Vec<u8>> {
    let pk = PKey::from_rsa(rsa_private(k)?).map_err(e)?;
    let mut ctx = PkeyCtx::new(&pk).map_err(e)?;
    ctx.decrypt_init().map_err(e)?;
    ctx.set_rsa_padding(Padding::PKCS1_OAEP).map_err(e)?;
    ctx.set_rsa_oaep_md(oaep_md(h)).map_err(e)?;
    ctx.set_rsa_mgf1_md(oaep_md(h)).map_err(e)?;
    let mut out = Vec::new();
    ctx.decrypt_to_vec(ct, &mut out).map_err(|_| Error::Decrypt)?;
    Ok(out)
}

fn nist_group(crv: &str) -> Result<EcGroup> {
    EcGroup::from_curve_name(match crv { "P-256" => Nid::X9_62_PRIME256V1, "P-384" => Nid::SECP384R1, "P-521" => Nid::SECP521R1,
        other => return Err(Error::Key(format!("unsupported curve {other:?}"))) }).map_err(e)
}

pub fn ec_generate(crv: &str) -> Result<Jwk> {
    if crv == "X25519" {
        let sk = PKey::generate_x25519().map_err(e)?;
        return Ok(ec_jwk(crv, &sk.raw_private_key().map_err(e)?, &sk.raw_public_key().map_err(e)?, None));
    }
    let g = nist_group(crv)?;
    let n = curve_len(crv)? as i32;
    let key = EcKey::generate(&g).map_err(e)?;
    let mut ctx = BigNumContext::new().map_err(e)?;
    let (mut x, mut y) = (BigNum::new().map_err(e)?, BigNum::new().map_err(e)?);
    key.public_key().affine_coordinates(&g, &mut x, &mut y, &mut ctx).map_err(e)?;
    Ok(ec_jwk(crv, &key.private_key().to_vec_padded(n).map_err(e)?, &x.to_vec_padded(n).map_err(e)?, Some(&y.to_vec_padded(n).map_err(e)?)))
}

/// ECDH. OpenSSL validates that the peer point is on the curve; X25519 all-zero output is rejected.
pub fn ecdh(private: &Jwk, public: &Jwk) -> Result<Vec<u8>> {
    let (crv, n) = check_agreement_key(private)?;
    let (pcrv, _) = check_agreement_key(public)?;
    if crv != pcrv { return Err(Error::Key("ECDH keys are on different curves".into())); }
    let (sk, pk): (PKey<Private>, PKey<Public>) = if crv == "X25519" {
        (PKey::private_key_from_raw_bytes(&private.coord("d", 32)?, Id::X25519).map_err(|x| Error::Key(x.to_string()))?,
         PKey::public_key_from_raw_bytes(&public.coord("x", 32)?, Id::X25519).map_err(|x| Error::Key(x.to_string()))?)
    } else {
        let g = nist_group(&crv)?;
        let mut ctx = BigNumContext::new().map_err(e)?;
        let mut pt = EcPoint::new(&g).map_err(e)?;
        let (px, py) = (bn(&private.coord("x", n)?)?, bn(&private.coord("y", n)?)?);
        pt.set_affine_coordinates_gfp(&g, &px, &py, &mut ctx).map_err(|x| Error::Key(x.to_string()))?;
        let dd = bn(&private.coord("d", n)?)?;
        let own = EcKey::from_private_components(&g, &dd, &pt).map_err(|x| Error::Key(x.to_string()))?;
        own.check_key().map_err(|x| Error::Key(x.to_string()))?;
        let (qx, qy) = (bn(&public.coord("x", n)?)?, bn(&public.coord("y", n)?)?);
        let peer = EcKey::from_public_key_affine_coordinates(&g, &qx, &qy)
            .map_err(|x| Error::Key(format!("peer public key is not on the curve: {x}")))?;
        (PKey::from_ec_key(own).map_err(e)?, PKey::from_ec_key(peer).map_err(e)?)
    };
    let mut d = Deriver::new(&sk).map_err(e)?;
    d.set_peer(&pk).map_err(|x| Error::Key(x.to_string()))?;
    let secret = d.derive_to_vec().map_err(|x| Error::Key(format!("ECDH failed: {x}")))?;
    if secret.iter().all(|b| *b == 0) { return Err(Error::Key("ECDH produced an all-zero secret".into())); }
    Ok(secret)
}
