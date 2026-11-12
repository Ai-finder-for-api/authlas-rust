//! Demonstrating Proof of Possession (RFC 9449).
//!
//! A DPoP proof is a JWT signed with a key the client holds, sent in the `DPoP` header. The one place JOSE lets a
//! header carry the verification key is here (`jwk`), so this module is the only code that uses it, and it demands
//! a public asymmetric key, a symmetric-free algorithm list, and `typ: dpop+jwt`.
use super::error::{ErrorCode, OAuthError, OResult};
use crate::{b64, crypto, jwa::{Algorithm, Family, Hash}, jwk::Jwk, jws, jwt::{self, Claims, ReplayCache}};
use serde_json::{Map, Value};
use url::Url;

pub const TYP: &str = "dpop+jwt";
/// Proofs older than this are refused, whatever the server clock leeway.
pub const MAX_PROOF_AGE: u64 = 300;

fn bad(m: &str) -> OAuthError { OAuthError::with(ErrorCode::InvalidDpopProof, m) }

/// `htu` comparison form: scheme and host lower-case, default port dropped, no query, no fragment (RFC 9449 4.2).
pub fn normalize_htu(uri: &str) -> Option<String> {
    let mut u = Url::parse(uri).ok()?;
    if !matches!(u.scheme(), "http" | "https") { return None; }
    u.set_query(None);
    u.set_fragment(None);
    Some(u.to_string())
}

/// `ath`: base64url of SHA-256 of the access token (RFC 9449 4.2).
pub fn access_token_hash(access_token: &str) -> crate::Result<String> {
    Ok(b64::encode(crypto::digest(Hash::Sha256, access_token.as_bytes())?))
}

/// Client side: creates a proof for one request.
/// `key` must be the client's private key; the matching public key goes into the header.
pub struct ProofBuilder<'a> {
    pub alg: Algorithm,
    pub key: &'a Jwk,
    pub method: &'a str,
    pub url: &'a str,
    pub access_token: Option<&'a str>,
    pub nonce: Option<&'a str>,
}

impl ProofBuilder<'_> {
    pub fn build(&self) -> crate::Result<String> {
        use crate::Error;
        if matches!(self.alg.family(), Family::Hmac) { return Err(Error::Algorithm("DPoP needs an asymmetric algorithm".into())); }
        if !self.key.is_private() { return Err(Error::Key("DPoP signing key must be private".into())); }
        let htu = normalize_htu(self.url).ok_or_else(|| Error::Malformed("htu must be an http(s) URL".into()))?;
        let mut jti = [0u8; 16];
        crypto::random(&mut jti)?;
        let mut c = Claims::new().jti(&b64::encode(jti)).set("htm", self.method.to_ascii_uppercase()).set("htu", htu).issued_at(jwt::unix_now());
        if let Some(t) = self.access_token { c = c.set("ath", access_token_hash(t)?); }
        if let Some(n) = self.nonce { c = c.set("nonce", n); }
        let public: Value = serde_json::from_str(&self.key.public()?.to_json())?;
        let mut h = Map::new();
        h.insert("typ".into(), Value::String(TYP.into()));
        h.insert("jwk".into(), public);
        jws::sign(self.alg, self.key, &h, &c.to_bytes())
    }
}

/// What the server expects of one proof.
pub struct Expect<'a> {
    pub algs: &'a [Algorithm],
    pub method: &'a str,
    /// The URL the request was made to, as the server sees it (behind a proxy: the public URL).
    pub url: &'a str,
    /// At a resource server: the presented access token, whose hash must be in `ath`.
    pub access_token: Option<&'a str>,
    /// Server-provided nonce the proof must carry (RFC 9449 8, 9). `None` means no nonce is required.
    pub nonce: Option<&'a str>,
    pub now: Option<u64>,
    pub leeway: u64,
    pub replay: Option<&'a dyn ReplayCache>,
}

/// The result of a good proof: the key the client proved it holds.
#[derive(Debug, Clone)]
pub struct Verified {
    pub jwk: Jwk,
    /// RFC 7638 thumbprint, SHA-256: the value for `cnf.jkt` and `dpop_jkt`.
    pub jkt: String,
    pub claims: Claims,
}

pub fn verify_proof(proof: &str, e: &Expect<'_>) -> OResult<Verified> {
    // 1. Header: typ, alg, jwk. A bad shape is the client's mistake, so these are invalid_dpop_proof.
    let header = jws::peek_header(proof).map_err(|_| bad("malformed proof"))?;
    if header.typ.as_deref() != Some(TYP) { return Err(bad("typ must be dpop+jwt")); }
    if header.raw.contains_key("x5c") || header.raw.contains_key("jku") || header.raw.contains_key("x5u") {
        return Err(bad("proof must not reference keys by URL or certificate"));
    }
    let jwk_val = header.raw.get("jwk").ok_or_else(|| bad("jwk header is required"))?;
    let jwk = Jwk::parse(&jwk_val.to_string()).map_err(|_| bad("jwk header is not a valid JWK"))?;
    if jwk.is_private() || jwk.kty == "oct" { return Err(bad("jwk header must be a public asymmetric key")); }
    if matches!(header.alg.family(), Family::Hmac) { return Err(bad("symmetric algorithms are not allowed")); }

    // 2. Signature, against the embedded key.
    let mut policy = jws::Policy::new(e.algs);
    policy.typ = Some(TYP);
    let (_, payload) = jws::verify(proof, &jwk, &policy).map_err(|_| bad("signature or algorithm rejected"))?;
    let claims = Claims::parse(&payload).map_err(|_| bad("payload is not a JSON object"))?;

    // 3. Claims.
    let now = e.now.unwrap_or_else(jwt::unix_now);
    let s = |n: &str| claims.str_claim(n).map_err(|_| bad("claim has the wrong type"));
    let jti = s("jti")?.ok_or_else(|| bad("jti is required"))?;
    if s("htm")? != Some(e.method.to_ascii_uppercase().as_str()) { return Err(bad("htm does not match the request method")); }
    let want_htu = normalize_htu(e.url).ok_or_else(|| OAuthError::new(ErrorCode::ServerError))?;
    match s("htu")?.and_then(normalize_htu) {
        Some(got) if got == want_htu => {}
        _ => return Err(bad("htu does not match the request URL")),
    }
    let iat = claims.date("iat").map_err(|_| bad("iat is invalid"))?.ok_or_else(|| bad("iat is required"))?;
    let leeway = e.leeway.min(60);
    if iat > now + leeway { return Err(bad("iat is in the future")); }
    if now.saturating_sub(iat) > MAX_PROOF_AGE + leeway { return Err(bad("proof is too old")); }

    if let Some(tok) = e.access_token {
        let want = access_token_hash(tok).map_err(|_| OAuthError::new(ErrorCode::ServerError))?;
        match s("ath")? { Some(got) if crypto::ct_eq(got.as_bytes(), want.as_bytes()) => {}, _ => return Err(bad("ath does not match the access token")) }
    }
    if let Some(n) = e.nonce {
        match s("nonce")? {
            Some(got) if crypto::ct_eq(got.as_bytes(), n.as_bytes()) => {}
            // RFC 9449 8: tell the client which nonce to use.
            _ => return Err(OAuthError::with(ErrorCode::UseDpopNonce, "resubmit with the server nonce")),
        }
    }
    // Replay is recorded last so a rejected proof does not use up its jti.
    if let Some(r) = e.replay {
        let key = format!("dpop\n{}", jwk.thumbprint(Hash::Sha256).map_err(|_| bad("unusable jwk"))?) + "\n" + jti;
        if !r.first_use(&key, iat + MAX_PROOF_AGE + leeway, now) { return Err(bad("proof was already used")); }
    }
    let jkt = jwk.thumbprint(Hash::Sha256).map_err(|_| bad("unusable jwk"))?;
    Ok(Verified { jwk, jkt, claims })
}

/// Resource server: the access token's `cnf.jkt` must equal the proof key's thumbprint (RFC 9449 7.1).
pub fn check_binding(token_claims: &Claims, proof: &Verified) -> OResult<()> {
    let denied = || OAuthError::with(ErrorCode::InvalidToken, "access token is not bound to this DPoP key");
    let cnf = token_claims.cnf().map_err(|_| denied())?.ok_or_else(denied)?;
    let jkt = cnf.jkt.ok_or_else(denied)?;
    if crypto::ct_eq(jkt.as_bytes(), proof.jkt.as_bytes()) { Ok(()) } else { Err(denied()) }
}

/// Authorization server: a `dpop_jkt` on the authorization request (RFC 9449 10) must equal the proof key at the token endpoint.
pub fn check_dpop_jkt(authorization_request_jkt: &str, proof: &Verified) -> OResult<()> {
    if crypto::ct_eq(authorization_request_jkt.as_bytes(), proof.jkt.as_bytes()) { Ok(()) }
    else { Err(OAuthError::with(ErrorCode::InvalidDpopProof, "proof key does not match dpop_jkt")) }
}

/// Server-issued nonces (RFC 9449 8): `base64url(timestamp) "." base64url(HMAC(secret, timestamp))`, valid for `lifetime` seconds.
/// Stateless, so every instance sharing `secret` accepts the same nonces.
pub struct NonceSource { secret: Vec<u8>, pub lifetime: u64 }

impl NonceSource {
    pub fn new(secret: &[u8], lifetime: u64) -> crate::Result<Self> {
        if secret.len() < 32 { return Err(crate::Error::Key("nonce secret must be at least 32 bytes".into())); }
        Ok(NonceSource { secret: secret.to_vec(), lifetime })
    }
    fn mac(&self, t: &[u8]) -> crate::Result<Vec<u8>> { crypto::hmac(Hash::Sha256, &self.secret, &[b"dpop-nonce\0".as_slice(), t].concat()) }
    pub fn issue(&self, now: Option<u64>) -> crate::Result<String> {
        let t = now.unwrap_or_else(jwt::unix_now).to_be_bytes();
        Ok(format!("{}.{}", b64::encode(t), b64::encode(self.mac(&t)?)))
    }
    pub fn is_valid(&self, nonce: &str, now: Option<u64>) -> bool {
        let Some((t, m)) = nonce.split_once('.') else { return false };
        let (Ok(t), Ok(m)) = (b64::decode(t), b64::decode(m)) else { return false };
        let Ok(arr): Result<[u8; 8], _> = t.as_slice().try_into() else { return false };
        let Ok(want) = self.mac(&arr) else { return false };
        if !crypto::ct_eq(&want, &m) { return false; }
        let issued = u64::from_be_bytes(arr);
        let now = now.unwrap_or_else(jwt::unix_now);
        issued <= now + 5 && now.saturating_sub(issued) <= self.lifetime
    }
}

/// Headers for a `use_dpop_nonce` response (RFC 9449 8): the error, plus the `DPoP-Nonce` header.
pub fn nonce_challenge(nonce: &str) -> (u16, [(&'static str, String); 1]) {
    (400, [("DPoP-Nonce", nonce.to_string())])
}
