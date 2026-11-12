//! Token Status List (draft-ietf-oauth-status-list-21): revocation and suspension of credentials and tokens.
//!
//! Three roles:
//! * **Status issuer**: keep a [`StatusList`] (1, 2, 4 or 8 bits per token), and publish it as a signed `statuslist+jwt`
//!   ([`StatusListTokenIssue`]).
//! * **Issuer of the referenced token**: put a [`StatusReference`] (`idx` and `uri`) in the token's `status` claim.
//! * **Relying party or holder**: read the reference, fetch the list (after [`crate::ssrf::ssrf_check`]), verify it with
//!   [`verify_token`], and read the value with [`VerifiedStatusList::status`].
//!
//! Rules that are enforced here because getting them wrong silently accepts revoked credentials:
//! * the list token's `sub` must equal the `uri` in the reference (a list for another token must not answer for this one);
//! * an index outside the list is an error, not "valid";
//! * a list token past `exp` is refused; `iat` and `ttl` bound how long a copy may be reused;
//! * decompression is capped, so a few KiB of input cannot expand to gigabytes;
//! * only signature algorithms are accepted by default; a MAC needs `allow_mac` (11.6);
//! * the status value of a token never overrides a failed check of the token itself: run [`ensure_accepted`] only after the
//!   referenced token verified (8.3).
//!
//! CWT/CBOR status lists are not implemented; the JSON/JWT form is.
use crate::jwa::{Algorithm, Family};
use crate::jwk::Jwk;
use crate::jwt::{self, Claims};
use crate::{b64, jws, Error, Result};
use serde_json::{json, Map, Value};

pub const TYP: &str = "statuslist+jwt";
pub const MEDIA_TYPE: &str = "application/statuslist+jwt";

pub const VALID: u8 = 0x00;
pub const INVALID: u8 = 0x01;
pub const SUSPENDED: u8 = 0x02;

/// Largest uncompressed list accepted by default: 16 MiB, which is 134 million entries at 1 bit.
pub const DEFAULT_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Largest base64url `lst` accepted (before decompression).
pub const MAX_ENCODED: usize = 4 * 1024 * 1024;

fn bad(m: &str) -> Error { Error::Malformed(format!("status list: {m}")) }

/// Name of a registered status type, for messages.
pub fn status_name(v: u8) -> &'static str {
    match v { VALID => "VALID", INVALID => "INVALID", SUSPENDED => "SUSPENDED", 0x03 | 0x0c..=0x0f => "application-specific", _ => "unregistered" }
}

// ---------------------------------------------------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusList { bits: u8, bytes: Vec<u8> }

impl StatusList {
    /// A list of `entries` tokens, all `VALID`. `bits` must be 1, 2, 4 or 8.
    pub fn new(bits: u8, entries: usize) -> Result<StatusList> {
        if !matches!(bits, 1 | 2 | 4 | 8) { return Err(bad("bits must be 1, 2, 4 or 8")); }
        if entries == 0 { return Err(bad("a list needs at least one entry")); }
        let n = entries.checked_mul(bits as usize).ok_or_else(|| bad("too many entries"))?.div_ceil(8);
        if n > DEFAULT_MAX_BYTES { return Err(bad("list is larger than the default limit")); }
        Ok(StatusList { bits, bytes: vec![0; n] })
    }

    pub fn bits(&self) -> u8 { self.bits }
    /// Number of addressable entries. May exceed the number requested in [`StatusList::new`] by up to 7 bits of padding.
    pub fn len(&self) -> usize { self.bytes.len() * 8 / self.bits as usize }
    pub fn is_empty(&self) -> bool { self.bytes.is_empty() }

    /// Bits are packed from the least significant bit of each byte, bytes in order (section 4.1, 11.1).
    pub fn get(&self, idx: usize) -> Option<u8> {
        let bit = idx.checked_mul(self.bits as usize)?;
        let b = *self.bytes.get(bit / 8)?;
        Some((b >> (bit % 8)) & (((1u16 << self.bits) - 1) as u8))
    }

    pub fn set(&mut self, idx: usize, value: u8) -> Result<()> {
        if (value as u16) >= (1u16 << self.bits) { return Err(bad("value does not fit in the list's bits")); }
        let bit = idx.checked_mul(self.bits as usize).ok_or_else(|| bad("index out of range"))?;
        let mask = (((1u16 << self.bits) - 1) as u8) << (bit % 8);
        let byte = self.bytes.get_mut(bit / 8).ok_or_else(|| bad("index out of range"))?;
        *byte = (*byte & !mask) | (value << (bit % 8));
        Ok(())
    }

    /// Raw packed bytes, before compression.
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }

    pub fn from_bytes(bits: u8, bytes: Vec<u8>) -> Result<StatusList> {
        if !matches!(bits, 1 | 2 | 4 | 8) { return Err(bad("bits must be 1, 2, 4 or 8")); }
        if bytes.is_empty() { return Err(bad("empty list")); }
        Ok(StatusList { bits, bytes })
    }

    /// `{"bits": n, "lst": "<base64url of zlib-compressed bytes>"}` (section 4.2). Highest compression level.
    pub fn to_json(&self) -> Value {
        json!({ "bits": self.bits, "lst": b64::encode(miniz_oxide::deflate::compress_to_vec_zlib(&self.bytes, 10)) })
    }

    /// Reads the JSON form. `max_bytes` caps the uncompressed size.
    pub fn from_json(v: &Value, max_bytes: usize) -> Result<StatusList> {
        let o = v.as_object().ok_or_else(|| bad("status_list must be an object"))?;
        let bits = match o.get("bits").and_then(Value::as_u64) { Some(b @ (1 | 2 | 4 | 8)) => b as u8, _ => return Err(bad("bits must be 1, 2, 4 or 8")) };
        let lst = o.get("lst").and_then(Value::as_str).ok_or_else(|| bad("lst must be a string"))?;
        if lst.is_empty() || lst.len() > MAX_ENCODED { return Err(bad("lst is empty or too large")); }
        let z = b64::decode(lst)?;
        let raw = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&z, max_bytes).map_err(|_| bad("lst is not valid zlib data, or expands beyond the limit"))?;
        StatusList::from_bytes(bits, raw)
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Reference in the referenced token
// ---------------------------------------------------------------------------------------------------------------------

/// The `status.status_list` object of a referenced token (section 6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReference { pub idx: u64, pub uri: String }

impl StatusReference {
    pub fn new(idx: u64, uri: &str) -> Result<StatusReference> {
        if idx > (1 << 53) { return Err(bad("idx is too large")); }
        if uri.is_empty() || uri.len() > 2048 || uri.bytes().any(|b| b <= 0x20 || b == 0x7f) { return Err(bad("uri is malformed")); }
        url::Url::parse(uri).map_err(|_| bad("uri is not a URI"))?;
        Ok(StatusReference { idx, uri: uri.to_string() })
    }

    /// `Ok(None)` when the token has no `status` claim or no `status_list` member in it (another mechanism may be used).
    /// A `status_list` that is present but malformed is an error.
    pub fn from_claims(claims: &Map<String, Value>) -> Result<Option<StatusReference>> {
        let Some(status) = claims.get("status") else { return Ok(None) };
        let s = status.as_object().ok_or_else(|| bad("status must be an object"))?;
        if s.is_empty() { return Err(bad("status must reference at least one mechanism")); }
        let Some(sl) = s.get("status_list") else { return Ok(None) };
        let o = sl.as_object().ok_or_else(|| bad("status_list must be an object"))?;
        let idx = o.get("idx").and_then(Value::as_u64).ok_or_else(|| bad("idx must be a non-negative integer"))?;
        let uri = o.get("uri").and_then(Value::as_str).ok_or_else(|| bad("uri must be a string"))?;
        StatusReference::new(idx, uri).map(Some)
    }

    /// The value for a `status` claim.
    pub fn to_claim(&self) -> Value { json!({ "status_list": { "idx": self.idx, "uri": self.uri } }) }
}

// ---------------------------------------------------------------------------------------------------------------------
// Status list token: issue
// ---------------------------------------------------------------------------------------------------------------------

pub struct StatusListTokenIssue<'a> {
    pub alg: Algorithm,
    pub key: &'a Jwk,
    /// Where this token is served; goes into `sub` and must equal `uri` in every reference to it.
    pub uri: &'a str,
    pub list: &'a StatusList,
    pub now: Option<u64>,
    /// Seconds until the token expires (`exp`). Recommended.
    pub lifetime: Option<u64>,
    /// Seconds a copy may be reused before fetching again (`ttl`). Recommended.
    pub ttl: Option<u64>,
    /// `iss`, when the status issuer should be named (lets a verifier pin it).
    pub issuer: Option<&'a str>,
}

impl<'a> StatusListTokenIssue<'a> {
    pub fn new(alg: Algorithm, key: &'a Jwk, uri: &'a str, list: &'a StatusList) -> Self {
        StatusListTokenIssue { alg, key, uri, list, now: None, lifetime: Some(86_400), ttl: Some(3_600), issuer: None }
    }

    pub fn sign(&self) -> Result<String> {
        if matches!(self.alg.family(), Family::Hmac) { return Err(Error::Algorithm("sign status lists with an asymmetric algorithm unless you control every verifier".into())); }
        StatusReference::new(0, self.uri)?;
        if self.ttl == Some(0) || self.lifetime == Some(0) { return Err(bad("ttl and lifetime must be positive")); }
        let now = self.now.unwrap_or_else(jwt::unix_now);
        let mut c = Claims::new().subject(self.uri).issued_at(now).set("status_list", self.list.to_json());
        if let Some(i) = self.issuer { c = c.issuer(i); }
        if let Some(l) = self.lifetime { c = c.expires_at(now + l); }
        if let Some(t) = self.ttl { c = c.set("ttl", t); }
        jwt::sign(self.alg, self.key, &c, Some(TYP))
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Status list token: verify
// ---------------------------------------------------------------------------------------------------------------------

pub struct TokenPolicy<'a> {
    pub algs: &'a [Algorithm],
    /// The `uri` from the reference. The token's `sub` must equal it.
    pub uri: &'a str,
    pub now: Option<u64>,
    pub leeway: u64,
    /// Local freshness rule: refuse a list issued longer ago than this.
    pub max_age: Option<u64>,
    /// Pin the status issuer (`iss`). When set, the token must carry it.
    pub issuer: Option<&'a str>,
    pub max_bytes: usize,
    /// Permit HMAC-protected lists (11.6). Off by default.
    pub allow_mac: bool,
    /// Refuse lists without `exp`. Off by default, as the draft only recommends it.
    pub require_exp: bool,
}

impl<'a> TokenPolicy<'a> {
    pub fn new(algs: &'a [Algorithm], uri: &'a str) -> Self {
        TokenPolicy { algs, uri, now: None, leeway: 30, max_age: None, issuer: None, max_bytes: DEFAULT_MAX_BYTES, allow_mac: false, require_exp: false }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedStatusList {
    pub list: StatusList,
    pub uri: String,
    pub iat: u64,
    pub exp: Option<u64>,
    pub ttl: Option<u64>,
}

/// Bounds for deciding when to fetch again (11.5): a hostile or careless status issuer must not make clients hammer a URL
/// with `ttl: 1`, nor keep a stale list for a year with `ttl: 31536000`.
#[derive(Debug, Clone, Copy)]
pub struct RefreshBounds { pub min_ttl: u64, pub max_ttl: u64, pub default_ttl: u64 }
impl Default for RefreshBounds { fn default() -> Self { RefreshBounds { min_ttl: 60, max_ttl: 86_400, default_ttl: 3_600 } } }

impl VerifiedStatusList {
    /// The status at `idx`. An index beyond the list is an error: nothing can be said about the token, so reject it (8.3 step 6).
    pub fn status(&self, idx: u64) -> Result<u8> {
        usize::try_from(idx).ok().and_then(|i| self.list.get(i)).ok_or_else(|| Error::Claim("status index is outside the status list".into()))
    }

    /// When a copy fetched at `fetched_at` stops being reusable: its `ttl` (clamped to `b`), and never later than `exp`.
    pub fn refresh_at(&self, fetched_at: u64, b: RefreshBounds) -> u64 {
        let t = self.ttl.unwrap_or(b.default_ttl).clamp(b.min_ttl, b.max_ttl.max(b.min_ttl));
        let at = fetched_at.saturating_add(t);
        self.exp.map_or(at, |e| at.min(e))
    }
}

/// Verifies a status list token (section 5.1 and 8.3 steps 3, 4, 5).
pub fn verify_token(token: &str, key: &Jwk, p: &TokenPolicy<'_>) -> Result<VerifiedStatusList> {
    let h = jws::peek_header(token)?;
    if !p.allow_mac && matches!(h.alg.family(), Family::Hmac) { return Err(Error::Algorithm("MAC-protected status lists are not accepted by this policy".into())); }
    let mut jp = jws::Policy::new(p.algs);
    jp.typ = Some(TYP);
    let (_, payload) = jws::verify(token, key, &jp)?;
    let c = Claims::parse(&payload).map_err(|_| Error::Claim("payload is not a JSON object".into()))?;
    let now = p.now.unwrap_or_else(jwt::unix_now);
    let leeway = p.leeway.min(300);

    match c.str_claim("sub")? { Some(s) if crate::crypto::ct_eq(s.as_bytes(), p.uri.as_bytes()) => {}, Some(_) => return Err(Error::Claim("sub does not equal the uri of the reference".into())), None => return Err(Error::Claim("sub is missing".into())) }
    if let Some(want) = p.issuer { match c.str_claim("iss")? { Some(i) if i == want => {}, _ => return Err(Error::Claim("iss is not the expected status issuer".into())) } }
    let iat = c.date("iat")?.ok_or_else(|| Error::Claim("iat is missing".into()))?;
    if iat > now.saturating_add(leeway) { return Err(Error::Claim("iat is in the future".into())); }
    if let Some(max) = p.max_age { if now.saturating_sub(iat) > max.saturating_add(leeway) { return Err(Error::Claim("status list is older than the freshness policy allows".into())); } }
    let exp = c.date("exp")?;
    match exp { Some(e) if now >= e.saturating_add(leeway) => return Err(Error::Claim("status list token has expired".into())), None if p.require_exp => return Err(Error::Claim("exp is required".into())), _ => {} }
    if let Some(nbf) = c.date("nbf")? { if now.saturating_add(leeway) < nbf { return Err(Error::Claim("status list token is not valid yet".into())); } }
    let ttl = match c.map.get("ttl") {
        None => None,
        Some(v) => match (v.as_u64(), v.as_f64()) {
            (Some(t), _) if t > 0 && t <= (1 << 53) => Some(t),
            (None, Some(f)) if f > 0.0 && f <= 9.0e15 => Some(f.ceil() as u64),
            _ => return Err(Error::Claim("ttl must be a positive number".into())),
        },
    };
    let list = StatusList::from_json(c.map.get("status_list").ok_or_else(|| Error::Claim("status_list is missing".into()))?, p.max_bytes)?;
    Ok(VerifiedStatusList { list, uri: p.uri.to_string(), iat, exp, ttl })
}

/// Turns a status value into a decision. Run it only after the referenced token itself verified. `accept` is the set of values
/// the relying party takes as good, usually just `[VALID]`.
pub fn ensure_accepted(value: u8, accept: &[u8]) -> Result<()> {
    if accept.contains(&value) { Ok(()) } else { Err(Error::Claim(format!("credential status is {} ({value:#04x})", status_name(value)))) }
}
