//! SD-JWT-based Verifiable Digital Credentials (draft-ietf-oauth-sd-jwt-vc-26), on top of [`crate::sdjwt`] (RFC 9901).
//!
//! * [`VcIssue`] builds a credential: `typ: dc+sd-jwt`, a `vct`, optional `aka_vcts`, `status` and holder key, and refuses to hide
//!   the claims the draft says must stay in the clear (2.2.2.3).
//! * [`verify`] checks a presentation: the issuer must be authorised for the type *before* its key is looked up, the registered
//!   claims must not have arrived through a Disclosure, `vct` and `aka_vcts` must be well formed, and key binding follows the
//!   verifier's policy.
//! * [`IssuerMetadata`] reads `/.well-known/jwt-vc-issuer` documents (section 4).
//! * [`type_metadata`] resolves `extends` chains (cycle- and depth-limited, integrity-checked) and validates a credential
//!   against claim metadata (`path`, `mandatory`, `sd`).
//!
//! Not implemented: key discovery through an `x5c` chain (this crate has no certificate path validation; supply the key yourself
//! through the `keys` callback), SVG template rendering, and the CBOR/mdoc credential formats.
//!
//! Like the rest of the crate this module does no network I/O. Fetch documents yourself, after [`crate::ssrf::ssrf_check`].
use crate::jwa::{Algorithm, Hash};
use crate::jwk::{Jwk, JwkSet};
use crate::sdjwt::{self, Issued, KeyBindingPolicy, Seg, Shape, Slot};
use crate::status_list::StatusReference;
use crate::{crypto, jws, jwt, Error, Result};
use serde_json::{json, Map, Value};
use url::Url;

pub mod type_metadata;

pub const TYP: &str = "dc+sd-jwt";
/// Header `typ` used before the draft renamed it. Accepted only when the policy says so.
pub const LEGACY_TYP: &str = "vc+sd-jwt";
pub const MEDIA_TYPE: &str = "application/dc+sd-jwt";

/// Claims that must not be selectively disclosed, with all their sub-claims (2.2.2.3).
pub const NEVER_HIDDEN: &[&str] = &["iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status"];

fn bad(m: &str) -> Error { Error::Malformed(format!("sd-jwt vc: {m}")) }

/// `vct` and `aka_vcts` entries are Collision-Resistant Names (RFC 7515 section 2): a URI, a URN, or something rooted in a domain name.
/// A bare word like `identity` could collide with anything and is refused.
pub fn check_type_name(v: &str) -> Result<()> {
    if v.is_empty() || v.len() > 512 { return Err(bad("type name is empty or too long")); }
    if v.chars().any(|c| c.is_control() || c.is_whitespace()) { return Err(bad("type name has whitespace or control characters")); }
    if !(v.contains(':') || v.contains('.')) { return Err(bad("type name is not collision-resistant (use a URI, URN or domain-based name)")); }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------------
// Issuer identifiers and JWT VC Issuer Metadata
// ---------------------------------------------------------------------------------------------------------------------

/// `iss` for key discovery through metadata: https, host, no query, no fragment, no dot segments, no credentials (section 4).
pub fn check_issuer_identifier(iss: &str) -> Result<Url> {
    if iss.len() > 2048 || iss.bytes().any(|b| b <= 0x20 || b == 0x7f) || iss.contains('\\') { return Err(bad("iss is malformed")); }
    let u = Url::parse(iss).map_err(|_| bad("iss is not a URL"))?;
    if u.scheme() != "https" || u.host().is_none() { return Err(bad("iss must be an https URL")); }
    if u.query().is_some() || u.fragment().is_some() || iss.contains('#') || iss.contains('?') { return Err(bad("iss must not have a query or fragment")); }
    if !u.username().is_empty() || u.password().is_some() { return Err(bad("iss must not carry credentials")); }
    let after = iss.split_once("://").map(|(_, r)| r).unwrap_or("");
    if after.starts_with('/') { return Err(bad("iss has an empty authority")); }
    let path = after.find('/').map(|i| &after[i..]).unwrap_or("");
    if path.split('/').any(|s| s == "." || s == ".." || s.eq_ignore_ascii_case("%2e") || s.eq_ignore_ascii_case("%2e%2e")) { return Err(bad("iss has dot segments")); }
    Ok(u)
}

/// Where the issuer metadata lives: `/.well-known/jwt-vc-issuer` inserted between host and path, a trailing `/` dropped first (4.1).
pub fn issuer_metadata_url(iss: &str) -> Result<String> {
    let u = check_issuer_identifier(iss)?;
    Ok(format!("{}/.well-known/jwt-vc-issuer{}", u.origin().ascii_serialization(), u.path().trim_end_matches('/')))
}

#[derive(Debug, Clone)]
pub enum IssuerKeys {
    Inline(JwkSet),
    /// Fetch this URL (it already passed [`crate::ssrf::ssrf_check`]) and parse the body with [`JwkSet::parse`].
    Uri(String),
}

#[derive(Debug, Clone)]
pub struct IssuerMetadata { pub issuer: String, pub keys: IssuerKeys }

impl IssuerMetadata {
    /// `expected_iss` is the `iss` of the credential. A document that names another issuer must not be used (4.3).
    pub fn parse(body: &str, expected_iss: &str) -> Result<IssuerMetadata> {
        check_issuer_identifier(expected_iss)?;
        if body.len() > 256 * 1024 { return Err(bad("issuer metadata is too large")); }
        let o = crate::json::parse_object(body.as_bytes())?;
        match o.get("issuer").and_then(Value::as_str) {
            Some(i) if crypto::ct_eq(i.as_bytes(), expected_iss.as_bytes()) => {}
            Some(_) => return Err(Error::Claim("issuer in the metadata does not equal iss of the credential".into())),
            None => return Err(bad("issuer is missing")),
        }
        let keys = match (o.get("jwks"), o.get("jwks_uri")) {
            (Some(_), Some(_)) => return Err(bad("jwks and jwks_uri are mutually exclusive")),
            (None, None) => return Err(bad("one of jwks and jwks_uri is required")),
            (Some(j), None) => {
                let set = JwkSet::parse(&j.to_string())?;
                if set.keys.is_empty() { return Err(bad("jwks has no keys")); }
                if set.keys.iter().any(Jwk::is_private) { return Err(bad("jwks must hold public keys only")); }
                IssuerKeys::Inline(set)
            }
            (None, Some(Value::String(u))) => { crate::ssrf::ssrf_check(u)?; IssuerKeys::Uri(u.clone()) }
            (None, Some(_)) => return Err(bad("jwks_uri must be a string")),
        };
        Ok(IssuerMetadata { issuer: expected_iss.to_string(), keys })
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Issuing
// ---------------------------------------------------------------------------------------------------------------------

pub struct VcIssue<'a> {
    pub alg: Algorithm,
    pub key: &'a Jwk,
    /// `iss`. Must be an https identifier when keys are discovered through issuer metadata.
    pub issuer: &'a str,
    pub vct: &'a str,
    pub aka_vcts: &'a [&'a str],
    pub hash: Hash,
    /// Decoy digests. Forced to 0 when nothing is hidden: a credential without selectively disclosable claims must not contain `_sd`.
    pub decoys: usize,
    pub holder_key: Option<&'a Jwk>,
    pub status: Option<&'a StatusReference>,
    pub now: Option<u64>,
    /// Seconds the credential is valid (`exp`). `None` omits `exp`, which verifiers may refuse.
    pub lifetime: Option<u64>,
    /// Add `iat`.
    pub include_iat: bool,
}

impl<'a> VcIssue<'a> {
    pub fn new(alg: Algorithm, key: &'a Jwk, issuer: &'a str, vct: &'a str) -> Self {
        VcIssue { alg, key, issuer, vct, aka_vcts: &[], hash: Hash::Sha256, decoys: 0, holder_key: None, status: None, now: None, lifetime: Some(90 * 86_400), include_iat: true }
    }

    /// `claims` are the subject claims; `hide` lists what to make selectively disclosable. The registered claims are set from the
    /// struct fields: passing them in `claims` is an error, so two sources cannot disagree.
    pub fn issue(&self, claims: &Map<String, Value>, hide: &[Vec<Seg>]) -> Result<Issued> {
        check_type_name(self.vct)?;
        for t in self.aka_vcts { check_type_name(t)?; }
        if self.aka_vcts.contains(&self.vct) { return Err(bad("aka_vcts must not contain vct")); }
        for reserved in ["iss", "vct", "aka_vcts", "exp", "iat", "cnf", "status", "_sd", "_sd_alg"] {
            if claims.contains_key(reserved) { return Err(bad(&format!("set {reserved} through the issuer, not the claims"))); }
        }
        for p in hide {
            if let Some(Seg::Key(k)) = p.first() {
                if NEVER_HIDDEN.contains(&k.as_str()) { return Err(bad(&format!("{k} must not be selectively disclosed"))); }
            }
        }
        let mut all = claims.clone();
        let now = self.now.unwrap_or_else(jwt::unix_now);
        all.insert("iss".into(), json!(self.issuer));
        all.insert("vct".into(), json!(self.vct));
        if !self.aka_vcts.is_empty() { all.insert("aka_vcts".into(), json!(self.aka_vcts)); }
        if self.include_iat { all.insert("iat".into(), json!(now)); }
        if let Some(l) = self.lifetime { all.insert("exp".into(), json!(now + l)); }
        if let Some(s) = self.status { all.insert("status".into(), s.to_claim()); }
        let issuer = sdjwt::Issuer { alg: self.alg, key: self.key, hash: self.hash, decoys: if hide.is_empty() { 0 } else { self.decoys }, holder_key: self.holder_key, typ: TYP };
        issuer.issue(&all, hide)
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Verifying
// ---------------------------------------------------------------------------------------------------------------------

pub struct VcPolicy<'a> {
    pub algs: &'a [Algorithm],
    /// Called with `(iss, vct)` before any key is fetched. Return true only for issuers that may issue this type: a type name, an
    /// `extends` link or an `aka_vcts` entry never proves that (draft 7.7). There is no default on purpose.
    pub issuer_may_issue: &'a dyn Fn(&str, &str) -> bool,
    /// `Some`: key binding is required and checked. `None`: not required.
    pub key_binding: Option<KeyBindingPolicy<'a>>,
    /// Types the verifier asked for. Non-empty: the credential's `vct` or one of its `aka_vcts` must be among them.
    pub accept_types: &'a [&'a str],
    pub require_exp: bool,
    pub require_status: bool,
    pub now: Option<u64>,
    pub leeway: u64,
    /// Accept the pre-rename header `typ` `vc+sd-jwt`.
    pub accept_legacy_typ: bool,
    pub hashes: &'a [Hash],
}

impl<'a> VcPolicy<'a> {
    pub fn new(algs: &'a [Algorithm], issuer_may_issue: &'a dyn Fn(&str, &str) -> bool) -> Self {
        VcPolicy { algs, issuer_may_issue, key_binding: None, accept_types: &[], require_exp: true, require_status: false, now: None, leeway: 30,
            accept_legacy_typ: false, hashes: &[Hash::Sha256, Hash::Sha384, Hash::Sha512] }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedVc {
    pub claims: Map<String, Value>,
    pub header: jws::Header,
    pub issuer: String,
    pub vct: String,
    pub aka_vcts: Vec<String>,
    pub key_binding_verified: bool,
    pub status: Option<StatusReference>,
    /// For [`type_metadata::validate`].
    pub shape: Shape,
}

impl VerifiedVc {
    /// Is the credential of this type, by `vct` or `aka_vcts`? Says nothing about whether the issuer may issue it.
    pub fn is_of_type(&self, t: &str) -> bool { self.vct == t || self.aka_vcts.iter().any(|a| a == t) }
}

fn contains_disclosed(s: &Shape) -> bool {
    match s {
        Shape::Leaf => false,
        Shape::Object(m) => m.iter().any(|(_, mem)| mem.disclosed || contains_disclosed(&mem.shape)),
        Shape::Array(a) => a.iter().any(|slot| match slot { Slot::Hidden => true, Slot::Shown(mem) => mem.disclosed || contains_disclosed(&mem.shape) }),
    }
}

/// Verifies a presentation (`JWT~D1~...~[KB]`). `keys(iss, kid, alg)` returns the issuer's verification key, typically from
/// [`IssuerMetadata`] and [`JwkSet::select`]; it is called only after `issuer_may_issue` accepted the pair.
pub fn verify(presentation: &str, keys: &dyn Fn(&str, Option<&str>, Algorithm) -> Option<Jwk>, p: &VcPolicy<'_>) -> Result<VerifiedVc> {
    let parsed = sdjwt::split(presentation)?;
    let h = jws::peek_header(parsed.jwt)?;
    let typ = h.typ.clone().unwrap_or_default();
    let typ_ok = { let t = typ.to_ascii_lowercase(); t == TYP || (p.accept_legacy_typ && t == LEGACY_TYP) };
    if !typ_ok { return Err(Error::Claim(format!("header typ must be {TYP}"))); }
    let unverified = jwt::peek_claims_unverified(parsed.jwt)?;
    let iss = unverified.str_claim("iss")?.ok_or_else(|| Error::Claim("iss is missing".into()))?.to_string();
    let vct = unverified.str_claim("vct")?.ok_or_else(|| Error::Claim("vct is missing".into()))?.to_string();
    check_issuer_identifier(&iss)?;
    check_type_name(&vct)?;
    if !(p.issuer_may_issue)(&iss, &vct) { return Err(Error::Claim("this issuer is not authorised to issue this credential type".into())); }
    let key = keys(&iss, h.kid.as_deref(), h.alg).ok_or_else(|| Error::Key("no verification key for this issuer".into()))?;

    let mut require: Vec<&str> = vec!["vct"];
    if p.require_exp { require.push("exp"); }
    if p.require_status { require.push("status"); }
    let policy = sdjwt::VerifyPolicy {
        algs: p.algs, issuer: &iss, hashes: p.hashes,
        key_binding: p.key_binding.as_ref().map(|k| KeyBindingPolicy { algs: k.algs, audience: k.audience, nonce: k.nonce, max_age: k.max_age }),
        audience: None, typ: Some(&typ), now: p.now, leeway: p.leeway, require: &require,
    };
    let v = sdjwt::verify(presentation, &key, &policy)?;

    // Registered claims are never selectively disclosed (2.2.2.3), including their sub-claims. The merged claims no longer show
    // how a value arrived, so this reads the shape the verifier recorded.
    if let Shape::Object(members) = &v.shape {
        for (name, m) in members {
            if NEVER_HIDDEN.contains(&name.as_str()) && (m.disclosed || contains_disclosed(&m.shape)) {
                return Err(Error::Claim(format!("{name} was selectively disclosed, which this profile forbids")));
            }
        }
    }
    // The signed values must agree with what was read before verification: the issuer-signed payload is the only source of truth.
    if v.claims.get("iss").and_then(Value::as_str) != Some(iss.as_str()) { return Err(Error::Claim("iss changed during processing".into())); }
    if v.claims.get("vct").and_then(Value::as_str) != Some(vct.as_str()) { return Err(Error::Claim("vct changed during processing".into())); }

    let aka_vcts = match v.claims.get("aka_vcts") {
        None => vec![],
        Some(Value::Array(a)) if !a.is_empty() => {
            let list: Vec<String> = a.iter().map(|x| x.as_str().map(String::from).ok_or_else(|| Error::Claim("aka_vcts must hold strings".into()))).collect::<Result<_>>()?;
            for t in &list { check_type_name(t)?; }
            if list.contains(&vct) { return Err(Error::Claim("aka_vcts must not contain vct".into())); }
            list
        }
        Some(_) => return Err(Error::Claim("aka_vcts must be a non-empty array".into())),
    };
    if !p.accept_types.is_empty() && !p.accept_types.iter().any(|t| *t == vct || aka_vcts.iter().any(|a| a == t)) {
        return Err(Error::Claim("credential is not of an accepted type".into()));
    }
    let status = StatusReference::from_claims(&v.claims)?;
    if p.require_status && status.is_none() { return Err(Error::Claim("a status_list reference is required".into())); }
    // RFC 7800 section 3 asks for sub or iss next to cnf; SD-JWT VC lifts that. Nothing to enforce.
    Ok(VerifiedVc { claims: v.claims, header: v.header, issuer: iss, vct, aka_vcts, key_binding_verified: v.key_binding_verified, status, shape: v.shape })
}
