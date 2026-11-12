//! SD-JWT VC Type Metadata (draft-ietf-oauth-sd-jwt-vc-26, sections 5 and 6).
//!
//! * [`TypeMetadata::parse`]: one document, checked against the `vct` it was fetched for.
//! * [`check_integrity`]: the `#integrity` values (W3C SRI syntax), strongest hash wins.
//! * [`resolve`]: follows `extends`, refuses cycles and over-long chains, and merges claim metadata with the inheritance rules
//!   of 5.6.5 (a child may tighten `sd` and `mandatory`, never loosen them).
//! * [`validate`]: checks a processed credential against claim metadata. It reads the [`Shape`] that the SD-JWT verifier
//!   recorded, because the merged claims no longer show which values came through a Disclosure or where an undisclosed array
//!   element sits.
//!
//! No network I/O: `resolve` calls your `fetch` with the type identifier. For an `https` identifier it first runs
//! [`crate::ssrf::ssrf_check`]; anything else (a URN, say) goes to `fetch` as a registry lookup. `fetch` must enforce timeout,
//! size cap, redirect checks and "no error bodies" (draft section 3).
use super::VerifiedVc;
use crate::sdjwt::{Shape, Slot};
use crate::{crypto, jwa::Hash, Error, Result};
use base64::Engine;
use serde_json::{Map, Value};
use std::collections::HashSet;

/// Longest `extends` chain followed.
pub const MAX_CHAIN: usize = 8;
/// Largest Type Metadata document accepted.
pub const MAX_DOC_BYTES: usize = 256 * 1024;

fn bad(m: &str) -> Error { Error::Malformed(format!("type metadata: {m}")) }

// ---------------------------------------------------------------------------------------------------------------------
// Integrity (section 6)
// ---------------------------------------------------------------------------------------------------------------------

fn decode_digest(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD.decode(s).or_else(|_| STANDARD_NO_PAD.decode(s)).or_else(|_| URL_SAFE.decode(s)).or_else(|_| URL_SAFE_NO_PAD.decode(s)).ok()
}

/// Checks `bytes` against an SRI "integrity metadata" string such as `sha256-... sha384-...`. Of the hash algorithms this
/// implementation knows, the strongest one present decides, and any entry of that strength may match. A string with no known
/// algorithm is a failure (the document must not be processed).
pub fn check_integrity(bytes: &[u8], integrity: &str) -> Result<()> {
    let mut best: Option<(u8, Hash)> = None;
    let mut entries: Vec<(u8, Hash, Vec<u8>)> = vec![];
    for tok in integrity.split_ascii_whitespace() {
        let tok = tok.split('?').next().unwrap_or("");
        let Some((alg, b64)) = tok.split_once('-') else { continue };
        let (rank, h) = match alg { "sha256" => (1, Hash::Sha256), "sha384" => (2, Hash::Sha384), "sha512" => (3, Hash::Sha512), _ => continue };
        let Some(d) = decode_digest(b64) else { continue };
        if best.map_or(true, |(r, _)| rank > r) { best = Some((rank, h)); }
        entries.push((rank, h, d));
    }
    let (rank, hash) = best.ok_or_else(|| Error::Claim("integrity metadata names no supported hash algorithm".into()))?;
    let actual = crypto::digest(hash, bytes)?;
    if entries.iter().any(|(r, _, d)| *r == rank && crypto::ct_eq(d, &actual)) { Ok(()) } else { Err(Error::Claim("document does not match its integrity value".into())) }
}

/// An integrity string for `bytes`, for issuers that publish `vct#integrity`.
pub fn integrity_for(bytes: &[u8]) -> Result<String> {
    Ok(format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(crypto::digest(Hash::Sha256, bytes)?)))
}

// ---------------------------------------------------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum PathComp { Key(String), All, Index(usize) }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sd { Always, Allowed, Never }

#[derive(Debug, Clone, PartialEq)]
pub struct ClaimMeta {
    pub path: Vec<PathComp>,
    pub display: Option<Value>,
    pub mandatory: Option<bool>,
    pub sd: Option<Sd>,
    pub svg_id: Option<String>,
}

impl ClaimMeta {
    pub fn is_mandatory(&self) -> bool { self.mandatory.unwrap_or(false) }
    pub fn sd_or_default(&self) -> Sd { self.sd.unwrap_or(Sd::Allowed) }
}

#[derive(Debug, Clone)]
pub struct TypeMetadata {
    pub vct: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub extends: Option<String>,
    pub extends_integrity: Option<String>,
    pub display: Option<Value>,
    pub claims: Vec<ClaimMeta>,
}

fn parse_path(v: &Value) -> Result<Vec<PathComp>> {
    let a = v.as_array().filter(|a| !a.is_empty()).ok_or_else(|| bad("path must be a non-empty array"))?;
    if a.len() > 32 { return Err(bad("path is too long")); }
    a.iter().map(|c| match c {
        Value::String(s) => Ok(PathComp::Key(s.clone())),
        Value::Null => Ok(PathComp::All),
        Value::Number(n) => n.as_u64().and_then(|i| usize::try_from(i).ok()).map(PathComp::Index).ok_or_else(|| bad("path indexes must be non-negative integers")),
        _ => Err(bad("path components must be strings, null or non-negative integers")),
    }).collect()
}

impl TypeMetadata {
    /// `expected_vct` is the reference the document was fetched for; the document must name the same type (5.3).
    pub fn parse(body: &[u8], expected_vct: &str) -> Result<TypeMetadata> {
        if body.len() > MAX_DOC_BYTES { return Err(bad("document is too large")); }
        let o = crate::json::parse_object(body)?;
        match o.get("vct").and_then(Value::as_str) {
            Some(v) if v == expected_vct => {}
            Some(_) => return Err(Error::Claim("vct in the Type Metadata is not the type that was requested".into())),
            None => return Err(bad("vct is missing")),
        }
        let s = |k: &str| -> Result<Option<String>> { match o.get(k) { None => Ok(None), Some(Value::String(v)) => Ok(Some(v.clone())), Some(_) => Err(bad(&format!("{k} must be a string"))) } };
        let extends = s("extends")?;
        let extends_integrity = s("extends#integrity")?;
        if extends.is_none() && extends_integrity.is_some() { return Err(bad("extends#integrity without extends")); }
        let display = match o.get("display") { None => None, Some(v @ Value::Array(_)) => Some(v.clone()), Some(_) => return Err(bad("display must be an array")) };
        let claims = match o.get("claims") {
            None => vec![],
            Some(Value::Array(a)) => {
                if a.len() > 1024 { return Err(bad("too many claim entries")); }
                a.iter().map(|c| {
                    let m = c.as_object().ok_or_else(|| bad("a claim entry must be an object"))?;
                    let path = parse_path(m.get("path").ok_or_else(|| bad("a claim entry needs a path"))?)?;
                    let mandatory = match m.get("mandatory") { None => None, Some(Value::Bool(b)) => Some(*b), Some(_) => return Err(bad("mandatory must be a boolean")) };
                    let sd = match m.get("sd") {
                        None => None,
                        Some(Value::String(x)) => Some(match x.as_str() { "always" => Sd::Always, "allowed" => Sd::Allowed, "never" => Sd::Never, _ => return Err(bad("sd must be always, allowed or never")) }),
                        Some(_) => return Err(bad("sd must be a string")),
                    };
                    Ok(ClaimMeta { path, display: m.get("display").cloned(), mandatory, sd, svg_id: m.get("svg_id").and_then(Value::as_str).map(String::from) })
                }).collect::<Result<Vec<_>>>()?
            }
            Some(_) => return Err(bad("claims must be an array")),
        };
        Ok(TypeMetadata { vct: expected_vct.to_string(), name: s("name")?, description: s("description")?, extends, extends_integrity, display, claims })
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Resolved {
    pub vct: String,
    /// The type, then what it extends, then that one's parent, and so on.
    pub chain: Vec<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    /// The most specific `display` in the chain (5.5.2: a child's own display replaces the parent's).
    pub display: Option<Value>,
    /// Claim metadata after inheritance (5.6.5).
    pub claims: Vec<ClaimMeta>,
}

fn fetch_one(reference: &str, integrity: Option<&str>, fetch: &dyn Fn(&str) -> Option<Vec<u8>>) -> Result<TypeMetadata> {
    if reference.starts_with("http:") || reference.starts_with("HTTP:") { return Err(bad("type metadata must be retrieved over https")); }
    if reference.len() >= 6 && reference[..6].eq_ignore_ascii_case("https:") { crate::ssrf::ssrf_check(reference)?; }
    let body = fetch(reference).ok_or_else(|| Error::Claim(format!("type metadata for {reference} could not be retrieved")))?;
    if body.len() > MAX_DOC_BYTES { return Err(bad("document is too large")); }
    if let Some(i) = integrity { check_integrity(&body, i)?; }
    TypeMetadata::parse(&body, reference)
}

/// Combines a parent's claim metadata with the child's (5.6.5). Same path: child properties win, except that `sd` and
/// `mandatory` may only be tightened.
fn merge(parent: Vec<ClaimMeta>, child: Vec<ClaimMeta>) -> Result<Vec<ClaimMeta>> {
    let mut out = parent;
    for c in child {
        match out.iter_mut().find(|p| p.path == c.path) {
            None => out.push(c),
            Some(p) => {
                if let (Some(ps), Some(cs)) = (p.sd, c.sd) {
                    if ps != Sd::Allowed && ps != cs { return Err(Error::Claim("a type may not change sd of an inherited claim that is always or never".into())); }
                }
                if p.sd.map_or(false, |s| s != Sd::Allowed) && c.sd.is_none() { /* inherited unchanged */ }
                if p.is_mandatory() && c.mandatory == Some(false) { return Err(Error::Claim("a type may not make an inherited mandatory claim optional".into())); }
                if c.sd.is_some() { p.sd = c.sd; }
                if c.mandatory.is_some() { p.mandatory = c.mandatory; }
                if c.display.is_some() { p.display = c.display; }
                if c.svg_id.is_some() { p.svg_id = c.svg_id; }
            }
        }
    }
    Ok(out)
}

/// Fetches and merges the Type Metadata for `vct`. `vct_integrity` is the credential's `vct#integrity`.
pub fn resolve(vct: &str, vct_integrity: Option<&str>, fetch: &dyn Fn(&str) -> Option<Vec<u8>>) -> Result<Resolved> {
    let mut docs: Vec<TypeMetadata> = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    let mut next: Option<(String, Option<String>)> = Some((vct.to_string(), vct_integrity.map(String::from)));
    while let Some((reference, integrity)) = next.take() {
        if docs.len() >= MAX_CHAIN { return Err(Error::Claim("extends chain is too long".into())); }
        if !seen.insert(reference.clone()) { return Err(Error::Claim("circular extends chain".into())); }
        let d = fetch_one(&reference, integrity.as_deref(), fetch)?;
        next = d.extends.clone().map(|e| (e, d.extends_integrity.clone()));
        docs.push(d);
    }
    let chain: Vec<String> = docs.iter().map(|d| d.vct.clone()).collect();
    let name = docs[0].name.clone();
    let description = docs[0].description.clone();
    let display = docs.iter().find_map(|d| d.display.clone());
    // Merge from the root ancestor down to the requested type.
    let mut claims: Vec<ClaimMeta> = vec![];
    for d in docs.into_iter().rev() { claims = merge(claims, d.claims)?; }
    Ok(Resolved { vct: vct.to_string(), chain, name, description, display, claims })
}

// ---------------------------------------------------------------------------------------------------------------------
// Validation (5.6, 5.7)
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Sel<'a> { Root(&'a Shape), Node(&'a crate::sdjwt::Member), Hidden }

struct Walked<'a> { selected: Vec<Sel<'a>>, removed_absent: bool, removed_at_last: bool, saw_hidden: bool }

fn shape_of<'a>(s: &Sel<'a>) -> Option<&'a Shape> { match s { Sel::Root(sh) => Some(sh), Sel::Node(m) => Some(&m.shape), Sel::Hidden => None } }

/// Section 5.6.1.2. A string component on something that is not an object, or null or an index on something that is not an
/// array, aborts with an error.
fn walk<'a>(root: &'a Shape, path: &[PathComp]) -> Result<Walked<'a>> {
    let mut cur: Vec<Sel<'a>> = vec![Sel::Root(root)];
    let mut w = Walked { selected: vec![], removed_absent: false, removed_at_last: false, saw_hidden: false };
    for (n, comp) in path.iter().enumerate() {
        let last = n + 1 == path.len();
        let mut nxt: Vec<Sel<'a>> = vec![];
        for s in &cur {
            let Some(shape) = shape_of(s) else { w.saw_hidden = true; continue }; // contents of an undisclosed element are unknown
            match (comp, shape) {
                (PathComp::Key(k), Shape::Object(m)) => match m.iter().find(|(n, _)| n == k) {
                    Some((_, mem)) => nxt.push(Sel::Node(mem)),
                    None => { w.removed_absent = true; w.removed_at_last |= last; }
                },
                (PathComp::All, Shape::Array(a)) => for slot in a { nxt.push(match slot { Slot::Shown(m) => Sel::Node(m), Slot::Hidden => Sel::Hidden }); },
                (PathComp::Index(i), Shape::Array(a)) => match a.get(*i) {
                    Some(Slot::Shown(m)) => nxt.push(Sel::Node(m)),
                    Some(Slot::Hidden) => nxt.push(Sel::Hidden),
                    None => { w.removed_absent = true; w.removed_at_last |= last; }
                },
                (PathComp::Key(_), _) => return Err(Error::Claim("claim path expects an object here".into())),
                (_, _) => return Err(Error::Claim("claim path expects an array here".into())),
            }
        }
        cur = nxt;
    }
    w.selected = cur;
    Ok(w)
}

/// Validates a processed credential against claim metadata. `complete` is true for a holder that has every Disclosure (an absent
/// mandatory claim is then a defect); false for a verifier (a withheld claim looks like an absent one, so a mandatory claim that is
/// missing proves nothing unless `sd` is `never`, in which case it cannot have been withheld).
pub fn validate(claims: &[ClaimMeta], shape: &Shape, complete: bool) -> Result<()> {
    for c in claims {
        let w = walk(shape, &c.path)?;
        if c.is_mandatory() && w.removed_absent {
            let conclusive = complete || (c.sd_or_default() == Sd::Never && w.removed_at_last && !w.saw_hidden);
            if conclusive { return Err(Error::Claim(format!("mandatory claim {} is missing", describe(&c.path)))); }
        }
        for s in &w.selected {
            let (disclosable, present) = match s { Sel::Node(m) => (m.disclosed, true), Sel::Hidden => (true, false), Sel::Root(_) => (false, true) };
            let _ = present;
            match c.sd_or_default() {
                Sd::Always if !disclosable => return Err(Error::Claim(format!("claim {} must be selectively disclosable", describe(&c.path)))),
                Sd::Never if disclosable => return Err(Error::Claim(format!("claim {} must not be selectively disclosable", describe(&c.path)))),
                _ => {}
            }
        }
    }
    Ok(())
}

fn describe(p: &[PathComp]) -> String {
    p.iter().map(|c| match c { PathComp::Key(k) => k.clone(), PathComp::All => "*".into(), PathComp::Index(i) => i.to_string() }).collect::<Vec<_>>().join("/")
}

/// Runs the whole of 5.7 for a verified credential: resolve the metadata chain, then validate. Use `complete = false` as a verifier.
pub fn check_credential(vc: &VerifiedVc, vct_integrity: Option<&str>, fetch: &dyn Fn(&str) -> Option<Vec<u8>>, complete: bool) -> Result<Resolved> {
    let r = resolve(&vc.vct, vct_integrity, fetch)?;
    validate(&r.claims, &vc.shape, complete)?;
    Ok(r)
}

/// Which claims a UI should show, by path, in the type's `display` language, for convenience.
pub fn claim_labels(r: &Resolved, locale: &str) -> Map<String, Value> {
    let mut out = Map::new();
    for c in &r.claims {
        let Some(Value::Array(ds)) = &c.display else { continue };
        let pick = ds.iter().find(|d| d.get("locale").and_then(Value::as_str) == Some(locale)).or_else(|| ds.first());
        if let Some(label) = pick.and_then(|d| d.get("label")).and_then(Value::as_str) {
            out.insert(describe(&c.path), Value::String(label.chars().filter(|ch| !ch.is_control()).take(200).collect()));
        }
    }
    out
}
