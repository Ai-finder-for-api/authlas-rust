//! Selective Disclosure for JWTs (RFC 9901).
//!
//! Issuer: build an SD-JWT from a claims object, choosing which members and array elements are hidden.
//! Holder: pick which disclosures to reveal and add a key-binding JWT.
//! Verifier: check the issuer signature, rebuild the claims from the disclosures, and check key binding.
//!
//! Verification follows RFC 9901 7.1 and 7.3 step by step. The points that matter for safety:
//! * every disclosure must be referenced by exactly one digest (an unreferenced one is a rejection, not an ignore);
//! * a digest that appears twice, a duplicate claim name, or a disclosure named `_sd` or `...` is a rejection;
//! * whether key binding is required is the verifier's policy, never inferred from what the holder sent;
//! * the hash algorithm must be one the verifier accepts (no `md5`, no downgrade by `_sd_alg`).
use crate::{b64, crypto, error::{Error, Result}, jwa::{Algorithm, Hash}, jwk::Jwk, jws, jwt::{self, Claims, Validation}};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

pub const KB_TYP: &str = "kb+jwt";

fn hash_by_name(n: &str) -> Option<Hash> {
    match n { "sha-256" => Some(Hash::Sha256), "sha-384" => Some(Hash::Sha384), "sha-512" => Some(Hash::Sha512), _ => None }
}
fn hash_name(h: Hash) -> &'static str { match h { Hash::Sha256 => "sha-256", Hash::Sha384 => "sha-384", _ => "sha-512" } }
fn digest_b64(h: Hash, data: &str) -> Result<String> { Ok(b64::encode(crypto::digest(h, data.as_bytes())?)) }

fn bad(m: &str) -> Error { Error::Malformed(format!("sd-jwt: {m}")) }

// ---------- issuer ----------

/// Which parts of the claims are hidden. A path is a list of object keys / array indexes.
#[derive(Debug, Clone, PartialEq)]
pub enum Seg { Key(String), Index(usize) }

pub fn path(s: &str) -> Vec<Seg> {
    s.split('/').filter(|p| !p.is_empty()).map(|p| p.parse::<usize>().map(Seg::Index).unwrap_or_else(|_| Seg::Key(p.to_string()))).collect()
}

pub struct Issuer<'a> {
    pub alg: Algorithm,
    pub key: &'a Jwk,
    pub hash: Hash,
    /// Number of random decoy digests added at the top level (RFC 9901 4.2.5).
    pub decoys: usize,
    /// Holder's public key, put into `cnf.jwk` (RFC 9901 4.1.2).
    pub holder_key: Option<&'a Jwk>,
    /// `typ` of the issuer JWT, e.g. `dc+sd-jwt` for SD-JWT VC.
    pub typ: &'a str,
}

fn new_salt() -> Result<String> {
    let mut b = [0u8; 16]; // 128 bits (RFC 9901 9.3)
    crypto::random(&mut b)?;
    Ok(b64::encode(b))
}

fn disclosure_for(name: Option<&str>, value: &Value) -> Result<String> {
    let arr = match name { Some(n) => json!([new_salt()?, n, value]), None => json!([new_salt()?, value]) };
    Ok(b64::encode(serde_json::to_vec(&arr)?))
}

/// Result of issuing: the compact SD-JWT (`jwt~d1~d2~...~`) and the disclosures separately.
pub struct Issued { pub compact: String, pub disclosures: Vec<String> }

impl Issuer<'_> {
    /// `claims` is the full claim set. `hide` lists the paths to make selectively disclosable. A path to an object
    /// member hides that member; a path ending in an array index hides that element.
    pub fn issue(&self, claims: &Map<String, Value>, hide: &[Vec<Seg>]) -> Result<Issued> {
        let mut root = Value::Object(claims.clone());
        let mut disclosures = Vec::new();
        // Deepest paths first so a parent is hashed after its children were replaced by digests.
        let mut order: Vec<&Vec<Seg>> = hide.iter().collect();
        order.sort_by_key(|p| std::cmp::Reverse(p.len()));
        for p in order { self.hide_at(&mut root, p, &mut disclosures)?; }
        let mut obj = match root { Value::Object(o) => o, _ => unreachable!() };
        // Decoys at the top level.
        if self.decoys > 0 {
            let sd = obj.entry("_sd").or_insert_with(|| json!([]));
            for _ in 0..self.decoys {
                let mut r = [0u8; 16];
                crypto::random(&mut r)?;
                sd.as_array_mut().unwrap().push(json!(digest_b64(self.hash, &b64::encode(r))?));
            }
        }
        if let Some(Value::Array(a)) = obj.get_mut("_sd") {
            let mut s: Vec<String> = a.iter().filter_map(|v| v.as_str().map(String::from)).collect();
            s.sort(); // order must not reveal which digests are real (RFC 9901 4.2.4.1)
            *a = s.into_iter().map(Value::String).collect();
        }
        if !disclosures.is_empty() || self.decoys > 0 { obj.insert("_sd_alg".into(), json!(hash_name(self.hash))); }
        if let Some(hk) = self.holder_key {
            if hk.is_private() { return Err(Error::Key("holder key in cnf must be public".into())); }
            obj.insert("cnf".into(), json!({ "jwk": serde_json::from_str::<Value>(&hk.to_json())? }));
        }
        let mut h = Map::new();
        h.insert("typ".into(), json!(self.typ));
        if let Some(k) = &self.key.kid { h.insert("kid".into(), json!(k)); }
        let jws = jws::sign(self.alg, self.key, &h, &serde_json::to_vec(&obj)?)?;
        let mut compact = jws;
        compact.push('~');
        for d in &disclosures { compact.push_str(d); compact.push('~'); }
        Ok(Issued { compact, disclosures })
    }

    fn hide_at(&self, root: &mut Value, p: &[Seg], out: &mut Vec<String>) -> Result<()> {
        let (last, parents) = p.split_last().ok_or_else(|| bad("empty path"))?;
        let mut cur = root;
        for s in parents {
            cur = match (s, cur) {
                (Seg::Key(k), Value::Object(o)) => o.get_mut(k).ok_or_else(|| bad("path does not exist"))?,
                (Seg::Index(i), Value::Array(a)) => a.get_mut(*i).ok_or_else(|| bad("path does not exist"))?,
                _ => return Err(bad("path does not exist")),
            };
        }
        match (last, cur) {
            (Seg::Key(k), Value::Object(o)) => {
                if k == "_sd" || k == "..." { return Err(bad("reserved claim name")); }
                let v = o.remove(k).ok_or_else(|| bad("path does not exist"))?;
                let d = disclosure_for(Some(k), &v)?;
                let dg = digest_b64(self.hash, &d)?;
                o.entry("_sd").or_insert_with(|| json!([])).as_array_mut().ok_or_else(|| bad("_sd is not an array"))?.push(json!(dg));
                out.push(d);
            }
            (Seg::Index(i), Value::Array(a)) => {
                let v = a.get(*i).cloned().ok_or_else(|| bad("path does not exist"))?;
                let d = disclosure_for(None, &v)?;
                a[*i] = json!({ "...": digest_b64(self.hash, &d)? });
                out.push(d);
            }
            _ => return Err(bad("path does not exist")),
        }
        Ok(())
    }
}

// ---------- parsing ----------

#[derive(Debug, Clone)]
pub struct Parsed<'a> {
    pub jwt: &'a str,
    pub disclosures: Vec<&'a str>,
    pub kb_jwt: Option<&'a str>,
}

/// Splits `JWT~D1~...~Dn~[KB]`. The string after the last tilde is the key-binding JWT, or empty.
pub fn split(sd: &str) -> Result<Parsed<'_>> {
    if sd.len() > 1_000_000 { return Err(bad("too large")); }
    let parts: Vec<&str> = sd.split('~').collect();
    if parts.len() < 2 { return Err(bad("missing the trailing ~")); }
    let (jwt, rest) = (parts[0], &parts[1..]);
    let (kb, disclosures) = rest.split_last().ok_or_else(|| bad("malformed"))?;
    if disclosures.iter().any(|d| d.is_empty()) { return Err(bad("empty disclosure")); }
    if disclosures.len() > 1000 { return Err(bad("too many disclosures")); }
    // The final element is either empty or a key-binding JWT. Anything else (typically a missing trailing "~"
    // that leaves a disclosure in the last position) is malformed, whatever the key-binding policy says.
    if !kb.is_empty() && kb.split('.').count() != 3 { return Err(bad("the last element must be empty or a key-binding JWT (missing trailing ~?)")); }
    Ok(Parsed { jwt, disclosures: disclosures.to_vec(), kb_jwt: (!kb.is_empty()).then_some(*kb) })
}

// ---------- verifier ----------

pub struct KeyBindingPolicy<'a> {
    pub algs: &'a [Algorithm],
    pub audience: &'a str,
    pub nonce: &'a str,
    /// How old the key-binding JWT may be.
    pub max_age: u64,
}

pub struct VerifyPolicy<'a> {
    pub algs: &'a [Algorithm],
    pub issuer: &'a str,
    /// Hash algorithms accepted for `_sd_alg`. SHA-256 and up.
    pub hashes: &'a [Hash],
    /// `None`: key binding not required (a KB-JWT, if present, is still not checked, and is ignored).
    /// `Some`: required. The decision is the verifier's and does not depend on what was sent.
    pub key_binding: Option<KeyBindingPolicy<'a>>,
    /// Audience for the issuer JWT, when it has one.
    pub audience: Option<&'a str>,
    pub typ: Option<&'a str>,
    pub now: Option<u64>,
    pub leeway: u64,
    /// Claims that must be present after disclosure (e.g. `exp`).
    pub require: &'a [&'a str],
}

#[derive(Debug, Clone)]
pub struct Verified {
    /// The claims with disclosed values merged in, `_sd` and `_sd_alg` removed.
    pub claims: Map<String, Value>,
    pub header: jws::Header,
    pub key_binding_verified: bool,
    /// How the claims were issued: which members arrived through a Disclosure, and where undisclosed array elements sit.
    /// SD-JWT VC claim metadata (`sd`, `mandatory`, index paths) is checked against this.
    pub shape: Shape,
}

/// Structure of a processed SD-JWT payload, with the selective-disclosure facts that the merged claims no longer show.
#[derive(Debug, Clone, PartialEq)]
pub enum Shape {
    Leaf,
    /// Members present after processing. A member that was withheld is absent: it cannot be listed.
    Object(Vec<(String, Member)>),
    /// Array as issued: a withheld element keeps its position as [`Slot::Hidden`].
    Array(Vec<Slot>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub shape: Shape,
    /// The value arrived through a Disclosure (it is selectively disclosable). A plain member has `false`.
    pub disclosed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Slot { Hidden, Shown(Member) }

struct Walk<'a> {
    by_digest: std::collections::HashMap<String, &'a str>,
    seen: HashSet<String>,
    used: HashSet<String>,
    hash: Hash,
    depth_budget: usize,
}

impl Walk<'_> {
    fn take(&mut self, digest: &str) -> Result<Option<Vec<Value>>> {
        if !self.seen.insert(digest.to_string()) { return Err(bad("a digest appears more than once")); }
        let Some(d) = self.by_digest.get(digest) else { return Ok(None) }; // decoy or withheld: ignore
        self.used.insert(digest.to_string());
        let raw = b64::decode(d)?;
        let v: Value = serde_json::from_slice(&raw).map_err(|_| bad("disclosure is not JSON"))?;
        Ok(Some(v.as_array().cloned().ok_or_else(|| bad("disclosure is not an array"))?))
    }

    fn object(&mut self, o: &mut Map<String, Value>, depth: usize) -> Result<Vec<(String, Member)>> {
        if depth > self.depth_budget { return Err(bad("nesting too deep")); }
        let digests = match o.remove("_sd") {
            None => vec![],
            Some(Value::Array(a)) => a.into_iter().map(|v| v.as_str().map(String::from).ok_or_else(|| bad("_sd entries must be strings"))).collect::<Result<Vec<_>>>()?,
            Some(_) => return Err(bad("_sd must be an array")),
        };
        let mut members: Vec<(String, Member)> = Vec::with_capacity(o.len() + digests.len());
        // Members that were in the payload as issued.
        for (k, v) in o.iter_mut() {
            let shape = self.value(v, depth + 1)?;
            members.push((k.clone(), Member { shape, disclosed: false }));
        }
        // Members that came back through a Disclosure.
        for dg in digests {
            if let Some(arr) = self.take(&dg)? {
                let [_salt, name, value] = <[Value; 3]>::try_from(arr).map_err(|_| bad("object disclosure needs 3 elements"))?;
                let name = name.as_str().ok_or_else(|| bad("claim name must be a string"))?.to_string();
                if name == "_sd" || name == "..." { return Err(bad("disclosure uses a reserved claim name")); }
                if o.contains_key(&name) { return Err(bad("disclosed claim name already exists")); }
                let mut value = value;
                let shape = self.value(&mut value, depth + 1)?;
                o.insert(name.clone(), value);
                members.push((name, Member { shape, disclosed: true }));
            }
        }
        Ok(members)
    }

    fn value(&mut self, v: &mut Value, depth: usize) -> Result<Shape> {
        match v {
            Value::Object(o) => Ok(Shape::Object(self.object(o, depth)?)),
            Value::Array(a) => {
                if depth > self.depth_budget { return Err(bad("nesting too deep")); }
                let mut out = Vec::with_capacity(a.len());
                let mut slots = Vec::with_capacity(a.len());
                for item in std::mem::take(a) {
                    let digest = match &item { Value::Object(o) if o.len() == 1 => o.get("...").map(|x| x.as_str().map(String::from).ok_or_else(|| bad("... must be a string"))), _ => None };
                    match digest {
                        Some(d) => {
                            let d = d?;
                            if let Some(arr) = self.take(&d)? {
                                let [_salt, value] = <[Value; 2]>::try_from(arr).map_err(|_| bad("array disclosure needs 2 elements"))?;
                                let mut value = value;
                                let shape = self.value(&mut value, depth + 1)?;
                                out.push(value);
                                slots.push(Slot::Shown(Member { shape, disclosed: true }));
                            } else {
                                slots.push(Slot::Hidden); // no disclosure: the element is dropped from the claims but keeps its place
                            }
                        }
                        None => {
                            let mut item = item;
                            let shape = self.value(&mut item, depth + 1)?;
                            out.push(item);
                            slots.push(Slot::Shown(Member { shape, disclosed: false }));
                        }
                    }
                }
                *a = out;
                Ok(Shape::Array(slots))
            }
            _ => Ok(Shape::Leaf),
        }
    }
}

/// Verifies an SD-JWT or SD-JWT+KB presentation.
pub fn verify(sd: &str, issuer_key: &Jwk, p: &VerifyPolicy<'_>) -> Result<Verified> {
    let parsed = split(sd)?;
    // 7.1 step 2: issuer JWT.
    let mut jp = jws::Policy::new(p.algs);
    jp.typ = p.typ;
    let (header, payload) = jws::verify(parsed.jwt, issuer_key, &jp).map_err(|e| match e { Error::BadSignature => Error::BadSignature, o => o })?;
    let mut claims_map = crate::json::parse_object(&payload)?;
    // The issuer JWT is validated as a JWT too (iss, exp, nbf, ...). `exp` is optional here (RFC 9901 9.7 lets the
    // verifier require it through `require`).
    {
        let c = Claims { map: claims_map.clone() };
        let mut v = Validation::new(p.algs, p.issuer, p.audience.unwrap_or(""));
        v.now = p.now; v.leeway = p.leeway; v.require_exp = false;
        check_issuer_claims(&c, &v, p.audience.is_some())?;
    }
    // _sd_alg
    let hash = match claims_map.get("_sd_alg") {
        None => Hash::Sha256,
        Some(Value::String(n)) => hash_by_name(n).ok_or_else(|| bad("unknown _sd_alg"))?,
        Some(_) => return Err(bad("_sd_alg must be a string")),
    };
    if !p.hashes.contains(&hash) { return Err(Error::Algorithm("_sd_alg is not accepted by policy".into())); }
    claims_map.remove("_sd_alg");

    // Step 3: disclosures.
    let mut by_digest = std::collections::HashMap::new();
    for d in &parsed.disclosures {
        let dg = digest_b64(hash, d)?;
        if by_digest.insert(dg, *d).is_some() { return Err(bad("the same disclosure was sent twice")); }
    }
    let mut w = Walk { by_digest, seen: HashSet::new(), used: HashSet::new(), hash, depth_budget: 64 };
    let _ = w.hash;
    let shape = Shape::Object(w.object(&mut claims_map, 0)?);
    if w.used.len() != parsed.disclosures.len() { return Err(bad("a disclosure is not referenced by any digest")); }
    for r in p.require { if !claims_map.contains_key(*r) { return Err(Error::Claim(format!("{r} is missing"))); } }
    if claims_map.contains_key("_sd") { return Err(bad("_sd remained after processing")); }

    // Key binding (7.3).
    let mut kb_ok = false;
    match (&p.key_binding, parsed.kb_jwt) {
        (None, _) => {}
        (Some(_), None) => return Err(bad("key binding is required but the presentation has none")),
        (Some(k), Some(kb)) => {
            let cnf = Claims { map: claims_map.clone() }.cnf()?.ok_or_else(|| bad("key binding required but the SD-JWT has no cnf"))?;
            let holder = cnf.jwk.ok_or_else(|| bad("cnf has no jwk to verify key binding with"))?;
            let mut kp = jws::Policy::new(k.algs);
            kp.typ = Some(KB_TYP);
            let (_, kb_payload) = jws::verify(kb, &holder, &kp).map_err(|_| Error::BadSignature)?;
            let kc = Claims::parse(&kb_payload)?;
            let now = p.now.unwrap_or_else(jwt::unix_now);
            let iat = kc.date("iat")?.ok_or_else(|| Error::Claim("kb iat is missing".into()))?;
            if iat > now + p.leeway || now.saturating_sub(iat) > k.max_age + p.leeway { return Err(Error::Claim("key binding JWT is outside the accepted time window".into())); }
            // aud must be a single string equal to the verifier's identifier.
            match kc.map.get("aud") { Some(Value::String(a)) if a == k.audience => {}, _ => return Err(Error::Claim("kb aud does not match".into())) }
            match kc.str_claim("nonce")? { Some(n) if crypto::ct_eq(n.as_bytes(), k.nonce.as_bytes()) => {}, _ => return Err(Error::Claim("kb nonce does not match".into())) }
            // sd_hash covers everything before the key-binding JWT, including the final tilde.
            let end = sd.len() - kb.len();
            let want = digest_b64(hash, &sd[..end])?;
            match kc.str_claim("sd_hash")? { Some(h) if crypto::ct_eq(h.as_bytes(), want.as_bytes()) => {}, _ => return Err(Error::Claim("sd_hash does not match the presentation".into())) }
            kb_ok = true;
        }
    }
    Ok(Verified { claims: claims_map, header, key_binding_verified: kb_ok, shape })
}

fn check_issuer_claims(c: &Claims, v: &Validation<'_>, check_aud: bool) -> Result<()> {
    // Same rules as jwt::Validation::check, but `aud` is only checked when the verifier supplied one, because many
    // SD-JWT credentials have no `aud` (the key-binding JWT carries the audience).
    if check_aud { return v.check(c); }
    let mut c2 = c.clone();
    c2.map.insert("aud".into(), Value::String(v.audience.to_string()));
    // Put the same audience in so the shared checker passes for the other claims; a real `aud` in the token is replaced,
    // which is why this path is used only when the verifier did not ask for an audience check.
    v.check(&c2)
}

// ---------- holder ----------

/// Holder side: choose which disclosures to reveal and (optionally) add a key-binding JWT.
pub struct Presentation<'a> {
    pub sd_jwt: &'a str,
    /// Indexes into the disclosure list of `sd_jwt` to reveal.
    pub reveal: &'a [usize],
}

impl Presentation<'_> {
    /// Returns `JWT~D..~` (without key binding).
    pub fn build(&self) -> Result<String> {
        let p = split(self.sd_jwt)?;
        if p.kb_jwt.is_some() { return Err(bad("the holder must not receive a key-binding JWT")); } // RFC 9901 7.2
        let mut out = format!("{}~", p.jwt);
        let mut seen = HashSet::new();
        for &i in self.reveal {
            let d = p.disclosures.get(i).ok_or_else(|| bad("disclosure index out of range"))?;
            if !seen.insert(i) { continue; }
            out.push_str(d); out.push('~');
        }
        Ok(out)
    }

    /// Adds a key-binding JWT over `presentation` (RFC 9901 4.3).
    pub fn with_key_binding(presentation: &str, hash: Hash, alg: Algorithm, holder_key: &Jwk, audience: &str, nonce: &str) -> Result<String> {
        if !presentation.ends_with('~') { return Err(bad("presentation must end with ~")); }
        let c = Claims::new().set("nonce", nonce).audience(&[audience]).issued_at(jwt::unix_now()).set("sd_hash", digest_b64(hash, presentation)?);
        let kb = jwt::sign(alg, holder_key, &c, Some(KB_TYP))?;
        Ok(format!("{presentation}{kb}"))
    }
}

/// For a holder that wants to show a user what each disclosure contains before consenting.
pub fn describe(disclosure: &str) -> Result<(Option<String>, Value)> {
    let v: Value = serde_json::from_slice(&b64::decode(disclosure)?)?;
    let a = v.as_array().ok_or_else(|| bad("disclosure is not an array"))?;
    match a.as_slice() {
        [_, Value::String(n), val] => Ok((Some(n.clone()), val.clone())),
        [_, val] => Ok((None, val.clone())),
        _ => Err(bad("disclosure has the wrong length")),
    }
}

/// Digest of one disclosure, for looking it up in the issuer payload.
pub fn disclosure_digest(disclosure: &str, hash: Hash) -> Result<String> { digest_b64(hash, disclosure) }
