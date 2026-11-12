//! JSON Web Key (RFC 7517) and JWK Thumbprint (RFC 7638).
use crate::{b64, crypto, error::{Error, Result}, jwa::Hash};
use serde::{Deserialize, Serialize};

macro_rules! jwk_struct {
    ($($f:ident),*) => {
        #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
        pub struct Jwk {
            pub kty: String,
            #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
            pub use_: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub key_ops: Option<Vec<String>>,
            $( #[serde(default, skip_serializing_if = "Option::is_none")] pub $f: Option<String>, )*
        }
    };
}
jwk_struct!(alg, kid, crv, x, y, d, n, e, p, q, dp, dq, qi, k);

impl Jwk {
    pub fn parse(json: &str) -> Result<Jwk> {
        let k: Jwk = serde_json::from_str(json)?;
        if k.kty.is_empty() {
            return Err(Error::Malformed("jwk: empty kty".into()));
        }
        Ok(k)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("jwk serializes")
    }

    pub fn is_private(&self) -> bool {
        self.d.is_some() || self.k.is_some()
    }

    /// Copy with every private member removed. Symmetric keys have no public form.
    pub fn public(&self) -> Result<Jwk> {
        if self.kty == "oct" {
            return Err(Error::Key("oct keys have no public form".into()));
        }
        let mut c = self.clone();
        c.d = None; c.p = None; c.q = None; c.dp = None; c.dq = None; c.qi = None; c.k = None;
        Ok(c)
    }

    fn field(&self, name: &str) -> Option<&str> {
        match name {
            "crv" => self.crv.as_deref(), "x" => self.x.as_deref(), "y" => self.y.as_deref(),
            "d" => self.d.as_deref(), "n" => self.n.as_deref(), "e" => self.e.as_deref(),
            "p" => self.p.as_deref(), "q" => self.q.as_deref(), "dp" => self.dp.as_deref(),
            "dq" => self.dq.as_deref(), "qi" => self.qi.as_deref(), "k" => self.k.as_deref(),
            _ => None,
        }
    }

    /// Decoded value of a required member.
    pub fn req(&self, name: &str) -> Result<Vec<u8>> {
        let v = self.field(name).ok_or_else(|| Error::Key(format!("missing {name:?}")))?;
        b64::decode(v)
    }

    /// Decoded member that must be exactly `len` bytes (RFC 7518 6.2.1.2 and RFC 8037 2).
    pub fn coord(&self, name: &str, len: usize) -> Result<Vec<u8>> {
        let v = self.req(name)?;
        if v.len() != len {
            return Err(Error::Key(format!("{name:?} must be {len} bytes, got {}", v.len())));
        }
        Ok(v)
    }

    /// RFC 7638 thumbprint input: required members only, lexicographic order, no whitespace.
    pub fn thumbprint_input(&self) -> Result<String> {
        let names: &[&str] = match self.kty.as_str() {
            "EC" => &["crv", "kty", "x", "y"],
            "RSA" => &["e", "kty", "n"],
            "oct" => &["k", "kty"],
            "OKP" => &["crv", "kty", "x"],
            other => return Err(Error::Key(format!("thumbprint: unsupported kty {other:?}"))),
        };
        let mut m = serde_json::Map::new();
        for n in names {
            let v = if *n == "kty" { Some(self.kty.as_str()) } else { self.field(n) };
            let v = v.ok_or_else(|| Error::Key(format!("thumbprint: missing {n:?}")))?;
            m.insert((*n).into(), serde_json::Value::String(v.into()));
        }
        // serde_json::Map is a BTreeMap here, so keys serialize in sorted order.
        Ok(serde_json::to_string(&m)?)
    }

    pub fn thumbprint(&self, hash: Hash) -> Result<String> {
        Ok(b64::encode(crypto::digest(hash, self.thumbprint_input()?.as_bytes())?))
    }

    /// `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<value>` (RFC 9278).
    pub fn thumbprint_uri(&self, hash: Hash) -> Result<String> {
        let tag = match hash { Hash::Sha256 => "sha-256", Hash::Sha384 => "sha-384", Hash::Sha512 => "sha-512" };
        Ok(format!("urn:ietf:params:oauth:jwk-thumbprint:{tag}:{}", self.thumbprint(hash)?))
    }
}

/// JSON Web Key Set (RFC 7517 section 5).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn parse(json: &str) -> Result<JwkSet> {
        Ok(serde_json::from_str(json)?)
    }
    pub fn find_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }

    /// Picks the verification key for a token signed with `alg`.
    ///
    /// * With a `kid`: exactly one usable key must carry it. Two keys with one `kid` is an error, not "take the first".
    /// * Without a `kid`: exactly one usable key must exist in the set. Guessing among several would let a token choose its own key.
    ///
    /// "Usable" means: the key type matches the algorithm, `use` is absent or `sig`, `alg` is absent or equal, `key_ops` is absent or
    /// has `verify`, and for ECDSA the curve is the one the algorithm names. Symmetric keys are never selected from a (public) set.
    pub fn select(&self, kid: Option<&str>, alg: crate::jwa::Algorithm) -> Result<&Jwk> {
        use crate::jwa::Family;
        let kty = match alg.family() {
            Family::RsaPkcs1 | Family::RsaPss => "RSA",
            Family::Ecdsa => "EC",
            Family::EdDsa => "OKP",
            _ => return Err(Error::Algorithm(format!("{} keys are not selected from a JWK Set", alg.as_str()))),
        };
        let usable = |k: &&Jwk| {
            k.kty == kty
                && k.use_.as_deref().map_or(true, |u| u == "sig")
                && k.alg.as_deref().map_or(true, |a| a == alg.as_str())
                && k.key_ops.as_ref().map_or(true, |o| o.iter().any(|x| x == "verify"))
                && alg.curve().map_or(true, |c| k.crv.as_deref() == Some(c))
                && !k.is_private()
        };
        let mut hits = self.keys.iter().filter(usable).filter(|k| kid.map_or(true, |w| k.kid.as_deref() == Some(w)));
        match (hits.next(), hits.next()) {
            (Some(k), None) => Ok(k),
            (None, _) => Err(Error::Key("no key in the set fits this token".into())),
            (Some(_), Some(_)) => Err(Error::Key(if kid.is_some() { "several keys share this kid".into() } else { "token has no kid and the set has several usable keys".into() })),
        }
    }
}
