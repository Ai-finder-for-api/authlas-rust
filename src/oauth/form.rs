//! `application/x-www-form-urlencoded` parameters (RFC 6749 section 3.1 and appendix B).
//!
//! * Parameters sent without a value are treated as omitted (RFC 6749 3.1).
//! * A parameter that must occur once and occurs twice is an error, never "first wins" (RFC 6749 3.1).
//! * Size and count limits stop memory abuse before any parsing of meaning happens.
use crate::error::{Error, Result};
use std::collections::BTreeMap;

pub const MAX_BODY: usize = 64 * 1024;
pub const MAX_PARAMS: usize = 128;

/// Parameters that RFC 8707 / RFC 8693 / RFC 9396 explicitly allow to repeat.
pub const MULTI_VALUED: &[&str] = &["resource", "audience"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params {
    map: BTreeMap<String, Vec<String>>,
}

impl Params {
    pub fn parse(body: &str) -> Result<Params> {
        if body.len() > MAX_BODY {
            return Err(Error::Malformed("form body too large".into()));
        }
        let mut p = Params::default();
        let mut n = 0;
        for (k, v) in url::form_urlencoded::parse(body.as_bytes()) {
            n += 1;
            if n > MAX_PARAMS {
                return Err(Error::Malformed("too many parameters".into()));
            }
            if v.is_empty() { continue; }
            p.insert(k.into_owned(), v.into_owned())?;
        }
        Ok(p)
    }

    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<Params> {
        let mut p = Params::default();
        for (k, v) in pairs {
            if !v.is_empty() { p.insert(k.to_string(), v.to_string())?; }
        }
        Ok(p)
    }

    fn insert(&mut self, k: String, v: String) -> Result<()> {
        let e = self.map.entry(k.clone()).or_default();
        if !e.is_empty() && !MULTI_VALUED.contains(&k.as_str()) {
            return Err(Error::Malformed(format!("duplicate parameter {k:?}")));
        }
        e.push(v);
        Ok(())
    }

    /// The single value of `name`, or `None`. Errors if it was repeated (only possible for MULTI_VALUED names).
    pub fn get(&self, name: &str) -> Result<Option<&str>> {
        match self.map.get(name).map(Vec::as_slice) {
            None => Ok(None),
            Some([one]) => Ok(Some(one)),
            Some(_) => Err(Error::Malformed(format!("parameter {name:?} must not repeat"))),
        }
    }

    pub fn require(&self, name: &str) -> Result<&str> {
        self.get(name)?.ok_or_else(|| Error::Malformed(format!("missing parameter {name:?}")))
    }

    pub fn get_all(&self, name: &str) -> &[String] {
        self.map.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn contains(&self, name: &str) -> bool { self.map.contains_key(name) }

    pub fn names(&self) -> impl Iterator<Item = &str> { self.map.keys().map(String::as_str) }

    /// Names not in `known`: extension parameters, which a server must ignore unless it understands them.
    pub fn unknown<'a>(&'a self, known: &'a [&str]) -> impl Iterator<Item = &'a str> {
        self.names().filter(move |n| !known.contains(n))
    }
}

/// Encodes pairs as a form body. Values are percent-encoded, space becomes `+`.
pub fn encode<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs { s.append_pair(k, v); }
    s.finish()
}
