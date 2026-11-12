//! Scope values (RFC 6749 section 3.3): `scope-token *( SP scope-token )`,
//! `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`.
use crate::error::{Error, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope(Vec<String>);

fn valid_token(t: &str) -> bool {
    !t.is_empty() && t.bytes().all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b))
}

impl Scope {
    pub const MAX_TOKENS: usize = 64;

    /// Strict: exactly one space between tokens, no leading or trailing space, no control characters.
    /// Duplicates collapse. Order of first appearance is kept.
    pub fn parse(s: &str) -> Result<Scope> {
        if s.is_empty() { return Err(Error::Malformed("scope must not be empty".into())); }
        let mut v: Vec<String> = Vec::new();
        for t in s.split(' ') {
            if !valid_token(t) { return Err(Error::Malformed("scope contains an invalid token".into())); }
            if !v.iter().any(|x| x == t) { v.push(t.to_string()); }
            if v.len() > Self::MAX_TOKENS { return Err(Error::Malformed("too many scope tokens".into())); }
        }
        Ok(Scope(v))
    }

    pub fn from_tokens<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Result<Scope> {
        Scope::parse(&tokens.into_iter().collect::<Vec<_>>().join(" "))
    }

    pub fn contains(&self, t: &str) -> bool { self.0.iter().any(|x| x == t) }
    pub fn tokens(&self) -> impl Iterator<Item = &str> { self.0.iter().map(String::as_str) }
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
    pub fn is_subset_of(&self, other: &Scope) -> bool { self.0.iter().all(|t| other.contains(t)) }

    /// Tokens present in both, in `self` order.
    pub fn intersect(&self, other: &Scope) -> Scope {
        Scope(self.0.iter().filter(|t| other.contains(t)).cloned().collect())
    }
    /// Tokens of `self` that `allowed` does not contain.
    pub fn excess(&self, allowed: &Scope) -> Vec<&str> {
        self.0.iter().filter(|t| !allowed.contains(t)).map(String::as_str).collect()
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0.join(" ")) }
}
