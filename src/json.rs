//! Strict JSON object parsing: duplicate member names are an error
//! (RFC 7515 section 4 and RFC 8259 section 4: names SHOULD be unique; JOSE says MUST reject).
use crate::error::{Error, Result};
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

struct Strict(Map<String, Value>);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("a JSON object") }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Strict, A::Error> {
                let mut m = Map::new();
                while let Some((k, v)) = a.next_entry::<String, Value>()? {
                    if m.contains_key(&k) {
                        return Err(serde::de::Error::custom(format!("duplicate member {k:?}")));
                    }
                    m.insert(k, v);
                }
                Ok(Strict(m))
            }
        }
        d.deserialize_map(V)
    }
}

/// Parses a top-level JSON object, rejecting duplicate names at the top level.
pub fn parse_object(bytes: &[u8]) -> Result<Map<String, Value>> {
    serde_json::from_slice::<Strict>(bytes)
        .map(|s| s.0)
        .map_err(|e| Error::Malformed(format!("json object: {e}")))
}
