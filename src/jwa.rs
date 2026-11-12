//! JSON Web Algorithms (RFC 7518, RFC 8037) - signature algorithm registry.
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn output_len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    HS256, HS384, HS512,
    RS256, RS384, RS512,
    PS256, PS384, PS512,
    ES256, ES384, ES512,
    EdDSA,
    /// Unsecured JWS (RFC 7515 appendix A.5). Only usable with the `test-mode` feature.
    #[cfg(feature = "test-mode")]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family { Hmac, RsaPkcs1, RsaPss, Ecdsa, EdDsa, #[cfg(feature = "test-mode")] Unsecured }

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        use Algorithm::*;
        match self {
            HS256 => "HS256", HS384 => "HS384", HS512 => "HS512",
            RS256 => "RS256", RS384 => "RS384", RS512 => "RS512",
            PS256 => "PS256", PS384 => "PS384", PS512 => "PS512",
            ES256 => "ES256", ES384 => "ES384", ES512 => "ES512",
            EdDSA => "EdDSA",
            #[cfg(feature = "test-mode")]
            None => "none",
        }
    }

    pub fn family(self) -> Family {
        use Algorithm::*;
        match self {
            HS256 | HS384 | HS512 => Family::Hmac,
            RS256 | RS384 | RS512 => Family::RsaPkcs1,
            PS256 | PS384 | PS512 => Family::RsaPss,
            ES256 | ES384 | ES512 => Family::Ecdsa,
            EdDSA => Family::EdDsa,
            #[cfg(feature = "test-mode")]
            None => Family::Unsecured,
        }
    }

    /// Digest used by the algorithm (`None` for EdDSA, which hashes internally).
    pub fn hash(self) -> Option<Hash> {
        use Algorithm::*;
        match self {
            HS256 | RS256 | PS256 | ES256 => Some(Hash::Sha256),
            HS384 | RS384 | PS384 | ES384 => Some(Hash::Sha384),
            HS512 | RS512 | PS512 | ES512 => Some(Hash::Sha512),
            _ => Option::None,
        }
    }

    /// Curve required by an ECDSA algorithm.
    pub fn curve(self) -> Option<&'static str> {
        match self {
            Algorithm::ES256 => Some("P-256"),
            Algorithm::ES384 => Some("P-384"),
            Algorithm::ES512 => Some("P-521"),
            _ => Option::None,
        }
    }
}

impl std::str::FromStr for Algorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        use Algorithm::*;
        Ok(match s {
            "HS256" => HS256, "HS384" => HS384, "HS512" => HS512,
            "RS256" => RS256, "RS384" => RS384, "RS512" => RS512,
            "PS256" => PS256, "PS384" => PS384, "PS512" => PS512,
            "ES256" => ES256, "ES384" => ES384, "ES512" => ES512,
            "EdDSA" => EdDSA,
            #[cfg(feature = "test-mode")]
            "none" => None,
            other => return Err(Error::Algorithm(format!("unsupported alg {other:?}"))),
        })
    }
}
