//! Authlas: OAuth 2.x / JOSE / OpenID library (codename).
pub mod b64;
pub mod crypto;
pub mod error;
pub mod json;
pub mod jwa;
pub mod jwe;
pub mod jwk;
pub mod jwt;
pub mod oauth;
pub mod sdjwt;
pub mod ssrf;
pub mod x509;
pub mod jws;
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "oidc")]
pub mod oidc;
#[cfg(feature = "vc")]
pub mod sdjwt_vc;
#[cfg(feature = "vc")]
pub mod status_list;

pub use error::{Error, Result};

/// C ABI for bindings (Python, TypeScript, C#, C++). Off by default; enable the `capi` feature.
#[cfg(feature = "capi")]
pub mod capi;
