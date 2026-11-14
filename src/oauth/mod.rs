//! OAuth 2.x building blocks. Each module is transport-free: you pass in strings and get strings,
//! so the same code serves an MCP server, a web framework adapter or a C ABI caller.
//!
//! Defaults follow RFC 9700 (OAuth 2.0 Security BCP) and the OAuth 2.1 draft: PKCE is mandatory,
//! redirect URIs match exactly, implicit and password grants do not exist here.
pub mod assertion;
pub mod at_jwt;
pub mod bearer;
pub mod client_auth;
pub mod device;
pub mod dpop;
pub mod exchange;
pub mod error;
#[cfg(feature = "fapi2")]
pub mod fapi2;
pub mod form;
pub mod introspection;
pub mod metadata;
pub mod mtls;
pub mod par_host;
pub mod par_jar;
pub mod pkce;
pub mod rar_stepup;
pub mod redirect;
pub mod registration;
pub mod request;
pub mod revocation;
pub mod scope;
pub mod token;

pub use error::{ErrorCode, OAuthError, OResult};
