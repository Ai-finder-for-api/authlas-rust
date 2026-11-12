//! OpenID Connect Core 1.0 (authorization code flow), Discovery 1.0, RP-Initiated Logout 1.0 and Back-Channel Logout 1.0.
//!
//! Scope, stated plainly:
//! * Code flow only (`response_type=code`). Implicit and hybrid flows are not implemented: OAuth 2.1 and RFC 9700 retire them,
//!   and an ID token delivered through the browser is the thing most OIDC attacks need. `c_hash` is still computed and checked
//!   so a hybrid-flow ID token from a third-party OP can be validated.
//! * Request objects and PAR/JAR come from [`crate::oauth::par_jar`]; they are not repeated here.
//! * Signed or encrypted UserInfo responses and aggregated/distributed claims are not implemented.
//!
//! Modules: [`id_token`] issue and validate, [`request`] prompt/max_age/claims and the login decision, [`claims`] standard claims,
//! UserInfo, pairwise subjects, [`provider`] discovery document checks and logout.
pub mod claims;
pub mod id_token;
pub mod provider;
pub mod request;

pub use id_token::{half_hash, IdToken, IdTokenIssue, Validate};
