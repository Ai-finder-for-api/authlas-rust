//! Token revocation (RFC 7009).
//!
//! * An unknown, expired or already revoked token still gets a plain 200 (RFC 7009 2.2): revocation is idempotent
//!   and must not reveal whether a token existed.
//! * Only the client the token was issued to may revoke it. Anyone else gets a 200 and nothing happens.
//! * Revoking a refresh token also revokes the grant's access tokens (RFC 7009 2.1).
use super::error::{ErrorCode, OAuthError, OResult};
use super::form::Params;
use super::introspection::TokenTypeHint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request { pub token: String, pub hint: Option<TokenTypeHint> }

pub fn parse_request(body: &Params) -> OResult<Request> {
    let token = body.get("token").map_err(|_| OAuthError::invalid_request("token must not repeat"))?
        .ok_or_else(|| OAuthError::invalid_request("token is required"))?.to_string();
    let hint = body.get("token_type_hint").map_err(|_| OAuthError::invalid_request("token_type_hint must not repeat"))?.and_then(TokenTypeHint::parse);
    Ok(Request { token, hint })
}

/// What the revocation backend found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    Refresh { client_id: String, grant_id: String },
    Access { client_id: String, grant_id: String, jti: String },
    NotFound,
}

pub trait Revoker {
    /// Looks the token up, trying the hinted type first and then the other (RFC 7009 2.1).
    fn lookup(&self, token: &str, hint: Option<TokenTypeHint>) -> Found;
    fn revoke_grant(&self, grant_id: &str);
    fn revoke_access_jti(&self, jti: &str);
}

/// Runs a revocation for an already authenticated client. Always returns `Ok(())` (HTTP 200) unless the
/// request itself is malformed; the caller authenticates the client first and returns `invalid_client` on failure.
pub fn revoke(r: &dyn Revoker, authenticated_client: &str, req: &Request) -> Outcome {
    match r.lookup(&req.token, req.hint) {
        Found::NotFound => Outcome::NothingToDo,
        Found::Refresh { client_id, grant_id } | Found::Access { client_id, grant_id, .. } if client_id != authenticated_client => {
            let _ = grant_id; // someone else's token: do nothing, say nothing
            Outcome::NotYours
        }
        Found::Refresh { grant_id, .. } => { r.revoke_grant(&grant_id); Outcome::Revoked }
        Found::Access { jti, .. } => { r.revoke_access_jti(&jti); Outcome::Revoked }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome { Revoked, NothingToDo, NotYours }

impl Outcome {
    /// All outcomes look the same on the wire.
    pub fn http_status(self) -> u16 { 200 }
    /// For audit logs only.
    pub fn is_notable(self) -> bool { matches!(self, Outcome::NotYours) }
}

/// `unsupported_token_type` for servers that cannot revoke the given kind (RFC 7009 2.2.1).
pub fn unsupported_token_type() -> OAuthError { OAuthError::new(ErrorCode::UnsupportedTokenType) }
