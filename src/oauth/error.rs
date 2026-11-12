//! OAuth error responses: RFC 6749 5.2 and 4.1.2.1, RFC 6750 3.1, plus codes from the extension RFCs.
use serde_json::{json, Value};

pub type OResult<T> = std::result::Result<T, OAuthError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    // RFC 6749
    InvalidRequest, InvalidClient, InvalidGrant, UnauthorizedClient, UnsupportedGrantType, InvalidScope,
    AccessDenied, UnsupportedResponseType, ServerError, TemporarilyUnavailable,
    // RFC 6750
    InvalidToken, InsufficientScope,
    // RFC 7009
    UnsupportedTokenType,
    // RFC 8628
    AuthorizationPending, SlowDown, ExpiredToken,
    // RFC 8707
    InvalidTarget,
    // RFC 9396
    InvalidAuthorizationDetails,
    // RFC 9449
    InvalidDpopProof, UseDpopNonce,
    // RFC 9470
    InsufficientUserAuthentication,
    // RFC 9101
    InvalidRequestUri, InvalidRequestObject, RequestNotSupported, RequestUriNotSupported,
    // RFC 7591
    InvalidRedirectUri, InvalidClientMetadata, InvalidSoftwareStatement, UnapprovedSoftwareStatement,
    // OpenID Connect Core 3.1.2.6
    InteractionRequired, LoginRequired, AccountSelectionRequired, ConsentRequired, RegistrationNotSupported, UnmetAuthenticationRequirements,
    // CIBA
    ExpiredLoginHintToken, UnknownUserId, MissingUserCode, InvalidUserCode, InvalidBindingMessage,
    // OpenID4VCI
    InvalidProof, InvalidNonce,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        use ErrorCode::*;
        match self {
            InvalidRequest => "invalid_request", InvalidClient => "invalid_client", InvalidGrant => "invalid_grant",
            UnauthorizedClient => "unauthorized_client", UnsupportedGrantType => "unsupported_grant_type",
            InvalidScope => "invalid_scope", AccessDenied => "access_denied",
            UnsupportedResponseType => "unsupported_response_type", ServerError => "server_error",
            TemporarilyUnavailable => "temporarily_unavailable", InvalidToken => "invalid_token",
            InsufficientScope => "insufficient_scope", UnsupportedTokenType => "unsupported_token_type", AuthorizationPending => "authorization_pending",
            SlowDown => "slow_down", ExpiredToken => "expired_token", InvalidTarget => "invalid_target",
            InvalidAuthorizationDetails => "invalid_authorization_details", InvalidDpopProof => "invalid_dpop_proof",
            UseDpopNonce => "use_dpop_nonce", InsufficientUserAuthentication => "insufficient_user_authentication",
            InvalidRequestUri => "invalid_request_uri", InvalidRequestObject => "invalid_request_object",
            RequestNotSupported => "request_not_supported", RequestUriNotSupported => "request_uri_not_supported",
            InvalidRedirectUri => "invalid_redirect_uri", InvalidClientMetadata => "invalid_client_metadata",
            InvalidSoftwareStatement => "invalid_software_statement",
            UnapprovedSoftwareStatement => "unapproved_software_statement",
            InteractionRequired => "interaction_required", LoginRequired => "login_required",
            AccountSelectionRequired => "account_selection_required", ConsentRequired => "consent_required",
            RegistrationNotSupported => "registration_not_supported", UnmetAuthenticationRequirements => "unmet_authentication_requirements",
            ExpiredLoginHintToken => "expired_login_hint_token", UnknownUserId => "unknown_user_id",
            MissingUserCode => "missing_user_code", InvalidUserCode => "invalid_user_code",
            InvalidBindingMessage => "invalid_binding_message", InvalidProof => "invalid_proof",
            InvalidNonce => "invalid_nonce",
        }
    }

    pub fn parse(s: &str) -> Option<ErrorCode> {
        use ErrorCode::*;
        const ALL: &[ErrorCode] = &[
            InvalidRequest, InvalidClient, InvalidGrant, UnauthorizedClient, UnsupportedGrantType, InvalidScope,
            AccessDenied, UnsupportedResponseType, ServerError, TemporarilyUnavailable, InvalidToken,
            InsufficientScope, UnsupportedTokenType, AuthorizationPending, SlowDown, ExpiredToken, InvalidTarget,
            InvalidAuthorizationDetails, InvalidDpopProof, UseDpopNonce, InsufficientUserAuthentication,
            InvalidRequestUri, InvalidRequestObject, RequestNotSupported, RequestUriNotSupported,
            InvalidRedirectUri, InvalidClientMetadata, InvalidSoftwareStatement, UnapprovedSoftwareStatement,
            InteractionRequired, LoginRequired, AccountSelectionRequired, ConsentRequired, ExpiredLoginHintToken,
            UnknownUserId, MissingUserCode, InvalidUserCode, InvalidBindingMessage, InvalidProof, InvalidNonce,
            RegistrationNotSupported, UnmetAuthenticationRequirements,
        ];
        ALL.iter().copied().find(|c| c.as_str() == s)
    }

    /// HTTP status for a token-endpoint style response (RFC 6749 5.2). `invalid_client` is 401, the rest 400,
    /// server errors 500/503. Resource-server codes (RFC 6750 3.1) are 401 or 403.
    pub fn http_status(self) -> u16 {
        use ErrorCode::*;
        match self {
            InvalidClient | InvalidToken | InvalidDpopProof => 401,
            UseDpopNonce => 400,
            InsufficientScope | InsufficientUserAuthentication => 403,
            ServerError => 500,
            TemporarilyUnavailable => 503,
            _ => 400,
        }
    }
}

/// An error ready to be sent. `description` is for developers, never for end users, and never carries secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    pub code: ErrorCode,
    pub description: Option<String>,
    pub uri: Option<String>,
    pub state: Option<String>,
}

/// RFC 6749 appendix A.7: `error_description` is `%x20-21 / %x23-5B / %x5D-7E`. Anything else is replaced.
pub fn sanitize_description(s: &str) -> String {
    s.chars().map(|c| if matches!(c as u32, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E) { c } else { ' ' })
        .take(256).collect::<String>()
}

impl OAuthError {
    pub fn new(code: ErrorCode) -> Self { OAuthError { code, description: None, uri: None, state: None } }
    pub fn with(code: ErrorCode, description: &str) -> Self {
        OAuthError { code, description: Some(sanitize_description(description)), uri: None, state: None }
    }
    pub fn state(mut self, state: Option<&str>) -> Self { self.state = state.map(str::to_string); self }
    pub fn invalid_request(d: &str) -> Self { Self::with(ErrorCode::InvalidRequest, d) }
    pub fn invalid_grant(d: &str) -> Self { Self::with(ErrorCode::InvalidGrant, d) }
    pub fn invalid_client(d: &str) -> Self { Self::with(ErrorCode::InvalidClient, d) }

    pub fn status(&self) -> u16 { self.code.http_status() }

    /// Token endpoint body (RFC 6749 5.2). Serve with `Content-Type: application/json` and the no-store headers.
    pub fn to_json(&self) -> String {
        let mut v = json!({ "error": self.code.as_str() });
        if let Some(d) = &self.description { v["error_description"] = Value::String(d.clone()); }
        if let Some(u) = &self.uri { v["error_uri"] = Value::String(u.clone()); }
        v.to_string()
    }

    /// Pairs for a redirect response (RFC 6749 4.1.2.1), with `state` echoed and `iss` added when given (RFC 9207).
    pub fn to_params(&self, iss: Option<&str>) -> Vec<(String, String)> {
        let mut p = vec![("error".to_string(), self.code.as_str().to_string())];
        if let Some(d) = &self.description { p.push(("error_description".into(), d.clone())); }
        if let Some(u) = &self.uri { p.push(("error_uri".into(), u.clone())); }
        if let Some(s) = &self.state { p.push(("state".into(), s.clone())); }
        if let Some(i) = iss { p.push(("iss".into(), i.to_string())); }
        p
    }

    /// Parses an error response received by a client.
    pub fn from_json(body: &str) -> Option<OAuthError> {
        let v: Value = serde_json::from_str(body).ok()?;
        let code = ErrorCode::parse(v.get("error")?.as_str()?)?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(sanitize_description);
        Some(OAuthError { code, description: s("error_description"), uri: v.get("error_uri").and_then(Value::as_str).map(String::from), state: None })
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code.as_str())?;
        if let Some(d) = &self.description { write!(f, ": {d}")?; }
        Ok(())
    }
}
impl std::error::Error for OAuthError {}

/// Standard headers for any response containing tokens or credentials (RFC 6749 5.1).
pub const NO_STORE_HEADERS: [(&str, &str); 2] = [("Cache-Control", "no-store"), ("Pragma", "no-cache")];
