"""Stateless calls into the authlas Rust C ABI. Every function returns plain Python values (dicts, lists, strings, bytes)
and raises CoreError on failure. Stores and callbacks live in ``authlas_core.stores``.
"""
from __future__ import annotations

import ctypes
from typing import Any, Dict, List, Optional, Sequence

__all__ = [
    "Replay",
    "dpop_verify",
    "generate_ec_key",
    "public_jwk",
    "jwk_thumbprint",
    "jws_sign",
    "jws_verify",
    "jws_peek_header",
    "jwe_peek_header",
    "jwe_encrypt",
    "jwe_decrypt",
    "jwt_sign",
    "jwt_verify",
    "jwt_peek_claims",
    "jwt_encrypt_nested",
    "pkce_new",
    "pkce_generate",
    "pkce_s256_challenge",
    "pkce_valid_verifier",
    "pkce_verify",
    "redirect_validate",
    "redirect_matches",
    "bearer_parse",
    "bearer_challenge",
    "scope_parse",
    "scope_check",
    "dpop_proof",
    "dpop_ath",
    "dpop_normalize_htu",
    "dpop_nonce_issue",
    "dpop_nonce_check",
    "client_authenticate",
    "introspection_parse_request",
    "introspection_parse_response",
    "introspection_check",
    "introspection_sign_jwt",
    "introspection_verify_jwt",
    "exchange_decide",
    "exchange_response",
    "mtls_authenticate",
    "mtls_cnf",
    "mtls_check_binding",
    "mtls_same_certificate",
    "cert_info",
    "request_object_build",
    "request_object_verify",
    "request_uri_fingerprint",
    "as_metadata_parse",
    "as_metadata_normalize",
    "as_metadata_defaults",
    "resource_metadata_parse",
    "as_metadata_url",
    "oidc_metadata_url",
    "resource_metadata_url",
    "canonical_resource",
    "mcp_resource_metadata_urls",
    "mcp_as_discovery_urls",
    "www_authenticate_parse",
    "rar_parse",
    "rar_is_reduction",
    "sdjwt_issue",
    "sdjwt_present",
    "sdjwt_verify",
    "sdjwt_split",
    "sdjwt_describe",
    "sdjwt_disclosure_digest",
    "status_name",
    "status_list_verify",
    "ssrf_check",
    "is_public_ip",
    "unix_now",
    "basic_header",
]

from . import _call, _j, _json, _s, _text, load, _replay_struct, ReplayCache, CoreError

def _ALG_LIST(algs: Sequence[str]) -> bytes:
    return _j(list(algs))


# ---- keys -----------------------------------------------------------------------------------------------------------

def generate_ec_key(curve: str = "P-256") -> Dict[str, Any]:
    """A new EC key pair as a private JWK (keep it secret)."""
    return _json("authlas_jwk_generate_ec", _s(curve))


def public_jwk(key: Dict[str, Any]) -> Dict[str, Any]:
    """The public half of a JWK."""
    return _json("authlas_jwk_public", _j(key))


def jwk_thumbprint(key: Dict[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint."""
    return _text("authlas_jwk_thumbprint", _j(key))


# ---- JOSE -----------------------------------------------------------------------------------------------------------

def jws_sign(alg: str, key: Dict[str, Any], payload: bytes, header: Optional[Dict[str, Any]] = None) -> str:
    h = _j(header) if header is not None else None
    return _text("authlas_jws_sign", _s(alg), _j(key), h, payload, len(payload))


def jws_verify(token: str, key: Dict[str, Any], *, algs: Sequence[str], typ: Optional[str] = None, crit: Sequence[str] = ()) -> Dict[str, Any]:
    opts: Dict[str, Any] = {"algs": list(algs), "crit": list(crit)}
    if typ is not None:
        opts["typ"] = typ
    return _json("authlas_jws_verify", _s(token), _j(key), _j(opts))


def jws_peek_header(token: str) -> Dict[str, Any]:
    """The protected header, read without verifying. Never trust it for key choice on its own."""
    return _json("authlas_jws_peek_header", _s(token))


def jwe_peek_header(token: str) -> Dict[str, Any]:
    return _json("authlas_jwe_peek_header", _s(token))


def jwe_encrypt(alg: str, enc: str, key: Dict[str, Any], plaintext: bytes, header: Optional[Dict[str, Any]] = None) -> str:
    h = _j(header) if header is not None else None
    return _text("authlas_jwe_encrypt", _s(alg), _s(enc), _j(key), h, plaintext, len(plaintext))


def jwe_decrypt(token: str, key: Dict[str, Any], *, algs: Sequence[str], encs: Sequence[str]) -> bytes:
    return _call("authlas_jwe_decrypt", _s(token), _j(key), _j({"algs": list(algs), "encs": list(encs)}))


def jwt_sign(alg: str, key: Dict[str, Any], claims: Dict[str, Any], typ: Optional[str] = None) -> str:
    return _text("authlas_jwt_sign", _s(alg), _j(key), _j(claims), _s(typ))


def jwt_verify(token: str, key: Dict[str, Any], *, algs: Sequence[str], issuer: str, audience: str, typ: Optional[str] = None,
               leeway: int = 30, now: Optional[int] = None, replay: Optional["Replay"] = None) -> Dict[str, Any]:
    opts: Dict[str, Any] = {"algs": list(algs), "issuer": issuer, "audience": audience, "leeway": leeway}
    if typ is not None:
        opts["typ"] = typ
    if now is not None:
        opts["now"] = now
    return _json("authlas_jwt_verify", _s(token), _j(key), _j(opts), replay.handle if replay else None)


def dpop_verify(proof: str, *, algs: Sequence[str], method: str, url: str, access_token: Optional[str] = None,
                nonce: Optional[str] = None, leeway: int = 5, replay: Optional["Replay"] = None,
                now: Optional[int] = None) -> Dict[str, Any]:
    """Verifies a DPoP proof (RFC 9449 4.3). ``algs``, ``method`` and ``url`` are required; the library refuses without them.

    Pass ``replay`` so a proof can be used only once. Returns {"jkt", "jwk", "claims"}.
    """
    opts: Dict[str, Any] = {"algs": list(algs), "method": method, "url": url, "leeway": leeway}
    if access_token is not None:
        opts["access_token"] = access_token
    if nonce is not None:
        opts["nonce"] = nonce
    if now is not None:
        opts["now"] = now
    return _json("authlas_dpop_verify", _s(proof), _j(opts), replay.handle if replay else None)


def jwt_peek_claims(token: str) -> Dict[str, Any]:
    """The claims, read without verifying. For routing only."""
    return _json("authlas_jwt_peek_claims", _s(token))


def jwt_encrypt_nested(inner_jws: str, options: Dict[str, Any]) -> str:
    return _text("authlas_jwt_encrypt_nested", _s(inner_jws), _j(options))


class Replay:
    """Process-local replay cache for JWT ``jti`` values. Use a shared store (``ReplayCache``) across instances."""

    def __init__(self) -> None:
        self.handle = load().authlas_replay_new()

    def close(self) -> None:
        if self.handle:
            load().authlas_replay_free(self.handle)
            self.handle = None

    def __enter__(self) -> "Replay":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


# ---- PKCE, redirect, bearer, scope ----------------------------------------------------------------------------------

def pkce_new() -> Dict[str, str]:
    return _json("authlas_pkce_new")


def pkce_generate() -> Dict[str, str]:
    return _json("authlas_pkce_generate")


def pkce_s256_challenge(verifier: str) -> str:
    return _text("authlas_pkce_s256_challenge", _s(verifier))


def pkce_valid_verifier(verifier: str) -> bool:
    return bool(load().authlas_pkce_valid_verifier(_s(verifier)))


def pkce_verify(challenge: str, verifier: str) -> None:
    _call("authlas_pkce_verify", _s(challenge), _s(verifier))


def redirect_validate(uri: str, kind: str = "web") -> None:
    _call("authlas_redirect_validate", _s(uri), _s(kind))


def redirect_matches(registered: str, presented: str) -> bool:
    m = ctypes.c_int(0)
    rc = load().authlas_redirect_matches(_s(registered), _s(presented), ctypes.byref(m))
    if rc != 0:
        raise CoreError("invalid_argument", "redirect check failed")
    return bool(m.value)


def bearer_parse(header: str) -> Dict[str, str]:
    return _json("authlas_bearer_parse", _s(header))


def bearer_challenge(**options: Any) -> str:
    return _text("authlas_bearer_challenge", _j(options))


def scope_parse(scope: str) -> List[str]:
    return _json("authlas_scope_parse", _s(scope))


def scope_check(requested: str, allowed: str) -> Dict[str, Any]:
    return _json("authlas_scope_check", _s(requested), _s(allowed))


# ---- DPoP -----------------------------------------------------------------------------------------------------------

def dpop_proof(alg: str, key: Dict[str, Any], method: str, url: str, access_token: Optional[str] = None,
               nonce: Optional[str] = None) -> str:
    """Builds a DPoP proof JWT (RFC 9449 4.2). The key must be private."""
    return _text("authlas_dpop_build", _j(key), _s(method), _s(url), _s(access_token), _s(nonce), _s(alg))


def dpop_ath(access_token: str) -> str:
    return _text("authlas_dpop_ath", _s(access_token))


def dpop_normalize_htu(url: str) -> str:
    return _text("authlas_dpop_normalize_htu", _s(url))


def dpop_nonce_issue(secret: bytes, lifetime: int, now: Optional[int] = None) -> str:
    if len(secret) < 16:
        raise CoreError("invalid_argument", "nonce secret must be at least 16 bytes")
    buf = (ctypes.c_uint8 * len(secret)).from_buffer_copy(secret)
    return _text("authlas_dpop_nonce_issue", buf, len(secret), lifetime, now or 0)


def dpop_nonce_check(secret: bytes, lifetime: int, nonce: str, now: Optional[int] = None) -> None:
    if len(secret) < 16:
        raise CoreError("invalid_argument", "nonce secret must be at least 16 bytes")
    buf = (ctypes.c_uint8 * len(secret)).from_buffer_copy(secret)
    _call("authlas_dpop_nonce_check", buf, len(secret), lifetime, _s(nonce), now or 0)


# ---- client authentication (RFC 6749 2.3, RFC 7523) ----------------------------------------------------------------

def client_authenticate(presented: Dict[str, Any], registered: Dict[str, Any], token_endpoint: str, *,
                        issuer: Optional[str] = None, replay: Optional[ReplayCache] = None, now: Optional[int] = None) -> str:
    """Checks what the client presented against its registration. Returns the authenticated client_id.

    ``presented``: {"method", "client_id", "secret"} or {"method": "private_key_jwt", "assertion"}.
    ``registered``: {"client_id", "method", "secret", "secret_is_hash", "jwk", "assertion_algs"}.
    Pass ``replay`` (a ReplayCache subclass) for private_key_jwt so an assertion can be used once.
    """
    # Without a replay store the library skips the jti check, so an assertion could be reused. Refuse here instead.
    if presented.get("method") in ("private_key_jwt", "client_secret_jwt") and replay is None:
        raise CoreError("invalid_argument", "assertion authentication needs a replay store")
    return _text("authlas_client_authenticate", _j(presented), _j(registered), _s(token_endpoint), _s(issuer),
                 _replay_struct(replay), now or 0)


# ---- token introspection and exchange (RFC 7662, RFC 9701, RFC 8693) ------------------------------------------------

def introspection_parse_request(form_body: str) -> Dict[str, Any]:
    return _json("authlas_introspection_parse_request", _s(form_body))


def introspection_parse_response(body: str) -> Dict[str, Any]:
    return _json("authlas_introspection_parse_response", _s(body))


def introspection_check(body: str, resource: str, *, now: Optional[int] = None, leeway: int = 0) -> None:
    """Raises CoreError unless the response is active, in its validity window and issued for ``resource``."""
    _call("authlas_introspection_check", _s(body), _s(resource), now or 0, leeway)


def introspection_sign_jwt(alg: str, key: Dict[str, Any], issuer: str, audience: str, response: Dict[str, Any]) -> str:
    return _text("authlas_introspection_sign_jwt", _s(alg), _j(key), _s(issuer), _s(audience), _j(response))


def introspection_verify_jwt(token: str, key: Dict[str, Any], *, algs: Sequence[str], expected_issuer: str, me: str,
                             now: Optional[int] = None) -> Dict[str, Any]:
    return _json("authlas_introspection_verify_jwt", _s(token), _j(key), _ALG_LIST(algs), _s(expected_issuer), _s(me), now or 0)


def exchange_decide(rules: Sequence[Dict[str, Any]], client_id: str, subject_claims: Dict[str, Any], subject_scope: str,
                    request: Dict[str, Any], actor_claims: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Decides a token exchange (RFC 8693). The caller has already verified the subject and actor tokens."""
    return _json("authlas_exchange_decide", _j(list(rules)), _s(client_id), _j(subject_claims), _s(subject_scope),
                 _j(actor_claims) if actor_claims is not None else None, _j(request))


def exchange_response(access_token: str, issued_token_type: str, *, expires_in: int = 0, scope: Optional[str] = None) -> Dict[str, Any]:
    return _json("authlas_exchange_response", _s(access_token), _s(issued_token_type), expires_in, _s(scope))


# ---- mutual TLS (RFC 8705) -----------------------------------------------------------------------------------------

def _der(der: bytes):
    return (ctypes.c_uint8 * len(der)).from_buffer_copy(der)


def mtls_authenticate(der: bytes, *, chain_verified: bool, form_body: str, registration: Dict[str, Any],
                      authorization: Optional[str] = None, now: Optional[int] = None) -> str:
    """Authenticates a client by its certificate. ``chain_verified`` must be True only when the TLS layer checked the chain."""
    return _text("authlas_mtls_authenticate", _der(der), len(der), 1 if chain_verified else 0, _s(authorization),
                 _s(form_body), _j(registration), now or 0)


def mtls_cnf(der: bytes) -> Dict[str, Any]:
    return _json("authlas_mtls_cnf", _der(der), len(der))


def mtls_check_binding(der: bytes, token_claims: Dict[str, Any]) -> None:
    """Raises CoreError unless the token's cnf.x5t#S256 matches this certificate."""
    _call("authlas_mtls_check_binding", _der(der), len(der), _j(token_claims))


def mtls_same_certificate(der: bytes, bound_x5t_s256: str) -> None:
    _call("authlas_mtls_same_certificate", _der(der), len(der), _s(bound_x5t_s256))


def cert_info(der: bytes) -> Dict[str, Any]:
    """Reads a DER certificate. Does not validate a chain."""
    return _json("authlas_cert_info", _der(der), len(der))


# ---- request objects (RFC 9101) ------------------------------------------------------------------------------------

def request_object_build(alg: str, key: Dict[str, Any], client_id: str, issuer: str, params: Dict[str, Any], *,
                         lifetime: int = 300) -> str:
    return _text("authlas_request_object_build", _s(alg), _j(key), _s(client_id), _s(issuer), _j(params), lifetime)


def request_object_verify(obj: str, key: Dict[str, Any], *, algs: Sequence[str], client_id: str, issuer: str,
                          max_lifetime: int = 600, require_typ: bool = False, now: Optional[int] = None) -> str:
    """Returns the signed parameters as a query string. Anything outside the signed object is ignored."""
    return _text("authlas_request_object_verify", _s(obj), _j(key), _ALG_LIST(algs), _s(client_id), _s(issuer),
                 max_lifetime, 1 if require_typ else 0, now or 0)


def request_uri_fingerprint(request_uri: str) -> str:
    return _text("authlas_request_uri_fingerprint", _s(request_uri))


# ---- metadata and discovery ----------------------------------------------------------------------------------------

def as_metadata_parse(body: str, expected_issuer: str) -> Dict[str, Any]:
    return _json("authlas_as_metadata_parse", _s(body), _s(expected_issuer))


def as_metadata_normalize(body: str, expected_issuer: str) -> Dict[str, Any]:
    return _json("authlas_as_metadata_normalize", _s(body), _s(expected_issuer))


def as_metadata_defaults(issuer: str, base: Optional[str] = None) -> Dict[str, Any]:
    return _json("authlas_as_metadata_defaults", _s(issuer), _s(base))


def resource_metadata_parse(body: str, expected_resource: str) -> Dict[str, Any]:
    return _json("authlas_resource_metadata_parse", _s(body), _s(expected_resource))


def as_metadata_url(issuer: str) -> str:
    return _text("authlas_as_metadata_url", _s(issuer))


def oidc_metadata_url(issuer: str) -> str:
    return _text("authlas_oidc_metadata_url", _s(issuer))


def resource_metadata_url(resource: str) -> str:
    return _text("authlas_resource_metadata_url", _s(resource))


def canonical_resource(value: str) -> str:
    return _text("authlas_canonical_resource", _s(value))


def mcp_resource_metadata_urls(mcp_url: str) -> List[str]:
    return _json("authlas_mcp_resource_metadata_urls", _s(mcp_url))


def mcp_as_discovery_urls(issuer: str) -> List[str]:
    return _json("authlas_mcp_as_discovery_urls", _s(issuer))


def www_authenticate_parse(header: str) -> List[Dict[str, Any]]:
    return _json("authlas_www_authenticate_parse", _s(header))


# ---- RAR (RFC 9396) ------------------------------------------------------------------------------------------------

def rar_parse(details: Any, allowed_types: Sequence[str]) -> Any:
    return _json("authlas_rar_parse", _j(details), _j(list(allowed_types)))


def rar_is_reduction(requested: Any, granted: Any, allowed_types: Sequence[str]) -> bool:
    return bool(load().authlas_rar_is_reduction(_j(requested), _j(granted), _j(list(allowed_types))))


# ---- SD-JWT (RFC 9901) ---------------------------------------------------------------------------------------------

def sdjwt_issue(claims: Dict[str, Any], key: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
    return _json("authlas_sdjwt_issue", _j(claims), _j(key), _j(options))


def sdjwt_present(sd_jwt: str, options: Dict[str, Any]) -> str:
    return _text("authlas_sdjwt_present", _s(sd_jwt), _j(options))


def sdjwt_verify(sd_jwt: str, issuer_key: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
    return _json("authlas_sdjwt_verify", _s(sd_jwt), _j(issuer_key), _j(options))


def sdjwt_split(sd_jwt: str) -> Dict[str, Any]:
    return _json("authlas_sdjwt_split", _s(sd_jwt))


def sdjwt_describe(disclosure: str) -> Dict[str, Any]:
    return _json("authlas_sdjwt_describe", _s(disclosure))


def sdjwt_disclosure_digest(disclosure: str, hash: str = "sha-256") -> str:
    return _text("authlas_sdjwt_disclosure_digest", _s(disclosure), _s(hash))


# ---- token status lists ----------------------------------------------------------------------------------------------

def status_name(value: int) -> str:
    return _text("authlas_status_name", value)


def status_list_verify(token: str, key: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
    return _json("authlas_status_list_verify", _s(token), _j(key), _j(options))


# ---- network safety --------------------------------------------------------------------------------------------------

def ssrf_check(url: str) -> str:
    """Refuses anything that is not a public https URL. Returns the parsed URL."""
    return _text("authlas_ssrf_check", _s(url))


def is_public_ip(ip: str) -> bool:
    flag = ctypes.c_int(0)
    rc = load().authlas_is_public_ip(_s(ip), ctypes.byref(flag))
    if rc != 0:
        raise CoreError("invalid_argument", "not an IP address")
    return bool(flag.value)


def unix_now() -> int:
    """Current time in seconds, from the same clock the library uses for expiry checks."""
    return int(load().authlas_unix_now())


# ---- misc ------------------------------------------------------------------------------------------------------------

def basic_header(client_id: str, secret: str) -> str:
    return _text("authlas_basic_header", _s(client_id), _s(secret))
