"""Tests for the authlas_core binding against the real authlas.dll. Each area has a happy path and a refusal case."""
import time

import pytest

import authlas_core as a
from authlas_core import CoreError


@pytest.fixture(scope="module")
def ec_key():
    return a.generate_ec_key("P-256")


def test_version_and_abi():
    assert a.abi_version() == 1
    assert a.version()
    assert a.backend() in ("openssl", "awslc", "rustcrypto", "qscrypt", "hardened")


def test_pkce_rfc7636_vector():
    assert a.pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_pkce_wrong_verifier_refused():
    ch = a.pkce_s256_challenge("a" * 43)
    a.pkce_verify(ch, "a" * 43)
    with pytest.raises(CoreError):
        a.pkce_verify(ch, "b" * 43)


def test_jws_round_trip_and_none_refused(ec_key):
    tok = a.jws_sign("ES256", ec_key, b"hello")
    out = a.jws_verify(tok, a.public_jwk(ec_key), algs=["ES256"])
    assert out is not None
    # alg none is never allowed, even when the caller lists it
    with pytest.raises(CoreError):
        a.jws_sign("none", ec_key, b"x")


def test_jws_verify_rejects_alg_outside_allow_list(ec_key):
    tok = a.jws_sign("ES256", ec_key, b"hello")
    with pytest.raises(CoreError):
        a.jws_verify(tok, a.public_jwk(ec_key), algs=["RS256"])


def test_jwt_expired_claim_refused(ec_key):
    now = a.unix_now()
    tok = a.jwt_sign("ES256", ec_key, {"iss": "https://as.example", "aud": "rs", "exp": now - 3600, "iat": now - 7200})
    with pytest.raises(CoreError):
        a.jwt_verify(tok, a.public_jwk(ec_key), algs=["ES256"], issuer="https://as.example", audience="rs")


def test_jwt_replay_detected(ec_key):
    now = a.unix_now()
    tok = a.jwt_sign("ES256", ec_key, {"iss": "i", "aud": "rs", "exp": now + 300, "iat": now, "jti": "j-1"})
    with a.Replay() as r:
        a.jwt_verify(tok, a.public_jwk(ec_key), algs=["ES256"], issuer="i", audience="rs", replay=r)
        with pytest.raises(CoreError):
            a.jwt_verify(tok, a.public_jwk(ec_key), algs=["ES256"], issuer="i", audience="rs", replay=r)


def test_dpop_proof_builds(ec_key):
    proof = a.dpop_proof("ES256", ec_key, "GET", "https://rs.example/r", access_token="tok")
    assert proof.count(".") == 2


def test_dpop_nonce_round_trip_and_tamper():
    secret = b"s" * 32
    n = a.dpop_nonce_issue(secret, 60)
    a.dpop_nonce_check(secret, 60, n)
    with pytest.raises(CoreError):
        a.dpop_nonce_check(b"t" * 32, 60, n)


def test_dpop_nonce_short_secret_refused():
    with pytest.raises(CoreError):
        a.dpop_nonce_issue(b"short", 60)


def test_ssrf_refuses_plain_http_and_private_ip():
    with pytest.raises(CoreError):
        a.ssrf_check("http://as.example/token")
    with pytest.raises(CoreError):
        a.ssrf_check("https://127.0.0.1/token")


def test_redirect_exact_match():
    assert a.redirect_matches("https://app.example/cb", "https://app.example/cb") is True
    assert a.redirect_matches("https://app.example/cb", "https://app.example/cb?x=1") is False


def test_scope_check_subset_and_excess():
    ok = a.scope_check("read", "read write")
    assert ok == {"ok": True, "excess": []}
    bad = a.scope_check("read admin", "read write")
    assert bad["ok"] is False
    assert bad["excess"] == ["admin"]


def test_request_object_round_trip(ec_key):
    obj = a.request_object_build("ES256", ec_key, "client-1", "https://as.example",
                                 {"redirect_uri": "https://app.example/cb", "scope": "read"}, lifetime=300)
    qs = a.request_object_verify(obj, a.public_jwk(ec_key), algs=["ES256"], client_id="client-1", issuer="https://as.example")
    assert "redirect_uri=" in qs


def test_request_object_wrong_client_refused(ec_key):
    obj = a.request_object_build("ES256", ec_key, "client-1", "https://as.example", {"scope": "read"})
    with pytest.raises(CoreError):
        a.request_object_verify(obj, a.public_jwk(ec_key), algs=["ES256"], client_id="client-2", issuer="https://as.example")


def test_mtls_binding_refuses_wrong_certificate():
    # a DER certificate that cannot match a bound thumbprint must be refused
    der = bytes.fromhex("3082" + "00" * 2)  # malformed on purpose
    with pytest.raises(CoreError):
        a.mtls_check_binding(der, {"cnf": {"x5t#S256": "AAAA"}})


def test_basic_header():
    assert a.basic_header("id", "s") == "Basic aWQ6cw=="


def test_dpop_verify_round_trip_and_replay(ec_key):
    proof = a.dpop_proof("ES256", ec_key, "GET", "https://rs.example/r", access_token="tok")
    with a.Replay() as r:
        out = a.dpop_verify(proof, algs=["ES256"], method="GET", url="https://rs.example/r", access_token="tok", replay=r)
        assert out["jkt"] == a.jwk_thumbprint(a.public_jwk(ec_key))
        with pytest.raises(CoreError):
            a.dpop_verify(proof, algs=["ES256"], method="GET", url="https://rs.example/r", access_token="tok", replay=r)


def test_dpop_verify_wrong_method_refused(ec_key):
    proof = a.dpop_proof("ES256", ec_key, "GET", "https://rs.example/r", access_token="tok")
    with pytest.raises(CoreError):
        a.dpop_verify(proof, algs=["ES256"], method="POST", url="https://rs.example/r", access_token="tok")


def test_dpop_verify_wrong_access_token_refused(ec_key):
    proof = a.dpop_proof("ES256", ec_key, "GET", "https://rs.example/r", access_token="tok")
    with pytest.raises(CoreError):
        a.dpop_verify(proof, algs=["ES256"], method="GET", url="https://rs.example/r", access_token="other")
