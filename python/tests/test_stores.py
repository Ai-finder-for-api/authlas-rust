"""Stateful flows through host callbacks, against the real authlas.dll. Each store is an in-memory Python class."""
import threading

import pytest

import authlas_core as a
from authlas_core import CoreError


class MemPush(a.PushStore):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.items = {}

    def save(self, record):
        with self.lock:
            self.items[record["request_uri"]] = record

    def take(self, request_uri):
        with self.lock:
            return self.items.pop(request_uri, None)  # removed in the same step: single use


def test_par_push_then_redeem_once():
    store = MemPush()
    body = "client_id=app&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=xyz"
    pushed = a.par_push(store, "app", body, now=1000)
    assert pushed["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
    q = a.par_redeem(store, "app", pushed["request_uri"], now=1001)
    assert "state=xyz" in q
    with pytest.raises(CoreError):
        a.par_redeem(store, "app", pushed["request_uri"], now=1001)  # second use refused


def test_par_redeem_by_other_client_refused():
    store = MemPush()
    body = "client_id=app&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcb"
    pushed = a.par_push(store, "app", body, now=1000)
    with pytest.raises(CoreError):
        a.par_redeem(store, "evil", pushed["request_uri"], now=1001)


def test_par_store_failure_fails_closed():
    class Broken(MemPush):
        def save(self, record):
            raise RuntimeError("disk full")

    with pytest.raises(CoreError):
        a.par_push(Broken(), "app", "client_id=app&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcb", now=1000)


class MemReplay(a.ReplayCache):
    def __init__(self):
        self.seen = set()

    def first_use(self, key, exp, now):
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


def _assertion_setup():
    key = a.generate_ec_key("P-256")
    now = a.unix_now()
    client_id = "app"
    assertion = a.jwt_sign("ES256", key, {"iss": client_id, "sub": client_id, "aud": "https://as.example/token",
                                          "exp": now + 120, "iat": now, "jti": "assert-1"})
    registered = {"client_id": client_id, "method": "private_key_jwt", "assertion_algs": ["ES256"],
                  "jwk": a.public_jwk(key)}
    presented = {"method": "private_key_jwt", "assertion": assertion}
    return presented, registered, now


def test_client_auth_assertion_reuse_refused():
    presented, registered, now = _assertion_setup()
    replay = MemReplay()
    cid = a.client_authenticate(presented, registered, "https://as.example/token", issuer="https://as.example",
                                replay=replay, now=now)
    assert cid == "app"
    # Same assertion, same key, same time. Only the replay store differs, so a refusal here is the replay check.
    with pytest.raises(CoreError):
        a.client_authenticate(presented, registered, "https://as.example/token", issuer="https://as.example",
                              replay=replay, now=now)
    fresh = a.client_authenticate(presented, registered, "https://as.example/token", issuer="https://as.example",
                                  replay=MemReplay(), now=now)
    assert fresh == "app"


def test_client_auth_assertion_without_replay_store_refused():
    presented, registered, now = _assertion_setup()
    with pytest.raises(CoreError):
        a.client_authenticate(presented, registered, "https://as.example/token", issuer="https://as.example", now=now)


def test_replay_store_exception_fails_closed():
    presented, registered, now = _assertion_setup()

    class Broken(MemReplay):
        def first_use(self, key, exp, now):
            raise RuntimeError("store down")

    with pytest.raises(CoreError):
        a.client_authenticate(presented, registered, "https://as.example/token", issuer="https://as.example",
                              replay=Broken(), now=now)
