"""Revocation (RFC 7009) and client registration (RFC 7591/7592) through Python stores, against the real authlas.dll."""
import threading

import pytest

import authlas_core as a
from authlas_core import CoreError


class MemRevoke(a.RevocationStore):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.tokens = {}          # token -> {"kind", "client_id", "grant_id", "jti"}
        self.revoked_grants = set()
        self.revoked_jtis = set()

    def lookup(self, token, hint):
        with self.lock:
            t = self.tokens.get(token)
            if not t or t["grant_id"] in self.revoked_grants or t.get("jti") in self.revoked_jtis:
                return None
            return dict(t)

    def revoke_grant(self, grant_id):
        with self.lock:
            self.revoked_grants.add(grant_id)

    def revoke_access_jti(self, jti):
        with self.lock:
            self.revoked_jtis.add(jti)


def _revoke_store():
    s = MemRevoke()
    s.tokens["rt-alice"] = {"kind": "refresh", "client_id": "app", "grant_id": "g-alice"}
    s.tokens["at-alice"] = {"kind": "access", "client_id": "app", "grant_id": "g-alice", "jti": "j-alice"}
    s.tokens["at-bob"] = {"kind": "access", "client_id": "other", "grant_id": "g-bob", "jti": "j-bob"}
    return s


def test_revoke_own_refresh_token_revokes_grant():
    s = _revoke_store()
    assert a.revoke(s, "app", "token=rt-alice") == "revoked"
    assert "g-alice" in s.revoked_grants


def test_revoke_own_access_token_by_jti():
    s = _revoke_store()
    assert a.revoke(s, "app", "token=at-alice&token_type_hint=access_token") == "revoked"
    assert "j-alice" in s.revoked_jtis


def test_revoke_another_clients_token_refused():
    s = _revoke_store()
    assert a.revoke(s, "app", "token=at-bob") == "not_yours"
    assert "g-bob" not in s.revoked_grants and "j-bob" not in s.revoked_jtis


def test_revoke_unknown_token_reports_nothing():
    assert a.revoke(_revoke_store(), "app", "token=missing") == "nothing"


class MemClients(a.ClientStore):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.clients = {}

    def get(self, cid):
        with self.lock:
            c = self.clients.get(cid)
            return dict(c) if c else None

    def insert(self, rec):
        with self.lock:
            if rec["client_id"] in self.clients:
                return False
            self.clients[rec["client_id"]] = rec
            return True

    def replace(self, rec):
        with self.lock:
            if rec["client_id"] not in self.clients:
                return False
            self.clients[rec["client_id"]] = rec
            return True

    def remove(self, cid):
        with self.lock:
            return self.clients.pop(cid, None) is not None


_BODY = {"redirect_uris": ["https://app.example/cb"], "token_endpoint_auth_method": "none",
         "grant_types": ["authorization_code"], "response_types": ["code"]}


def test_open_registration_refused_without_initial_access_token():
    # Secure default: refuse open registration unless an initial access token is supplied.
    with pytest.raises(CoreError):
        a.client_register(MemClients(), "https://as.example/register", _BODY, now=1000)


def test_register_read_delete_with_registration_token():
    store = MemClients()
    policy = {"open": True}
    reg = a.client_register(store, "https://as.example/register", _BODY, policy=policy, now=1000)
    cid, token = reg["client_id"], reg["registration_access_token"]
    assert a.client_read(store, "https://as.example/register", cid, token, policy=policy)["client_id"] == cid
    with pytest.raises(CoreError):
        a.client_read(store, "https://as.example/register", cid, "not-the-token", policy=policy)
    a.client_delete(store, cid, token)
    with pytest.raises(CoreError):
        a.client_read(store, "https://as.example/register", cid, token, policy=policy)


def test_client_store_failure_fails_closed():
    class Broken(MemClients):
        def insert(self, rec):
            raise RuntimeError("db down")

    with pytest.raises(CoreError):
        a.client_register(Broken(), "https://as.example/register", _BODY, policy={"open": True}, now=1000)
