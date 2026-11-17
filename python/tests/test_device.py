"""Device grant (RFC 8628) through a Python store, against the real authlas.dll."""
import threading

import pytest

import authlas_core as a
from authlas_core import CoreError


class MemDevice(a.DeviceStore):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.records = {}   # device_hash -> record
        self.attempts = {}  # attempt_key -> count

    def insert(self, record):
        with self.lock:
            self.records[record["device_hash"]] = record
            return True

    def find_by_user_code(self, user_code):
        with self.lock:
            for r in self.records.values():
                if r["user_code"] == user_code:
                    return dict(r)
            return None

    def find_by_device_hash(self, device_hash):
        with self.lock:
            r = self.records.get(device_hash)
            return dict(r) if r else None

    def save(self, record):
        with self.lock:
            if record["device_hash"] not in self.records:
                return False
            self.records[record["device_hash"]] = record
            return True

    def find_attempts(self, attempt_key):
        with self.lock:
            return self.attempts.get(attempt_key, 0)

    def save_attempts(self, attempt_key, count):
        with self.lock:
            self.attempts[attempt_key] = count
            return True


def _start(store):
    return a.device_start(store, "tv-app", "https://as.example/device", scope="read", now=1000)


def test_full_grant_approve_then_poll_once():
    store = MemDevice()
    s = _start(store)
    assert s["user_code"] and s["device_code"]
    found = a.device_lookup(store, "session-1", s["user_code"], now=1001)
    assert found["client_id"] == "tv-app"
    assert a.device_decide(store, "session-1", s["user_code"], subject="alice", now=1002) == "approved"
    grant = a.device_poll(store, "tv-app", s["device_code"], now=1003)
    assert grant["subject"] == "alice"
    with pytest.raises(CoreError):
        a.device_poll(store, "tv-app", s["device_code"], now=1004)  # the grant is consumed


def test_poll_before_approval_is_pending():
    store = MemDevice()
    s = _start(store)
    with pytest.raises(CoreError) as e:
        a.device_poll(store, "tv-app", s["device_code"], now=1001)
    assert str(e.value) == "authorization_pending"  # the RFC 8628 3.5 code, not a generic failure


def test_poll_by_other_client_refused():
    store = MemDevice()
    s = _start(store)
    a.device_decide(store, "session-1", s["user_code"], subject="alice", now=1001)
    with pytest.raises(CoreError):
        a.device_poll(store, "other-app", s["device_code"], now=1002)


def test_wrong_codes_lock_out_the_attempt_key():
    store = MemDevice()
    good = _start(store)["user_code"]
    for _ in range(5):
        with pytest.raises(CoreError):
            a.device_lookup(store, "attacker-ip", "ZZZZ-ZZZZ", max_attempts=5, now=1001)
    # after the limit, a correct code from the same key is refused too
    with pytest.raises(CoreError) as e:
        a.device_lookup(store, "attacker-ip", good, max_attempts=5, now=1002)
    assert str(e.value) == "too many attempts"
    # another key is not affected
    assert a.device_lookup(store, "other-ip", good, max_attempts=5, now=1002)["client_id"] == "tv-app"


def test_wrong_guess_counts_even_when_no_record_matches():
    # Regression: a guess that matched no record was never counted (fixed in slice 6).
    store = MemDevice()
    with pytest.raises(CoreError):
        a.device_lookup(store, "key-x", "NOPE-NOPE", max_attempts=3, now=1001)
    assert store.attempts.get("key-x", 0) >= 1


def test_store_failure_fails_closed():
    class Broken(MemDevice):
        def insert(self, record):
            raise RuntimeError("db down")

    with pytest.raises(CoreError):
        _start(Broken())
