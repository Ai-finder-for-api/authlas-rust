"""Host storage for the stateful flows. Each class is a store the Rust library calls back into.

Implement the methods against your own database or map. Each method runs under the lock the store owns: the library
does not lock for you. Serialise every operation on one device code, or one client_id, as docs/CALLBACKS.md requires.

A method may raise. The exception becomes a failed status, and the library fails closed.
"""
from __future__ import annotations

import ctypes
import json
from typing import Any, Dict, List, Optional, Sequence

from . import _call, _j, _json, _s, _text, load, CoreError

_c_char = ctypes.c_char_p
_u64 = ctypes.c_uint64
_u32 = ctypes.c_uint32
_vp = ctypes.c_void_p


class _Buf(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("len", ctypes.c_size_t)]


_BUFP = ctypes.POINTER(_Buf)


def _write_out(out: Any, data: Optional[bytes]) -> int:
    """Copies ``data`` into the library's output buffer. ``None`` or b"" means "not found" (empty buffer)."""
    payload = data or b""
    return int(load().authlas_buf_write(out, payload, len(payload)))


def _guarded(fn):
    """Runs a store method. An exception becomes status 1 (failed) and never unwinds into C."""
    def wrapper(*args):
        try:
            return fn(*args)
        except Exception:
            return 1
    return wrapper


class _Store:
    """Keeps the ctypes callbacks alive and builds the C struct the library expects, once per store.

    Subclasses implement ``_build()``. ``to_c()`` returns the same struct on every call, so the callbacks are created
    once and never re-registered.
    """

    def __init__(self) -> None:
        self._refs: List[Any] = []
        self._c_struct: Any = None

    def to_c(self) -> Any:
        if self._c_struct is None:
            self._c_struct = self._build()
        return self._c_struct

    def _build(self) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def _struct(self, layout: Sequence[tuple], values: Dict[str, Any]):
        class S(ctypes.Structure):
            _fields_ = layout
        s = S()
        for name, value in values.items():
            setattr(s, name, value)
        self._refs.append(s)
        return s


# ---------------------------------------------------------------------------------------------------------------------
# PAR (RFC 9126): AuthlasPushStore { user, save(user, json), take(user, request_uri, out) }
# ---------------------------------------------------------------------------------------------------------------------

class PushStore(_Store):
    """Stores pushed authorization requests. ``save`` gets a record dict; ``take`` must remove and return it atomically."""

    def save(self, record: Dict[str, Any]) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def take(self, request_uri: str) -> Optional[Dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError

    def _build(self) -> Any:
        SAVE = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char)
        TAKE = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char, _BUFP)

        @_guarded
        def save(_user, record_json):
            self.save(json.loads(record_json.decode("utf-8")))
            return 0

        @_guarded
        def take(_user, request_uri, out):
            rec = self.take(request_uri.decode("utf-8"))
            return _write_out(out, _j(rec) if rec is not None else None)

        cs, ct = SAVE(save), TAKE(take)
        self._refs += [cs, ct]
        return self._struct([("user", _vp), ("save", _vp), ("take", _vp)],
                            {"user": None, "save": ctypes.cast(cs, _vp).value, "take": ctypes.cast(ct, _vp).value})


def par_push(store: PushStore, client_id: str, form_body: str, *, now: Optional[int] = None) -> Dict[str, Any]:
    """Stores a pushed authorization request. Returns {"request_uri", "expires_in"}."""
    return _json("authlas_par_push", store.to_c(), _s(client_id), _s(form_body), now or 0)


def par_redeem(store: PushStore, client_id: str, request_uri: str, *, now: Optional[int] = None) -> str:
    """Redeems a request_uri once. Returns the stored query string."""
    return _text("authlas_par_redeem", store.to_c(), _s(client_id), _s(request_uri), now or 0)


# ---------------------------------------------------------------------------------------------------------------------
# Revocation (RFC 7009): AuthlasRevocationStore { user, lookup, revoke_grant, revoke_access_jti }
# ---------------------------------------------------------------------------------------------------------------------

class RevocationStore(_Store):
    """Finds a token and revokes grants or single access tokens.

    ``lookup(token, hint)`` returns None or {"kind": "refresh"|"access", "client_id", "grant_id", "jti"}.
    """

    def lookup(self, token: str, hint: Optional[str]) -> Optional[Dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError

    def revoke_grant(self, grant_id: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def revoke_access_jti(self, jti: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def _build(self) -> Any:
        LOOK = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char, _c_char, _BUFP)
        GRANT = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char)
        JTI = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char)

        @_guarded
        def lookup(_user, token, hint, out):
            found = self.lookup(token.decode("utf-8"), hint.decode("utf-8") if hint else None)
            return _write_out(out, _j(found) if found is not None else None)

        @_guarded
        def grant(_user, grant_id):
            self.revoke_grant(grant_id.decode("utf-8"))
            return 0

        @_guarded
        def jti(_user, value):
            self.revoke_access_jti(value.decode("utf-8"))
            return 0

        fns = (LOOK(lookup), GRANT(grant), JTI(jti))
        self._refs += list(fns)
        return self._struct([("user", _vp), ("lookup", _vp), ("revoke_grant", _vp), ("revoke_access_jti", _vp)],
                            {"user": None, "lookup": ctypes.cast(fns[0], _vp).value,
                             "revoke_grant": ctypes.cast(fns[1], _vp).value, "revoke_access_jti": ctypes.cast(fns[2], _vp).value})


def revoke(store: RevocationStore, authenticated_client: str, form_body: str) -> str:
    """Runs RFC 7009 for an authenticated client. Returns "revoked", "nothing" or "not_yours"."""
    return _text("authlas_revoke", store.to_c(), _s(authenticated_client), _s(form_body))


# ---------------------------------------------------------------------------------------------------------------------
# Client registration (RFC 7591 / 7592): AuthlasClientStore { user, get, insert, replace, remove }
# ---------------------------------------------------------------------------------------------------------------------

class ClientStore(_Store):
    """Stores registered clients. Records hold secret material: never log them."""

    def get(self, client_id: str) -> Optional[Dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError

    def insert(self, record: Dict[str, Any]) -> bool:  # pragma: no cover
        raise NotImplementedError

    def replace(self, record: Dict[str, Any]) -> bool:  # pragma: no cover
        raise NotImplementedError

    def remove(self, client_id: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    def _build(self) -> Any:
        GET = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char, _BUFP)
        INS = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char)
        REP = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char)
        REM = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char)

        @_guarded
        def get(_user, cid, out):
            rec = self.get(cid.decode("utf-8"))
            return _write_out(out, _j(rec) if rec is not None else None)

        @_guarded
        def insert(_user, rec):
            return 0 if self.insert(json.loads(rec.decode("utf-8"))) else 1

        @_guarded
        def replace(_user, rec):
            return 0 if self.replace(json.loads(rec.decode("utf-8"))) else 1

        @_guarded
        def remove(_user, cid):
            return 0 if self.remove(cid.decode("utf-8")) else 1

        fns = (GET(get), INS(insert), REP(replace), REM(remove))
        self._refs += list(fns)
        return self._struct([("user", _vp), ("get", _vp), ("insert", _vp), ("replace", _vp), ("remove", _vp)],
                            {"user": None, **{n: ctypes.cast(f, _vp).value for n, f in zip(("get", "insert", "replace", "remove"), fns)}})


def client_register(store: ClientStore, endpoint: str, body: Dict[str, Any], *, policy: Optional[Dict[str, Any]] = None,
                    initial_access_token: Optional[str] = None, now: Optional[int] = None) -> Dict[str, Any]:
    """Registers a client (RFC 7591). The response carries the client secret and registration token once: show them then discard."""
    return _json("authlas_client_register", store.to_c(), _s(endpoint), _j(policy) if policy is not None else None,
                 _j(body), _s(initial_access_token), now or 0)


def client_read(store: ClientStore, endpoint: str, client_id: str, bearer: str, *, policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _json("authlas_client_read", store.to_c(), _s(endpoint), _j(policy) if policy is not None else None,
                 _s(client_id), _s(bearer))


def client_delete(store: ClientStore, client_id: str, bearer: str) -> None:
    _call("authlas_client_delete", store.to_c(), _s(client_id), _s(bearer))


# ---------------------------------------------------------------------------------------------------------------------
# Device grant (RFC 8628): AuthlasDeviceStore { user, insert, find_by_user_code, find_by_device_hash, save,
#                                               find_attempts, save_attempts }
# ---------------------------------------------------------------------------------------------------------------------

class DeviceStore(_Store):
    """Device records and per-caller attempt counters.

    Every operation on one device code must hold a lock keyed by its device_hash (or user_code) from the first read
    until the final save. Attempt counters need their own lock keyed by attempt_key.
    """

    def insert(self, record: Dict[str, Any]) -> bool:  # pragma: no cover
        raise NotImplementedError

    def find_by_user_code(self, user_code: str) -> Optional[Dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError

    def find_by_device_hash(self, device_hash: str) -> Optional[Dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError

    def save(self, record: Dict[str, Any]) -> bool:  # pragma: no cover
        raise NotImplementedError

    def find_attempts(self, attempt_key: str) -> int:  # pragma: no cover
        raise NotImplementedError

    def save_attempts(self, attempt_key: str, count: int) -> bool:  # pragma: no cover
        raise NotImplementedError

    def _build(self) -> Any:
        INS = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char)
        FBU = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char, _BUFP)
        FBH = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char, _BUFP)
        SAVE = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char)
        FA = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char, _BUFP)
        SA = ctypes.CFUNCTYPE(ctypes.c_int, _vp, _c_char, ctypes.c_uint32)

        @_guarded
        def insert(_user, rec):
            return 0 if self.insert(json.loads(rec.decode("utf-8"))) else 1

        @_guarded
        def by_user(_user, code, out):
            rec = self.find_by_user_code(code.decode("utf-8"))
            return _write_out(out, _j(rec) if rec is not None else None)

        @_guarded
        def by_hash(_user, h, out):
            rec = self.find_by_device_hash(h.decode("utf-8"))
            return _write_out(out, _j(rec) if rec is not None else None)

        @_guarded
        def save(_user, rec):
            return 0 if self.save(json.loads(rec.decode("utf-8"))) else 1

        @_guarded
        def find_attempts(_user, key, out):
            n = int(self.find_attempts(key.decode("utf-8")))
            return _write_out(out, str(n).encode() if n else None)

        @_guarded
        def save_attempts(_user, key, count):
            return 0 if self.save_attempts(key.decode("utf-8"), int(count)) else 1

        fns = (INS(insert), FBU(by_user), FBH(by_hash), SAVE(save), FA(find_attempts), SA(save_attempts))
        self._refs += list(fns)
        names = ("insert", "find_by_user_code", "find_by_device_hash", "save", "find_attempts", "save_attempts")
        return self._struct([("user", _vp)] + [(n, _vp) for n in names],
                            {"user": None, **{n: ctypes.cast(f, _vp).value for n, f in zip(names, fns)}})


def device_start(store: DeviceStore, client_id: str, verification_uri: str, *, scope: Optional[str] = None,
                 now: Optional[int] = None) -> Dict[str, Any]:
    """Starts a device authorization (RFC 8628 3.1). Returns the device_code (show to the device once), user_code and URIs."""
    return _json("authlas_device_start", store.to_c(), _s(client_id), _s(scope), _s(verification_uri), now or 0)


def device_lookup(store: DeviceStore, attempt_key: str, typed_user_code: str, *, max_attempts: int = 5,
                  now: Optional[int] = None) -> Dict[str, Any]:
    """Verification page lookup. A wrong code counts against ``attempt_key``. Returns {"client_id", "scope"}."""
    return _json("authlas_device_lookup", store.to_c(), _s(attempt_key), _s(typed_user_code), max_attempts, now or 0)


def device_decide(store: DeviceStore, attempt_key: str, typed_user_code: str, *, subject: Optional[str],
                  max_attempts: int = 5, now: Optional[int] = None) -> str:
    """Approves (subject set) or denies (subject None). Returns "approved" or "denied"."""
    return _text("authlas_device_decide", store.to_c(), _s(attempt_key), _s(typed_user_code), _s(subject),
                 max_attempts, now or 0)


def device_poll(store: DeviceStore, client_id: str, device_code: str, *, now: Optional[int] = None) -> Dict[str, Any]:
    """Polls at the token endpoint. On approval returns {"grant_id", "client_id", "scope", "subject"} once. Raises
    CoreError with the RFC 8628 code (authorization_pending, slow_down, access_denied, expired_token) otherwise."""
    return _json("authlas_device_poll", store.to_c(), _s(client_id), _s(device_code), now or 0)
