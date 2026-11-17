"""ctypes binding to the authlas Rust C ABI (authlas.dll / libauthlas.so / libauthlas.dylib).

Every function takes and returns JSON-compatible Python values. Errors raise CoreError with the library's kind and message.
Stateful flows (PAR, revocation, client registration, device grant, replay) take a store object whose methods are
called by the library. Each store method must hold its own lock, as docs/CALLBACKS.md describes.

Load order: AUTHLAS_CORE_LIB (a full path), then AUTHLAS_LIB_DIR, then the build directory of a source checkout.
"""
from __future__ import annotations

import ctypes
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

__all__ = ["load", "CoreError", "version", "backend", "abi_version"]


class CoreError(Exception):
    """A failed call. ``kind`` is the library status name, ``detail`` the JSON the library reported."""

    def __init__(self, kind: str, message: str, detail: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.kind = kind
        self.detail = detail or {}


_STATUS = {1: "malformed", 2: "algorithm", 3: "key", 4: "bad_signature", 5: "claim", 6: "crypto", 7: "unsupported",
           8: "decrypt", 9: "oauth", 10: "invalid_argument", 11: "panic"}

_REPO = Path(__file__).resolve().parents[2]


class _Buf(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("len", ctypes.c_size_t)]


def _names() -> List[str]:
    if sys.platform == "win32":
        return ["authlas.dll"]
    if sys.platform == "darwin":
        return ["libauthlas.dylib"]
    return ["libauthlas.so"]


def _find() -> Path:
    explicit = os.environ.get("AUTHLAS_CORE_LIB")
    if explicit:
        return Path(explicit)
    dirs = []
    if os.environ.get("AUTHLAS_LIB_DIR"):
        dirs.append(Path(os.environ["AUTHLAS_LIB_DIR"]))
    dirs.append(_REPO / "target" / "release")
    for d in dirs:
        for n in _names():
            p = d / n
            if p.is_file():
                return p
    raise ImportError("authlas core library not found; set AUTHLAS_CORE_LIB or AUTHLAS_LIB_DIR")


_lib: Optional[ctypes.CDLL] = None
_keep: List[Any] = []  # callback objects must stay alive while the library may call them


def load() -> ctypes.CDLL:
    """Loads the library once and declares every function signature."""
    global _lib
    if _lib is not None:
        return _lib
    path = _find()
    if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
        os.add_dll_directory(str(path.parent))
    if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
        # OpenSSL DLLs (libcrypto/libssl) are dependencies of authlas.dll and are looked up only in registered folders.
        for extra in os.environ.get("AUTHLAS_DLL_DIRS", "").split(os.pathsep):
            if extra:
                os.add_dll_directory(extra)
    lib = ctypes.CDLL(str(path))
    c = ctypes.c_char_p
    pb = ctypes.POINTER(_Buf)
    sz = ctypes.c_size_t
    u8p = ctypes.c_void_p
    lib.authlas_abi_version.restype = ctypes.c_uint32
    lib.authlas_version.restype = c
    lib.authlas_backend.restype = c
    lib.authlas_last_error.restype = c
    lib.authlas_buf_free.argtypes = [pb]
    # Pointer-returning functions must declare a 64-bit restype, or ctypes truncates the handle to 32 bits.
    lib.authlas_replay_new.restype = ctypes.c_void_p
    lib.authlas_replay_free.argtypes = [ctypes.c_void_p]
    lib.authlas_replay_free.restype = None
    # The replay handle is a pointer in these signatures; declare it so ctypes does not pass it as a 32-bit int.
    lib.authlas_jwt_verify.argtypes = [c, c, c, ctypes.c_void_p, pb]
    lib.authlas_at_jwt_verify.argtypes = [c, c, c, ctypes.c_void_p, pb]
    lib.authlas_dpop_verify.argtypes = [c, c, ctypes.c_void_p, pb]
    _lib = lib
    if lib.authlas_abi_version() != 1:
        raise ImportError("authlas core library has an incompatible ABI version")
    return lib


def _s(v: Optional[str]) -> Optional[bytes]:
    return None if v is None else v.encode("utf-8")


def _j(v: Any) -> bytes:
    return json.dumps(v, separators=(",", ":")).encode("utf-8")


def _call(fn: str, *args: Any) -> bytes:
    """Calls a function that ends with an output buffer. Raises CoreError on a non-zero status."""
    lib = load()
    out = _Buf()
    rc = getattr(lib, fn)(*args, ctypes.byref(out))
    try:
        if rc != 0:
            raw = (lib.authlas_last_error() or b"{}").decode("utf-8", "replace")
            try:
                detail = json.loads(raw)
            except ValueError:
                detail = {"message": raw}
            kind = detail.get("kind") or _STATUS.get(rc, "internal")
            raise CoreError(kind, detail.get("message") or "failed", detail)
        return ctypes.string_at(out.data, out.len) if out.data and out.len else b""
    finally:
        lib.authlas_buf_free(ctypes.byref(out))


def _text(fn: str, *args: Any) -> str:
    return _call(fn, *args).decode("utf-8")


def _json(fn: str, *args: Any) -> Any:
    return json.loads(_call(fn, *args) or b"null")


def version() -> str:
    return (load().authlas_version() or b"").decode()


def backend() -> str:
    return (load().authlas_backend() or b"").decode()


def abi_version() -> int:
    return int(load().authlas_abi_version())


# ---------------------------------------------------------------------------------------------------------------------
# Host callbacks. Each store is a ctypes struct of function pointers. Python keeps the callbacks alive in _keep.
# A callback must not raise into C: exceptions are caught and turned into a non-zero status.
# ---------------------------------------------------------------------------------------------------------------------

_CB_STATUS_FAIL = 1


def _set_out(out_ptr: Any, data: bytes) -> int:
    """Writes ``data`` into an AuthlasBuf for the library to copy. Returns 0."""
    lib = load()
    buf = ctypes.cast(out_ptr, ctypes.POINTER(_Buf))
    return int(lib.authlas_buf_write(buf, data, len(data)))


def _guard(fn: Callable[..., int]) -> Callable[..., int]:
    def wrapped(*args: Any) -> int:
        try:
            return fn(*args)
        except Exception:  # never unwind into C
            return _CB_STATUS_FAIL
    return wrapped


class ReplayCache:
    """Replay store for assertion and DPoP proof JTIs. Subclass and implement ``first_use``; one store is shared across instances.

    ``first_use(key, exp, now)`` returns True the first time ``key`` is seen (and remembers it until ``exp``), False on
    a replay. A failing store must raise, which is reported to the library as a failure, so authentication fails closed.
    """

    def first_use(self, key: str, exp: int, now: int) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def _c(self) -> Any:
        lib = load()
        FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64)

        def cb(_user, key, exp, now):
            try:
                return 1 if self.first_use(key.decode("utf-8"), int(exp), int(now)) else 0
            except Exception:
                return -1

        fn = FN(cb)
        _keep.append((self, fn))
        return fn


def _replay_struct(r: Optional[ReplayCache]) -> Any:
    class _R(ctypes.Structure):
        _fields_ = [("user", ctypes.c_void_p), ("first_use", ctypes.c_void_p)]
    s = _R()
    if r is not None:
        fn = r._c()
        s.first_use = ctypes.cast(fn, ctypes.c_void_p).value
    return s


# Public surface: stateless calls from api.py, stores from stores.py. Import last, after the loader is defined.
from .api import *  # noqa: E402,F401,F403
from .stores import (  # noqa: E402,F401
    ClientStore, DeviceStore, PushStore, RevocationStore,
    client_delete, client_read, client_register,
    device_decide, device_lookup, device_poll, device_start,
    par_push, par_redeem, revoke,
)
