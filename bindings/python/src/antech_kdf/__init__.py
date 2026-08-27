"""ctypes wrapper over libantech_kdf_ffi. Crypto lives in the native library."""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

__version__ = "0.1.0"

Password = Union[str, bytes, bytearray]


class AntechError(Exception):
    pass


class InvalidInput(AntechError):
    pass


class InvalidHash(AntechError):
    pass


class InvalidConfig(AntechError):
    pass


class InternalError(AntechError):
    pass


ANTECH_OK = 0
ANTECH_VERIFICATION_FAILED = 1
ANTECH_INVALID_INPUT = -1
ANTECH_INVALID_HASH = -2
ANTECH_INTERNAL_ERROR = -3
ANTECH_INVALID_CONFIG = -4

GRAPH_REDUCED_CRITICAL_PATH = 1
GRAPH_CACHE_LOCALITY = 2
GRAPH_COMBINED_FRONTIER = 3


class _AntechConfig(ctypes.Structure):
    _fields_ = [
        ("memory_kib", ctypes.c_uint32),
        ("salt_length", ctypes.c_uint32),
        ("block_size", ctypes.c_uint32),
        ("fan_in", ctypes.c_uint32),
        ("graph", ctypes.c_uint32),
        ("output_length", ctypes.c_uint32),
    ]


class _AntechRehashPolicy(ctypes.Structure):
    _fields_ = [
        ("minimum_memory_kib", ctypes.c_uint32),
        ("preferred_memory_kib", ctypes.c_uint32),
        ("preferred_fan_in", ctypes.c_uint32),
        ("preferred_output_length", ctypes.c_uint32),
        ("preferred_secret_required", ctypes.c_uint32),
        ("preferred_associated_data", ctypes.c_uint32),
    ]


def _lib_candidates() -> list[Path]:
    here = Path(__file__).resolve().parent
    roots: list[Path] = []
    # Walk up looking for VERSION + sdk/native
    for p in [here, *here.parents]:
        if (p / "VERSION").is_file() and (p / "sdk").is_dir():
            roots.append(p)
            break
    roots.append(Path.cwd())
    names = [
        "antech_kdf.dll",
        "antech_kdf_ffi.dll",
        "libantech_kdf.so",
        "libantech_kdf_ffi.so",
        "libantech_kdf.dylib",
        "libantech_kdf_ffi.dylib",
    ]
    out: list[Path] = []
    env = os.environ.get("ANTECH_KDF_LIB")
    if env:
        ep = Path(env)
        if ep.is_file():
            out.append(ep)
        elif ep.is_dir():
            for n in names:
                out.append(ep / n)
    for root in roots:
        for sub in ("sdk/native", "target/release", "target/debug"):
            d = root / sub
            for n in names:
                out.append(d / n)
    for n in names:
        out.append(here / "native" / n)
    return out


def _load_lib() -> ctypes.CDLL:
    last: Optional[OSError] = None
    for path in _lib_candidates():
        if not path.is_file():
            continue
        try:
            return ctypes.CDLL(str(path))
        except OSError as e:
            last = e
    raise InternalError(
        "native library not found; run sdk/scripts/build-native.(sh|ps1) "
        f"or set ANTECH_KDF_LIB (last error: {last})"
    )


_LIB = _load_lib()


def _bind(name: str, restype, argtypes) -> None:
    fn = getattr(_LIB, name)
    fn.restype = restype
    fn.argtypes = argtypes


_bind("antech_version", ctypes.c_char_p, [])
_bind("antech_free", None, [ctypes.c_void_p])
_bind("antech_config_default", ctypes.c_int, [ctypes.POINTER(_AntechConfig)])
_bind("antech_rehash_policy_default", ctypes.c_int, [ctypes.POINTER(_AntechRehashPolicy)])
_bind(
    "antech_hash_bytes",
    ctypes.c_int,
    [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p)],
)
_bind(
    "antech_hash_with_config_bytes",
    ctypes.c_int,
    [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(_AntechConfig),
        ctypes.POINTER(ctypes.c_void_p),
    ],
)
_bind(
    "antech_hash_with_config_and_salt",
    ctypes.c_int,
    [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(_AntechConfig),
        ctypes.POINTER(ctypes.c_void_p),
    ],
)
_bind(
    "antech_verify_bytes",
    ctypes.c_int,
    [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p],
)
_bind(
    "antech_hash_with_inputs_bytes",
    ctypes.c_int,
    [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(_AntechConfig),
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_void_p),
    ],
)
_bind(
    "antech_hash_with_inputs_and_salt",
    ctypes.c_int,
    [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(_AntechConfig),
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_void_p),
    ],
)
_bind(
    "antech_verify_with_inputs_bytes",
    ctypes.c_int,
    [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ],
)
_bind("antech_needs_rehash", ctypes.c_int, [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)])
_bind(
    "antech_needs_rehash_with_policy",
    ctypes.c_int,
    [ctypes.c_char_p, ctypes.POINTER(_AntechRehashPolicy), ctypes.POINTER(ctypes.c_int)],
)


def _raise(st: int) -> None:
    if st == ANTECH_OK:
        return
    if st == ANTECH_INVALID_INPUT:
        raise InvalidInput()
    if st == ANTECH_INVALID_HASH:
        raise InvalidHash()
    if st == ANTECH_INVALID_CONFIG:
        raise InvalidConfig()
    raise InternalError(f"status={st}")


def _pw_bytes(password: Password) -> bytes:
    if isinstance(password, str):
        return password.encode("utf-8")
    return bytes(password)


def _take(ptr: ctypes.c_void_p) -> str:
    if not ptr:
        raise InternalError("null string")
    s = ctypes.cast(ptr, ctypes.c_char_p).value
    _LIB.antech_free(ptr)
    if s is None:
        raise InternalError("null string")
    return s.decode("utf-8")


@dataclass
class Config:
    memory_kib: int = 16384
    salt_length: int = 16
    block_size: int = 32
    fan_in: int = 2
    graph: int = GRAPH_COMBINED_FRONTIER
    output_length: int = 32

    def _c(self) -> _AntechConfig:
        return _AntechConfig(
            self.memory_kib,
            self.salt_length,
            self.block_size,
            self.fan_in,
            self.graph,
            self.output_length,
        )

    @classmethod
    def default(cls) -> "Config":
        c = _AntechConfig()
        _raise(_LIB.antech_config_default(ctypes.byref(c)))
        return cls(
            c.memory_kib,
            c.salt_length,
            c.block_size,
            c.fan_in,
            c.graph,
            c.output_length,
        )


@dataclass
class RehashPolicy:
    minimum_memory_kib: int = 16384
    preferred_memory_kib: int = 16384
    preferred_fan_in: int = 2
    preferred_output_length: int = 32
    preferred_secret_required: bool = False
    preferred_associated_data: bool = False

    def _c(self) -> _AntechRehashPolicy:
        return _AntechRehashPolicy(
            self.minimum_memory_kib,
            self.preferred_memory_kib,
            self.preferred_fan_in,
            self.preferred_output_length,
            1 if self.preferred_secret_required else 0,
            1 if self.preferred_associated_data else 0,
        )

    @classmethod
    def default(cls) -> "RehashPolicy":
        p = _AntechRehashPolicy()
        _raise(_LIB.antech_rehash_policy_default(ctypes.byref(p)))
        return cls(
            p.minimum_memory_kib,
            p.preferred_memory_kib,
            p.preferred_fan_in,
            p.preferred_output_length,
            bool(p.preferred_secret_required),
            bool(p.preferred_associated_data),
        )


def _as_ptr(data: bytes):
    if not data:
        return None, None
    buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    return ctypes.cast(buf, ctypes.c_void_p), buf


def _opt_buf(data: Optional[bytes]) -> tuple[Optional[ctypes.c_void_p], int, object]:
    # None → absent; b'' → present empty (non-null scratch). See antech_kdf.h.
    if data is None:
        return None, 0, None
    if len(data) == 0:
        scratch = (ctypes.c_uint8 * 1)(0)
        return ctypes.cast(scratch, ctypes.c_void_p), 0, scratch
    buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    return ctypes.cast(buf, ctypes.c_void_p), len(data), buf


def _call_hash(fn, *args) -> str:
    out = ctypes.c_void_p()
    _raise(fn(*args, ctypes.byref(out)))
    return _take(out)


def _as_verified(st: int) -> bool:
    if st == ANTECH_OK:
        return True
    if st == ANTECH_VERIFICATION_FAILED:
        return False
    _raise(st)
    return False


def version() -> str:
    v = _LIB.antech_version()
    return v.decode("utf-8") if v else __version__


def hash(password: Password) -> str:
    pw = _pw_bytes(password)
    ptr, _keep = _as_ptr(pw)
    return _call_hash(_LIB.antech_hash_bytes, ptr, len(pw))


def hash_with_config(password: Password, config: Config) -> str:
    pw = _pw_bytes(password)
    cfg = config._c()
    ptr, _keep = _as_ptr(pw)
    return _call_hash(
        _LIB.antech_hash_with_config_bytes, ptr, len(pw), ctypes.byref(cfg)
    )


def hash_with_config_and_salt(password: Password, salt: bytes, config: Config) -> str:
    pw = _pw_bytes(password)
    cfg = config._c()
    pw_ptr, _pw = _as_ptr(pw)
    salt_ptr, _salt = _as_ptr(salt)
    return _call_hash(
        _LIB.antech_hash_with_config_and_salt,
        pw_ptr,
        len(pw),
        salt_ptr,
        len(salt),
        ctypes.byref(cfg),
    )


def verify(password: Password, encoded_hash: str) -> bool:
    pw = _pw_bytes(password)
    ptr, _keep = _as_ptr(pw)
    return _as_verified(
        _LIB.antech_verify_bytes(ptr, len(pw), encoded_hash.encode("utf-8"))
    )


def hash_with_inputs(
    password: Password,
    config: Config,
    *,
    secret: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
) -> str:
    pw = _pw_bytes(password)
    cfg = config._c()
    pw_ptr, _pw = _as_ptr(pw)
    sec_ptr, sec_len, _sec = _opt_buf(secret)
    ad_ptr, ad_len, _ad = _opt_buf(associated_data)
    return _call_hash(
        _LIB.antech_hash_with_inputs_bytes,
        pw_ptr,
        len(pw),
        ctypes.byref(cfg),
        sec_ptr,
        sec_len,
        ad_ptr,
        ad_len,
    )


def hash_with_inputs_and_salt(
    password: Password,
    salt: bytes,
    config: Config,
    *,
    secret: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
) -> str:
    pw = _pw_bytes(password)
    cfg = config._c()
    pw_ptr, _pw = _as_ptr(pw)
    salt_ptr, _salt = _as_ptr(salt)
    sec_ptr, sec_len, _sec = _opt_buf(secret)
    ad_ptr, ad_len, _ad = _opt_buf(associated_data)
    return _call_hash(
        _LIB.antech_hash_with_inputs_and_salt,
        pw_ptr,
        len(pw),
        salt_ptr,
        len(salt),
        ctypes.byref(cfg),
        sec_ptr,
        sec_len,
        ad_ptr,
        ad_len,
    )


def verify_with_inputs(
    password: Password,
    encoded_hash: str,
    *,
    secret: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
) -> bool:
    pw = _pw_bytes(password)
    pw_ptr, _pw = _as_ptr(pw)
    sec_ptr, sec_len, _sec = _opt_buf(secret)
    ad_ptr, ad_len, _ad = _opt_buf(associated_data)
    return _as_verified(
        _LIB.antech_verify_with_inputs_bytes(
            pw_ptr,
            len(pw),
            encoded_hash.encode("utf-8"),
            sec_ptr,
            sec_len,
            ad_ptr,
            ad_len,
        )
    )


def needs_rehash(encoded_hash: str) -> bool:
    out = ctypes.c_int()
    _raise(_LIB.antech_needs_rehash(encoded_hash.encode("utf-8"), ctypes.byref(out)))
    return out.value != 0


def needs_rehash_with_policy(encoded_hash: str, policy: RehashPolicy) -> bool:
    out = ctypes.c_int()
    p = policy._c()
    _raise(
        _LIB.antech_needs_rehash_with_policy(
            encoded_hash.encode("utf-8"), ctypes.byref(p), ctypes.byref(out)
        )
    )
    return out.value != 0


# Avoid shadowing builtin hash in docs; keep name for API parity.
__all__ = [
    "Config",
    "RehashPolicy",
    "hash",
    "hash_with_config",
    "hash_with_config_and_salt",
    "hash_with_inputs",
    "hash_with_inputs_and_salt",
    "verify",
    "verify_with_inputs",
    "needs_rehash",
    "needs_rehash_with_policy",
    "version",
    "AntechError",
    "InvalidInput",
    "InvalidHash",
    "InvalidConfig",
    "InternalError",
    "GRAPH_COMBINED_FRONTIER",
]
