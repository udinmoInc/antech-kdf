"""Antech KDF — ctypes wrapper over libantech_kdf_ffi."""

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
_LIB.antech_version.restype = ctypes.c_char_p
_LIB.antech_free.argtypes = [ctypes.c_void_p]
_LIB.antech_config_default.argtypes = [ctypes.POINTER(_AntechConfig)]
_LIB.antech_config_default.restype = ctypes.c_int
_LIB.antech_rehash_policy_default.argtypes = [ctypes.POINTER(_AntechRehashPolicy)]
_LIB.antech_rehash_policy_default.restype = ctypes.c_int
_LIB.antech_hash_bytes.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_void_p),
]
_LIB.antech_hash_bytes.restype = ctypes.c_int
_LIB.antech_hash_with_config_bytes.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(_AntechConfig),
    ctypes.POINTER(ctypes.c_void_p),
]
_LIB.antech_hash_with_config_bytes.restype = ctypes.c_int
_LIB.antech_hash_with_config_and_salt.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(_AntechConfig),
    ctypes.POINTER(ctypes.c_void_p),
]
_LIB.antech_hash_with_config_and_salt.restype = ctypes.c_int
_LIB.antech_verify_bytes.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]
_LIB.antech_verify_bytes.restype = ctypes.c_int
_LIB.antech_needs_rehash.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
_LIB.antech_needs_rehash.restype = ctypes.c_int
_LIB.antech_needs_rehash_with_policy.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(_AntechRehashPolicy),
    ctypes.POINTER(ctypes.c_int),
]
_LIB.antech_needs_rehash_with_policy.restype = ctypes.c_int


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

    def _c(self) -> _AntechRehashPolicy:
        return _AntechRehashPolicy(
            self.minimum_memory_kib,
            self.preferred_memory_kib,
            self.preferred_fan_in,
            self.preferred_output_length,
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
        )


def version() -> str:
    v = _LIB.antech_version()
    return v.decode("utf-8") if v else __version__


def hash(password: Password) -> str:
    pw = _pw_bytes(password)
    out = ctypes.c_void_p()
    buf = (ctypes.c_uint8 * len(pw)).from_buffer_copy(pw) if pw else None
    ptr = ctypes.cast(buf, ctypes.c_void_p) if buf is not None else None
    _raise(_LIB.antech_hash_bytes(ptr, len(pw), ctypes.byref(out)))
    return _take(out)


def hash_with_config(password: Password, config: Config) -> str:
    pw = _pw_bytes(password)
    out = ctypes.c_void_p()
    cfg = config._c()
    buf = (ctypes.c_uint8 * len(pw)).from_buffer_copy(pw) if pw else None
    ptr = ctypes.cast(buf, ctypes.c_void_p) if buf is not None else None
    _raise(
        _LIB.antech_hash_with_config_bytes(ptr, len(pw), ctypes.byref(cfg), ctypes.byref(out))
    )
    return _take(out)


def hash_with_config_and_salt(password: Password, salt: bytes, config: Config) -> str:
    pw = _pw_bytes(password)
    out = ctypes.c_void_p()
    cfg = config._c()
    pw_buf = (ctypes.c_uint8 * len(pw)).from_buffer_copy(pw) if pw else None
    salt_buf = (ctypes.c_uint8 * len(salt)).from_buffer_copy(salt) if salt else None
    _raise(
        _LIB.antech_hash_with_config_and_salt(
            ctypes.cast(pw_buf, ctypes.c_void_p) if pw_buf else None,
            len(pw),
            ctypes.cast(salt_buf, ctypes.c_void_p) if salt_buf else None,
            len(salt),
            ctypes.byref(cfg),
            ctypes.byref(out),
        )
    )
    return _take(out)


def verify(password: Password, encoded_hash: str) -> bool:
    pw = _pw_bytes(password)
    buf = (ctypes.c_uint8 * len(pw)).from_buffer_copy(pw) if pw else None
    ptr = ctypes.cast(buf, ctypes.c_void_p) if buf is not None else None
    st = _LIB.antech_verify_bytes(ptr, len(pw), encoded_hash.encode("utf-8"))
    if st == ANTECH_OK:
        return True
    if st == ANTECH_VERIFICATION_FAILED:
        return False
    _raise(st)
    return False


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
    "verify",
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
