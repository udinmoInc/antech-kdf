# Backend sketch: register/login with the Python SDK.

from antech_kdf import hash, verify


def register_user(password: str) -> str:
    return hash(password)


def login_user(password: str, stored_hash: str) -> bool:
    return verify(password, stored_hash)
