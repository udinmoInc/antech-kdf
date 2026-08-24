# Backend Integration Example: Python + FastAPI
# Demonstrates strictly where hash_password() and verify_password() are invoked.

from antech_kdf import hash_password, verify_password

def register_user(password: str) -> str:
    return hash_password(password)

def login_user(password: str, stored_hash: str) -> bool:
    return verify_password(password, stored_hash)
