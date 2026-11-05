"""
Password hashing.

Werkzeug's helpers produce salted, slow hashes (scrypt by default), so two users
with the same password get different hashes and brute force is expensive.
"""
from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    return check_password_hash(password_hash, password)
