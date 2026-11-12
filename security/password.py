"""
Password hashing.

Passwords are stored with scrypt, a salted, slow and memory-hard password
hashing function. The parameters follow the OWASP Password Storage Cheat Sheet
minimum for scrypt: N=2^17 (128 MiB), r=8, p=1. Werkzeug's own default
(N=2^15) is below that, so the method is set explicitly here.

Each hash string stores its own algorithm, parameters and random salt, e.g.
    scrypt:131072:8:1$<16-char salt>$<128 hex digest>
so older hashes still verify, and needs_rehash() lets the login upgrade them.
"""
from werkzeug.security import check_password_hash, generate_password_hash

PASSWORD_METHOD = "scrypt:131072:8:1"


def hash_password(password: str) -> str:
    return generate_password_hash(password, method=PASSWORD_METHOD)


def verify_password(password_hash: str, password: str) -> bool:
    return check_password_hash(password_hash, password)


def needs_rehash(password_hash: str) -> bool:
    """True when a stored hash uses weaker or different parameters than today's."""
    return not password_hash.startswith(PASSWORD_METHOD + "$")
