"""
WebShield configuration.

All settings live here so that security-relevant options (cookie flags,
session lifetime, database location) are visible in one place.
"""
import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # A random key is generated on every start unless one is provided through
    # the environment. Never hard-code a production secret key in source code.
    SECRET_KEY = os.environ.get("WEBSHIELD_SECRET_KEY") or secrets.token_hex(32)

    # Main application database (real users, posts, comments, logs).
    DATABASE = os.path.join(BASE_DIR, "database", "webshield.db")

    # --- Session security -------------------------------------------------
    SESSION_COOKIE_HTTPONLY = True        # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE = "Strict"    # Not sent on cross-site requests
    SESSION_COOKIE_SECURE = False         # Set True when served over HTTPS
    SESSION_COOKIE_NAME = "webshield_session"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Reject request bodies larger than 64 KB.
    MAX_CONTENT_LENGTH = 64 * 1024

    # Never run the debugger in this app: it would expose stack traces.
    DEBUG = False
    TESTING = False

    # Bind only to the loopback interface so the vulnerable labs are never
    # reachable from other machines on the network.
    HOST = "127.0.0.1"
    PORT = int(os.environ.get("WEBSHIELD_PORT", "5000"))
