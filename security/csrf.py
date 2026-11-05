"""
Minimal CSRF protection (synchroniser token pattern).

A random token is stored in the server-signed session and embedded in every
form. A POST without the matching token is rejected with HTTP 400.
"""
import hmac
import secrets

from flask import abort, request, session


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, description="Missing or invalid CSRF token.")
