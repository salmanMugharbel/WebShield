"""Authorisation helpers."""
from functools import wraps

from flask import flash, redirect, request, session, url_for


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access the security laboratories.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped
