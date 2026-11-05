"""
Authentication (SECURE implementation used by the real application).

* parameterised SQL only
* salted password hashes (werkzeug / scrypt)
* server-side validation
* session regenerated on login (prevents session fixation)
"""
import sqlite3

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from database.db import get_db
from security.logger import log_event
from security.password import hash_password, verify_password
from security.validation import validate_password, validate_username

bp = Blueprint("auth", __name__)


def _safe_next(target):
    # Only allow relative paths on this site (prevents open redirects).
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("dashboard.index")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = validate_username(username) or validate_password(password)
        if not error and password != confirm:
            error = "Passwords do not match."

        if not error:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hash_password(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "That username is already taken."
            else:
                log_event("Registration", "New account registered.", "NORMAL")
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("auth.login"))

        flash(error, "error")
        return render_template("register.html", username=username), 400

    return render_template("register.html", username="")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = None
        if username and password and len(username) <= 30 and len(password) <= 128:
            user = get_db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if user and verify_password(user["password_hash"], password):
            next_url = _safe_next(request.args.get("next"))
            session.clear()                 # new session => no fixation
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log_event("Authentication", "Successful login (secure login form).", "NORMAL", "secure")
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(next_url)

        # Same message for unknown user and wrong password (no user enumeration).
        log_event("Authentication", "Failed login attempt rejected.", "BLOCKED", "secure")
        flash("Invalid username or password.", "error")
        return render_template("login.html", username=username), 401

    return render_template("login.html", username="")


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("dashboard.index"))
