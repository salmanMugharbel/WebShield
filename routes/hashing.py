"""Hashing laboratory (Module H)."""
from flask import Blueprint, flash, render_template, request, session

from database.db import get_db
from security.auth_guard import login_required
from security.hashing import (
    ALGORITHMS,
    avalanche,
    cost_comparison,
    describe_stored_hash,
    hash_all,
    hmac_demo,
    salting_demo,
)
from security.logger import log_event
from security.password import PASSWORD_METHOD

bp = Blueprint("hashing", __name__, url_prefix="/hashing")

MAX_INPUT = 200


def _arg(source, name, default=""):
    value = source.get(name, default)
    if len(value) > MAX_INPUT:
        flash(f"Inputs are limited to {MAX_INPUT} characters.", "error")
        return None
    return value


@bp.route("/", methods=["GET", "POST"])
@login_required
def lab():
    ctx = {"algorithms": ALGORITHMS, "password_method": PASSWORD_METHOD}
    status = 200

    # 1. Hash generator (GET)
    text = _arg(request.args, "text")
    if text is None:
        text, status = "", 400
    ctx["text"] = text
    if text:
        ctx["hashes"] = hash_all(text)
        log_event("Hashing", f"Input hashed with {len(ctx['hashes'])} algorithms (hash generator).", "NORMAL", "secure")

    # 2. Avalanche effect (GET)
    a, b = _arg(request.args, "a"), _arg(request.args, "b")
    if a is None or b is None:
        a, b, status = "", "", 400
    ctx["a"], ctx["b"] = a, b
    if a and b:
        ctx["aval"] = avalanche(a, b)
        log_event("Hashing", f"Avalanche demo: {ctx['aval']['pct']}% of SHA-256 output bits changed.", "NORMAL", "secure")

    # 3-5. Salting, cost and HMAC demos (POST, CSRF-protected)
    if request.method == "POST":
        demo = request.form.get("demo", "")
        if demo == "salting":
            pw = _arg(request.form, "salt_input")
            if pw:
                ctx["salting"] = salting_demo(pw)
                ctx["salt_input"] = pw
                log_event("Hashing", "Salting demo: unsalted hashes identical, salted hashes unique.", "INFO", "secure")
        elif demo == "cost":
            ctx["cost"] = cost_comparison("WebShield-demo-input")
            log_event("Hashing", "Cost comparison of fast hash vs. password-hashing functions.", "INFO", "secure")
        elif demo == "hmac":
            msg, changed, key = (_arg(request.form, n) for n in ("message", "received", "key"))
            if msg and changed is not None and key:
                ctx["hmac"] = hmac_demo(msg, changed, key)
                ctx["message"], ctx["received"] = msg, changed
                if ctx["hmac"]["valid"]:
                    log_event("Hashing", "HMAC verified: message unchanged.", "NORMAL", "secure")
                else:
                    log_event("Hashing", "HMAC mismatch: modified message detected and rejected.", "BLOCKED", "secure")
            else:
                flash("Message and key are required for the HMAC demo.", "error")
                status = 400

    # 6. Structure of the signed-in user's own stored hash (digest masked)
    row = get_db().execute("SELECT password_hash FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    ctx["stored"] = describe_stored_hash(row["password_hash"]) if row else None

    return render_template("hashing_lab.html", **ctx), status
