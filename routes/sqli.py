"""SQL Injection laboratory (runs the isolated sandbox in vulnerable/)."""
from flask import Blueprint, flash, render_template, request

from security.auth_guard import login_required
from security.logger import log_event
from security.validation import MAX_LAB_INPUT, detect_sql_injection
from vulnerable.sqli_sandbox import (
    LAB_ACCOUNTS,
    SECURE_QUERY,
    VULNERABLE_TEMPLATE,
    secure_login,
    vulnerable_login,
)

bp = Blueprint("sqli", __name__, url_prefix="/sqli")

EXAMPLE_INPUTS = [
    ("Normal login", "alice", "Wonderland1"),
    ("Wrong password", "alice", "guess123"),
    ("Always-true condition", "' OR '1'='1' --", "anything"),
    ("Comment out password check", "lab_admin' --", "anything"),
    ("UNION query", "x' UNION SELECT 1, sqlite_version(), 'injected' --", "anything"),
    ("Special characters (legitimate)", "O'Brien", "anything"),
]


@bp.route("/", methods=["GET", "POST"])
@login_required
def lab():
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if len(username) > MAX_LAB_INPUT or len(password) > MAX_LAB_INPUT:
            flash(f"Lab inputs are limited to {MAX_LAB_INPUT} characters.", "error")
            return render_template("sqli_lab.html", **_ctx()), 400

        vuln = vulnerable_login(username, password)
        safe = secure_login(username, password)
        indicators = detect_sql_injection(username, password)
        bypass = vuln["authenticated"] and not safe["authenticated"]

        # --- activity log (no passwords, no raw payloads) ---
        if bypass:
            log_event("SQL Injection", "Injected input manipulated the concatenated query and "
                      f"bypassed login as '{vuln['user'][:30]}'.", "EXPLOITED", "vulnerable")
            log_event("SQL Injection", "Parameterised query treated the same input as data; "
                      "login refused.", "BLOCKED", "secure")
        elif indicators:
            log_event("SQL Injection", "Suspicious input detected (" + ", ".join(indicators)
                      + "); no bypass occurred.", "DETECTED", "vulnerable")
            log_event("SQL Injection", "Parameterised query handled the input safely.",
                      "BLOCKED", "secure")
        else:
            log_event("SQL Injection", "Normal input - both implementations behaved the same.",
                      "NORMAL", "secure")

        result = {
            "username": username,
            "vuln": vuln,
            "safe": safe,
            "indicators": indicators,
            "bypass": bypass,
        }
    return render_template("sqli_lab.html", result=result, **_ctx())


def _ctx():
    return {
        "accounts": LAB_ACCOUNTS,
        "examples": EXAMPLE_INPUTS,
        "vuln_template": VULNERABLE_TEMPLATE,
        "secure_query": SECURE_QUERY,
    }
