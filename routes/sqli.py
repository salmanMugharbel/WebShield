"""SQL Injection laboratory (runs the isolated sandbox in vulnerable/)."""
from flask import Blueprint, flash, render_template, request

from security.attack_catalog import ATTACKS
from security.auth_guard import login_required
from security.logger import log_event
from security.validation import MAX_LAB_INPUT, classify_sqli_technique, detect_sql_injection
from vulnerable.sqli_sandbox import (
    LAB_ACCOUNTS,
    SECURE_QUERY,
    VULNERABLE_TEMPLATE,
    secure_login,
    vulnerable_login,
)

bp = Blueprint("sqli", __name__, url_prefix="/sqli")

# Example inputs organised by attack technique (ids match the Attack Catalogue).
EXAMPLE_GROUPS = [
    ("NORMAL", "Normal use", [
        ("Normal login", "alice", "Wonderland1"),
        ("Wrong password", "alice", "guess123"),
    ]),
    ("SQLI-T1", "Always-true condition (tautology)", [
        ("OR '1'='1'", "' OR '1'='1' --", "anything"),
        ("OR 1=1 + OFFSET", "' OR 1=1 LIMIT 1 OFFSET 2 --", "anything"),
    ]),
    ("SQLI-T2", "Comment truncation", [
        ("-- comment", "lab_admin' --", "anything"),
        ("/* comment", "bob' /*", "anything"),
    ]),
    ("SQLI-T3", "UNION-based extraction", [
        ("UNION constant row", "x' UNION SELECT 1, sqlite_version(), 'injected' --", "anything"),
        ("UNION list users", "x' UNION SELECT id, username, role FROM lab_users --", "anything"),
    ]),
    ("SQLI-T4", "Stacked queries", [
        ("; DROP TABLE", "x'; DROP TABLE lab_users; --", "anything"),
    ]),
    ("SQLI-T5", "Error-based probing", [
        ("Lone quote", "'", "anything"),
        ("O'Brien (legitimate)", "O'Brien", "anything"),
    ]),
    ("SQLI-T6", "Blind (boolean condition)", [
        ("AND 1=1 (true)", "alice' AND 1=1 --", "anything"),
        ("AND 1=2 (false)", "alice' AND 1=2 --", "anything"),
    ]),
]

TECHNIQUES = [dict(zip(("id", "name", "category", "owasp", "layer", "how", "defence", "lab", "tests"), a))
              for a in ATTACKS if a[0].startswith("SQLI-T")]


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
        techniques = classify_sqli_technique(username, password)
        bypass = vuln["authenticated"] and not safe["authenticated"]
        tech_text = ", ".join(f"{tid} {name}" for tid, name in techniques) or "no known technique"

        # --- activity log (no passwords, no raw payloads) ---
        if bypass:
            log_event("SQL Injection", f"[{tech_text}] Injected input manipulated the concatenated query and "
                      f"bypassed login as '{vuln['user'][:30]}'.", "EXPLOITED", "vulnerable")
            log_event("SQL Injection", f"[{tech_text}] Parameterised query treated the same input as data; "
                      "login refused.", "BLOCKED", "secure")
        elif indicators:
            log_event("SQL Injection", f"[{tech_text}] Suspicious input detected ("
                      + ", ".join(indicators) + "); no bypass occurred.", "DETECTED", "vulnerable")
            log_event("SQL Injection", f"[{tech_text}] Parameterised query handled the input safely.",
                      "BLOCKED", "secure")
        else:
            log_event("SQL Injection", "Normal input - both implementations behaved the same.",
                      "NORMAL", "secure")

        result = {
            "username": username,
            "vuln": vuln,
            "safe": safe,
            "indicators": indicators,
            "techniques": techniques,
            "bypass": bypass,
        }
    return render_template("sqli_lab.html", result=result, **_ctx())


def _ctx():
    return {
        "accounts": LAB_ACCOUNTS,
        "example_groups": EXAMPLE_GROUPS,
        "techniques": TECHNIQUES,
        "vuln_template": VULNERABLE_TEMPLATE,
        "secure_query": SECURE_QUERY,
    }
