"""
Server-side input validation.

Client-side checks (HTML `required`, `pattern`, `maxlength`) improve usability
but can be bypassed with any HTTP client, so the server re-checks everything.
"""
import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
MAX_LAB_INPUT = 200
MAX_COMMENT = 500
MAX_SEARCH = 200


def validate_username(username: str):
    if not username:
        return "Username is required."
    if not USERNAME_RE.fullmatch(username):
        return "Username must be 3-30 characters: letters, digits or underscore."
    return None


def validate_password(password: str):
    if not password:
        return "Password is required."
    if len(password) < 8 or len(password) > 128:
        return "Password must be between 8 and 128 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain at least one letter and one digit."
    return None


def validate_text(value: str, field: str, max_len: int, required=True):
    if required and not value.strip():
        return f"{field} cannot be empty."
    if len(value) > max_len:
        return f"{field} must be at most {max_len} characters."
    return None


# --- Detection (for EDUCATIONAL labelling only) ------------------------------
# These patterns are NOT the defence. Blacklists are easy to bypass; the real
# protection is parameterised queries and output encoding. They are used only
# to tell the student "this input looks like an attack" in the activity log.

_SQLI_PATTERNS = [
    (re.compile(r"'"), "single quote"),
    (re.compile(r"--"), "SQL comment (--)"),
    (re.compile(r"/\*"), "block comment (/*)"),
    (re.compile(r";"), "statement separator (;)"),
    (re.compile(r"\bOR\b", re.I), "OR keyword"),
    (re.compile(r"\bUNION\b", re.I), "UNION keyword"),
    (re.compile(r"\b(DROP|DELETE|INSERT|UPDATE|ATTACH)\b", re.I), "data-modifying keyword"),
]


_TECHNIQUES = [
    # (catalogue id, name, pattern) - checked in this order
    ("SQLI-T4", "Stacked queries", re.compile(r";\s*\w+", re.I)),
    ("SQLI-T3", "UNION-based extraction", re.compile(r"\bUNION\b(\s+ALL)?\s+SELECT\b", re.I)),
    ("SQLI-T1", "Always-true condition (tautology)",
     re.compile(r"\bOR\b\s*(?:'[^']*'\s*=\s*'[^']*'|\d+\s*=\s*\d+|'?\w+'?\s*(?:LIKE|IS)\b|1\b|TRUE\b)", re.I)),
    ("SQLI-T6", "Blind (boolean condition)", re.compile(r"'\s*AND\b\s*(?:\d+\s*=\s*\d+|'[^']*'\s*=)", re.I)),
    ("SQLI-T2", "Comment truncation", re.compile(r"'\s*\)?\s*(--|/\*|#)")),
]


def classify_sqli_technique(*values):
    """
    Name the SQL Injection technique(s) an input uses, so the lab and the
    activity log can organise attempts by technique. Educational labelling
    only - the defence is still the parameterised query.
    """
    text = " ".join(v or "" for v in values)
    found = [(tid, name) for tid, name, rx in _TECHNIQUES if rx.search(text)]
    # A comment after a tautology/UNION/stacked query is part of that technique.
    if len(found) > 1:
        found = [f for f in found if f[0] != "SQLI-T2"]
    if not found and text.count("'") % 2 == 1:
        found.append(("SQLI-T5", "Error-based probing (unbalanced quote)"))
    return found


def detect_sql_injection(*values):
    found = []
    for value in values:
        for pattern, label in _SQLI_PATTERNS:
            if pattern.search(value or "") and label not in found:
                found.append(label)
    return found
