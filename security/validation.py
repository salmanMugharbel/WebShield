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


def detect_sql_injection(*values):
    found = []
    for value in values:
        for pattern, label in _SQLI_PATTERNS:
            if pattern.search(value or "") and label not in found:
                found.append(label)
    return found
