"""
!!! INTENTIONALLY VULNERABLE - SQL INJECTION DEMONSTRATION SANDBOX !!!

vulnerable_login() builds SQL by string concatenation (UNSAFE).
secure_login() runs the same lookup with placeholders (SAFE).
Both run against the same isolated in-memory database so the comparison is fair.
"""
import hashlib
import sqlite3

# Fictional lab accounts. These are shown to students on the lab page.
# They exist only in memory and are unrelated to real application accounts.
LAB_ACCOUNTS = [
    ("alice", "Wonderland1", "student"),
    ("bob", "Builder2024", "student"),
    ("lab_admin", "AdminDemo99", "administrator"),
]

VULNERABLE_TEMPLATE = (
    "SELECT id, username, role FROM lab_users "
    "WHERE username = '{username}' AND password_hash = '{password_hash}'"
)
SECURE_QUERY = (
    "SELECT id, username, role FROM lab_users "
    "WHERE username = ? AND password_hash = ?"
)

_MAX_STEPS = 50  # progress-handler ticks (x1000 VM instructions) before abort


def _lab_hash(password: str) -> str:
    # Unsalted SHA-256 is NOT appropriate for real passwords; it is used here
    # only so the sandbox does not hold plaintext. The main app uses scrypt.
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _authorizer(action, arg1, arg2, dbname, source):
    allowed = (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION)
    return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY


def _build_sandbox():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE lab_users (id INTEGER PRIMARY KEY, username TEXT, "
        "password_hash TEXT, role TEXT)"
    )
    conn.executemany(
        "INSERT INTO lab_users (username, password_hash, role) VALUES (?, ?, ?)",
        [(u, _lab_hash(p), r) for u, p, r in LAB_ACCOUNTS],
    )
    conn.commit()
    # From here on the sandbox is read-only and time-limited.
    conn.set_authorizer(_authorizer)
    steps = {"n": 0}

    def _progress():
        steps["n"] += 1
        return 1 if steps["n"] > _MAX_STEPS else 0

    conn.set_progress_handler(_progress, 1000)
    return conn


def _result(query, rows=None, error=None):
    rows = rows or []
    return {
        "query": query,
        "rows": [{"id": r[0], "username": r[1], "role": r[2]} for r in rows],
        "authenticated": bool(rows),
        "user": rows[0][1] if rows else None,
        "role": rows[0][2] if rows else None,
        "error": error,
    }


def vulnerable_login(username: str, password: str) -> dict:
    """UNSAFE: user input is pasted directly into the SQL text."""
    query = VULNERABLE_TEMPLATE.format(
        username=username, password_hash=_lab_hash(password)
    )
    conn = _build_sandbox()
    try:
        rows = conn.execute(query).fetchmany(10)  # <- input can change the query
        return _result(query, rows)
    except (sqlite3.Error, sqlite3.Warning) as exc:
        # Show only a generic message - never the raw database error.
        text = str(exc)
        msg = "The injected input broke the SQL syntax, so the query failed."
        if "not authorized" in text or "interrupted" in text:
            msg = "The sandbox refused this statement (only read-only SELECT is allowed)."
        elif "one statement" in text:
            msg = "Stacked queries (;) are rejected by sqlite3.execute()."
        return _result(query, error=msg)
    finally:
        conn.close()


def secure_login(username: str, password: str) -> dict:
    """SAFE: the query structure is fixed; input is bound as data."""
    conn = _build_sandbox()
    try:
        rows = conn.execute(SECURE_QUERY, (username, _lab_hash(password))).fetchmany(10)
        return _result(SECURE_QUERY, rows)
    finally:
        conn.close()
