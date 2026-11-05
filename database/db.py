"""
Database access helpers for the MAIN application.

Every query in the main application uses parameterised SQL ("?" placeholders).
The intentionally vulnerable code lives in the separate `vulnerable/` package
and never touches this database.
"""
import os
import sqlite3

from flask import current_app, g

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def connect(path):
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    """Return one connection per request (stored on flask.g)."""
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_schema(conn):
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        conn.executescript(fh.read())


def seed(conn):
    """Insert fictional demo content (no real people, no real passwords)."""
    from security.password import hash_password

    cur = conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        ("demo_student", hash_password("DemoPass123")),
    )
    user_id = cur.lastrowid
    conn.execute(
        "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
        (
            user_id,
            "XSS Lab discussion board",
            "Fictional discussion thread used by the Stored XSS demonstration.",
        ),
    )
    conn.execute(
        "INSERT INTO comments (post_id, user_id, comment_content) VALUES (?, ?, ?)",
        (1, user_id, "Welcome to the stored XSS lab! Try posting a comment."),
    )
    conn.execute(
        "INSERT INTO activity_logs (event_type, implementation, description, security_status)"
        " VALUES (?, ?, ?, ?)",
        ("System", "application", "Database initialised with fictional demo data.", "INFO"),
    )
    conn.commit()


def init_db(path):
    """Create (or recreate) the database file at `path`."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = connect(path)
    try:
        init_schema(conn)
        seed(conn)
    finally:
        conn.close()


def ensure_db(app):
    """Create the database on first start if it does not exist yet."""
    path = app.config["DATABASE"]
    if not os.path.exists(path):
        init_db(path)
