"""
Activity logging.

Only a short classification is stored - never passwords, session tokens or the
raw attack payload.
"""
from database.db import get_db


def log_event(event_type, description, status, implementation="application"):
    db = get_db()
    db.execute(
        "INSERT INTO activity_logs (event_type, implementation, description, security_status)"
        " VALUES (?, ?, ?, ?)",
        (event_type, implementation, description[:500], status),
    )
    db.commit()
