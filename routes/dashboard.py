"""Dashboard, security comparison and documentation pages."""
from flask import Blueprint, render_template

from database.db import get_db

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def index():
    db = get_db()
    recent = db.execute(
        "SELECT event_type, implementation, description, security_status, created_at"
        " FROM activity_logs ORDER BY id DESC LIMIT 6"
    ).fetchall()
    stats = db.execute(
        "SELECT"
        " (SELECT COUNT(*) FROM users) AS users,"
        " (SELECT COUNT(*) FROM comments) AS comments,"
        " (SELECT COUNT(*) FROM activity_logs WHERE security_status = 'EXPLOITED') AS exploited,"
        " (SELECT COUNT(*) FROM activity_logs WHERE security_status = 'BLOCKED') AS blocked"
    ).fetchone()
    return render_template("dashboard.html", recent=recent, stats=stats)


@bp.route("/security")
def security_comparison():
    return render_template("security_comparison.html")


@bp.route("/docs")
def documentation():
    return render_template("documentation.html")
