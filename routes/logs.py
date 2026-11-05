"""Security activity log viewer."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from database.db import get_db
from security.auth_guard import login_required

bp = Blueprint("logs", __name__, url_prefix="/logs")

STATUSES = ("EXPLOITED", "BLOCKED", "DETECTED", "NORMAL", "INFO")


@bp.route("/")
@login_required
def index():
    status = request.args.get("status", "")
    db = get_db()
    if status in STATUSES:
        rows = db.execute(
            "SELECT * FROM activity_logs WHERE security_status = ? ORDER BY id DESC LIMIT 200",
            (status,),
        ).fetchall()
    else:
        status = ""
        rows = db.execute("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("activity_logs.html", logs=rows, status=status, statuses=STATUSES)


@bp.route("/clear", methods=["POST"])
@login_required
def clear():
    db = get_db()
    db.execute("DELETE FROM activity_logs")
    db.execute(
        "INSERT INTO activity_logs (event_type, implementation, description, security_status)"
        " VALUES ('System', 'application', 'Activity log cleared.', 'INFO')"
    )
    db.commit()
    flash("Activity log cleared.", "success")
    return redirect(url_for("logs.index"))
