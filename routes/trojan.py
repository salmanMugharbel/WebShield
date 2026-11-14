"""Trojan Horse Defence lab: upload scanner and source integrity monitor."""
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from database.db import get_db
from security import integrity
from security.auth_guard import login_required
from security.file_scanner import ALLOWED, MAX_UPLOAD, scan
from security.logger import log_event
from security.trojan_samples import SAMPLES

bp = Blueprint("trojan", __name__, url_prefix="/trojan")


def _record(result):
    db = get_db()
    db.execute(
        "INSERT INTO file_scans (user_id, filename, size, sha256, detected_type, verdict, reasons)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (session["user_id"], result["filename"][:255], result["size"], result["sha256"],
         result["detected"][:100], result["verdict"], "; ".join(result["reasons"])[:1000]),
    )
    db.commit()
    status = {"BLOCKED": "BLOCKED", "SUSPICIOUS": "DETECTED", "ACCEPTED": "NORMAL"}[result["verdict"]]
    reason = result["reasons"][0] if result["reasons"] else "all eight checks passed"
    log_event("Trojan Horse", f"Upload {result['verdict'].lower()}: {reason}"[:400], status, "secure")


@bp.route("/", methods=["GET", "POST"])
@login_required
def lab():
    result, integ, status = None, None, 200
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "scan":
            sample_key = request.form.get("sample", "")
            upload = request.files.get("file")
            if upload and upload.filename:
                data = upload.read(MAX_UPLOAD + 1)   # never more than limit+1 bytes in memory
                result = scan(upload.filename, data)
            elif sample_key in SAMPLES:
                name, data, _desc, _exp = SAMPLES[sample_key]
                result = scan(name, data)
            else:
                flash("Choose a file to upload or one of the built-in samples.", "error")
                status = 400
            if result:
                _record(result)
        elif action == "verify":
            integ = integrity.verify(manifest=current_app.config["INTEGRITY_MANIFEST"])
            if integ["error"]:
                log_event("Integrity", "Integrity check could not run: no baseline manifest.", "INFO", "secure")
            elif integ["ok"]:
                log_event("Integrity", f"Source integrity verified: {integ['checked']} files unchanged.", "NORMAL", "secure")
            else:
                n = len(integ["modified"]) + len(integ["missing"]) + len(integ["added"])
                log_event("Integrity", f"Source integrity check found {n} changed file(s).", "DETECTED", "secure")
        else:
            return redirect(url_for("trojan.lab"))

    scans = get_db().execute(
        "SELECT filename, size, sha256, detected_type, verdict, reasons, created_at FROM file_scans"
        " WHERE user_id = ? ORDER BY id DESC LIMIT 10", (session["user_id"],)).fetchall()
    return render_template("trojan_lab.html", result=result, integ=integ, scans=scans, samples=SAMPLES,
                           allowed=sorted(ALLOWED), max_upload=MAX_UPLOAD), status
