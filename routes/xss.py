"""
XSS laboratory.

SECURE rendering happens in the main application (Jinja2 auto-escaping +
strict Content-Security-Policy).

INTENTIONALLY VULNERABLE rendering happens ONLY under /xss/sandbox/*, which:
  * is loaded inside <iframe sandbox="allow-scripts allow-modals">,
  * sends a `Content-Security-Policy: sandbox ...` header, so even when opened
    directly the page runs in an opaque (unique, cookie-less) origin,
  * blocks all network access (connect-src/img-src/form-action),
  * therefore cannot read the WebShield session cookie or main-app DOM.
"""
from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from database.db import get_db
from security.auth_guard import login_required
from security.logger import log_event
from security.safe_rendering import detect_xss, html_encode
from security.validation import MAX_COMMENT, MAX_SEARCH, validate_text

bp = Blueprint("xss", __name__, url_prefix="/xss")

LAB_POST_ID = 1

SANDBOX_CSP = (
    "sandbox allow-scripts allow-modals; "
    "default-src 'none'; "
    "script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; "
    "img-src data:; "
    "connect-src 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'self'"
)

EXAMPLE_PAYLOADS = [
    ("Plain text", "Hello WebShield"),
    ("HTML formatting", "<b>bold</b> and <i>italic</i>"),
    ("Script tag", "<script>alert('XSS from script tag')</script>"),
    ("Image onerror", "<img src=x onerror=\"alert('XSS via onerror')\">"),
    ("DOM defacement", "<img src=x onerror=\"document.body.innerHTML='<h2>Page defaced by injected script</h2>'\">"),
]


def _comments():
    return get_db().execute(
        "SELECT c.id, c.comment_content, c.created_at, c.user_id, u.username"
        " FROM comments c JOIN users u ON u.id = c.user_id"
        " WHERE c.post_id = ? ORDER BY c.id DESC LIMIT 50",
        (LAB_POST_ID,),
    ).fetchall()


def _sandbox(template, **ctx):
    resp = render_template(template, **ctx)
    return resp, 200, {"Content-Security-Policy": SANDBOX_CSP}


# ----------------------------------------------------------------- main lab
@bp.route("/")
@login_required
def lab():
    q = request.args.get("q", "")
    if len(q) > MAX_SEARCH:
        flash(f"Search is limited to {MAX_SEARCH} characters.", "error")
        q = ""
    indicators = detect_xss(q) if q else []
    if q:
        if indicators:
            log_event("Reflected XSS", "Search input contained " + ", ".join(indicators)
                      + "; unsafe rendering would execute it (sandbox only).",
                      "EXPLOITED", "vulnerable")
            log_event("Reflected XSS", "Output encoding displayed the search input as text.",
                      "BLOCKED", "secure")
        else:
            log_event("Reflected XSS", "Normal search text reflected.", "NORMAL", "secure")
    return render_template(
        "xss_lab.html",
        q=q,
        q_encoded=html_encode(q) if q else "",
        indicators=indicators,
        comments=_comments(),
        examples=EXAMPLE_PAYLOADS,
        max_comment=MAX_COMMENT,
    )


@bp.route("/comment", methods=["POST"])
@login_required
def add_comment():
    content = request.form.get("comment", "")
    error = validate_text(content, "Comment", MAX_COMMENT)
    if error:
        flash(error, "error")
        return redirect(url_for("xss.lab") + "#stored")

    db = get_db()
    db.execute(
        "INSERT INTO comments (post_id, user_id, comment_content) VALUES (?, ?, ?)",
        (LAB_POST_ID, session["user_id"], content),
    )
    db.commit()

    indicators = detect_xss(content)
    if indicators:
        log_event("Stored XSS", "Stored comment contained " + ", ".join(indicators)
                  + "; it executes when rendered unsafely (sandbox only).",
                  "EXPLOITED", "vulnerable")
        log_event("Stored XSS", "Escaped rendering displayed the stored comment as text.",
                  "BLOCKED", "secure")
    else:
        log_event("Stored XSS", "Normal comment stored.", "NORMAL", "secure")
    flash("Comment saved to the database.", "success")
    return redirect(url_for("xss.lab") + "#stored")


@bp.route("/comment/<int:comment_id>/delete", methods=["POST"])
@login_required
def delete_comment(comment_id):
    db = get_db()
    row = db.execute("SELECT user_id FROM comments WHERE id = ?", (comment_id,)).fetchone()
    if row is None:
        abort(404)
    # Authorisation: users may only delete their own comments.
    if row["user_id"] != session["user_id"]:
        log_event("Authorization", "Attempt to delete another user's comment was refused.",
                  "BLOCKED", "secure")
        abort(403)
    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    db.commit()
    flash("Comment deleted.", "success")
    return redirect(url_for("xss.lab") + "#stored")


@bp.route("/dom-log", methods=["POST"])
@login_required
def dom_log():
    """Called by main.js so DOM-based demonstrations appear in the activity log."""
    payload = request.form.get("payload", "")[:MAX_SEARCH]
    indicators = detect_xss(payload)
    if indicators:
        log_event("DOM-based XSS", "URL fragment contained " + ", ".join(indicators)
                  + "; innerHTML sink executed it (sandbox only).", "EXPLOITED", "vulnerable")
        log_event("DOM-based XSS", "textContent sink displayed the fragment as text.",
                  "BLOCKED", "secure")
    else:
        log_event("DOM-based XSS", "Normal text written to the DOM.", "NORMAL", "secure")
    return ("", 204)


# ------------------------------------- INTENTIONALLY VULNERABLE sandbox pages
@bp.route("/sandbox/reflected")
def sandbox_reflected():
    q = request.args.get("q", "")[:MAX_SEARCH]
    return _sandbox("vulnerable/reflected.html", q=q)


@bp.route("/sandbox/stored")
@login_required
def sandbox_stored():
    return _sandbox("vulnerable/stored.html", comments=_comments())


@bp.route("/sandbox/dom")
def sandbox_dom():
    return _sandbox("vulnerable/dom.html")
