"""
WebShield - SQL Injection & XSS demonstration and prevention platform.

Run:  python app.py      then open http://127.0.0.1:5000
"""
from flask import Flask, render_template, request

from config import Config
from database.db import close_db, ensure_db
from security.csrf import csrf_protect, get_csrf_token

# Content Security Policy for the MAIN application.
# No inline scripts are allowed, so even if an injection slipped through,
# the browser would refuse to execute it.
MAIN_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "frame-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'self'"
)


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    ensure_db(app)
    app.teardown_appcontext(close_db)

    # Blueprints (server-side layer)
    from routes.auth import bp as auth_bp
    from routes.dashboard import bp as dashboard_bp
    from routes.logs import bp as logs_bp
    from routes.sqli import bp as sqli_bp
    from routes.xss import bp as xss_bp

    for bp in (dashboard_bp, auth_bp, sqli_bp, xss_bp, logs_bp):
        app.register_blueprint(bp)

    @app.before_request
    def _csrf():
        csrf_protect()

    @app.context_processor
    def _inject():
        return {"csrf_token": get_csrf_token}

    @app.after_request
    def _security_headers(resp):
        # Sandbox routes set their own, isolated policy (see routes/xss.py).
        if not request.path.startswith("/xss/sandbox/"):
            resp.headers.setdefault("Content-Security-Policy", MAIN_CSP)
            resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # Generic error pages - never expose stack traces or SQL errors.
    @app.errorhandler(400)
    def _bad_request(e):
        return render_template("error.html", code=400, message=e.description), 400

    @app.errorhandler(404)
    def _not_found(_e):
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(413)
    def _too_large(_e):
        return render_template("error.html", code=413, message="Request too large."), 413

    @app.errorhandler(500)
    def _server_error(_e):
        return render_template(
            "error.html", code=500, message="An internal error occurred."
        ), 500

    return app


if __name__ == "__main__":
    application = create_app()
    print(f" * WebShield running on http://{Config.HOST}:{Config.PORT} (local only)")
    application.run(host=Config.HOST, port=Config.PORT, debug=False)
