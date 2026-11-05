"""XSS laboratory tests (unsafe sandbox rendering vs. secure encoding)."""
import os
import re
import sqlite3

from security.safe_rendering import html_encode

SCRIPT = "<script>alert('XSS')</script>"
IMG = "<img src=x onerror=\"alert(1)\">"


def _token(client, path="/xss/"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def _post_comment(client, text):
    return client.post("/xss/comment", data={"comment": text, "csrf_token": _token(client)})


def _secure_comment_list(html):
    # the secure list lives in <ul class="comments"> on the main lab page
    return html.split('<ul class="comments">', 1)[1].split("</ul>", 1)[0]


def test_normal_comment(logged_in, case, app):
    case("XSS-01", "Hello WebShield", "Saved to DB and displayed unchanged")
    r = _post_comment(logged_in, "Hello WebShield")
    html = logged_in.get("/xss/").get_data(as_text=True)
    conn = sqlite3.connect(app.config["DATABASE"])
    stored = conn.execute("SELECT comment_content FROM comments ORDER BY id DESC LIMIT 1").fetchone()[0]
    conn.close()
    case.actual = f"{r.status_code}, stored={stored!r}, displayed={'Hello WebShield' in _secure_comment_list(html)}"
    assert stored == "Hello WebShield" and "Hello WebShield" in _secure_comment_list(html)


def test_html_comment_encoded(logged_in, case):
    case("XSS-02", "<b>bold</b>", "Secure view shows &lt;b&gt;bold&lt;/b&gt; (text, not formatting)")
    _post_comment(logged_in, "<b>bold</b>")
    secure = _secure_comment_list(logged_in.get("/xss/").get_data(as_text=True))
    case.actual = f"encoded={'&lt;b&gt;bold&lt;/b&gt;' in secure}, raw tag present={'<b>bold</b>' in secure}"
    assert "&lt;b&gt;bold&lt;/b&gt;" in secure and "<b>bold</b>" not in secure


def test_stored_script_secure_vs_vulnerable(logged_in, case):
    case("XSS-03", SCRIPT, "Secure page: encoded text; vulnerable sandbox page: raw <script> (isolated)")
    _post_comment(logged_in, SCRIPT)
    secure = _secure_comment_list(logged_in.get("/xss/").get_data(as_text=True))
    sandbox = logged_in.get("/xss/sandbox/stored").get_data(as_text=True)
    case.actual = f"secure encoded={'&lt;script&gt;' in secure}, sandbox raw={SCRIPT in sandbox}"
    assert "&lt;script&gt;" in secure and "<script>alert" not in secure
    assert SCRIPT in sandbox


def test_stored_img_onerror(logged_in, case, app):
    case("XSS-04", IMG, "Secure page encodes the tag; activity log records EXPLOITED + BLOCKED")
    _post_comment(logged_in, IMG)
    secure = _secure_comment_list(logged_in.get("/xss/").get_data(as_text=True))
    conn = sqlite3.connect(app.config["DATABASE"])
    statuses = {r[0] for r in conn.execute("SELECT security_status FROM activity_logs WHERE event_type='Stored XSS'")}
    conn.close()
    case.actual = f"encoded={'&lt;img' in secure}, log statuses={sorted(statuses)}"
    assert "&lt;img" in secure and "<img src=x" not in secure and statuses == {"EXPLOITED", "BLOCKED"}


def test_reflected_search(logged_in, case):
    case("XSS-05", f"GET /xss/?q={SCRIPT}", "Main page shows encoded text; raw payload only in sandbox iframe page")
    html = logged_in.get("/xss/", query_string={"q": SCRIPT}).get_data(as_text=True)
    sandbox = logged_in.get("/xss/sandbox/reflected", query_string={"q": SCRIPT}).get_data(as_text=True)
    case.actual = f"main raw script={SCRIPT in html}, main encoded={'&lt;script&gt;' in html}, sandbox raw={SCRIPT in sandbox}"
    assert SCRIPT not in html and "&lt;script&gt;" in html and SCRIPT in sandbox


def test_reflected_normal_text(logged_in, case):
    case("XSS-06", "GET /xss/?q=firewall", "Search term displayed; logged as NORMAL")
    html = logged_in.get("/xss/", query_string={"q": "firewall"}).get_data(as_text=True)
    case.actual = f"displayed={'<mark>firewall</mark>' in html}, badge NORMAL={'NORMAL TEXT' in html}"
    assert "<mark>firewall</mark>" in html and "NORMAL TEXT" in html


def test_sandbox_isolation_headers(client, case):
    case("XSS-07", "GET /xss/sandbox/reflected", "CSP 'sandbox' (opaque origin) and connect-src 'none'")
    r = client.get("/xss/sandbox/reflected", query_string={"q": "x"})
    csp = r.headers.get("Content-Security-Policy", "")
    case.actual = csp[:80] + "..."
    assert csp.startswith("sandbox allow-scripts") and "allow-same-origin" not in csp
    assert "connect-src 'none'" in csp


def test_main_csp_blocks_inline(logged_in, case):
    case("XSS-08", "GET /xss/", "Main CSP has script-src 'self' (no unsafe-inline); iframes have sandbox attribute")
    r = logged_in.get("/xss/")
    html = r.get_data(as_text=True)
    csp = r.headers["Content-Security-Policy"]
    frames = re.findall(r"<iframe[^>]*>", html)
    case.actual = f"unsafe-inline={'unsafe-inline' in csp}, frames={len(frames)}, all sandboxed={all('sandbox=' in f for f in frames)}"
    assert "unsafe-inline" not in csp and frames and all('sandbox="allow-scripts allow-modals"' in f for f in frames)


def test_dom_secure_uses_textcontent(case):
    case("XSS-09", "static/js/main.js and templates", "Main-app JS writes untrusted data with textContent, never innerHTML")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "js", "main.js"), encoding="utf-8").read()
    code_only = "\n".join(l for l in js.splitlines() if not l.strip().startswith(("*", "/*", "//")))
    dom = open(os.path.join(root, "templates", "vulnerable", "dom.html"), encoding="utf-8").read()
    case.actual = f"main.js innerHTML={'innerHTML' in code_only}, textContent={'textContent' in code_only}, sandbox uses innerHTML={'innerHTML' in dom}"
    assert "innerHTML" not in code_only and "textContent" in code_only and "innerHTML" in dom


def test_dom_log_endpoint(logged_in, case, app):
    case("XSS-10", f"POST /xss/dom-log payload={IMG}", "204; logged as DOM-based XSS EXPLOITED + BLOCKED")
    r = logged_in.post("/xss/dom-log", data={"payload": IMG, "csrf_token": _token(logged_in)})
    conn = sqlite3.connect(app.config["DATABASE"])
    statuses = {x[0] for x in conn.execute("SELECT security_status FROM activity_logs WHERE event_type='DOM-based XSS'")}
    conn.close()
    case.actual = f"{r.status_code}, statuses={sorted(statuses)}"
    assert r.status_code == 204 and statuses == {"EXPLOITED", "BLOCKED"}


def test_comment_validation(logged_in, case):
    case("XSS-11", "empty comment and 501-character comment", "Both rejected; nothing stored")
    before = logged_in.get("/xss/").get_data(as_text=True).count('class="comment-body"')
    _post_comment(logged_in, "   ")
    _post_comment(logged_in, "a" * 501)
    after = logged_in.get("/xss/").get_data(as_text=True).count('class="comment-body"')
    case.actual = f"comments before={before}, after={after}"
    assert before == after


def test_cannot_delete_others_comment(client, csrf, case):
    case("XSS-12", "user mallory_x deletes demo_student's comment #1", "403 Forbidden (authorisation)")
    client.post("/register", data={"username": "mallory_x", "password": "Mallory123",
                                   "confirm": "Mallory123", "csrf_token": csrf("/register")})
    client.post("/login", data={"username": "mallory_x", "password": "Mallory123", "csrf_token": csrf()})
    r = client.post("/xss/comment/1/delete", data={"csrf_token": _token(client)})
    case.actual = str(r.status_code)
    assert r.status_code == 403


def test_html_encode_helper(case):
    case("XSS-13", "<a href=\"x\" onclick='y'>&</a>", "All of & < > \" ' encoded")
    out = html_encode("<a href=\"x\" onclick='y'>&</a>")
    case.actual = out
    assert "<" not in out and ">" not in out and '"' not in out and "'" not in out and "&amp;" in out
