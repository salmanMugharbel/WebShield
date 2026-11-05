"""Authentication, session, CSRF and database tests (secure main application)."""
import sqlite3


def _register(client, csrf, username, password, confirm=None):
    return client.post("/register", data={
        "username": username, "password": password,
        "confirm": confirm if confirm is not None else password,
        "csrf_token": csrf("/register"),
    })


def test_register_and_login(client, csrf, case, app):
    case("AUTH-01", "register alice_test / Secret123, then log in", "302 redirect to dashboard, session created")
    r = _register(client, csrf, "alice_test", "Secret123")
    assert r.status_code == 302
    r = client.post("/login", data={"username": "alice_test", "password": "Secret123", "csrf_token": csrf()})
    with client.session_transaction() as s:
        uid = s.get("user_id")
    case.actual = f"register {r.status_code}, login redirect, user_id in session={uid is not None}"
    assert r.status_code == 302 and uid is not None


def test_password_is_hashed(client, csrf, case, app):
    case("AUTH-02", "register bob_test / Secret123", "users.password_hash is a salted hash, not plaintext")
    _register(client, csrf, "bob_test", "Secret123")
    conn = sqlite3.connect(app.config["DATABASE"])
    stored = conn.execute("SELECT password_hash FROM users WHERE username = ?", ("bob_test",)).fetchone()[0]
    conn.close()
    case.actual = f"stored value starts with '{stored.split('$')[0]}', plaintext present={'Secret123' in stored}"
    assert "Secret123" not in stored and stored.startswith(("scrypt:", "pbkdf2:"))


def test_invalid_login(client, csrf, case):
    case("AUTH-03", "demo_student / WrongPass1", "401, generic 'Invalid username or password'")
    r = client.post("/login", data={"username": "demo_student", "password": "WrongPass1", "csrf_token": csrf()})
    body = r.get_data(as_text=True)
    case.actual = f"{r.status_code}, generic message shown={'Invalid username or password' in body}"
    assert r.status_code == 401 and "Invalid username or password" in body


def test_unknown_user_same_message(client, csrf, case):
    case("AUTH-04", "nobody_here / Whatever1", "401 with the same generic message (no user enumeration)")
    r = client.post("/login", data={"username": "nobody_here", "password": "Whatever1", "csrf_token": csrf()})
    body = r.get_data(as_text=True)
    case.actual = f"{r.status_code}, generic message shown={'Invalid username or password' in body}"
    assert r.status_code == 401 and "Invalid username or password" in body


def test_sqli_against_real_login(client, csrf, case):
    case("AUTH-05", "username: ' OR '1'='1' --  password: x", "Login refused (main app uses parameterised SQL)")
    r = client.post("/login", data={"username": "' OR '1'='1' --", "password": "x", "csrf_token": csrf()})
    with client.session_transaction() as s:
        uid = s.get("user_id")
    case.actual = f"{r.status_code}, session user_id={uid}"
    assert r.status_code == 401 and uid is None


def test_server_side_validation(client, csrf, case):
    case("AUTH-06", "username 'a<b>' / password 'short'", "400, registration rejected by server validation")
    r = _register(client, csrf, "a<b>", "short")
    case.actual = f"{r.status_code}, validation message shown={'Username must be' in r.get_data(as_text=True)}"
    assert r.status_code == 400


def test_duplicate_username(client, csrf, case):
    case("AUTH-07", "register demo_student again", "400 'already taken' (UNIQUE constraint)")
    r = _register(client, csrf, "demo_student", "Another123")
    case.actual = f"{r.status_code}, 'already taken' shown={'already taken' in r.get_data(as_text=True)}"
    assert r.status_code == 400 and "already taken" in r.get_data(as_text=True)


def test_csrf_required(client, case):
    case("AUTH-08", "POST /login without csrf_token", "400 Bad Request")
    client.get("/login")
    r = client.post("/login", data={"username": "demo_student", "password": "DemoPass123"})
    case.actual = str(r.status_code)
    assert r.status_code == 400


def test_logout_and_protected_pages(logged_in, case):
    case("AUTH-09", "log out, then GET /sqli/", "302 redirect to /login (authorisation enforced)")
    html = logged_in.get("/").get_data(as_text=True)
    import re
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    logged_in.post("/logout", data={"csrf_token": token})
    r = logged_in.get("/sqli/")
    case.actual = f"{r.status_code} -> {r.headers.get('Location')}"
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_session_cookie_flags(client, csrf, case):
    case("AUTH-10", "successful login", "Set-Cookie has HttpOnly and SameSite=Strict")
    r = client.post("/login", data={"username": "demo_student", "password": "DemoPass123", "csrf_token": csrf()})
    cookie = r.headers.get("Set-Cookie", "")
    case.actual = f"HttpOnly={'HttpOnly' in cookie}, SameSite=Strict={'SameSite=Strict' in cookie}"
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_security_headers_and_errors(client, case):
    case("AUTH-11", "GET /does-not-exist", "Generic 404 page, CSP header without unsafe-inline")
    r = client.get("/does-not-exist")
    csp = r.headers.get("Content-Security-Policy", "")
    case.actual = f"{r.status_code}, CSP script-src 'self' only={'unsafe-inline' not in csp}, traceback={'Traceback' in r.get_data(as_text=True)}"
    assert r.status_code == 404 and "script-src 'self'" in csp and "unsafe-inline" not in csp


def test_open_redirect_blocked(client, csrf, case):
    case("AUTH-12", "POST /login?next=//evil.example", "Redirect stays on site ('/')")
    r = client.post("/login?next=//evil.example", data={
        "username": "demo_student", "password": "DemoPass123", "csrf_token": csrf()})
    case.actual = f"Location={r.headers.get('Location')}"
    assert r.headers["Location"] == "/"
