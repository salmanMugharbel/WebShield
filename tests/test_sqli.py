"""SQL Injection laboratory tests (vulnerable vs. secure)."""
import re
import sqlite3

import pytest

from vulnerable.sqli_sandbox import secure_login, vulnerable_login


def _lab(client, username, password):
    html = client.get("/sqli/").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    return client.post("/sqli/", data={"username": username, "password": password, "csrf_token": token})


def test_normal_login(case):
    case("SQLI-01", "alice / Wonderland1", "Both implementations log in as alice")
    v, s = vulnerable_login("alice", "Wonderland1"), secure_login("alice", "Wonderland1")
    case.actual = f"vulnerable={v['user']}, secure={s['user']}"
    assert v["user"] == "alice" and s["user"] == "alice"


def test_invalid_login(case):
    case("SQLI-02", "alice / wrongpass", "Both implementations refuse the login")
    v, s = vulnerable_login("alice", "wrongpass"), secure_login("alice", "wrongpass")
    case.actual = f"vulnerable auth={v['authenticated']}, secure auth={s['authenticated']}"
    assert not v["authenticated"] and not s["authenticated"]


def test_special_characters(case):
    case("SQLI-03", "O'Brien / anything", "Vulnerable: query syntax error; Secure: handled normally (no match)")
    v, s = vulnerable_login("O'Brien", "anything"), secure_login("O'Brien", "anything")
    case.actual = f"vulnerable error={bool(v['error'])}, secure error={s['error']}, secure auth={s['authenticated']}"
    assert v["error"] and s["error"] is None and not s["authenticated"]


@pytest.mark.parametrize("cid,payload,expected_user", [
    ("SQLI-04", "' OR '1'='1' --", "alice"),
    ("SQLI-05", "lab_admin' --", "lab_admin"),
    ("SQLI-06", "' OR 1=1 LIMIT 1 OFFSET 2 --", "lab_admin"),
])
def test_injection_bypasses_vulnerable_only(case, cid, payload, expected_user):
    case(cid, f"{payload} / anything", f"Vulnerable bypassed as {expected_user}; Secure refused")
    v, s = vulnerable_login(payload, "anything"), secure_login(payload, "anything")
    case.actual = f"vulnerable user={v['user']}, secure auth={s['authenticated']}"
    assert v["user"] == expected_user and not s["authenticated"]


def test_union_injection(case):
    case("SQLI-07", "x' UNION SELECT 1, sqlite_version(), 'injected' --", "Vulnerable returns attacker-chosen row; Secure returns nothing")
    payload = "x' UNION SELECT 1, sqlite_version(), 'injected' --"
    v, s = vulnerable_login(payload, "x"), secure_login(payload, "x")
    case.actual = f"vulnerable role={v['role']}, secure rows={len(s['rows'])}"
    assert v["role"] == "injected" and s["rows"] == []


def test_stacked_query_cannot_modify(case):
    case("SQLI-08", "x'; DROP TABLE lab_users; --", "Rejected (single statement only); table still exists")
    v = vulnerable_login("x'; DROP TABLE lab_users; --", "x")
    after = vulnerable_login("alice", "Wonderland1")
    case.actual = f"error={v['error']!r}, alice still logs in={after['authenticated']}"
    assert v["error"] and after["authenticated"]


def test_sandbox_is_read_only(case):
    case("SQLI-09", "x' OR (WITH RECURSIVE c(n) AS (...) SELECT count(*) FROM c) --", "Sandbox authorizer refuses recursive / non-SELECT operations")
    v = vulnerable_login("x' OR (WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c) SELECT count(*) FROM c) --", "x")
    case.actual = f"error={v['error']!r}"
    assert v["error"] and "sandbox refused" in v["error"]


def test_parameterised_query_structure_fixed(case):
    case("SQLI-10", "' OR '1'='1' --", "Secure SQL text identical for any input (only ? placeholders)")
    s1, s2 = secure_login("' OR '1'='1' --", "a"), secure_login("alice", "b")
    case.actual = f"same SQL text={s1['query'] == s2['query']}, payload in SQL={'OR' in s1['query']}"
    assert s1["query"] == s2["query"] and "OR '1'" not in s1["query"]


def test_lab_page_comparison_and_logging(logged_in, case, app):
    case("SQLI-11", "POST /sqli/ username=lab_admin' --", "Page shows bypass on vulnerable + block on secure; logs EXPLOITED & BLOCKED")
    r = _lab(logged_in, "lab_admin' --", "anything")
    html = r.get_data(as_text=True)
    conn = sqlite3.connect(app.config["DATABASE"])
    statuses = [row[0] for row in conn.execute(
        "SELECT security_status FROM activity_logs WHERE event_type = 'SQL Injection'")]
    conn.close()
    case.actual = f"{r.status_code}, bypass shown={'Authentication BYPASSED' in html}, logs={statuses}"
    assert "Authentication BYPASSED" in html and "Injection BLOCKED" in html
    assert set(statuses) == {"EXPLOITED", "BLOCKED"}


def test_no_password_in_logs(logged_in, case, app):
    case("SQLI-12", "POST /sqli/ alice / Wonderland1", "Password text never written to activity_logs")
    _lab(logged_in, "alice", "Wonderland1")
    conn = sqlite3.connect(app.config["DATABASE"])
    text = " ".join(row[0] for row in conn.execute("SELECT description FROM activity_logs"))
    conn.close()
    case.actual = f"password present in logs={'Wonderland1' in text}"
    assert "Wonderland1" not in text


def test_main_db_untouched_by_lab(logged_in, case, app):
    case("SQLI-13", "x' UNION SELECT id, username, password_hash FROM users --", "Fails: main users table is not reachable from the sandbox")
    v = vulnerable_login("x' UNION SELECT id, username, password_hash FROM users --", "x")
    case.actual = f"authenticated={v['authenticated']}, error={v['error']!r}"
    assert not v["authenticated"] and v["error"]


def test_lab_input_length_limit(logged_in, case):
    case("SQLI-14", "username of 201 characters", "400, rejected by server-side validation")
    r = _lab(logged_in, "a" * 201, "x")
    case.actual = str(r.status_code)
    assert r.status_code == 400
