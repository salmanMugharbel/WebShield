"""Attack catalogue and SQL Injection technique organisation tests."""
import glob
import os
import re
import sqlite3

from security.attack_catalog import ATTACKS, CATEGORIES
from security.validation import classify_sqli_technique

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ids(found):
    return [t for t, _ in found]


def test_catalogue_page(client, case):
    case("ATK-01", "GET /attacks", f"{len(CATEGORIES)} categories and {len(ATTACKS)} attacks listed, public page")
    html = client.get("/attacks").get_data(as_text=True)
    cats = sum(1 for key, *_ in CATEGORIES if f'id="cat-{key}"' in html)
    rows = sum(1 for a in ATTACKS if f"<code>{a[0]}</code>" in html)
    case.actual = f"categories={cats}, attack rows={rows}"
    assert cats == len(CATEGORIES) and rows == len(ATTACKS)


def test_catalogue_consistency(app, case):
    case("ATK-02", "every catalogue entry", "Has a defence, a valid lab link, an OWASP code and only test IDs that exist in the suite")
    text = "".join(open(f, encoding="utf-8").read() for f in glob.glob(os.path.join(ROOT, "tests", "test_*.py")))
    existing = set(re.findall(r'"([A-Z]+-\d+)"', text))
    problems = []
    with app.test_request_context():
        from flask import url_for
        for a in ATTACKS:
            try:
                url_for(a[7])
            except Exception:
                problems.append(f"{a[0]} bad lab")
            missing = [t for t in a[8] if t not in existing]
            if not a[6] or not a[3] or not a[8] or missing:
                problems.append(f"{a[0]} {missing}")
    case.actual = f"{len(ATTACKS)} entries checked, problems={problems}"
    assert not problems


def test_tautology(case):
    case("SQLI-15", "' OR '1'='1' --  and  ' OR 1=1 LIMIT 1 OFFSET 2 --", "Classified as SQLI-T1 tautology")
    a, b = classify_sqli_technique("' OR '1'='1' --"), classify_sqli_technique("' OR 1=1 LIMIT 1 OFFSET 2 --")
    case.actual = f"{_ids(a)}, {_ids(b)}"
    assert _ids(a) == _ids(b) == ["SQLI-T1"]


def test_comment_truncation(case):
    case("SQLI-16", "lab_admin' --  and  bob' /*", "Classified as SQLI-T2 comment truncation")
    a, b = classify_sqli_technique("lab_admin' --"), classify_sqli_technique("bob' /*")
    case.actual = f"{_ids(a)}, {_ids(b)}"
    assert _ids(a) == _ids(b) == ["SQLI-T2"]


def test_union(case):
    case("SQLI-17", "x' UNION SELECT id, username, role FROM lab_users --", "Classified as SQLI-T3 UNION")
    r = classify_sqli_technique("x' UNION SELECT id, username, role FROM lab_users --")
    case.actual = str(_ids(r))
    assert _ids(r) == ["SQLI-T3"]


def test_stacked(case):
    case("SQLI-18", "x'; DROP TABLE lab_users; --", "Classified as SQLI-T4 stacked queries")
    r = classify_sqli_technique("x'; DROP TABLE lab_users; --")
    case.actual = str(_ids(r))
    assert _ids(r) == ["SQLI-T4"]


def test_error_blind_and_normal(case):
    case("SQLI-19", "'  /  alice' AND 1=2 --  /  alice  /  Sir Lancelot or knight", "T5, T6, and nothing for normal text")
    r = [_ids(classify_sqli_technique(x)) for x in ("'", "alice' AND 1=2 --", "alice", "Sir Lancelot or knight")]
    case.actual = str(r)
    assert r == [["SQLI-T5"], ["SQLI-T6"], [], []]


def test_lab_groups_and_log(logged_in, case, app):
    case("SQLI-20", "POST /sqli/ username=bob' /*", "Page groups inputs by technique, shows SQLI-T2 badge; log names the technique")
    html = logged_in.get("/sqli/").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    r = logged_in.post("/sqli/", data={"username": "bob' /*", "password": "x", "csrf_token": token})
    page = r.get_data(as_text=True)
    conn = sqlite3.connect(app.config["DATABASE"])
    logs = [x[0] for x in conn.execute("SELECT description FROM activity_logs WHERE event_type='SQL Injection'")]
    conn.close()
    groups = page.count('class="tech-head"')
    case.actual = f"technique groups={groups}, badge={'SQLI-T2 · Comment truncation' in page}, log tagged={all('[SQLI-T2' in x for x in logs)}"
    assert groups == 7 and "SQLI-T2 · Comment truncation" in page and logs and all("[SQLI-T2" in x for x in logs)
