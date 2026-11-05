"""
Shared pytest fixtures.

Every test gets a fresh temporary database, so tests never touch the real
database/webshield.db file.

The `case` fixture records Test-ID / Input / Expected / Actual for each test.
After the run, docs/TEST_REPORT.md is generated from the ACTUAL outcomes, so no
test can be reported as passed without having been executed.
"""
import os
import re
import sys
from datetime import datetime

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import create_app  # noqa: E402

_RECORDS = {}


@pytest.fixture
def app(tmp_path):
    application = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.db")})
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


def get_csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF token not found in page"
    return match.group(1)


@pytest.fixture
def csrf(client):
    return lambda path="/login": get_csrf(client, path)


@pytest.fixture
def logged_in(client):
    token = get_csrf(client)
    resp = client.post("/login", data={
        "username": "demo_student", "password": "DemoPass123", "csrf_token": token,
    })
    assert resp.status_code == 302
    return client


class Case:
    def __init__(self, nodeid):
        self.nodeid = nodeid
        self.id = self.input = self.expected = self.actual = ""

    def __call__(self, case_id, input_value, expected):
        self.id, self.input, self.expected = case_id, input_value, expected
        return self


@pytest.fixture
def case(request):
    c = Case(request.node.nodeid)
    _RECORDS[request.node.nodeid] = {"case": c, "outcome": "not run"}
    return c


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    rec = _RECORDS.get(item.nodeid)
    if rec is None:
        return
    if rep.when == "call":
        rec["outcome"] = "PASS" if rep.passed else "FAIL"
        if rep.failed and not rec["case"].actual:
            rec["case"].actual = "Assertion failed: " + str(rep.longrepr).splitlines()[-1][:150]
    elif rep.failed:
        rec["outcome"] = "ERROR"


def _md(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def pytest_sessionfinish(session, exitstatus):
    if not _RECORDS:
        return
    rows = sorted(_RECORDS.values(), key=lambda r: r["case"].id)
    passed = sum(1 for r in rows if r["outcome"] == "PASS")
    lines = [
        "# WebShield - Test Execution Report",
        "",
        f"Generated automatically by `pytest` on {datetime.now():%Y-%m-%d %H:%M:%S}.",
        "Every row below comes from an actual test execution (see `tests/conftest.py`).",
        "",
        f"**Result: {passed} / {len(rows)} test cases passed.**",
        "",
        "| Test ID | Input | Expected result | Actual result | Status |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        c = r["case"]
        lines.append(
            f"| {_md(c.id)} | `{_md(c.input)}` | {_md(c.expected)} | {_md(c.actual)} | **{r['outcome']}** |"
        )
    out = os.path.join(ROOT, "docs", "TEST_REPORT.md")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
