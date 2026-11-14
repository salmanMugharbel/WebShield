"""Trojan horse protection tests: upload scanner and source integrity monitor."""
import io
import json
import os
import re
import shutil
import sqlite3
import zipfile

from app import create_app
from security import integrity
from security.file_scanner import MAX_UPLOAD, scan
from security.trojan_samples import SAMPLES


def _token(client):
    html = client.get("/trojan/").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def _sample(key):
    name, data, _d, _e = SAMPLES[key]
    return scan(name, data)


def test_clean_files_accepted(case):
    case("TROJ-01", "invoice_2026.pdf, profile_photo.png, meeting_notes.txt, course_report.docx", "All four ACCEPTED")
    verdicts = {k: _sample(k)["verdict"] for k in ("clean_pdf", "clean_png", "clean_txt", "clean_docx")}
    case.actual = str(verdicts)
    assert set(verdicts.values()) == {"ACCEPTED"}


def test_real_upload_recorded(logged_in, case, app):
    case("TROJ-02", "multipart upload of report.pdf", "ACCEPTED; metadata and SHA-256 saved in file_scans; log NORMAL")
    data = SAMPLES["clean_pdf"][1]
    r = logged_in.post("/trojan/", data={"csrf_token": _token(logged_in), "action": "scan",
                                         "file": (io.BytesIO(data), "report.pdf")}, content_type="multipart/form-data")
    conn = sqlite3.connect(app.config["DATABASE"])
    row = conn.execute("SELECT filename, verdict, length(sha256) FROM file_scans").fetchone()
    log = conn.execute("SELECT security_status FROM activity_logs WHERE event_type='Trojan Horse'").fetchone()
    conn.close()
    case.actual = f"{r.status_code}, row={row}, log={log}"
    assert r.status_code == 200 and row == ("report.pdf", "ACCEPTED", 64) and log == ("NORMAL",)


def test_double_extension(case):
    case("TROJ-03", "invoice.pdf.exe (MZ content)", "BLOCKED: .exe not allowed, double extension, executable content")
    r = _sample("double_ext")
    fails = [c["rule"] for c in r["checks"] if c["status"] == "fail"]
    case.actual = f"{r['verdict']}, failed checks={fails}"
    assert r["verdict"] == "BLOCKED" and {"Extension allow-list", "Hidden extension", "Content signature"} <= set(fails)


def test_disguised_executable(case):
    case("TROJ-04", "holiday.jpg whose content starts with MZ", "BLOCKED by content signature (magic bytes)")
    r = _sample("disguised")
    fails = [c["rule"] for c in r["checks"] if c["status"] == "fail"]
    case.actual = f"{r['verdict']}, detected={r['detected']}, failed={fails}"
    assert r["verdict"] == "BLOCKED" and fails == ["Content signature"]


def test_rtlo_name(logged_in, case):
    case("TROJ-05", "invoice[U+202E]fdp.exe", "BLOCKED; hidden character shown as [U+202E] on the page")
    r = logged_in.post("/trojan/", data={"csrf_token": _token(logged_in), "action": "scan", "sample": "rtlo"})
    html = r.get_data(as_text=True)
    res = _sample("rtlo")
    case.actual = f"{res['verdict']}, visible name={res['filename']}, page shows marker={'[U+202E]' in html}, raw char on page={chr(0x202e) in html.split('Scan result')[1]}"
    assert res["verdict"] == "BLOCKED" and "[U+202E]" in html and chr(0x202e) not in html.split("Scan result")[1]


def test_macro_document(case):
    case("TROJ-06", "salary_review.docx with vbaProject.bin; report.docm", "Both BLOCKED")
    a = _sample("macro_docx")
    b = scan("report.docm", SAMPLES["macro_docx"][1])
    case.actual = f"docx={a['verdict']} ({a['reasons'][0]}), docm={b['verdict']}"
    assert a["verdict"] == b["verdict"] == "BLOCKED" and "macro" in a["reasons"][0].lower()


def test_known_bad_hash(case):
    case("TROJ-07", "free_game.txt (fictional sample on blocklist)", "BLOCKED by known-malware SHA-256")
    r = _sample("known_bad")
    case.actual = f"{r['verdict']}, reasons={r['reasons']}"
    assert r["verdict"] == "BLOCKED" and any("blocklist" in x for x in r["reasons"])


def test_script_droppers(case):
    case("TROJ-08", "update.ps1, run.js, setup.bat, macro.vbs, page.html", "All BLOCKED by extension allow-list")
    names = ["update.ps1", "run.js", "setup.bat", "macro.vbs", "page.html"]
    verdicts = {n: scan(n, b"harmless text")["verdict"] for n in names}
    case.actual = str(verdicts)
    assert set(verdicts.values()) == {"BLOCKED"}


def test_polyglot_and_pdf_launch(case):
    case("TROJ-09", "avatar.png with appended <script>; statement.pdf with /Launch", "PNG SUSPICIOUS; PDF BLOCKED")
    a, b = _sample("polyglot"), _sample("pdf_launch")
    case.actual = f"png={a['verdict']}, pdf={b['verdict']}"
    assert a["verdict"] == "SUSPICIOUS" and b["verdict"] == "BLOCKED"


def test_size_limits(logged_in, case):
    case("TROJ-10", "empty.txt, 1 MB + 1 byte file, 3 MB request", "Empty and oversize BLOCKED; 3 MB request rejected with 413")
    empty = scan("empty.txt", b"")["verdict"]
    big = scan("big.txt", b"a" * (MAX_UPLOAD + 1))["verdict"]
    r = logged_in.post("/trojan/", data={"csrf_token": _token(logged_in), "action": "scan",
                                         "file": (io.BytesIO(b"a" * (3 * 1024 * 1024)), "huge.txt")},
                       content_type="multipart/form-data")
    case.actual = f"empty={empty}, oversize={big}, 3 MB request status={r.status_code}"
    assert empty == big == "BLOCKED" and r.status_code == 413


def test_requires_login_and_csrf(client, logged_in, case):
    case("TROJ-11", "POST /trojan/ without login; then logged in without CSRF token", "302 to login; 400")
    anon = create_app({"TESTING": True, "DATABASE": logged_in.application.config["DATABASE"],
                       "SKIP_INTEGRITY_CHECK": True}).test_client().get("/trojan/")
    r = logged_in.post("/trojan/", data={"action": "scan", "sample": "clean_pdf"})
    case.actual = f"anonymous={anon.status_code}, no token={r.status_code}"
    assert anon.status_code == 302 and r.status_code == 400


def test_upload_never_stored(logged_in, case, app, tmp_path):
    case("TROJ-12", "upload a file containing a unique marker", "Marker absent from the database; no upload directory created")
    marker = b"UNIQUE-MARKER-7f3c9a"
    logged_in.post("/trojan/", data={"csrf_token": _token(logged_in), "action": "scan",
                                     "file": (io.BytesIO(b"notes " + marker), "notes.txt")}, content_type="multipart/form-data")
    with open(app.config["DATABASE"], "rb") as fh:
        in_db = marker in fh.read()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    upload_dirs = [d for d in ("uploads", "static/uploads") if os.path.exists(os.path.join(root, d))]
    case.actual = f"marker in DB={in_db}, upload dirs={upload_dirs}"
    assert not in_db and not upload_dirs


def _copy_project(tmp_path):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dst = tmp_path / "proj"
    for entry in integrity.WATCH:
        src = os.path.join(root, entry)
        if os.path.isdir(src):
            shutil.copytree(src, dst / entry, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.db"))
        else:
            os.makedirs(dst, exist_ok=True)
            shutil.copy(src, dst / entry)
    return str(dst)


def test_integrity_detects_modification(case, tmp_path):
    case("TROJ-13", "add a backdoor line to routes/auth.py after the baseline", "Verify reports routes/auth.py as MODIFIED")
    root = _copy_project(tmp_path)
    manifest = str(tmp_path / "m.json")
    integrity.build_manifest(root, manifest)
    clean = integrity.verify(root, manifest)["ok"]
    with open(os.path.join(root, "routes", "auth.py"), "a", encoding="utf-8") as fh:
        fh.write("\n# simulated Trojan: if username == 'ghost': grant admin\n")
    r = integrity.verify(root, manifest)
    case.actual = f"before change ok={clean}; after: ok={r['ok']}, modified={r['modified']}"
    assert clean and not r["ok"] and r["modified"] == ["routes/auth.py"]


def test_integrity_detects_added_and_missing(case, tmp_path):
    case("TROJ-14", "delete security/csrf.py and add static/js/miner.js", "Verify reports one MISSING and one ADDED file")
    root = _copy_project(tmp_path)
    manifest = str(tmp_path / "m.json")
    integrity.build_manifest(root, manifest)
    os.remove(os.path.join(root, "security", "csrf.py"))
    with open(os.path.join(root, "static", "js", "miner.js"), "w") as fh:
        fh.write("// simulated injected script")
    r = integrity.verify(root, manifest)
    case.actual = f"missing={r['missing']}, added={r['added']}"
    assert r["missing"] == ["security/csrf.py"] and r["added"] == ["static/js/miner.js"]


def test_startup_check_logs_tampering(case, tmp_path):
    case("TROJ-15", "start the app with a baseline that does not match the code", "Start-up writes an Integrity DETECTED log entry")
    manifest = tmp_path / "bad.json"
    manifest.write_text(json.dumps({"created": "test", "files": {"app.py": "0" * 64}}))
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "s.db"), "INTEGRITY_MANIFEST": str(manifest)})
    conn = sqlite3.connect(app.config["DATABASE"])
    rows = conn.execute("SELECT security_status, description FROM activity_logs WHERE event_type='Integrity'").fetchall()
    conn.close()
    case.actual = f"log={rows}"
    assert rows and rows[0][0] == "DETECTED"


def test_filename_escaped(logged_in, case):
    case("TROJ-16", "upload named <script>alert(1)</script>.txt", "File name shown as encoded text in result and history")
    logged_in.post("/trojan/", data={"csrf_token": _token(logged_in), "action": "scan",
                                     "file": (io.BytesIO(b"hello"), "<script>alert(1)</script>.txt")},
                   content_type="multipart/form-data")
    html = logged_in.get("/trojan/").get_data(as_text=True)
    case.actual = f"raw tag present={'<script>alert(1)' in html}, encoded={'&lt;script&gt;alert(1)' in html}"
    assert "<script>alert(1)" not in html and "&lt;script&gt;alert(1)" in html


def test_zip_bomb(case):
    case("TROJ-17", "report.docx expanding to 25 MB of zeros", "BLOCKED as a possible ZIP bomb")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/big.bin", b"\0" * (25 * 1024 * 1024))
    r = scan("report.docx", buf.getvalue())
    case.actual = f"compressed={len(buf.getvalue()):,} bytes, verdict={r['verdict']}, reason={r['reasons'][0]}"
    assert r["verdict"] == "BLOCKED" and "ZIP bomb" in r["reasons"][0]
