"""
File integrity monitor - protection against trojanised application code.

A Trojan horse does not always arrive as an upload: an attacker with server
access, or a compromised update, can quietly modify the application itself
(for example adding a hidden admin account to the login route). This module
keeps a manifest of SHA-256 hashes of every source file and reports any file
that was modified, deleted or added since the trusted baseline.

The baseline is created only from the command line by the developer:

    python -m security.integrity --build     # after a reviewed change
    python -m security.integrity --verify

The web interface can verify but never re-baseline, so an attacker who gains
access through the web cannot "approve" their own changes.
"""
import argparse
import hashlib
import json
import os
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "security", "integrity_manifest.json")

WATCH = ["app.py", "config.py", "routes", "security", "vulnerable", "database", "templates", "static"]
SKIP_DIRS = {"__pycache__"}
SKIP_SUFFIX = (".pyc", ".db", ".db-journal")
TEXT_SUFFIX = (".py", ".html", ".js", ".css", ".sql", ".svg", ".json", ".txt", ".md")


def _norm(rel: str) -> str:
    return rel.replace(os.sep, "/")


def iter_files(root: str):
    for entry in WATCH:
        path = os.path.join(root, entry)
        if os.path.isfile(path):
            yield _norm(entry)
        elif os.path.isdir(path):
            for dirpath, dirnames, filenames in os.walk(path):
                dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
                for f in sorted(filenames):
                    rel = _norm(os.path.relpath(os.path.join(dirpath, f), root))
                    if f.endswith(SKIP_SUFFIX) or rel == "security/integrity_manifest.json":
                        continue
                    yield rel


def file_hash(path: str) -> str:
    with open(path, "rb") as fh:
        data = fh.read()
    if path.endswith(TEXT_SUFFIX):
        data = data.replace(b"\r\n", b"\n")   # same hash on Windows and Linux checkouts
    return hashlib.sha256(data).hexdigest()


def compute(root: str = ROOT) -> dict:
    return {rel: file_hash(os.path.join(root, rel)) for rel in iter_files(root)}


def build_manifest(root: str = ROOT, manifest: str = MANIFEST) -> dict:
    data = {
        "algorithm": "SHA-256",
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "files": compute(root),
    }
    with open(manifest, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    return data


def verify(root: str = ROOT, manifest: str = MANIFEST) -> dict:
    if not os.path.exists(manifest):
        return {"ok": False, "baseline": None, "checked": 0, "modified": [], "missing": [], "added": [],
                "error": "No integrity manifest found. Run: python -m security.integrity --build"}
    with open(manifest, encoding="utf-8") as fh:
        base = json.load(fh)
    expected = base.get("files", {})
    current = compute(root)
    modified = sorted(f for f in expected if f in current and current[f] != expected[f])
    missing = sorted(f for f in expected if f not in current)
    added = sorted(f for f in current if f not in expected)
    return {"ok": not (modified or missing or added), "baseline": base.get("created"), "checked": len(current),
            "modified": modified, "missing": missing, "added": added, "error": None}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="WebShield source integrity monitor")
    ap.add_argument("--build", action="store_true", help="create a new trusted baseline")
    ap.add_argument("--verify", action="store_true", help="compare files with the baseline")
    args = ap.parse_args()
    if args.build:
        m = build_manifest()
        print(f"Baseline written: {len(m['files'])} files hashed with SHA-256 -> {MANIFEST}")
    else:
        r = verify()
        if r["error"]:
            print(r["error"])
        else:
            print(f"Checked {r['checked']} files against baseline {r['baseline']}: {'OK' if r['ok'] else 'CHANGED'}")
            for label in ("modified", "missing", "added"):
                for f in r[label]:
                    print(f"  {label.upper():8} {f}")
        raise SystemExit(0 if r["ok"] else 1)
