"""Hashing laboratory and password-storage tests (Module H)."""
import re
import sqlite3

from werkzeug.security import generate_password_hash

from security.hashing import avalanche, cost_comparison, digest, hash_all, hmac_demo, salting_demo
from security.password import PASSWORD_METHOD


def _token(client, path="/hashing/"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def test_known_vectors(case):
    case("HASH-01", "abc", "Digests match published test vectors (MD5, SHA-1, SHA-256, SHA3-256)")
    got = {n: digest(n, b"abc") for n in ("md5", "sha1", "sha256", "sha3_256")}
    expected = {
        "md5": "900150983cd24fb0d6963f7d28e17f72",
        "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha3_256": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    }
    case.actual = "all match" if got == expected else f"mismatch: {got}"
    assert got == expected


def test_fixed_output_length(case):
    case("HASH-02", "'a' and a 200-character string", "Digest length depends only on the algorithm")
    short, long = hash_all("a"), hash_all("x" * 200)
    same = all(len(s["hex"]) == len(l["hex"]) for s, l in zip(short, long))
    case.actual = f"11 algorithms, same length for both inputs={same}; SHA-256 bits={short[4]['bits']}"
    assert same and short[4]["bits"] == 256


def test_deterministic(case):
    case("HASH-03", "WebShield hashed twice", "Identical digest both times")
    a, b = digest("sha256", b"WebShield"), digest("sha256", b"WebShield")
    case.actual = f"equal={a == b}"
    assert a == b


def test_avalanche(case):
    case("HASH-04", "WebShield vs WebShielD", "About half of the 256 SHA-256 bits change (30-70%)")
    r = avalanche("WebShield", "WebShielD")
    case.actual = f"{r['diff']} / {r['bits']} bits changed ({r['pct']}%)"
    assert 30 <= r["pct"] <= 70


def test_salting(case):
    case("HASH-05", "Summer2026 hashed for two users", "Unsalted hashes equal; salted hashes differ")
    r = salting_demo("Summer2026")
    case.actual = f"unsalted equal={r['unsalted_equal']}, salted equal={r['salted_equal']}"
    assert r["unsalted_equal"] and not r["salted_equal"]


def test_password_storage_method(client, csrf, case, app):
    case("HASH-06", "register hash_user / Secret123", f"Stored as {PASSWORD_METHOD} with salt, no plaintext")
    client.post("/register", data={"username": "hash_user", "password": "Secret123",
                                   "confirm": "Secret123", "csrf_token": csrf("/register")})
    conn = sqlite3.connect(app.config["DATABASE"])
    stored = conn.execute("SELECT password_hash FROM users WHERE username='hash_user'").fetchone()[0]
    conn.close()
    method, salt, hexd = stored.split("$")
    case.actual = f"method={method}, salt length={len(salt)}, digest bits={len(hexd) * 4}, plaintext present={'Secret123' in stored}"
    assert method == PASSWORD_METHOD and len(salt) >= 16 and "Secret123" not in stored


def test_rehash_on_login(client, csrf, case, app):
    case("HASH-07", "log in with an old pbkdf2:sha256:1000 hash", f"Hash upgraded to {PASSWORD_METHOD} after login")
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                 ("legacy_user", generate_password_hash("Legacy123", method="pbkdf2:sha256:1000")))
    conn.commit()
    client.post("/login", data={"username": "legacy_user", "password": "Legacy123", "csrf_token": csrf()})
    after = conn.execute("SELECT password_hash FROM users WHERE username='legacy_user'").fetchone()[0]
    conn.close()
    case.actual = f"method after login={after.split('$')[0]}"
    assert after.startswith(PASSWORD_METHOD + "$")


def test_hmac_valid(case):
    case("HASH-08", "same message and key", "HMAC tags match")
    r = hmac_demo("Transfer 10 credits to bob", "Transfer 10 credits to bob", "lab-demo-key")
    case.actual = f"valid={r['valid']}"
    assert r["valid"]


def test_hmac_tamper_detected(logged_in, case, app):
    case("HASH-09", "message changed from 10 to 99 credits", "Tags differ; page reports rejection; log BLOCKED")
    r = logged_in.post("/hashing/", data={"demo": "hmac", "message": "Transfer 10 credits to bob",
                                          "received": "Transfer 99 credits to bob", "key": "lab-demo-key",
                                          "csrf_token": _token(logged_in)})
    conn = sqlite3.connect(app.config["DATABASE"])
    statuses = [x[0] for x in conn.execute("SELECT security_status FROM activity_logs WHERE description LIKE 'HMAC%'")]
    conn.close()
    case.actual = f"{r.status_code}, rejected shown={'Tags differ' in r.get_data(as_text=True)}, log={statuses}"
    assert "Tags differ" in r.get_data(as_text=True) and statuses == ["BLOCKED"]


def test_work_factor(case):
    case("HASH-10", "one hash per method", "PBKDF2 (600k) and scrypt (N=2^17) far slower than SHA-256")
    rows = cost_comparison("x")
    fast, pbkdf2, scrypt = (r["ms"] for r in rows)
    case.actual = f"SHA-256 {fast} ms, PBKDF2 {pbkdf2} ms, scrypt {scrypt} ms"
    assert pbkdf2 > 100 * fast and scrypt > 100 * fast


def test_generator_page(logged_in, case):
    case("HASH-11", "GET /hashing/?text=abc", "Table lists 11 algorithms with SHA-256 vector; MD5 marked broken")
    html = logged_in.get("/hashing/", query_string={"text": "abc"}).get_data(as_text=True)
    rows = html.count('<code class="hex">')
    case.actual = f"digest cells={rows}, SHA-256 vector shown={'ba7816bf' in html}, broken badge={'Broken' in html}"
    assert rows >= 11 and "ba7816bf8f01cfea" in html and "Broken – do not use" in html


def test_requires_login(client, case):
    case("HASH-12", "GET /hashing/ without login", "302 redirect to /login")
    r = client.get("/hashing/")
    case.actual = f"{r.status_code} -> {r.headers.get('Location')}"
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_input_limit(logged_in, case):
    case("HASH-13", "201-character text", "400, rejected by server-side validation")
    r = logged_in.get("/hashing/", query_string={"text": "a" * 201})
    case.actual = str(r.status_code)
    assert r.status_code == 400


def test_stored_hash_masked(logged_in, case, app):
    case("HASH-14", "GET /hashing/ as demo_student", "Hash structure shown; full digest never on the page")
    conn = sqlite3.connect(app.config["DATABASE"])
    stored = conn.execute("SELECT password_hash FROM users WHERE username='demo_student'").fetchone()[0]
    conn.close()
    html = logged_in.get("/hashing/").get_data(as_text=True)
    digest_hex = stored.split("$")[2]
    case.actual = f"method shown={'scrypt' in html}, full digest present={digest_hex in html}, salt present={stored.split('$')[1] in html}"
    assert digest_hex not in html and stored.split("$")[1] not in html and "N = 131072" in html


def test_post_requires_csrf(logged_in, case):
    case("HASH-15", "POST /hashing/ demo=cost without CSRF token", "400 Bad Request")
    r = logged_in.post("/hashing/", data={"demo": "cost"})
    case.actual = str(r.status_code)
    assert r.status_code == 400


def test_logs_have_no_input(logged_in, case, app):
    case("HASH-16", "hash 'MySecretPhrase42'", "Log records the action, never the hashed text")
    logged_in.get("/hashing/", query_string={"text": "MySecretPhrase42"})
    conn = sqlite3.connect(app.config["DATABASE"])
    text = " ".join(x[0] for x in conn.execute("SELECT description FROM activity_logs"))
    conn.close()
    case.actual = f"input in logs={'MySecretPhrase42' in text}, hashing logged={'hash generator' in text}"
    assert "MySecretPhrase42" not in text and "hash generator" in text
