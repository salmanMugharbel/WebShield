"""
Attack catalogue: every attack covered by WebShield, organised in one place.

Each entry records the category, the OWASP Top 10 (2021) risk, the layer it
targets, how it works, the defence WebShield implements, where it is
demonstrated and which automated tests verify the defence.
"""

CATEGORIES = [
    ("injection", "Injection attacks", "Untrusted input is interpreted as code by the database or the browser."),
    ("session", "Request, session and access-control attacks", "Abusing the user's session or the application's trust in requests."),
    ("crypto", "Password and cryptographic attacks", "Recovering, forging or bypassing secrets protected by hashing."),
    ("malware", "Trojan horse and integrity attacks", "Malicious code disguised as something legitimate, or tampered code."),
    ("availability", "Availability (denial-of-service) attacks", "Exhausting server resources with oversized or expensive requests."),
]

OWASP = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
}

# id, name, category, owasp codes, layer, how it works, defence, lab endpoint, tests
ATTACKS = [
    # ---------------- Injection ----------------
    ("SQLI-T1", "SQL Injection: always-true condition (tautology)", "injection", ["A03"], "Server / Database",
     "Input such as ' OR '1'='1' -- makes the WHERE clause true for every row, so the login returns the first account.",
     "Parameterised queries (input bound as data)", "sqli.lab", ["SQLI-04", "SQLI-15"]),
    ("SQLI-T2", "SQL Injection: comment truncation", "injection", ["A03"], "Server / Database",
     "A quote closes the string and -- comments out the rest of the query, removing the password check.",
     "Parameterised queries", "sqli.lab", ["SQLI-05", "SQLI-16"]),
    ("SQLI-T3", "SQL Injection: UNION-based data extraction", "injection", ["A03"], "Server / Database",
     "UNION SELECT appends attacker-chosen rows, which can reveal data from other columns or tables.",
     "Parameterised queries; least-privilege sandbox (main DB unreachable)", "sqli.lab", ["SQLI-07", "SQLI-13", "SQLI-17"]),
    ("SQLI-T4", "SQL Injection: stacked queries", "injection", ["A03"], "Server / Database",
     "A semicolon starts a second statement such as DROP TABLE.",
     "Parameterised queries; single-statement execute(); read-only authorizer", "sqli.lab", ["SQLI-08", "SQLI-18"]),
    ("SQLI-T5", "SQL Injection: error-based probing", "injection", ["A03", "A05"], "Server / Database",
     "A lone quote breaks the syntax; detailed error messages would reveal table and column names.",
     "Parameterised queries; generic error messages only", "sqli.lab", ["SQLI-03"]),
    ("SQLI-T6", "SQL Injection: blind / time-based (conceptual)", "injection", ["A03"], "Server / Database",
     "The attacker infers data one bit at a time from true/false page differences or deliberate delays.",
     "Parameterised queries; query time limit and recursive queries refused in the sandbox", "sqli.lab", ["SQLI-09"]),
    ("XSS-R", "Reflected Cross-Site Scripting", "injection", ["A03"], "Server → Browser",
     "A script in a crafted link is echoed back by the server and runs in the victim's browser.",
     "Jinja2 output encoding; strict Content-Security-Policy", "xss.lab", ["XSS-05", "XSS-08"]),
    ("XSS-S", "Stored Cross-Site Scripting", "injection", ["A03"], "Database → Browser",
     "A script saved in a comment runs for every visitor who views it.",
     "Output encoding on render; CSP; HttpOnly cookies", "xss.lab", ["XSS-03", "XSS-04"]),
    ("XSS-D", "DOM-based Cross-Site Scripting", "injection", ["A03"], "Browser",
     "Client-side JavaScript writes the URL fragment into the page with innerHTML.",
     "textContent instead of innerHTML; CSP", "xss.lab", ["XSS-09", "XSS-10"]),

    # ---------------- Session / access control ----------------
    ("CSRF", "Cross-Site Request Forgery", "session", ["A01"], "Browser → Server",
     "Another site makes the victim's browser submit a form to WebShield using the victim's session.",
     "Synchroniser CSRF token on every POST; SameSite=Strict cookie", "auth.login", ["AUTH-08", "HASH-15"]),
    ("SESS-FIX", "Session fixation", "session", ["A07"], "Server",
     "The attacker plants a known session identifier before the victim logs in, then reuses it.",
     "Session cleared and recreated at login", "auth.login", ["AUTH-01"]),
    ("SESS-HIJ", "Session hijacking via script", "session", ["A07"], "Browser",
     "An injected script reads document.cookie and sends the session to the attacker.",
     "HttpOnly + SameSite=Strict cookies; 30-minute expiry; CSP", "auth.login", ["AUTH-10"]),
    ("REDIR", "Open redirect", "session", ["A01"], "Server",
     "A login link with ?next=//evil.example sends the user to a phishing site after login.",
     "Only relative same-site redirect targets accepted", "auth.login", ["AUTH-12"]),
    ("ENUM", "User enumeration", "session", ["A07"], "Server",
     "Different error messages reveal which usernames exist.",
     "Identical message for unknown user and wrong password", "auth.login", ["AUTH-03", "AUTH-04"]),
    ("IDOR", "Broken access control (acting on others' data)", "session", ["A01"], "Server",
     "A user sends a request to delete a comment that belongs to someone else.",
     "Ownership check on the server; 403 Forbidden", "xss.lab", ["XSS-12"]),

    # ---------------- Crypto / password ----------------
    ("PW-PLAIN", "Plaintext or weak password storage", "crypto", ["A02"], "Database",
     "A stolen database exposes passwords directly, or hashed with a fast algorithm such as MD5.",
     "scrypt N=2^17, r=8, p=1 with a random salt; rehash on login", "hashing.lab", ["AUTH-02", "HASH-06", "HASH-07"]),
    ("PW-GUESS", "Offline brute-force and dictionary guessing", "crypto", ["A02", "A07"], "Database",
     "With stolen hashes the attacker tries billions of guesses per second against a fast hash.",
     "Deliberately slow, memory-hard scrypt (about 0.5 s per hash)", "hashing.lab", ["HASH-10"]),
    ("PW-RAINBOW", "Precomputed (rainbow) tables", "crypto", ["A02"], "Database",
     "Tables of precomputed digests reverse unsalted hashes instantly.",
     "Unique random salt per password", "hashing.lab", ["HASH-05"]),
    ("HASH-COLL", "Hash collision attacks (MD5, SHA-1)", "crypto", ["A02"], "Server",
     "Two different files with the same MD5/SHA-1 digest let a malicious file pass as a trusted one.",
     "SHA-256 / scrypt only; MD5 and SHA-1 shown as broken", "hashing.lab", ["HASH-11"]),
    ("TAMPER", "Message tampering and length extension", "crypto", ["A02", "A08"], "Server",
     "A message is changed and its plain hash recomputed, or hash(secret + message) is extended.",
     "HMAC-SHA256 tags; HMAC-signed session cookie", "hashing.lab", ["HASH-09"]),
    ("TIMING", "Timing attack on comparisons", "crypto", ["A02"], "Server",
     "Byte-by-byte comparison returns earlier on a mismatch, leaking the correct value gradually.",
     "Constant-time hmac.compare_digest()", "hashing.lab", ["HASH-08"]),

    # ---------------- Trojan horse / integrity ----------------
    ("TROJ-DISG", "Trojan horse: executable disguised as a document or image", "malware", ["A04", "A08"], "Server",
     "A Windows program renamed holiday.jpg; the extension says image but the content is executable.",
     "Magic-byte (file signature) check against the extension; executable signatures blocked", "trojan.lab", ["TROJ-04"]),
    ("TROJ-EXT", "Trojan horse: double extension and right-to-left override", "malware", ["A04"], "Server",
     "invoice.pdf.exe, or a name using the invisible U+202E character so 'exe' displays as 'pdf'.",
     "Extension allow-list on the final extension; dangerous inner extensions and control characters rejected", "trojan.lab", ["TROJ-03", "TROJ-05"]),
    ("TROJ-MACRO", "Trojan horse: macro-enabled office document", "malware", ["A04", "A08"], "Server",
     "A .docm or a .docx carrying vbaProject.bin runs malicious macros when opened.",
     "Macro formats blocked; ZIP container inspected for vbaProject.bin", "trojan.lab", ["TROJ-06"]),
    ("TROJ-KNOWN", "Trojan horse: known malicious file", "malware", ["A08"], "Server",
     "A file already identified as malware is uploaded again under a new name.",
     "SHA-256 of every upload compared with a blocklist of known-bad hashes", "trojan.lab", ["TROJ-07"]),
    ("TROJ-SCRIPT", "Trojan horse: script dropper", "malware", ["A04"], "Server",
     "A .ps1, .js, .bat or .vbs file downloads and installs the real malware when run.",
     "Strict extension allow-list (pdf, png, jpg, gif, txt, docx)", "trojan.lab", ["TROJ-08"]),
    ("TROJ-POLY", "Trojan horse: polyglot file with embedded code", "malware", ["A04"], "Server",
     "A valid image that also contains <script> or <?php code, executed if served with the wrong type.",
     "Embedded code markers detected; files never stored, served or executed", "trojan.lab", ["TROJ-09", "TROJ-12"]),
    ("TROJ-CODE", "Trojanised application code (tampering / supply chain)", "malware", ["A08"], "Server",
     "An attacker or a compromised update secretly modifies the application's own source files.",
     "File integrity monitor: SHA-256 manifest of all source files, checked at start-up and on demand", "trojan.lab", ["TROJ-13", "TROJ-14"]),

    # ---------------- Availability ----------------
    ("DOS-SIZE", "Oversized request / upload", "availability", ["A05"], "Server",
     "Huge request bodies or files exhaust memory and disk.",
     "MAX_CONTENT_LENGTH (2 MB); 1 MB upload limit; 200-character lab inputs", "trojan.lab", ["TROJ-10", "SQLI-14"]),
    ("DOS-QUERY", "Runaway database query", "availability", ["A04"], "Database",
     "An injected recursive query keeps the database busy indefinitely.",
     "Sandbox progress handler and authorizer abort expensive queries", "sqli.lab", ["SQLI-09"]),
]


def grouped():
    """Attacks grouped by category, in catalogue order."""
    out = []
    for key, title, blurb in CATEGORIES:
        items = [dict(zip(("id", "name", "category", "owasp", "layer", "how", "defence", "lab", "tests"), a))
                 for a in ATTACKS if a[2] == key]
        out.append({"key": key, "title": title, "blurb": blurb, "attacks": items})
    return out


def owasp_counts():
    counts = {}
    for a in ATTACKS:
        for code in a[3]:
            counts[code] = counts.get(code, 0) + 1
    return [(OWASP[c], counts[c]) for c in sorted(counts)]
