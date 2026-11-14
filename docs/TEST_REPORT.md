# WebShield - Test Execution Report

Generated automatically by `pytest` on 2026-11-14 23:59:47.
Every row below comes from an actual test execution (see `tests/conftest.py`).

**Result: 80 / 80 test cases passed.**

| Test ID | Input | Expected result | Actual result | Status |
|---|---|---|---|---|
| ATK-01 | `GET /attacks` | 5 categories and 30 attacks listed, public page | categories=5, attack rows=30 | **PASS** |
| ATK-02 | `every catalogue entry` | Has a defence, a valid lab link, an OWASP code and only test IDs that exist in the suite | 30 entries checked, problems=[] | **PASS** |
| AUTH-01 | `register alice_test / Secret123, then log in` | 302 redirect to dashboard, session created | register 302, login redirect, user_id in session=True | **PASS** |
| AUTH-02 | `register bob_test / Secret123` | users.password_hash is a salted hash, not plaintext | stored value starts with 'scrypt:131072:8:1', plaintext present=False | **PASS** |
| AUTH-03 | `demo_student / WrongPass1` | 401, generic 'Invalid username or password' | 401, generic message shown=True | **PASS** |
| AUTH-04 | `nobody_here / Whatever1` | 401 with the same generic message (no user enumeration) | 401, generic message shown=True | **PASS** |
| AUTH-05 | `username: ' OR '1'='1' --  password: x` | Login refused (main app uses parameterised SQL) | 401, session user_id=None | **PASS** |
| AUTH-06 | `username 'a<b>' / password 'short'` | 400, registration rejected by server validation | 400, validation message shown=True | **PASS** |
| AUTH-07 | `register demo_student again` | 400 'already taken' (UNIQUE constraint) | 400, 'already taken' shown=True | **PASS** |
| AUTH-08 | `POST /login without csrf_token` | 400 Bad Request | 400 | **PASS** |
| AUTH-09 | `log out, then GET /sqli/` | 302 redirect to /login (authorisation enforced) | 302 -> /login?next=/sqli/ | **PASS** |
| AUTH-10 | `successful login` | Set-Cookie has HttpOnly and SameSite=Strict | HttpOnly=True, SameSite=Strict=True | **PASS** |
| AUTH-11 | `GET /does-not-exist` | Generic 404 page, CSP header without unsafe-inline | 404, CSP script-src 'self' only=True, traceback=False | **PASS** |
| AUTH-12 | `POST /login?next=//evil.example` | Redirect stays on site ('/') | Location=/ | **PASS** |
| HASH-01 | `abc` | Digests match published test vectors (MD5, SHA-1, SHA-256, SHA3-256) | all match | **PASS** |
| HASH-02 | `'a' and a 200-character string` | Digest length depends only on the algorithm | 11 algorithms, same length for both inputs=True; SHA-256 bits=256 | **PASS** |
| HASH-03 | `WebShield hashed twice` | Identical digest both times | equal=True | **PASS** |
| HASH-04 | `WebShield vs WebShielD` | About half of the 256 SHA-256 bits change (30-70%) | 133 / 256 bits changed (52.0%) | **PASS** |
| HASH-05 | `Summer2026 hashed for two users` | Unsalted hashes equal; salted hashes differ | unsalted equal=True, salted equal=False | **PASS** |
| HASH-06 | `register hash_user / Secret123` | Stored as scrypt:131072:8:1 with salt, no plaintext | method=scrypt:131072:8:1, salt length=16, digest bits=512, plaintext present=False | **PASS** |
| HASH-07 | `log in with an old pbkdf2:sha256:1000 hash` | Hash upgraded to scrypt:131072:8:1 after login | method after login=scrypt:131072:8:1 | **PASS** |
| HASH-08 | `same message and key` | HMAC tags match | valid=True | **PASS** |
| HASH-09 | `message changed from 10 to 99 credits` | Tags differ; page reports rejection; log BLOCKED | 200, rejected shown=True, log=['BLOCKED'] | **PASS** |
| HASH-10 | `one hash per method` | PBKDF2 (600k) and scrypt (N=2^17) far slower than SHA-256 | SHA-256 0.0025 ms, PBKDF2 742.9 ms, scrypt 1188.9 ms | **PASS** |
| HASH-11 | `GET /hashing/?text=abc` | Table lists 11 algorithms with SHA-256 vector; MD5 marked broken | digest cells=12, SHA-256 vector shown=True, broken badge=True | **PASS** |
| HASH-12 | `GET /hashing/ without login` | 302 redirect to /login | 302 -> /login?next=/hashing/ | **PASS** |
| HASH-13 | `201-character text` | 400, rejected by server-side validation | 400 | **PASS** |
| HASH-14 | `GET /hashing/ as demo_student` | Hash structure shown; full digest never on the page | method shown=True, full digest present=False, salt present=False | **PASS** |
| HASH-15 | `POST /hashing/ demo=cost without CSRF token` | 400 Bad Request | 400 | **PASS** |
| HASH-16 | `hash 'MySecretPhrase42'` | Log records the action, never the hashed text | input in logs=False, hashing logged=True | **PASS** |
| SQLI-01 | `alice / Wonderland1` | Both implementations log in as alice | vulnerable=alice, secure=alice | **PASS** |
| SQLI-02 | `alice / wrongpass` | Both implementations refuse the login | vulnerable auth=False, secure auth=False | **PASS** |
| SQLI-03 | `O'Brien / anything` | Vulnerable: query syntax error; Secure: handled normally (no match) | vulnerable error=True, secure error=None, secure auth=False | **PASS** |
| SQLI-04 | `' OR '1'='1' -- / anything` | Vulnerable bypassed as alice; Secure refused | vulnerable user=alice, secure auth=False | **PASS** |
| SQLI-05 | `lab_admin' -- / anything` | Vulnerable bypassed as lab_admin; Secure refused | vulnerable user=lab_admin, secure auth=False | **PASS** |
| SQLI-06 | `' OR 1=1 LIMIT 1 OFFSET 2 -- / anything` | Vulnerable bypassed as lab_admin; Secure refused | vulnerable user=lab_admin, secure auth=False | **PASS** |
| SQLI-07 | `x' UNION SELECT 1, sqlite_version(), 'injected' --` | Vulnerable returns attacker-chosen row; Secure returns nothing | vulnerable role=injected, secure rows=0 | **PASS** |
| SQLI-08 | `x'; DROP TABLE lab_users; --` | Rejected (single statement only); table still exists | error='Stacked queries (;) are rejected by sqlite3.execute().', alice still logs in=True | **PASS** |
| SQLI-09 | `x' OR (WITH RECURSIVE c(n) AS (...) SELECT count(*) FROM c) --` | Sandbox authorizer refuses recursive / non-SELECT operations | error='The sandbox refused this statement (only read-only SELECT is allowed).' | **PASS** |
| SQLI-10 | `' OR '1'='1' --` | Secure SQL text identical for any input (only ? placeholders) | same SQL text=True, payload in SQL=False | **PASS** |
| SQLI-11 | `POST /sqli/ username=lab_admin' --` | Page shows bypass on vulnerable + block on secure; logs EXPLOITED & BLOCKED | 200, bypass shown=True, logs=['EXPLOITED', 'BLOCKED'] | **PASS** |
| SQLI-12 | `POST /sqli/ alice / Wonderland1` | Password text never written to activity_logs | password present in logs=False | **PASS** |
| SQLI-13 | `x' UNION SELECT id, username, password_hash FROM users --` | Fails: main users table is not reachable from the sandbox | authenticated=False, error='The injected input broke the SQL syntax, so the query failed.' | **PASS** |
| SQLI-14 | `username of 201 characters` | 400, rejected by server-side validation | 400 | **PASS** |
| SQLI-15 | `' OR '1'='1' --  and  ' OR 1=1 LIMIT 1 OFFSET 2 --` | Classified as SQLI-T1 tautology | ['SQLI-T1'], ['SQLI-T1'] | **PASS** |
| SQLI-16 | `lab_admin' --  and  bob' /*` | Classified as SQLI-T2 comment truncation | ['SQLI-T2'], ['SQLI-T2'] | **PASS** |
| SQLI-17 | `x' UNION SELECT id, username, role FROM lab_users --` | Classified as SQLI-T3 UNION | ['SQLI-T3'] | **PASS** |
| SQLI-18 | `x'; DROP TABLE lab_users; --` | Classified as SQLI-T4 stacked queries | ['SQLI-T4'] | **PASS** |
| SQLI-19 | `'  /  alice' AND 1=2 --  /  alice  /  Sir Lancelot or knight` | T5, T6, and nothing for normal text | [['SQLI-T5'], ['SQLI-T6'], [], []] | **PASS** |
| SQLI-20 | `POST /sqli/ username=bob' /*` | Page groups inputs by technique, shows SQLI-T2 badge; log names the technique | technique groups=7, badge=True, log tagged=True | **PASS** |
| TROJ-01 | `invoice_2026.pdf, profile_photo.png, meeting_notes.txt, course_report.docx` | All four ACCEPTED | {'clean_pdf': 'ACCEPTED', 'clean_png': 'ACCEPTED', 'clean_txt': 'ACCEPTED', 'clean_docx': 'ACCEPTED'} | **PASS** |
| TROJ-02 | `multipart upload of report.pdf` | ACCEPTED; metadata and SHA-256 saved in file_scans; log NORMAL | 200, row=('report.pdf', 'ACCEPTED', 64), log=('NORMAL',) | **PASS** |
| TROJ-03 | `invoice.pdf.exe (MZ content)` | BLOCKED: .exe not allowed, double extension, executable content | BLOCKED, failed checks=['Extension allow-list', 'Hidden extension', 'Content signature'] | **PASS** |
| TROJ-04 | `holiday.jpg whose content starts with MZ` | BLOCKED by content signature (magic bytes) | BLOCKED, detected=Windows executable (MZ/PE header), failed=['Content signature'] | **PASS** |
| TROJ-05 | `invoice[U+202E]fdp.exe` | BLOCKED; hidden character shown as [U+202E] on the page | BLOCKED, visible name=invoice[U+202E]fdp.exe, page shows marker=True, raw char on page=False | **PASS** |
| TROJ-06 | `salary_review.docx with vbaProject.bin; report.docm` | Both BLOCKED | docx=BLOCKED (Document contains a VBA macro project (vbaProject.bin).), docm=BLOCKED | **PASS** |
| TROJ-07 | `free_game.txt (fictional sample on blocklist)` | BLOCKED by known-malware SHA-256 | BLOCKED, reasons=['SHA-256 matches blocklist entry: WebShield.Demo.Trojan (fictional blocklist entry).'] | **PASS** |
| TROJ-08 | `update.ps1, run.js, setup.bat, macro.vbs, page.html` | All BLOCKED by extension allow-list | {'update.ps1': 'BLOCKED', 'run.js': 'BLOCKED', 'setup.bat': 'BLOCKED', 'macro.vbs': 'BLOCKED', 'page.html': 'BLOCKED'} | **PASS** |
| TROJ-09 | `avatar.png with appended <script>; statement.pdf with /Launch` | PNG SUSPICIOUS; PDF BLOCKED | png=SUSPICIOUS, pdf=BLOCKED | **PASS** |
| TROJ-10 | `empty.txt, 1 MB + 1 byte file, 3 MB request` | Empty and oversize BLOCKED; 3 MB request rejected with 413 | empty=BLOCKED, oversize=BLOCKED, 3 MB request status=413 | **PASS** |
| TROJ-11 | `POST /trojan/ without login; then logged in without CSRF token` | 302 to login; 400 | anonymous=302, no token=400 | **PASS** |
| TROJ-12 | `upload a file containing a unique marker` | Marker absent from the database; no upload directory created | marker in DB=False, upload dirs=[] | **PASS** |
| TROJ-13 | `add a backdoor line to routes/auth.py after the baseline` | Verify reports routes/auth.py as MODIFIED | before change ok=True; after: ok=False, modified=['routes/auth.py'] | **PASS** |
| TROJ-14 | `delete security/csrf.py and add static/js/miner.js` | Verify reports one MISSING and one ADDED file | missing=['security/csrf.py'], added=['static/js/miner.js'] | **PASS** |
| TROJ-15 | `start the app with a baseline that does not match the code` | Start-up writes an Integrity DETECTED log entry | log=[('DETECTED', 'Start-up check: 48 source file(s) differ from the trusted baseline.')] | **PASS** |
| TROJ-16 | `upload named <script>alert(1)</script>.txt` | File name shown as encoded text in result and history | raw tag present=False, encoded=True | **PASS** |
| TROJ-17 | `report.docx expanding to 25 MB of zeros` | BLOCKED as a possible ZIP bomb | compressed=25,739 bytes, verdict=BLOCKED, reason=Archive expands to 26,214,408 bytes in 2 entries (possible ZIP bomb). | **PASS** |
| XSS-01 | `Hello WebShield` | Saved to DB and displayed unchanged | 302, stored='Hello WebShield', displayed=True | **PASS** |
| XSS-02 | `<b>bold</b>` | Secure view shows &lt;b&gt;bold&lt;/b&gt; (text, not formatting) | encoded=True, raw tag present=False | **PASS** |
| XSS-03 | `<script>alert('XSS')</script>` | Secure page: encoded text; vulnerable sandbox page: raw <script> (isolated) | secure encoded=True, sandbox raw=True | **PASS** |
| XSS-04 | `<img src=x onerror="alert(1)">` | Secure page encodes the tag; activity log records EXPLOITED + BLOCKED | encoded=True, log statuses=['BLOCKED', 'EXPLOITED'] | **PASS** |
| XSS-05 | `GET /xss/?q=<script>alert('XSS')</script>` | Main page shows encoded text; raw payload only in sandbox iframe page | main raw script=False, main encoded=True, sandbox raw=True | **PASS** |
| XSS-06 | `GET /xss/?q=firewall` | Search term displayed; logged as NORMAL | displayed=True, badge NORMAL=True | **PASS** |
| XSS-07 | `GET /xss/sandbox/reflected` | CSP 'sandbox' (opaque origin) and connect-src 'none' | sandbox allow-scripts allow-modals; default-src 'none'; script-src 'unsafe-inlin... | **PASS** |
| XSS-08 | `GET /xss/` | Main CSP has script-src 'self' (no unsafe-inline); iframes have sandbox attribute | unsafe-inline=False, frames=2, all sandboxed=True | **PASS** |
| XSS-09 | `static/js/main.js and templates` | Main-app JS writes untrusted data with textContent, never innerHTML | main.js innerHTML=False, textContent=True, sandbox uses innerHTML=True | **PASS** |
| XSS-10 | `POST /xss/dom-log payload=<img src=x onerror="alert(1)">` | 204; logged as DOM-based XSS EXPLOITED + BLOCKED | 204, statuses=['BLOCKED', 'EXPLOITED'] | **PASS** |
| XSS-11 | `empty comment and 501-character comment` | Both rejected; nothing stored | comments before=1, after=1 | **PASS** |
| XSS-12 | `user mallory_x deletes demo_student's comment #1` | 403 Forbidden (authorisation) | 403 | **PASS** |
| XSS-13 | `<a href="x" onclick='y'>&</a>` | All of & < > " ' encoded | &lt;a href=&#34;x&#34; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt; | **PASS** |
