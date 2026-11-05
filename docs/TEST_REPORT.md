# WebShield - Test Execution Report

Generated automatically by `pytest` on 2026-11-05 16:30:22.
Every row below comes from an actual test execution (see `tests/conftest.py`).

**Result: 39 / 39 test cases passed.**

| Test ID | Input | Expected result | Actual result | Status |
|---|---|---|---|---|
| AUTH-01 | `register alice_test / Secret123, then log in` | 302 redirect to dashboard, session created | register 302, login redirect, user_id in session=True | **PASS** |
| AUTH-02 | `register bob_test / Secret123` | users.password_hash is a salted hash, not plaintext | stored value starts with 'scrypt:32768:8:1', plaintext present=False | **PASS** |
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
