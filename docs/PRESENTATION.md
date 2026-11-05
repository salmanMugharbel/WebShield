# WebShield — Technical Explanation for the Project Presentation

## 1. The problem (1 minute)
SQL Injection and Cross-Site Scripting are both **injection** flaws (OWASP Top 10, A03). Both happen when an
application mixes **code** with **untrusted data**:

* **SQLi**: the data is mixed into a *SQL statement* and the database runs it as code.
* **XSS**: the data is mixed into an *HTML page* and the browser runs it as code.

The fix follows the same idea in both cases: **keep data and code separate**, using parameterised queries for SQL and
output encoding for HTML.

## 2. What we built (1 minute)
A Flask + SQLite web application with three clear layers:

1. **Client:** Jinja2 templates, CSS and one JavaScript file that only uses safe DOM APIs.
2. **Server:** Flask blueprints for auth, labs and logs, plus a `security/` package for validation, hashing, CSRF,
   encoding and logging.
3. **Database:** SQLite with four related tables and integrity constraints.

Each vulnerability has a lab that sends **the same input** to a vulnerable and a secure implementation and shows the
results side by side. Every run is recorded in the activity log.

## 3. Live demo script (4 minutes)
1. **Dashboard:** point out the architecture diagram and the stats.
2. **Login** as `demo_student`, then try `' OR '1'='1' --` on the *real* login. It is refused because that login is parameterised.
3. **SQLi Lab:** click *Comment out password check* (`lab_admin' --`) and run it.
   * Vulnerable panel: the printed query shows that `--` commented out the password check, so we are logged in as administrator.
   * Secure panel: the SQL text still contains only `?`, and the input was looked up as a literal username.
   * Show `O'Brien`: the vulnerable version breaks even for a legitimate name.
4. **XSS Lab:**
   * Reflected: click *Script tag*, then Search. An alert appears in the red sandbox, while the green panel shows the text and its encoded form `&lt;script&gt;`.
   * Stored: post *DOM defacement*. The sandbox iframe gets defaced, the secure list shows the raw characters, and the payload is in the DB exactly as typed. The lesson is to encode on output.
   * DOM: click *Image onerror*, then Render. `innerHTML` runs the handler; `textContent` doesn't.
5. **Activity Logs:** filter by EXPLOITED and BLOCKED. No passwords or payloads are logged.

## 4. Why the parameterised query is safe
With concatenation, the database receives a single string and parses user input as SQL.
With placeholders, the driver sends the **statement template** and the **values** separately. The statement is
compiled first, so its structure is fixed before the values arrive. A value can only ever be compared as data, so
`' OR '1'='1' --` is just an odd username that matches nothing.

## 5. Why encoding stops XSS
The browser decides what is markup by looking at characters like `<`, `>`, `"` and `'`. Encoding turns them into
entities (`&lt;`, `&gt;`, `&quot;`, `&#39;`), which the browser *displays* but doesn't *parse*. Jinja2 does this
automatically for every `{{ value }}`; the vulnerable templates switch it off with `|safe`. On the client side,
`textContent` never parses HTML, while `innerHTML` does.

## 6. How we kept the platform itself secure (likely examiner question)
* The vulnerable SQL runs only against a **throw-away in-memory database** with fictional accounts. An **authorizer**
  allows only `SELECT`, so it can't modify data or reach the real database.
* Vulnerable HTML is served only from `/xss/sandbox/*` inside `<iframe sandbox>` **and** with a `CSP: sandbox`
  header. It runs in an opaque origin with no network access, so it can't read cookies or the main page.
* The main app's CSP forbids inline scripts. Cookies are `HttpOnly` and `SameSite=Strict`, every POST needs a CSRF
  token, debug mode is off, error pages are generic, and the server binds to `127.0.0.1` only.

## 7. Defence in depth: one control per layer
| Layer | Main control | Supporting controls |
|---|---|---|
| Client | `textContent`, CSP compliance | HTML validation attributes (usability only) |
| Server | Parameterised SQL, output encoding | Validation, CSRF, hashing, sessions, authorisation |
| Database | Constraints | Least privilege, hashed passwords, hidden errors |

## 8. Testing
39 automated pytest cases, all passing. The report (`docs/TEST_REPORT.md`) is generated from the actual run, with
ID, input, expected, actual and status. A Playwright script also checks the isolation in a real browser.

## 9. Key takeaways
1. Never build SQL or HTML by joining strings with user input.
2. Input validation and blacklists help, but they are **not** the defence.
3. Use the framework's safe defaults (placeholders, auto-escaping) and don't switch them off.
4. Add layers (CSP, HttpOnly, least privilege) so that a single mistake doesn't become a breach.
