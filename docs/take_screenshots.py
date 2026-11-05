"""
Capture screenshots of the running application and verify XSS isolation in a
real browser.

Requirements: `pip install -r requirements-dev.txt` and Microsoft Edge or
Google Chrome installed. Start the app first (`python app.py`), then run:

    python docs/take_screenshots.py
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("WEBSHIELD_URL", "http://127.0.0.1:5000")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshots")
os.makedirs(OUT, exist_ok=True)


def shot(page, name, full=True):
    path = os.path.join(OUT, name)
    page.screenshot(path=path, full_page=full)
    print("saved", path)


def main():
    dialogs = []
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(channel="msedge")
        except Exception:
            browser = p.chromium.launch(channel="chrome")
        page = browser.new_page(viewport={"width": 1440, "height": 900})

        def on_dialog(d):
            dialogs.append(d.message)
            d.accept()

        page.on("dialog", on_dialog)

        page.goto(BASE + "/")
        shot(page, "01_dashboard.png")

        page.goto(BASE + "/register")
        shot(page, "02_register.png", full=False)

        page.goto(BASE + "/login")
        page.fill("#username", "demo_student")
        page.fill("#password", "DemoPass123")
        shot(page, "03_login.png", full=False)
        page.click("button[type=submit]")
        page.wait_for_url(BASE + "/")

        # SQL Injection lab
        page.goto(BASE + "/sqli/")
        shot(page, "04_sqli_lab.png")
        page.fill("#lab-username", "lab_admin' --")
        page.fill("#lab-password", "anything")
        page.click("#sqli-form button[type=submit]")
        page.locator("#results").scroll_into_view_if_needed()
        page.locator("#results").screenshot(path=os.path.join(OUT, "05_sqli_injection_result.png"))
        print("saved 05_sqli_injection_result.png")
        page.fill("#lab-username", "alice")
        page.fill("#lab-password", "Wonderland1")
        page.click("#sqli-form button[type=submit]")
        page.locator("#results").screenshot(path=os.path.join(OUT, "06_sqli_normal_login.png"))
        print("saved 06_sqli_normal_login.png")

        # XSS lab - reflected
        page.goto(BASE + "/xss/?q=" + "%3Cimg%20src%3Dx%20onerror%3D%22document.body.innerHTML%3D'%3Ch2%3EPage%20defaced%20by%20injected%20script%3C%2Fh2%3E'%22%3E")
        page.wait_for_timeout(800)
        page.locator("#reflected").screenshot(path=os.path.join(OUT, "07_xss_reflected.png"))
        print("saved 07_xss_reflected.png")

        # XSS lab - stored
        page.fill("#comment", "<img src=x onerror=\"document.body.innerHTML='<h2>Stored XSS executed in sandbox</h2>'\">")
        page.click("#stored button[type=submit]:not(.link-btn)")
        page.wait_for_timeout(800)
        page.locator("#stored").screenshot(path=os.path.join(OUT, "08_xss_stored.png"))
        print("saved 08_xss_stored.png")

        # XSS lab - DOM based (uses an alert so we can count dialogs)
        before = len(dialogs)
        page.fill("#dom-input", "<img src=x onerror=\"alert('DOM XSS in sandbox')\">")
        page.click("#dom-run")
        page.wait_for_timeout(1200)
        safe_text = page.text_content("#dom-safe-output")
        page.locator("#dom").screenshot(path=os.path.join(OUT, "09_xss_dom.png"))
        print("saved 09_xss_dom.png")
        dom_alerts = dialogs[before:]

        # Verify the main document was NOT affected by any payload
        main_cookie_visible = page.evaluate("document.cookie")
        main_intact = page.locator("#dom-safe-output").count() == 1

        page.goto(BASE + "/security")
        shot(page, "10_security_comparison.png")
        page.goto(BASE + "/logs/")
        shot(page, "11_activity_logs.png")
        page.goto(BASE + "/docs")
        shot(page, "12_documentation.png")

        mobile = browser.new_page(viewport={"width": 390, "height": 844})
        mobile.goto(BASE + "/")
        mobile.screenshot(path=os.path.join(OUT, "13_mobile_dashboard.png"))
        print("saved 13_mobile_dashboard.png")
        browser.close()

    print("\n--- Browser verification ---")
    print("DOM alert fired inside sandbox:", dom_alerts)
    print("Secure panel text:", safe_text)
    print("Main page DOM intact:", main_intact)
    print("Session cookie readable by JS (should be empty):", repr(main_cookie_visible))
    ok = bool(dom_alerts) and main_intact and "<img" in (safe_text or "") and not main_cookie_visible
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
