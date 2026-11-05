/*
 * WebShield client-side script (Layer 1).
 *
 * Rules followed in this file:
 *  - untrusted values are written with textContent / value, never innerHTML
 *  - no inline event handlers (the Content-Security-Policy forbids them)
 *  - the only intentionally unsafe sink lives in the sandboxed iframe page
 *    templates/vulnerable/dom.html, never here.
 */
(function () {
  "use strict";

  // ---- Mobile sidebar toggle ------------------------------------------------
  var toggle = document.getElementById("menu-toggle");
  var sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", function () {
      sidebar.classList.toggle("open");
    });
  }

  // ---- SQLi lab: example buttons fill username + password -------------------
  document.querySelectorAll("[data-fill-username]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.getElementById("lab-username").value = btn.dataset.fillUsername;
      document.getElementById("lab-password").value = btn.dataset.fillPassword;
      document.getElementById("lab-username").focus();
    });
  });

  // ---- XSS lab: example buttons fill a target input ------------------------
  document.querySelectorAll("[data-fill-target]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = document.getElementById(btn.dataset.fillTarget);
      if (target) {
        target.value = btn.dataset.fillValue; // .value is a safe sink
        target.focus();
      }
    });
  });

  // ---- Confirmation for destructive forms ----------------------------------
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      if (!window.confirm(form.dataset.confirm)) { ev.preventDefault(); }
    });
  });

  // ---- DOM-based XSS demonstration -----------------------------------------
  var domRun = document.getElementById("dom-run");
  if (domRun) {
    var domInput = document.getElementById("dom-input");
    var domFrame = document.getElementById("dom-frame");
    var safeOut = document.getElementById("dom-safe-output");
    var baseSrc = domFrame.getAttribute("src").split("#")[0];
    var csrf = document.querySelector('meta[name="csrf-token"]').content;

    var run = function () {
      var value = domInput.value;
      if (!value) { return; }

      // VULNERABLE side: put the value in the URL fragment of the sandboxed
      // iframe; its own script then (unsafely) uses innerHTML.
      domFrame.src = baseSrc + "?t=" + Date.now() + "#" + encodeURIComponent(value);

      // SECURE side: textContent never parses HTML.
      safeOut.classList.remove("muted");
      safeOut.textContent = "Hello, " + value;

      // Record the demonstration in the activity log (server classifies it).
      var body = new URLSearchParams();
      body.set("csrf_token", csrf);
      body.set("payload", value);
      fetch("/xss/dom-log", { method: "POST", body: body, credentials: "same-origin" })
        .catch(function () { /* logging is best-effort */ });
    };

    domRun.addEventListener("click", run);
    domInput.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter") { ev.preventDefault(); run(); }
    });
  }
})();
