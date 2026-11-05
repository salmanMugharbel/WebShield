"""
Output encoding helpers.

Jinja2 auto-escaping already encodes every `{{ value }}` in HTML templates.
These helpers exist so the encoding step can be shown and tested explicitly.
"""
import re

from markupsafe import escape

_XSS_PATTERNS = [
    (re.compile(r"<\s*script", re.I), "<script> tag"),
    (re.compile(r"\bon[a-z]+\s*=", re.I), "inline event handler (on...=)"),
    (re.compile(r"javascript\s*:", re.I), "javascript: URL"),
    (re.compile(r"<\s*(iframe|img|svg|object|embed|a|body|style)\b", re.I), "HTML tag"),
]


def html_encode(value: str) -> str:
    """Encode &, <, >, " and ' so the browser shows them as text."""
    return str(escape(value))


def detect_xss(value: str):
    """Educational detection only - the defence is output encoding."""
    found = []
    for pattern, label in _XSS_PATTERNS:
        if pattern.search(value or ""):
            found.append(label)
    if not found and re.search(r"[<>]", value or ""):
        found.append("angle brackets")
    return found
