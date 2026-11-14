"""
Trojan horse protection for file uploads.

A Trojan horse is malicious code disguised as something harmless: an invoice,
a photo, an update. Uploaded files are the most common way one reaches a web
application. Every upload is checked by eight independent rules before it
could be accepted:

 1. File name     - no path parts, control or right-to-left override characters
 2. Allow-list    - final extension must be pdf, png, jpg/jpeg, gif, txt or docx
 3. Hidden ext.   - no dangerous extension hidden earlier in the name
 4. Size          - not empty and at most MAX_UPLOAD bytes
 5. Signature     - the file's magic bytes must match its extension, and
                    executable signatures (MZ, ELF, Mach-O, #!) are refused
 6. Containers    - DOCX (ZIP) must not contain macros or be a ZIP bomb;
                    legacy OLE office files are refused
 7. Embedded code - script/launch markers inside the content are flagged
 8. Known malware - SHA-256 compared with a blocklist of known-bad hashes

Files are analysed in memory only. They are never written to disk, never
served back and never executed; only metadata and the SHA-256 are recorded.
"""
import hashlib
import io
import re
import unicodedata
import zipfile

from security.trojan_samples import KNOWN_BAD_SHA256

MAX_UPLOAD = 1024 * 1024          # 1 MB
MAX_ZIP_ENTRIES = 1000
MAX_ZIP_UNCOMPRESSED = 20 * 1024 * 1024

# extension -> expected content type
ALLOWED = {"pdf": "pdf", "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "gif": "gif", "txt": "text", "docx": "zip"}

DANGEROUS_EXT = {
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msp", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "reg", "sh", "bash", "py", "pl", "php", "phtml",
    "asp", "aspx", "jsp", "apk", "app", "dmg", "iso", "img", "docm", "dotm", "xlsm", "xltm", "pptm",
    "potm", "ppam", "xlam", "html", "htm", "svg",
}

SIGNATURES = [
    (b"%PDF-", "pdf", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (b"\xff\xd8\xff", "jpeg", "JPEG image"),
    (b"GIF87a", "gif", "GIF image"),
    (b"GIF89a", "gif", "GIF image"),
    (b"PK\x03\x04", "zip", "ZIP container (DOCX/XLSX/JAR/APK)"),
    (b"MZ", "pe", "Windows executable (MZ/PE header)"),
    (b"\x7fELF", "elf", "Linux executable (ELF)"),
    (b"\xcf\xfa\xed\xfe", "macho", "macOS executable (Mach-O)"),
    (b"\xfe\xed\xfa\xcf", "macho", "macOS executable (Mach-O)"),
    (b"\xca\xfe\xba\xbe", "macho", "Mach-O universal binary / Java class"),
    (b"#!", "script", "Script with interpreter line (#!)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "Legacy Office/OLE document (can carry macros)"),
]
EXECUTABLE = {"pe", "elf", "macho", "script"}

CODE_MARKERS = [
    (rb"<\s*script", "HTML <script> tag"),
    (rb"<\?php", "PHP code"),
    (rb"<%", "server-side template code"),
    (rb"powershell", "PowerShell command"),
    (rb"wscript\.shell", "Windows Script Host object"),
    (rb"cmd(\.exe)?\s+/c", "command-line execution"),
    (rb"/javascript", "PDF JavaScript action"),
]
PDF_LAUNCH = re.compile(rb"/launch\b", re.I)

BIDI_AND_CONTROL = re.compile("[\u0000-\u001f\u007f‎‏‪-‮⁦-⁩]")


def visible_name(name: str) -> str:
    """Make hidden characters visible, e.g. U+202E becomes [U+202E]."""
    return BIDI_AND_CONTROL.sub(lambda m: f"[U+{ord(m.group()):04X}]", name)[:200]


def detect_type(data: bytes):
    for magic, kind, label in SIGNATURES:
        if data.startswith(magic):
            return kind, label
    try:
        text = data.decode("utf-8")
        if "\x00" not in text:
            return "text", "Plain text (UTF-8)"
    except UnicodeDecodeError:
        pass
    return "unknown", "Unknown binary data"


def scan(filename: str, data: bytes) -> dict:
    checks = []

    def add(rule, status, detail):
        checks.append({"rule": rule, "status": status, "detail": detail})

    name = unicodedata.normalize("NFC", filename or "")
    sha256 = hashlib.sha256(data).hexdigest()
    kind, kind_label = detect_type(data)

    # 1. File name
    if not name.strip():
        add("File name", "fail", "No file name supplied.")
    elif BIDI_AND_CONTROL.search(name):
        add("File name", "fail", "Contains control or right-to-left override characters used to disguise the real extension.")
    elif "/" in name or "\\" in name or ".." in name:
        add("File name", "fail", "Contains path components or '..' (path traversal).")
    elif len(name) > 100:
        add("File name", "fail", "Longer than 100 characters.")
    else:
        add("File name", "pass", "Plain file name.")

    parts = [p.lower().strip() for p in name.split(".")]
    ext = parts[-1] if len(parts) > 1 else ""
    inner = parts[1:-1]

    # 2. Extension allow-list
    if ext in ALLOWED:
        add("Extension allow-list", "pass", f".{ext} is an allowed type.")
    elif ext in DANGEROUS_EXT:
        add("Extension allow-list", "fail", f".{ext} is an executable, script or macro format.")
    else:
        add("Extension allow-list", "fail", f".{ext or '(none)'} is not on the allow-list.")

    # 3. Hidden / double extension
    hidden = [p for p in inner if p in DANGEROUS_EXT or p in ALLOWED]
    dangerous_hidden = [p for p in inner if p in DANGEROUS_EXT]
    if dangerous_hidden:
        add("Hidden extension", "fail", f"Dangerous extension .{dangerous_hidden[0]} hidden inside the name.")
    elif hidden and ext not in ALLOWED:
        add("Hidden extension", "fail", f"Double extension: looks like .{hidden[-1]} but is really .{ext}.")
    elif hidden:
        add("Hidden extension", "warn", f"Double extension (.{hidden[-1]}.{ext}).")
    else:
        add("Hidden extension", "pass", "Single extension.")

    # 4. Size
    if not data:
        add("Size", "fail", "File is empty.")
    elif len(data) > MAX_UPLOAD:
        add("Size", "fail", f"{len(data):,} bytes exceeds the {MAX_UPLOAD:,}-byte limit.")
    else:
        add("Size", "pass", f"{len(data):,} bytes.")

    # 5. Content signature (magic bytes)
    expected = ALLOWED.get(ext)
    if kind in EXECUTABLE:
        add("Content signature", "fail", f"Content is a {kind_label} even though it is named .{ext or '(none)'}.")
    elif kind == "ole":
        add("Content signature", "fail", kind_label + " - refused because it can contain macros.")
    elif expected and kind != expected:
        add("Content signature", "fail", f"Name says .{ext} but the content is: {kind_label}.")
    elif expected:
        add("Content signature", "pass", f"Content matches .{ext}: {kind_label}.")
    else:
        add("Content signature", "warn", f"Detected: {kind_label}.")

    # 6. Containers (DOCX / ZIP)
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = z.infolist()
                names = [i.filename.lower() for i in infos]
                total = sum(i.file_size for i in infos)
                if len(infos) > MAX_ZIP_ENTRIES or total > MAX_ZIP_UNCOMPRESSED:
                    add("Macros and containers", "fail", f"Archive expands to {total:,} bytes in {len(infos)} entries (possible ZIP bomb).")
                elif any(n.endswith("vbaproject.bin") for n in names):
                    add("Macros and containers", "fail", "Document contains a VBA macro project (vbaProject.bin).")
                elif any(n.endswith((".exe", ".dll", ".js", ".vbs", ".ps1", ".bat")) for n in names):
                    add("Macros and containers", "fail", "Archive contains an executable or script file.")
                elif "[content_types].xml" not in names:
                    add("Macros and containers", "warn", "ZIP is not a valid Office Open XML document.")
                else:
                    add("Macros and containers", "pass", "Office document without macros.")
        except zipfile.BadZipFile:
            add("Macros and containers", "fail", "Corrupt ZIP container.")
    else:
        add("Macros and containers", "pass", "Not a container format." if kind != "ole" else "Legacy OLE container refused above.")

    # 7. Embedded code markers (polyglots)
    lowered = data.lower()
    found = [label for rx, label in CODE_MARKERS if re.search(rx, lowered)]
    if kind == "pdf" and PDF_LAUNCH.search(data):
        add("Embedded code", "fail", "PDF contains a /Launch action that can start programs.")
    elif found and kind != "text":
        add("Embedded code", "warn", "Code hidden inside a " + kind_label + ": " + ", ".join(found) + ".")
    elif found:
        add("Embedded code", "warn", "Text contains code: " + ", ".join(found) + ".")
    else:
        add("Embedded code", "pass", "No script or launch markers.")

    # 8. Known malware hash
    if sha256 in KNOWN_BAD_SHA256:
        add("Known-malware hash", "fail", f"SHA-256 matches blocklist entry: {KNOWN_BAD_SHA256[sha256]}.")
    else:
        add("Known-malware hash", "pass", "SHA-256 not on the blocklist.")

    statuses = {c["status"] for c in checks}
    verdict = "BLOCKED" if "fail" in statuses else "SUSPICIOUS" if "warn" in statuses else "ACCEPTED"
    reasons = [c["detail"] for c in checks if c["status"] != "pass"]
    return {
        "filename": visible_name(name),
        "size": len(data),
        "sha256": sha256,
        "detected": kind_label,
        "checks": checks,
        "verdict": verdict,
        "reasons": reasons,
    }
