"""
Harmless, fictional sample files for the Trojan Horse Defence lab and tests.

None of these files contains working malicious code. The "executables" are
only the two-byte MZ marker followed by plain text; they cannot run. They let
students see how each scanner rule reacts without handling real malware.
They are generated in memory and are never written to disk by the app.
"""
import hashlib
import io
import struct
import zipfile
import zlib

# A harmless file used to demonstrate the known-malware hash blocklist.
FICTIONAL_TROJAN = (b"WebShield fictional Trojan sample. This text is harmless and exists only so that "
                    b"its SHA-256 hash can appear on the demo blocklist.\n")

KNOWN_BAD_SHA256 = {
    hashlib.sha256(FICTIONAL_TROJAN).hexdigest(): "WebShield.Demo.Trojan (fictional blocklist entry)",
}


def _png(extra: bytes = b"") -> bytes:
    def chunk(kind, payload):
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\x22\xd3\xee")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"") + extra


def _pdf(extra: bytes = b"") -> bytes:
    return (b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n" + extra +
            b"trailer << /Root 1 0 R >>\n%%EOF\n")


def _docx(with_macro: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Fictional report</w:t></w:r></w:p></w:body></w:document>')
        if with_macro:
            z.writestr("word/vbaProject.bin", b"Fictional placeholder for a macro project - contains no code.")
    return buf.getvalue()


FAKE_EXE = b"MZ" + b" This is NOT a program. Fictional bytes that only imitate an executable header for the WebShield lab.\n"

# key -> (file name, bytes, what it demonstrates, expected verdict)
SAMPLES = {
    "clean_pdf": ("invoice_2026.pdf", _pdf(), "Legitimate PDF invoice", "ACCEPTED"),
    "clean_png": ("profile_photo.png", _png(), "Legitimate PNG image", "ACCEPTED"),
    "clean_txt": ("meeting_notes.txt", b"Meeting notes: review the WebShield labs on Friday.\n", "Legitimate text file", "ACCEPTED"),
    "clean_docx": ("course_report.docx", _docx(), "Legitimate Word document without macros", "ACCEPTED"),
    "double_ext": ("invoice.pdf.exe", FAKE_EXE, "Double extension: looks like a PDF, really an .exe", "BLOCKED"),
    "disguised": ("holiday.jpg", FAKE_EXE, "Executable content renamed to .jpg", "BLOCKED"),
    "rtlo": ("invoice‮fdp.exe", FAKE_EXE, "Right-to-left override: displays as invoiceexe.pdf", "BLOCKED"),
    "macro_docx": ("salary_review.docx", _docx(with_macro=True), "Word document carrying a VBA macro project", "BLOCKED"),
    "script": ("security_update.ps1", b"Write-Output 'Fictional script - does nothing'\n", "PowerShell script posing as an update", "BLOCKED"),
    "polyglot": ("avatar.png", _png(b"<script>alert('hidden')</script>"), "Valid PNG with a script appended (polyglot)", "SUSPICIOUS"),
    "pdf_launch": ("statement.pdf", _pdf(b"3 0 obj << /S /Launch /F (calc) >> endobj\n"), "PDF with a /Launch action", "BLOCKED"),
    "known_bad": ("free_game.txt", FICTIONAL_TROJAN, "File whose SHA-256 is on the known-malware blocklist", "BLOCKED"),
}
