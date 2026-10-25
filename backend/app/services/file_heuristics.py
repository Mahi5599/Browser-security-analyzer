"""Metadata-only download heuristics (no file contents are ever inspected).

Each rule returns a (weight, reason). Weights are combined noisy-OR style in
``file_analyzer`` so several weak signals can add up but never exceed 1.
"""
from __future__ import annotations

import re
from typing import Optional

# Extensions that execute code when opened.
EXECUTABLE_EXT = {
    "exe": 0.30, "scr": 0.40, "com": 0.35, "pif": 0.40, "msi": 0.25,
    "bat": 0.30, "cmd": 0.30, "vbs": 0.35, "vbe": 0.40, "js": 0.25,
    "wsf": 0.35, "hta": 0.40, "ps1": 0.30, "jar": 0.25, "apk": 0.25,
    "lnk": 0.30, "iso": 0.15, "dll": 0.20,
}
# Extensions a user expects to be inert data.
DOCUMENT_EXT = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "mov", "zip",
}
EXPECTED_MIME = {
    "pdf": {"application/pdf"},
    "txt": {"text/plain"},
    "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"}, "png": {"image/png"}, "gif": {"image/gif"},
    "doc": {"application/msword"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "xls": {"application/vnd.ms-excel"},
    "xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    "zip": {"application/zip", "application/x-zip-compressed"},
    "exe": {"application/x-msdownload", "application/vnd.microsoft.portable-executable",
            "application/x-dosexec", "application/x-msdos-program"},
}
# MIME types that mean "this is a program".
EXECUTABLE_MIME = {
    "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
    "application/vnd.microsoft.portable-executable", "application/x-executable",
    "application/x-sh", "application/x-bat", "application/java-archive",
    "application/vnd.android.package-archive", "application/x-msi",
}
GENERIC_MIME = {"application/octet-stream", "binary/octet-stream", ""}

_BIDI = re.compile("[‪-‮⁦-⁩]")  # right-to-left override tricks


def basename(name: str) -> str:
    return re.split(r"[\\/]", name)[-1]


def extensions(filename: str) -> list[str]:
    """All dot-separated suffixes, lower-cased, trailing spaces/dots stripped.
    ``invoice.pdf.exe`` -> ['pdf', 'exe']."""
    parts = basename(filename).strip().rstrip(". ").lower().split(".")
    return [p.strip() for p in parts[1:] if p.strip()]


def evaluate(filename: str, mime_type: Optional[str]) -> list[tuple[float, str]]:
    findings: list[tuple[float, str]] = []
    name = basename(filename)
    exts = extensions(name)
    final = exts[-1] if exts else ""
    mime = (mime_type or "").split(";")[0].strip().lower()
    is_exec_ext = final in EXECUTABLE_EXT

    if _BIDI.search(name):
        findings.append((0.55, "Filename contains a right-to-left override character "
                               "(disguises the real extension)"))

    if len(exts) >= 2 and is_exec_ext and exts[-2] in DOCUMENT_EXT:
        findings.append((0.60, f"Double extension '.{exts[-2]}.{final}': an executable "
                               f"disguised as a .{exts[-2]} file"))
    elif len(exts) >= 2 and is_exec_ext and exts[-2] in EXECUTABLE_EXT:
        findings.append((0.15, f"Stacked executable extensions '.{exts[-2]}.{final}'"))

    if is_exec_ext:
        findings.append((EXECUTABLE_EXT[final], f"Risky file type '.{final}' can run code when opened"))

    if mime in EXECUTABLE_MIME and final and not is_exec_ext:
        findings.append((0.45, f"Server says the file is a program ({mime}) but it is named "
                               f"'.{final}' (executable masquerading as a "
                               f"{'document' if final in DOCUMENT_EXT else 'different type'})"))
    elif mime not in GENERIC_MIME and final in DOCUMENT_EXT:
        expected = EXPECTED_MIME.get(final)
        if expected and mime not in expected:
            findings.append((0.20, f"MIME type '{mime}' does not match extension '.{final}'"))
    elif mime not in GENERIC_MIME and is_exec_ext and final in EXPECTED_MIME \
            and mime not in EXPECTED_MIME[final]:
        findings.append((0.20, f"MIME type '{mime}' does not match extension '.{final}'"))
    return findings
