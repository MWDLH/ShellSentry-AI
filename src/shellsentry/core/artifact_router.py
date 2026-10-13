"""Content-aware routing for text scripts and unsupported binary artifacts."""

from __future__ import annotations

import os
import re

from .models import ArtifactProfile


LANGUAGE_EXTENSIONS = {
    "php": {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar"},
    "java": {".jsp", ".jspx", ".java"},
    "go": {".go"},
    "dotnet": {".asp", ".aspx", ".asmx", ".ashx", ".ascx", ".cs"},
    "python": {".py", ".pyw"},
    "powershell": {".ps1", ".psm1", ".psd1"},
    "javascript": {".js", ".mjs", ".cjs", ".jsx"},
    "typescript": {".ts", ".tsx"},
    "html": {".html", ".htm", ".xhtml", ".svg"},
    "shell": {".sh", ".bash", ".zsh", ".ksh"},
    "perl": {".pl", ".pm", ".cgi"},
    "ruby": {".rb"},
    "vbscript": {".vbs", ".vbe", ".wsf"},
    "batch": {".bat", ".cmd"},
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".so", ".dylib", ".elf", ".bin", ".pyc",
    ".class", ".jar", ".war", ".apk", ".dex", ".pdf", ".doc", ".docx",
}

# ZIP 是容器而非待审计脚本：放行给 InputHandler 做内存解包（见 route_bytes）。
ZIP_EXTENSIONS = {".zip"}

CONTENT_HINTS = [
    ("php", re.compile(r"<\?php|\$_(?:GET|POST|REQUEST|COOKIE)|\bbase64_decode\s*\(", re.I)),
    ("java", re.compile(r"<%@\s*page|Runtime\.getRuntime|ProcessBuilder|javax?\.servlet", re.I)),
    # go 放在 python 之前：`import (` 这类写法在 Go 里也出现，靠顺序保证 Go 优先胜出
    ("go", re.compile(r"^\s*package\s+\w+\s*$|^func\s+(?:\([^)]*\)\s*)?\w+\s*\(", re.I | re.M)),
    ("powershell", re.compile(r"\b(?:Invoke-Expression|IEX|Invoke-WebRequest|DownloadString)\b|\$env:", re.I)),
    ("python", re.compile(r"^\s*(?:def|class|import|from)\s+|\bsubprocess\.(?:run|Popen)\b", re.I | re.M)),
    ("javascript", re.compile(r"\b(?:document\.|window\.|require\s*\(|fetch\s*\(|=>)")),
    ("html", re.compile(r"<!doctype\s+html|<html\b|<script\b|on(?:error|load|click)\s*=", re.I)),
    ("shell", re.compile(r"^#!\s*/(?:usr/)?bin/(?:ba)?sh|\b(?:curl|wget)\b.*\|\s*(?:ba)?sh\b", re.I | re.M)),
    ("dotnet", re.compile(r"<%@\s*(?:Page|WebHandler)|System\.Diagnostics\.Process|Request\[(?:\"|')", re.I)),
]


def _language_from_extension(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    for language, extensions in LANGUAGE_EXTENSIONS.items():
        if ext in extensions:
            return language
    return "unknown"


def detect_language(filename: str, text: str) -> tuple[str, float]:
    extension_language = _language_from_extension(filename)
    scores: dict[str, int] = {}
    for language, pattern in CONTENT_HINTS:
        if pattern.search(text[:200_000]):
            scores[language] = scores.get(language, 0) + 1

    if scores:
        content_language = max(scores, key=scores.get)
        if extension_language == content_language:
            return content_language, 0.98
        if extension_language == "unknown":
            return content_language, 0.82
        return extension_language, 0.72
    if extension_language != "unknown":
        return extension_language, 0.9
    return "generic_text", 0.45


def route_text(filename: str, text: str) -> ArtifactProfile:
    language, confidence = detect_language(filename, text)
    kind = "browser_script" if language in {"javascript", "typescript", "html"} else "source_code"
    return ArtifactProfile(kind=kind, language=language, confidence=confidence, supported=True)


def route_bytes(filename: str, data: bytes) -> ArtifactProfile:
    ext = os.path.splitext(filename)[1].lower()
    # 压缩包是容器：内层文本脚本由 InputHandler.process_upload 在内存中解包后逐个审计，
    # 因此必须在这里放行。此前按"二进制"（可打印率低）直接拒绝，导致解包逻辑永远不可达、
    # 而界面上却写着"将在服务端内存中展开"——功能与承诺不符。
    if ext in ZIP_EXTENSIONS:
        return ArtifactProfile(
            kind="archive",
            language="archive",
            confidence=0.9,
            supported=True,
            is_binary=True,
            reason="",
        )
    magic_binary = (
        data.startswith(b"MZ")
        or data.startswith(b"\x7fELF")
        or data.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"))
        or ext in BINARY_EXTENSIONS
    )
    sample = data[:8192]
    nul_ratio = sample.count(b"\x00") / max(1, len(sample))
    printable_ratio = sum(byte in b"\t\n\r" or 32 <= byte <= 126 for byte in sample) / max(1, len(sample))
    if magic_binary or nul_ratio > 0.08 or (len(sample) > 64 and printable_ratio < 0.45):
        return ArtifactProfile(
            kind="binary",
            language="binary",
            confidence=0.99 if magic_binary else 0.82,
            supported=False,
            is_binary=True,
            reason="当前版本仅支持文本型脚本和源码，二进制文件未执行也未分析",
        )

    text = data.decode("utf-8", errors="ignore")
    return route_text(filename, text)

