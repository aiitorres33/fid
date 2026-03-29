from __future__ import annotations

from fid.models import Signature


SIGNATURES: list[Signature] = [
    Signature("PNG", "image/png", ("png",), 0, "89504E470D0A1A0A", 100, "image"),
    Signature("JPEG", "image/jpeg", ("jpg", "jpeg"), 0, "FFD8FF", 90, "image"),
    Signature("GIF", "image/gif", ("gif",), 0, "47494638??61", 90, "image"),
    Signature("BMP", "image/bmp", ("bmp",), 0, "424D", 80, "image"),
    Signature("PDF", "application/pdf", ("pdf",), 0, "25504446", 100, "document"),
    Signature("ZIP", "application/zip", ("zip", "docx", "xlsx", "pptx", "apk", "jar"), 0, "504B0304", 60, "archive"),
    Signature("GZIP", "application/gzip", ("gz",), 0, "1F8B", 100, "archive"),
    Signature("7Z", "application/x-7z-compressed", ("7z",), 0, "377ABCAF271C", 100, "archive"),
    Signature("RAR", "application/vnd.rar", ("rar",), 0, "526172211A0700", 100, "archive"),
    Signature("ELF", "application/x-elf", ("elf",), 0, "7F454C46", 100, "executable"),
    Signature("PE", "application/vnd.microsoft.portable-executable", ("exe", "dll"), 0, "4D5A", 100, "executable"),
    Signature("MP3_ID3", "audio/mpeg", ("mp3",), 0, "494433", 70, "audio"),
    Signature("WAV", "audio/wav", ("wav",), 0, "52494646", 70, "audio"),
    Signature("DICOM", "application/dicom", ("dcm",), 128, "4449434D", 100, "medical"),
    Signature("TAR", "application/x-tar", ("tar",), 257, "7573746172", 100, "archive"),
]

PHP_TAGS = [
    b"<?php",
    b"<?=",
    b"<? ",
]

SCRIPT_MARKERS = [
    b"<script",
    b"eval(",
    b"base64_decode(",
    b"powershell",
    b"cmd.exe",
    b"CreateRemoteThread",
    b"VirtualAlloc",
    b"WriteProcessMemory",
    b"ShellExecute",
    b"wscript.shell",
    b"mshta",
    b"certutil",
    b"rundll32",
    b"wget ",
    b"curl ",
    b"nc -e",
    b"/bin/sh",
    b"/bin/bash",
]

SUSPICIOUS_EXTENSIONS = {
    ".php", ".phtml", ".phar", ".asp", ".aspx", ".jsp", ".jspx",
    ".exe", ".dll", ".scr", ".js", ".vbs", ".hta", ".ps1", ".bat", ".cmd"
}
