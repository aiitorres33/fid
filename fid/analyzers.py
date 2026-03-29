from __future__ import annotations

import zipfile
from pathlib import Path
from dataclasses import asdict

from fid.models import MatchResult, PolyglotResult, HeuristicResult
from fid.signatures import SIGNATURES, PHP_TAGS, SCRIPT_MARKERS, SUSPICIOUS_EXTENSIONS
from fid.utils import search_pattern_anywhere, read_full_limited, shannon_entropy


def refine_zip_type(path: Path, primary: MatchResult) -> MatchResult:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = set(archive.namelist())

            if "word/document.xml" in names:
                return MatchResult("DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ["docx"], 0, "504B0304", 85, "document")
            if "xl/workbook.xml" in names:
                return MatchResult("XLSX", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ["xlsx"], 0, "504B0304", 85, "document")
            if "ppt/presentation.xml" in names:
                return MatchResult("PPTX", "application/vnd.openxmlformats-officedocument.presentationml.presentation", ["pptx"], 0, "504B0304", 85, "document")
            if "META-INF/MANIFEST.MF" in names:
                return MatchResult("JAR", "application/java-archive", ["jar"], 0, "504B0304", 85, "archive")
            if "AndroidManifest.xml" in names:
                return MatchResult("APK", "application/vnd.android.package-archive", ["apk"], 0, "504B0304", 85, "archive")
    except Exception:
        pass

    return primary


def detect_polyglot(path: Path, primary: MatchResult | None) -> PolyglotResult:
    data = read_full_limited(path, 4 * 1024 * 1024)
    reasons: list[str] = []
    embedded: list[dict] = []

    for sig in SIGNATURES:
        hits = search_pattern_anywhere(data, sig.pattern, exclude_offset_zero=True)
        for off in hits[:5]:
            embedded.append({
                "name": sig.name,
                "offset": off,
                "pattern": sig.pattern,
            })

    for marker in PHP_TAGS:
        index = data.find(marker)
        if index != -1:
            reasons.append(f"Found PHP marker at offset {index}: {marker.decode(errors='ignore')!r}")

    if primary and primary.name in {"JPEG", "PNG", "GIF", "PDF"}:
        for marker in PHP_TAGS:
            index = data.find(marker)
            if index > 0:
                reasons.append(f"Possible polyglot file with embedded PHP at offset {index}")

    if primary and embedded:
        reasons.append("Detected additional embedded file signatures inside the file")

    return PolyglotResult(
        detected=bool(reasons or embedded),
        reasons=reasons,
        embedded_signatures=embedded[:20],
    )


def heuristic_analysis(path: Path, primary: MatchResult | None) -> HeuristicResult:
    score = 0
    reasons: list[str] = []

    data = read_full_limited(path, 2 * 1024 * 1024)
    entropy = shannon_entropy(data)
    ext = path.suffix.lower()

    if primary and ext and ext.replace(".", "") not in [e.lower() for e in primary.extensions]:
        score += 2
        reasons.append(f"Extension {ext} does not match detected type ({primary.name})")

    if ext in SUSPICIOUS_EXTENSIONS:
        score += 1
        reasons.append(f"Sensitive or executable extension: {ext}")

    lower_data = data.lower()
    marker_hits = 0

    for marker in SCRIPT_MARKERS:
        if marker.lower() in lower_data:
            marker_hits += 1

    if marker_hits >= 1:
        score += min(marker_hits, 4)
        reasons.append(f"Found {marker_hits} potentially suspicious strings")

    if primary and primary.name in {"JPEG", "PNG", "GIF", "PDF"}:
        for tag in PHP_TAGS:
            if tag.lower() in lower_data:
                score += 4
                reasons.append("Embedded PHP code inside a non-PHP file type")
                break

    if len(data) >= 1024 and entropy > 7.5:
        score += 2
        reasons.append(f"High entropy ({entropy:.2f}); may indicate compression, encryption, or obfuscation")

    return HeuristicResult(
        suspicious=score >= 4,
        score=score,
        reasons=reasons,
        entropy=round(entropy, 4),
    )


def structural_validation(path: Path, primary: MatchResult | None) -> dict:
    if not primary:
        return {"valid": None, "checks": ["No primary type detected"]}

    checks: list[str] = []
    valid: bool | None = None

    try:
        if primary.name == "PNG":
            with path.open("rb") as f:
                signature = f.read(8)
                valid = signature == bytes.fromhex("89504E470D0A1A0A")
                checks.append("Valid PNG signature" if valid else "Invalid PNG signature")

        elif primary.name == "PDF":
            with path.open("rb") as f:
                data = f.read(4096)
                valid = data.startswith(b"%PDF")
                checks.append("PDF header present" if valid else "PDF header missing")

        elif primary.name == "PE":
            with path.open("rb") as f:
                header = f.read(2)
                valid = header == b"MZ"
                checks.append("MZ header present" if valid else "MZ header missing")

        elif primary.name == "ELF":
            with path.open("rb") as f:
                header = f.read(4)
                valid = header == b"\x7fELF"
                checks.append("Valid ELF header" if valid else "Invalid ELF header")

        elif primary.name in {"DOCX", "XLSX", "PPTX", "ZIP", "APK", "JAR"}:
            try:
                with zipfile.ZipFile(path, "r"):
                    valid = True
                    checks.append("ZIP container is structurally readable")
            except zipfile.BadZipFile:
                valid = False
                checks.append("Corrupted or invalid ZIP container")
        else:
            checks.append("No specific structural validation implemented for this type")
            valid = None

    except Exception as exc:
        valid = False
        checks.append(f"Validation error: {exc}")

    return {"valid": valid, "checks": checks}
