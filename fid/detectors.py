from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import mimetypes

from fid.analyzers import detect_polyglot, heuristic_analysis, refine_zip_type, structural_validation
from fid.integrations import run_binwalk, run_yara
from fid.models import MatchResult
from fid.signatures import SIGNATURES
from fid.utils import match_at, max_needed_bytes, read_prefix


def detect_primary_type(path: Path) -> tuple[MatchResult | None, list[MatchResult]]:
    needed = max_needed_bytes(SIGNATURES)
    prefix = read_prefix(path, needed)

    matches: list[MatchResult] = []

    for sig in SIGNATURES:
        if match_at(prefix, sig.offset, sig.pattern):
            matches.append(
                MatchResult(
                    name=sig.name,
                    mime=sig.mime,
                    extensions=list(sig.extensions),
                    offset=sig.offset,
                    pattern=sig.pattern,
                    priority=sig.priority,
                    category=sig.category,
                )
            )

    if not matches:
        return None, []

    matches.sort(key=lambda item: (item.priority, len(item.pattern)), reverse=True)
    return matches[0], matches


def analyze_file(
    path_str: str,
    use_binwalk: bool = False,
    extract: bool = False,
    recursive: bool = False,
    yara_rules: str | None = None,
) -> dict:
    path = Path(path_str)

    if not path.exists():
        return {"file": str(path), "error": f"File does not exist: {path}"}
    if not path.is_file():
        return {"file": str(path), "error": f"Not a regular file: {path}"}

    primary, all_matches = detect_primary_type(path)
    refined = refine_zip_type(path, primary) if primary and primary.name == "ZIP" else primary

    polyglot = detect_polyglot(path, refined)
    heuristics = heuristic_analysis(path, refined)
    validation = structural_validation(path, refined)

    guessed_mime, _ = mimetypes.guess_type(str(path))

    result = {
        "file": str(path),
        "size": path.stat().st_size,
        "extension": path.suffix.lower(),
        "guessed_mime_by_extension": guessed_mime,
        "detected": refined is not None,
        "primary_type": asdict(refined) if refined else None,
        "all_header_matches": [asdict(match) for match in all_matches],
        "structural_validation": validation,
        "polyglot_analysis": asdict(polyglot),
        "heuristic_analysis": asdict(heuristics),
    }

    if use_binwalk:
        result["binwalk"] = run_binwalk(path, extract=extract, recursive=recursive)

    if yara_rules:
        result["yara"] = run_yara(path, Path(yara_rules))

    return result
