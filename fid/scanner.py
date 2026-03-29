from __future__ import annotations

from pathlib import Path

from fid.detectors import analyze_file


def scan_directory(
    directory: str,
    recursive_scan: bool = True,
    use_binwalk: bool = False,
    extract: bool = False,
    recursive_binwalk: bool = False,
    yara_rules: str | None = None,
    max_files: int | None = None,
) -> dict:
    base = Path(directory)

    if not base.exists():
        return {"error": f"Directory does not exist: {base}"}
    if not base.is_dir():
        return {"error": f"Not a directory: {base}"}

    files = list(base.rglob("*")) if recursive_scan else list(base.glob("*"))
    files = [file for file in files if file.is_file()]

    if max_files is not None:
        files = files[:max_files]

    results: list[dict] = []

    for file in files:
        try:
            results.append(
                analyze_file(
                    str(file),
                    use_binwalk=use_binwalk,
                    extract=extract,
                    recursive=recursive_binwalk,
                    yara_rules=yara_rules,
                )
            )
        except Exception as exc:
            results.append({
                "file": str(file),
                "error": str(exc),
            })

    summary = {
        "total_files": len(results),
        "detected_files": sum(1 for item in results if item.get("detected")),
        "suspicious_files": sum(1 for item in results if item.get("heuristic_analysis", {}).get("suspicious")),
        "polyglot_files": sum(1 for item in results if item.get("polyglot_analysis", {}).get("detected")),
        "errors": sum(1 for item in results if "error" in item),
    }

    return {
        "directory": str(base),
        "summary": summary,
        "results": results,
    }
