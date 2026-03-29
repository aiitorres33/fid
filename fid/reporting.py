from __future__ import annotations

from pathlib import Path

from fid.utils import safe_text


def generate_html_report(report_data: dict, output_path: str) -> None:
    output = Path(output_path)

    if "results" in report_data:
        items = report_data["results"]
        title = f"Scan report: {safe_text(report_data.get('directory', 'directory'))}"
        summary = report_data.get("summary", {})
    else:
        items = [report_data]
        title = f"File report: {safe_text(report_data.get('file', 'file'))}"
        summary = None

    cards: list[str] = []

    for item in items:
        file_name = safe_text(item.get("file", "N/A"))
        size = safe_text(item.get("size", "N/A"))
        error = safe_text(item.get("error", ""))

        primary = item.get("primary_type") or {}
        primary_name = safe_text(primary.get("name", "unknown"))
        primary_mime = safe_text(primary.get("mime", "unknown"))

        validation = item.get("structural_validation", {})
        validation_ok = safe_text(validation.get("valid", "N/A"))
        validation_checks = "<br>".join(safe_text(check) for check in validation.get("checks", []))

        heuristics = item.get("heuristic_analysis", {})
        suspicious = safe_text(heuristics.get("suspicious", "N/A"))
        score = safe_text(heuristics.get("score", "N/A"))
        entropy = safe_text(heuristics.get("entropy", "N/A"))
        reasons = "<br>".join(safe_text(reason) for reason in heuristics.get("reasons", []))

        polyglot = item.get("polyglot_analysis", {})
        poly_detected = safe_text(polyglot.get("detected", "N/A"))
        poly_reasons = "<br>".join(safe_text(reason) for reason in polyglot.get("reasons", []))

        yara_block = ""
        if "yara" in item:
            yara_data = item["yara"]
            yara_matches = "<br>".join(safe_text(match) for match in yara_data.get("matches", []))
            yara_error = safe_text(yara_data.get("error", ""))
            yara_block = f"""
            <div><strong>YARA matches:</strong><br>{yara_matches or 'None'}</div>
            <div><strong>YARA error:</strong> {yara_error or 'None'}</div>
            """

        card = f"""
        <div class="card">
            <h2>{file_name}</h2>
            <div><strong>Size:</strong> {size} bytes</div>
            <div><strong>Error:</strong> {error or 'None'}</div>
            <div><strong>Primary type:</strong> {primary_name}</div>
            <div><strong>MIME:</strong> {primary_mime}</div>
            <div><strong>Structural validation:</strong> {validation_ok}</div>
            <div><strong>Checks:</strong><br>{validation_checks or 'None'}</div>
            <div><strong>Polyglot:</strong> {poly_detected}</div>
            <div><strong>Polyglot reasons:</strong><br>{poly_reasons or 'None'}</div>
            <div><strong>Suspicious:</strong> {suspicious}</div>
            <div><strong>Score:</strong> {score}</div>
            <div><strong>Entropy:</strong> {entropy}</div>
            <div><strong>Heuristic reasons:</strong><br>{reasons or 'None'}</div>
            {yara_block}
        </div>
        """
        cards.append(card)

    summary_html = ""
    if summary:
        summary_html = f"""
        <div class="summary">
            <h2>Summary</h2>
            <div><strong>Total files:</strong> {safe_text(summary.get('total_files'))}</div>
            <div><strong>Detected:</strong> {safe_text(summary.get('detected_files'))}</div>
            <div><strong>Suspicious:</strong> {safe_text(summary.get('suspicious_files'))}</div>
            <div><strong>Polyglot:</strong> {safe_text(summary.get('polyglot_files'))}</div>
            <div><strong>Errors:</strong> {safe_text(summary.get('errors'))}</div>
        </div>
        """

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    margin: 0;
    padding: 20px;
}}
h1 {{
    margin-bottom: 10px;
}}
.summary, .card {{
    background: #111827;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 16px;
    margin-bottom: 16px;
}}
.card h2 {{
    margin-top: 0;
    word-break: break-all;
}}
strong {{
    color: #93c5fd;
}}
</style>
</head>
<body>
<h1>{title}</h1>
{summary_html}
{"".join(cards)}
</body>
</html>
"""
    output.write_text(document, encoding="utf-8")
