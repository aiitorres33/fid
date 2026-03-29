#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from fid.detectors import analyze_file
from fid.reporting import generate_html_report
from fid.scanner import scan_directory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="fid.py - file identification tool using magic numbers, heuristics, polyglot analysis, YARA, binwalk, and HTML reporting"
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--file", help="File to analyze")
    target.add_argument("--scan-dir", help="Directory to scan")

    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--html-report", help="Write an HTML report to this path")

    parser.add_argument("--binwalk", action="store_true", help="Run binwalk if available")
    parser.add_argument("--extract", action="store_true", help="Use binwalk -e")
    parser.add_argument("--recursive-binwalk", action="store_true", help="Use binwalk -Me")

    parser.add_argument("--yara-rules", help="Path to a YARA rule file")
    parser.add_argument("--no-recursive-dir", action="store_true", help="Do not recurse into subdirectories")
    parser.add_argument("--max-files", type=int, help="Maximum number of files to process in scan-dir mode")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.file:
        result = analyze_file(
            args.file,
            use_binwalk=args.binwalk,
            extract=args.extract,
            recursive=args.recursive_binwalk,
            yara_rules=args.yara_rules,
        )
    else:
        result = scan_directory(
            args.scan_dir,
            recursive_scan=not args.no_recursive_dir,
            use_binwalk=args.binwalk,
            extract=args.extract,
            recursive_binwalk=args.recursive_binwalk,
            yara_rules=args.yara_rules,
            max_files=args.max_files,
        )

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("\n[+] Analysis complete")
        if "summary" in result:
            print(f"[+] Directory: {result.get('directory')}")
            print(f"[+] Summary: {result.get('summary')}")
        else:
            print(f"[+] File: {result.get('file')}")
            print(f"[+] Detected: {result.get('detected')}")
            primary = result.get("primary_type")
            if primary:
                print(f"[+] Primary type: {primary['name']} ({primary['mime']})")
            else:
                print("[!] Primary type: unknown")

    if args.html_report:
        generate_html_report(result, args.html_report)
        print(f"[+] HTML report written to: {args.html_report}")


if __name__ == "__main__":
    main()
