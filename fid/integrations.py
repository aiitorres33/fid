from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def run_binwalk(path: Path, extract: bool = False, recursive: bool = False) -> dict:
    binwalk_path = shutil.which("binwalk")
    if not binwalk_path:
        return {
            "available": False,
            "error": "binwalk is not installed or not present in PATH",
        }

    command = [binwalk_path, str(path)]
    if extract and recursive:
        command = [binwalk_path, "-Me", str(path)]
    elif extract:
        command = [binwalk_path, "-e", str(path)]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return {
            "available": True,
            "command": command,
            "returncode": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "command": command,
            "error": "binwalk exceeded the time limit",
        }


def run_yara(path: Path, rule_path: Path) -> dict:
    yara_path = shutil.which("yara")
    if not yara_path:
        return {
            "available": False,
            "error": "yara is not installed or not present in PATH",
        }

    if not rule_path.exists():
        return {
            "available": True,
            "error": f"Rule file does not exist: {rule_path}",
        }

    command = [yara_path, str(rule_path), str(path)]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        matches = [line.strip() for line in process.stdout.splitlines() if line.strip()]
        return {
            "available": True,
            "command": command,
            "returncode": process.returncode,
            "matches": matches,
            "stdout": process.stdout,
            "stderr": process.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "command": command,
            "error": "yara exceeded the time limit",
        }
