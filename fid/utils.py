from __future__ import annotations

import html
import math
from pathlib import Path
from typing import Any

from fid.models import Signature


def pattern_to_bytes(pattern: str) -> list[int | None]:
    result: list[int | None] = []
    if len(pattern) % 2 != 0:
        raise ValueError(f"Invalid hex pattern: {pattern}")

    for i in range(0, len(pattern), 2):
        chunk = pattern[i:i + 2]
        result.append(None if chunk == "??" else int(chunk, 16))

    return result


def match_at(data: bytes, offset: int, pattern: str) -> bool:
    signature = pattern_to_bytes(pattern)

    if offset < 0 or len(data) < offset + len(signature):
        return False

    for i, value in enumerate(signature):
        if value is None:
            continue
        if data[offset + i] != value:
            return False

    return True


def search_pattern_anywhere(data: bytes, pattern: str, exclude_offset_zero: bool = False) -> list[int]:
    signature = pattern_to_bytes(pattern)
    hits: list[int] = []
    sig_len = len(signature)

    for off in range(0, len(data) - sig_len + 1):
        if exclude_offset_zero and off == 0:
            continue

        matched = True
        for i, value in enumerate(signature):
            if value is None:
                continue
            if data[off + i] != value:
                matched = False
                break

        if matched:
            hits.append(off)

    return hits


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    frequency = [0] * 256
    for b in data:
        frequency[b] += 1

    length = len(data)
    entropy = 0.0

    for count in frequency:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def max_needed_bytes(signatures: list[Signature]) -> int:
    return max(sig.offset + len(sig.pattern) // 2 for sig in signatures)


def read_prefix(path: Path, size: int) -> bytes:
    with path.open("rb") as f:
        return f.read(size)


def read_full_limited(path: Path, limit: int = 4 * 1024 * 1024) -> bytes:
    with path.open("rb") as f:
        return f.read(limit)


def safe_text(value: Any) -> str:
    return html.escape(str(value))
