from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Signature:
    name: str
    mime: str
    extensions: tuple[str, ...]
    offset: int
    pattern: str
    priority: int = 50
    category: str = "generic"


@dataclass
class MatchResult:
    name: str
    mime: str
    extensions: list[str]
    offset: int
    pattern: str
    priority: int
    category: str


@dataclass
class PolyglotResult:
    detected: bool
    reasons: list[str]
    embedded_signatures: list[dict[str, Any]]


@dataclass
class HeuristicResult:
    suspicious: bool
    score: int
    reasons: list[str]
    entropy: float | None
