from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Tuple


@dataclass
class CodeFinding:
    file_path: Path
    line_no: int
    line: str
    message: str
    rule_id: str
    severity: str
    confidence: str


SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]([A-Za-z0-9\-_/]{8,})['\"]"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
]


def redact_secret(value: str, keep: int = 2) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def iter_python_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.py"):
        if path.is_file():
            yield path


def iter_text_files(root: Path, max_size: int = 2_000_000) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and path.suffix not in {".png", ".jpg", ".jpeg", ".gif", ".pdf"}:
            try:
                if path.stat().st_size <= max_size:
                    yield path
            except OSError:
                continue


def find_secrets(content: str) -> List[Tuple[str, str]]:
    matches = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.findall(content):
            secret = match if isinstance(match, str) else match[0]
            matches.append((pattern.pattern, secret))
    return matches
