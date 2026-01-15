from __future__ import annotations

import re
from pathlib import Path
from typing import List

from report import Evidence, Finding

from code_scan.utils import CodeFinding, iter_python_files


PYTHON_RULES = [
    ("PY-EVAL", re.compile(r"\b(eval|exec)\("), "Use of eval/exec can lead to code injection.", "High"),
    ("PY-PICKLE", re.compile(r"pickle\.load\("), "Pickle deserialization can be unsafe.", "High"),
    ("PY-YAML", re.compile(r"yaml\.load\("), "Use yaml.safe_load instead of yaml.load.", "Medium"),
    ("PY-SUBPROCESS", re.compile(r"subprocess\.(Popen|call|run)\(.*shell=True"), "shell=True can lead to command injection.", "High"),
    ("PY-RANDOM", re.compile(r"random\.(choice|randint|randrange|random)"), "random is not suitable for security tokens.", "Low"),
]


def scan_python_code(root: Path) -> List[Finding]:
    findings: List[Finding] = []
    for file_path in iter_python_files(root):
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for idx, line in enumerate(lines, start=1):
            for rule_id, pattern, message, severity in PYTHON_RULES:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            id=rule_id,
                            title=message,
                            severity=severity,
                            confidence="Medium",
                            evidence=[
                                Evidence(
                                    description=message,
                                    location=f"{file_path}:{idx}",
                                    snippet=line.strip(),
                                )
                            ],
                            remediation="Review the usage and apply safer alternatives.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"],
                        )
                    )

    return findings
