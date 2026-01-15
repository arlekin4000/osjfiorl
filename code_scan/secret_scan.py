from __future__ import annotations

from pathlib import Path
from typing import List

from report import Evidence, Finding

from code_scan.utils import find_secrets, iter_text_files, redact_secret


def scan_secrets(root: Path) -> List[Finding]:
    findings: List[Finding] = []
    for file_path in iter_text_files(root):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line_no, line in enumerate(content.splitlines(), start=1):
            matches = find_secrets(line)
            for pattern, secret in matches:
                findings.append(
                    Finding(
                        id="secret-detected",
                        title="Возможный секрет в коде",
                        severity="Высокая",
                        confidence="Средняя",
                        evidence=[
                            Evidence(
                                description=f"Совпадение по шаблону: {pattern}",
                                location=f"{file_path}:{line_no}",
                                snippet=redact_secret(secret),
                            )
                        ],
                        remediation="Удалите секреты из кода и смените компрометированные учетные данные.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
                        ],
                    )
                )

    return findings
