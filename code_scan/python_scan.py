from __future__ import annotations

import re
from pathlib import Path
from typing import List

from report import Evidence, Finding

from code_scan.utils import iter_python_files


PYTHON_RULES = [
    ("PY-EVAL", re.compile(r"\b(eval|exec)\("), "Использование eval/exec может привести к инъекциям кода.", "Высокая"),
    ("PY-PICKLE", re.compile(r"pickle\.(load|loads)\("), "Десериализация pickle небезопасна.", "Высокая"),
    ("PY-YAML", re.compile(r"yaml\.load\("), "Используйте yaml.safe_load вместо yaml.load.", "Средняя"),
    ("PY-SUBPROCESS", re.compile(r"subprocess\.(Popen|call|run)\(.*shell=True"), "shell=True может привести к командной инъекции.", "Высокая"),
    ("PY-RANDOM", re.compile(r"random\.(choice|randint|randrange|random)"), "random не подходит для токенов безопасности.", "Низкая"),
    ("PY-VERIFY-FALSE", re.compile(r"verify\s*=\s*False"), "Отключена проверка TLS (verify=False).", "Высокая"),
    ("PY-UNVERIFIED-SSL", re.compile(r"ssl\._create_unverified_context"), "Создается небезопасный SSL контекст.", "Высокая"),
    ("PY-WEAK-HASH", re.compile(r"hashlib\.(md5|sha1)\("), "Используется слабая хэш-функция (md5/sha1).", "Низкая"),
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
                            confidence="Средняя",
                            evidence=[
                                Evidence(
                                    description=message,
                                    location=f"{file_path}:{idx}",
                                    snippet=line.strip(),
                                )
                            ],
                            remediation="Проверьте использование и примените безопасные альтернативы.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"],
                        )
                    )

    return findings
