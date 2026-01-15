from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import List

from report import Evidence, Finding


SEVERITY_MAP = {
    "critical": "Критическая",
    "high": "Высокая",
    "moderate": "Средняя",
    "medium": "Средняя",
    "low": "Низкая",
    "info": "Инфо",
}


def audit_python_deps(root: Path) -> List[Finding]:
    findings: List[Finding] = []
    requirements = root / "requirements.txt"
    if requirements.exists():
        if shutil.which("pip-audit"):
            try:
                result = subprocess.run(
                    ["pip-audit", "-r", str(requirements), "-f", "json"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.stdout:
                    data = json.loads(result.stdout)
                    for vuln in data:
                        findings.append(
                            Finding(
                                id="pip-audit",
                                title=f"Уязвимость зависимости: {vuln.get('name')}",
                                severity="Средняя",
                                confidence="Высокая",
                                evidence=[
                                    Evidence(
                                        description="Отчет pip-audit",
                                        location=str(requirements),
                                        snippet=str(vuln.get("id")),
                                    )
                                ],
                                remediation="Обновите зависимость до исправленной версии.",
                                references=vuln.get("aliases", []),
                            )
                        )
            except (OSError, json.JSONDecodeError):
                pass
        else:
            findings.append(
                Finding(
                    id="pip-audit-missing",
                    title="pip-audit недоступен",
                    severity="Инфо",
                    confidence="Высокая",
                    evidence=[
                        Evidence(
                            description="Аудит зависимостей пропущен",
                            location=str(requirements),
                            snippet="pip-audit не установлен",
                        )
                    ],
                    remediation="Установите pip-audit и повторите запуск для проверки зависимостей.",
                    references=["https://pypi.org/project/pip-audit/"],
                )
            )

    return findings


def audit_node_deps(root: Path) -> List[Finding]:
    findings: List[Finding] = []
    package_lock = root / "package-lock.json"
    if package_lock.exists():
        if shutil.which("npm"):
            try:
                result = subprocess.run(
                    ["npm", "audit", "--json"],
                    cwd=str(root),
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.stdout:
                    data = json.loads(result.stdout)
                    advisories = data.get("advisories") or {}
                    for advisory in advisories.values():
                        findings.append(
                            Finding(
                                id="npm-audit",
                                title=f"Уязвимость зависимости: {advisory.get('module_name')}",
                                severity=SEVERITY_MAP.get(str(advisory.get("severity", "medium")).lower(), "Средняя"),
                                confidence="Высокая",
                                evidence=[
                                    Evidence(
                                        description="Отчет npm audit",
                                        location=str(package_lock),
                                        snippet=str(advisory.get("title")),
                                    )
                                ],
                                remediation="Обновите зависимость до исправленной версии.",
                                references=[advisory.get("url", "")],
                            )
                        )
            except (OSError, json.JSONDecodeError):
                pass
        else:
            findings.append(
                Finding(
                    id="npm-audit-missing",
                    title="npm audit недоступен",
                    severity="Инфо",
                    confidence="Высокая",
                    evidence=[
                        Evidence(
                            description="Аудит зависимостей пропущен",
                            location=str(package_lock),
                            snippet="npm не установлен",
                        )
                    ],
                    remediation="Установите npm и выполните npm audit для проверки зависимостей.",
                    references=["https://docs.npmjs.com/cli/v9/commands/npm-audit"],
                )
            )

    return findings
