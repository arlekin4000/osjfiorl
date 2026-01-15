from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import List

from report import Evidence, Finding


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
                                title=f"Dependency vulnerability: {vuln.get('name')}",
                                severity="Medium",
                                confidence="High",
                                evidence=[
                                    Evidence(
                                        description="pip-audit report",
                                        location=str(requirements),
                                        snippet=str(vuln.get("id")),
                                    )
                                ],
                                remediation="Upgrade the dependency to a fixed version.",
                                references=vuln.get("aliases", []),
                            )
                        )
            except (OSError, json.JSONDecodeError):
                pass
        else:
            findings.append(
                Finding(
                    id="pip-audit-missing",
                    title="pip-audit not available",
                    severity="Info",
                    confidence="High",
                    evidence=[
                        Evidence(
                            description="Dependency audit skipped",
                            location=str(requirements),
                            snippet="pip-audit not installed",
                        )
                    ],
                    remediation="Install pip-audit and re-run for dependency vulnerability scanning.",
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
                                title=f"Dependency vulnerability: {advisory.get('module_name')}",
                                severity=str(advisory.get("severity", "medium")).title(),
                                confidence="High",
                                evidence=[
                                    Evidence(
                                        description="npm audit report",
                                        location=str(package_lock),
                                        snippet=str(advisory.get("title")),
                                    )
                                ],
                                remediation="Upgrade the dependency to a fixed version.",
                                references=[advisory.get("url", "")],
                            )
                        )
            except (OSError, json.JSONDecodeError):
                pass
        else:
            findings.append(
                Finding(
                    id="npm-audit-missing",
                    title="npm audit not available",
                    severity="Info",
                    confidence="High",
                    evidence=[
                        Evidence(
                            description="Dependency audit skipped",
                            location=str(package_lock),
                            snippet="npm not installed",
                        )
                    ],
                    remediation="Install npm and run npm audit for dependency vulnerability scanning.",
                    references=["https://docs.npmjs.com/cli/v9/commands/npm-audit"],
                )
            )

    return findings
