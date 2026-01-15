from __future__ import annotations

from dataclasses import dataclass
from typing import List

import requests

from report import Evidence, Finding


SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/phpinfo.php",
    "/debug",
    "/admin",
    "/swagger",
    "/openapi.json",
    "/graphql",
]


@dataclass
class MisconfigResult:
    findings: List[Finding]


DIRECTORY_LISTING_PATTERNS = [
    "Index of /",
    "Directory listing for",
    "Parent Directory",
]


def check_directory_listing(base_url: str, session: requests.Session, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    try:
        response = session.get(base_url, timeout=timeout)
    except requests.RequestException:
        return findings

    if response.ok and response.headers.get("content-type", "").startswith("text/html"):
        for pattern in DIRECTORY_LISTING_PATTERNS:
            if pattern in response.text:
                findings.append(
                    Finding(
                        id="dir-listing",
                        title="Possible directory listing enabled",
                        severity="Low",
                        confidence="Medium",
                        evidence=[
                            Evidence(
                                description="Directory listing pattern",
                                location=base_url,
                                snippet=pattern,
                            )
                        ],
                        remediation="Disable directory listing on web servers.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
                    )
                )
                break

    return findings


def check_sensitive_paths(base_url: str, session: requests.Session, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException:
            continue

        if response.status_code and response.status_code < 400:
            findings.append(
                Finding(
                    id="sensitive-path",
                    title="Potentially sensitive path accessible",
                    severity="Medium",
                    confidence="Medium",
                    evidence=[
                        Evidence(
                            description="Accessible path",
                            location=url,
                            snippet=f"Status {response.status_code}",
                        )
                    ],
                    remediation="Restrict access to sensitive endpoints or remove them from public exposure.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"],
                )
            )

    return findings


def run_misconfig_checks(base_url: str, session: requests.Session, timeout: float) -> MisconfigResult:
    findings = []
    findings.extend(check_directory_listing(base_url, session, timeout))
    findings.extend(check_sensitive_paths(base_url, session, timeout))
    return MisconfigResult(findings=findings)
