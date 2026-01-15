from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import requests
from urllib.parse import urlparse, urlunparse

from report import Evidence, Finding


SECURITY_HEADERS = {
    "content-security-policy": "CSP helps mitigate XSS and data injection.",
    "strict-transport-security": "HSTS enforces HTTPS.",
    "x-frame-options": "Protects against clickjacking.",
    "x-content-type-options": "Prevents MIME-sniffing.",
    "referrer-policy": "Controls referrer information leakage.",
    "permissions-policy": "Restricts browser features.",
    "cross-origin-opener-policy": "Isolates browsing context.",
    "cross-origin-resource-policy": "Controls cross-origin resource sharing.",
    "cross-origin-embedder-policy": "Ensures cross-origin isolation.",
}


@dataclass
class HeaderCheckResult:
    findings: List[Finding]
    stats: Dict[str, int]


def _has_csp_antipattern(csp: str) -> bool:
    csp = csp.lower()
    return "unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp


def _is_potentially_sensitive_cookie(name: str) -> bool:
    name = name.lower()
    return any(token in name for token in ["session", "auth", "token", "jwt", "sid"])


def check_headers(pages: Iterable[Dict[str, str]]) -> HeaderCheckResult:
    findings: List[Finding] = []
    stats: Dict[str, int] = {"pages_checked": 0}

    for page in pages:
        headers = {k.lower(): v for k, v in page.items()}
        stats["pages_checked"] += 1

        for header, description in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    Finding(
                        id=f"header-{header}",
                        title=f"Missing security header: {header}",
                        severity="Low",
                        confidence="High",
                        evidence=[
                            Evidence(
                                description="Header missing",
                                location="response headers",
                            )
                        ],
                        remediation=f"Set the {header} header. {description}",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
                        ],
                    )
                )

        csp = headers.get("content-security-policy")
        if csp and _has_csp_antipattern(csp):
            findings.append(
                Finding(
                    id="csp-unsafe",
                    title="CSP allows unsafe directives",
                    severity="Medium",
                    confidence="Medium",
                    evidence=[
                        Evidence(
                            description="CSP header",
                            location="content-security-policy",
                            snippet=csp,
                        )
                    ],
                    remediation="Avoid using 'unsafe-inline', 'unsafe-eval', or wildcard sources in CSP.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                    ],
                )
            )

        xfo = headers.get("x-frame-options")
        if xfo is None and "frame-ancestors" not in (csp or ""):
            findings.append(
                Finding(
                    id="clickjacking-protection",
                    title="Missing clickjacking protection",
                    severity="Medium",
                    confidence="Medium",
                    evidence=[
                        Evidence(
                            description="No X-Frame-Options or frame-ancestors", location="response headers"
                            )
                    ],
                    remediation="Add X-Frame-Options or CSP frame-ancestors directive.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
                )
            )

        acao = headers.get("access-control-allow-origin")
        acc = headers.get("access-control-allow-credentials")
        if acao == "*" and acc and acc.lower() == "true":
            findings.append(
                Finding(
                    id="cors-credentials-wildcard",
                    title="CORS allows credentials with wildcard origin",
                    severity="High",
                    confidence="High",
                    evidence=[
                        Evidence(
                            description="CORS headers",
                            location="access-control-allow-origin",
                            snippet=f"ACAO: {acao}, ACAC: {acc}",
                        )
                    ],
                    remediation="Avoid using Access-Control-Allow-Origin: * together with credentials.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                )
            )

        set_cookie = headers.get("set-cookie")
        if set_cookie:
            cookies = set_cookie.split(",")
            for cookie in cookies:
                parts = [p.strip() for p in cookie.split(";")]
                name = parts[0].split("=")[0]
                flags = {p.lower() for p in parts[1:]}
                missing_flags = []
                if "secure" not in flags:
                    missing_flags.append("Secure")
                if "httponly" not in flags:
                    missing_flags.append("HttpOnly")
                if not any(flag.startswith("samesite") for flag in flags):
                    missing_flags.append("SameSite")
                if missing_flags:
                    severity = "Medium" if _is_potentially_sensitive_cookie(name) else "Low"
                    findings.append(
                        Finding(
                            id="cookie-flags",
                            title=f"Cookie missing security flags: {name}",
                            severity=severity,
                            confidence="Medium",
                            evidence=[
                                Evidence(
                                    description="Set-Cookie header",
                                    location="set-cookie",
                                    snippet=cookie,
                                )
                            ],
                            remediation="Set Secure, HttpOnly, and SameSite on sensitive cookies.",
                            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
                        )
                    )

        server = headers.get("server") or headers.get("x-powered-by")
        if server:
            findings.append(
                Finding(
                    id="version-disclosure",
                    title="Server version disclosure",
                    severity="Info",
                    confidence="Medium",
                    evidence=[
                        Evidence(
                            description="Server header",
                            location="server/x-powered-by",
                            snippet=server,
                        )
                    ],
                    remediation="Consider removing or minimizing version information in headers.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Information_Exposure.html"],
                )
            )

    return HeaderCheckResult(findings=findings, stats=stats)


def check_https_redirect(base_url: str, session: requests.Session, timeout: float) -> Optional[Finding]:
    parsed = urlparse(base_url)
    if parsed.scheme != "https":
        return Finding(
            id="https-missing",
            title="Target does not use HTTPS",
            severity="High",
            confidence="High",
            evidence=[Evidence(description="URL scheme", location=base_url)],
            remediation="Serve the application over HTTPS and redirect HTTP to HTTPS.",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
        )

    http_url = urlunparse(parsed._replace(scheme="http", netloc=parsed.netloc))
    try:
        response = session.get(http_url, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None

    location = response.headers.get("location", "")
    if response.status_code in {301, 302, 307, 308} and location.startswith("https://"):
        return None

    return Finding(
        id="https-redirect-missing",
        title="HTTPS redirect not enforced",
        severity="Medium",
        confidence="Medium",
        evidence=[Evidence(description="HTTP response", location=http_url, snippet=f"Status {response.status_code}")],
        remediation="Redirect HTTP traffic to HTTPS with a 301/308 response.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections"],
    )
