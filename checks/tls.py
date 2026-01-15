from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import List

from report import Evidence, Finding


@dataclass
class TLSResult:
    findings: List[Finding]
    supported_versions: List[str]


TLS_VERSIONS = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]


def _test_tls_version(host: str, port: int, version: ssl.TLSVersion) -> bool:
    context = ssl.create_default_context()
    context.minimum_version = version
    context.maximum_version = version
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.do_handshake()
                return True
    except ssl.SSLError:
        return False
    except OSError:
        return False


def check_tls(host: str, port: int = 443) -> TLSResult:
    findings: List[Finding] = []
    supported = []

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.do_handshake()
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            Finding(
                id="tls-cert-invalid",
                title="TLS certificate validation failed",
                severity="High",
                confidence="High",
                evidence=[Evidence(description="Certificate verification error", location=f"{host}:{port}", snippet=str(exc))],
                remediation="Ensure the TLS certificate chain is valid and trusted.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
            )
        )
    except OSError:
        pass

    for name, version in TLS_VERSIONS:
        if _test_tls_version(host, port, version):
            supported.append(name)

    if supported:
        if any(v in supported for v in ["TLSv1", "TLSv1.1"]):
            findings.append(
                Finding(
                    id="tls-legacy",
                    title="Legacy TLS versions supported",
                    severity="Medium",
                    confidence="Medium",
                    evidence=[
                        Evidence(
                            description="Supported versions",
                            location=f"{host}:{port}",
                            snippet=", ".join(supported),
                        )
                    ],
                    remediation="Disable TLS 1.0/1.1 and require TLS 1.2+.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                )
            )
    else:
        findings.append(
            Finding(
                id="tls-unreachable",
                title="Unable to determine TLS versions",
                severity="Info",
                confidence="Low",
                evidence=[
                    Evidence(
                        description="No TLS handshake succeeded",
                        location=f"{host}:{port}",
                    )
                ],
                remediation="Verify TLS configuration and network connectivity.",
                references=[],
            )
        )

    return TLSResult(findings=findings, supported_versions=supported)
