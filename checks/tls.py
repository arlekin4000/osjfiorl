from __future__ import annotations

import socket
import ssl
from datetime import datetime, timedelta
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
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    except ValueError:
                        expires = None
                    if expires and expires - datetime.utcnow() <= timedelta(days=30):
                        findings.append(
                            Finding(
                                id="tls-cert-expiring",
                                title="Срок действия TLS сертификата скоро истекает",
                                severity="Средняя",
                                confidence="Высокая",
                                evidence=[
                                    Evidence(
                                        description="Дата окончания сертификата",
                                        location=f"{host}:{port}",
                                        snippet=expires.isoformat(),
                                    )
                                ],
                                remediation="Обновите сертификат до истечения срока действия.",
                                references=[
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                                ],
                            )
                        )
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            Finding(
                id="tls-cert-invalid",
                title="Ошибка проверки TLS сертификата",
                severity="Высокая",
                confidence="Высокая",
                evidence=[Evidence(description="Ошибка проверки сертификата", location=f"{host}:{port}", snippet=str(exc))],
                remediation="Убедитесь, что цепочка сертификатов корректна и доверена.",
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
                    title="Поддерживаются устаревшие версии TLS",
                    severity="Средняя",
                    confidence="Средняя",
                    evidence=[
                        Evidence(
                            description="Поддерживаемые версии",
                            location=f"{host}:{port}",
                            snippet=", ".join(supported),
                        )
                    ],
                    remediation="Отключите TLS 1.0/1.1 и требуйте TLS 1.2+.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                )
            )
    else:
        findings.append(
            Finding(
                id="tls-unreachable",
                title="Не удалось определить версии TLS",
                severity="Инфо",
                confidence="Низкая",
                evidence=[
                    Evidence(
                        description="TLS рукопожатие не удалось",
                        location=f"{host}:{port}",
                    )
                ],
                remediation="Проверьте настройки TLS и сетевую доступность.",
                references=[],
            )
        )

    return TLSResult(findings=findings, supported_versions=supported)
