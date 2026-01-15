from __future__ import annotations

from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse, urlunparse

import requests

from report import Evidence, Finding


SECURITY_HEADERS = {
    "content-security-policy": "CSP снижает риск XSS и инъекций.",
    "strict-transport-security": "HSTS принудительно включает HTTPS.",
    "x-frame-options": "Защита от clickjacking.",
    "x-content-type-options": "Предотвращает MIME sniffing.",
    "referrer-policy": "Контроль утечек referrer.",
    "permissions-policy": "Ограничение опасных возможностей браузера.",
    "cross-origin-opener-policy": "Изоляция контекста окна.",
    "cross-origin-resource-policy": "Контроль междоменных ресурсов.",
    "cross-origin-embedder-policy": "Требования для cross-origin isolation.",
}


@dataclass
class HeaderCheckResult:
    findings: List[Finding]
    stats: Dict[str, int]


def _has_csp_antipattern(csp: str) -> bool:
    csp = csp.lower()
    return "unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp


def _has_weak_referrer_policy(policy: str) -> bool:
    policy = policy.lower()
    return policy in {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}


def _has_weak_permissions_policy(policy: str) -> bool:
    return "*" in policy


def _is_potentially_sensitive_cookie(name: str) -> bool:
    name = name.lower()
    return any(token in name for token in ["session", "auth", "token", "jwt", "sid"])


def _parse_hsts(value: str) -> Dict[str, str]:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    data: Dict[str, str] = {}
    for part in parts:
        if "=" in part:
            key, val = part.split("=", 1)
            data[key.lower()] = val
        else:
            data[part.lower()] = ""
    return data


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
                        title=f"Отсутствует заголовок безопасности: {header}",
                        severity="Низкая",
                        confidence="Высокая",
                        evidence=[
                            Evidence(
                                description="Заголовок отсутствует",
                                location="заголовки ответа",
                            )
                        ],
                        remediation=f"Установите заголовок {header}. {description}",
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
                    title="CSP содержит небезопасные директивы",
                    severity="Средняя",
                    confidence="Средняя",
                    evidence=[
                        Evidence(
                            description="Заголовок CSP",
                            location="content-security-policy",
                            snippet=csp,
                        )
                    ],
                    remediation="Исключите 'unsafe-inline', 'unsafe-eval' и wildcard-источники в CSP.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                    ],
                )
            )

        if csp and "default-src" not in csp.lower():
            findings.append(
                Finding(
                    id="csp-no-default-src",
                    title="CSP без директивы default-src",
                    severity="Средняя",
                    confidence="Средняя",
                    evidence=[
                        Evidence(
                            description="Заголовок CSP",
                            location="content-security-policy",
                            snippet=csp,
                        )
                    ],
                    remediation="Добавьте default-src для базового ограничения источников.",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
                    ],
                )
            )

        if csp and "object-src" in csp.lower() and "object-src 'none'" not in csp.lower():
            findings.append(
                Finding(
                    id="csp-object-src",
                    title="CSP допускает object-src",
                    severity="Низкая",
                    confidence="Средняя",
                    evidence=[
                        Evidence(
                            description="Директива object-src",
                            location="content-security-policy",
                            snippet=csp,
                        )
                    ],
                    remediation="Рекомендуется установить object-src 'none'.",
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
                    title="Нет защиты от clickjacking",
                    severity="Средняя",
                    confidence="Средняя",
                    evidence=[
                        Evidence(
                            description="Нет X-Frame-Options или frame-ancestors",
                            location="заголовки ответа",
                            )
                    ],
                    remediation="Добавьте X-Frame-Options или директиву frame-ancestors в CSP.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
                )
            )
        elif xfo and xfo.lower() not in {"deny", "sameorigin"}:
            findings.append(
                Finding(
                    id="xfo-invalid",
                    title="Некорректное значение X-Frame-Options",
                    severity="Низкая",
                    confidence="Высокая",
                    evidence=[
                        Evidence(
                            description="X-Frame-Options",
                            location="x-frame-options",
                            snippet=xfo,
                        )
                    ],
                    remediation="Используйте значения DENY или SAMEORIGIN.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
                )
            )

        xcto = headers.get("x-content-type-options")
        if xcto and xcto.lower() != "nosniff":
            findings.append(
                Finding(
                    id="xcto-weak",
                    title="Некорректный X-Content-Type-Options",
                    severity="Низкая",
                    confidence="Высокая",
                    evidence=[
                        Evidence(
                            description="X-Content-Type-Options",
                            location="x-content-type-options",
                            snippet=xcto,
                        )
                    ],
                    remediation="Установите X-Content-Type-Options: nosniff.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                )
            )

        referrer = headers.get("referrer-policy")
        if referrer and _has_weak_referrer_policy(referrer):
            findings.append(
                Finding(
                    id="referrer-policy-weak",
                    title="Слабая политика Referrer-Policy",
                    severity="Низкая",
                    confidence="Высокая",
                    evidence=[
                        Evidence(
                            description="Referrer-Policy",
                            location="referrer-policy",
                            snippet=referrer,
                        )
                    ],
                    remediation="Используйте stricter варианты, например strict-origin или no-referrer.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                )
            )

        permissions = headers.get("permissions-policy")
        if permissions and _has_weak_permissions_policy(permissions):
            findings.append(
                Finding(
                    id="permissions-policy-weak",
                    title="Слишком широкая Permissions-Policy",
                    severity="Низкая",
                    confidence="Средняя",
                    evidence=[
                        Evidence(
                            description="Permissions-Policy",
                            location="permissions-policy",
                            snippet=permissions,
                        )
                    ],
                    remediation="Ограничьте доступ к чувствительным возможностям браузера.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
                    )
            )

        hsts = headers.get("strict-transport-security")
        if hsts:
            hsts_data = _parse_hsts(hsts)
            max_age = int(hsts_data.get("max-age", "0") or 0)
            if max_age < 15_552_000:
                findings.append(
                    Finding(
                        id="hsts-short",
                        title="Слишком маленький max-age в HSTS",
                        severity="Низкая",
                        confidence="Средняя",
                        evidence=[
                            Evidence(
                                description="Strict-Transport-Security",
                                location="strict-transport-security",
                                snippet=hsts,
                            )
                        ],
                        remediation="Установите max-age минимум на 6 месяцев.",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                        ],
                    )
                )
            if "includesubdomains" not in hsts_data:
                findings.append(
                    Finding(
                        id="hsts-no-subdomains",
                        title="HSTS без includeSubDomains",
                        severity="Низкая",
                        confidence="Средняя",
                        evidence=[
                            Evidence(
                                description="Strict-Transport-Security",
                                location="strict-transport-security",
                                snippet=hsts,
                            )
                        ],
                        remediation="Рассмотрите includeSubDomains, чтобы защитить поддомены.",
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                        ],
                    )
                )

        acao = headers.get("access-control-allow-origin")
        acc = headers.get("access-control-allow-credentials")
        if acao == "*" and acc and acc.lower() == "true":
            findings.append(
                Finding(
                    id="cors-credentials-wildcard",
                    title="CORS разрешает credentials при wildcard Origin",
                    severity="Высокая",
                    confidence="Высокая",
                    evidence=[
                        Evidence(
                            description="CORS заголовки",
                            location="access-control-allow-origin",
                            snippet=f"ACAO: {acao}, ACAC: {acc}",
                        )
                    ],
                    remediation="Не используйте Access-Control-Allow-Origin: * вместе с credentials.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                )
            )

        set_cookie = headers.get("set-cookie")
        if set_cookie:
            cookie = SimpleCookie()
            cookie.load(set_cookie)
            for name, morsel in cookie.items():
                flags = {key.lower() for key, value in morsel.items() if value}
                missing_flags = []
                if "secure" not in flags and not morsel["secure"]:
                    missing_flags.append("Secure")
                if "httponly" not in flags and not morsel["httponly"]:
                    missing_flags.append("HttpOnly")
                if not morsel["samesite"]:
                    missing_flags.append("SameSite")
                if missing_flags:
                    severity = "Средняя" if _is_potentially_sensitive_cookie(name) else "Низкая"
                    findings.append(
                        Finding(
                            id="cookie-flags",
                            title=f"Cookie без защитных флагов: {name}",
                            severity=severity,
                            confidence="Средняя",
                            evidence=[
                                Evidence(
                                    description="Set-Cookie",
                                    location="set-cookie",
                                    snippet=set_cookie,
                                )
                            ],
                            remediation="Установите Secure, HttpOnly и SameSite для чувствительных cookie.",
                            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
                        )
                    )

                if morsel["samesite"].lower() == "none" and not morsel["secure"]:
                    findings.append(
                        Finding(
                            id="cookie-samesite-none",
                            title=f"SameSite=None без Secure: {name}",
                            severity="Средняя",
                            confidence="Высокая",
                            evidence=[
                                Evidence(
                                    description="Set-Cookie",
                                    location="set-cookie",
                                    snippet=set_cookie,
                                )
                            ],
                            remediation="При SameSite=None обязательно используйте Secure.",
                            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
                        )
                    )

        server = headers.get("server") or headers.get("x-powered-by")
        if server:
            findings.append(
                Finding(
                    id="version-disclosure",
                    title="Раскрытие версии сервера",
                    severity="Инфо",
                    confidence="Средняя",
                    evidence=[
                        Evidence(
                            description="Server/X-Powered-By",
                            location="server/x-powered-by",
                            snippet=server,
                        )
                    ],
                    remediation="Рекомендуется убрать или минимизировать версии в заголовках.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Information_Exposure.html"],
                )
            )

    return HeaderCheckResult(findings=findings, stats=stats)


def check_https_redirect(base_url: str, session: requests.Session, timeout: float) -> Optional[Finding]:
    parsed = urlparse(base_url)
    if parsed.scheme != "https":
        return Finding(
            id="https-missing",
            title="Целевой ресурс не использует HTTPS",
            severity="Высокая",
            confidence="Высокая",
            evidence=[Evidence(description="Схема URL", location=base_url)],
            remediation="Используйте HTTPS и перенаправляйте HTTP на HTTPS.",
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
        title="Нет перенаправления с HTTP на HTTPS",
        severity="Средняя",
        confidence="Средняя",
        evidence=[Evidence(description="HTTP ответ", location=http_url, snippet=f"Статус {response.status_code}")],
        remediation="Настройте редирект HTTP->HTTPS (301/308).",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections"],
    )
