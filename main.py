from __future__ import annotations

import argparse
import importlib.util
import logging
import sys
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

import requests

from checks.http_headers import check_headers, check_https_redirect
from checks.misconfig import run_misconfig_checks
from checks.tls import check_tls
from code_scan.dependency_audit import audit_node_deps, audit_python_deps
from code_scan.python_scan import scan_python_code
from code_scan.secret_scan import scan_secrets
from crawler import CrawlConfig, Crawler
from report import AuditReport, Evidence, Finding, build_report


logger = logging.getLogger("security_audit")

HELP_TEXT = """\
Security Audit Assistant — безопасный пассивный аудит

Использование:
  audit.py --url https://example.com [параметры]

Примеры:
  audit.py --url https://example.com
  audit.py --url https://example.com --code ./repo --out report.json --html report.html

Параметры:
  --url             Целевой URL (обязательно)
  --code            Путь к исходному коду для статического анализа
  --out             Путь для JSON отчета
  --html            Путь для HTML отчета
  --timeout         HTTP таймаут в секундах (по умолчанию 10)
  --max-pages       Максимум страниц для краулинга (по умолчанию 50)
  --max-depth       Максимальная глубина краулинга (по умолчанию 2)
  --rate            Ограничение частоты (запросов/сек, по умолчанию 2)
  --user-agent      Пользовательский User-Agent
  --parallelism     Параллелизм краулинга
  --disable-crawl   Отключить краулинг
  --disable-tls     Отключить проверки TLS
  --disable-headers Отключить проверку HTTP заголовков
  --disable-misconfig Отключить проверки конфигурации
  --disable-code    Отключить анализ кода
  --dry-run         Не выполнять сетевые запросы
  --log-level       Уровень логирования (INFO/DEBUG/ERROR)
  -h, --help        Показать эту справку
"""


class RussianArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        return HELP_TEXT

    def error(self, message: str) -> None:
        self.print_help()
        self.exit(2, f"\nошибка: {message}\n")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = RussianArgumentParser(add_help=True)
    parser.add_argument("--url", help="Целевой URL (https://example.com)")
    parser.add_argument("--code", help="Путь к исходному коду для статического анализа")
    parser.add_argument("--out", help="Путь для JSON отчета")
    parser.add_argument("--html", help="Путь для HTML отчета")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP таймаут в секундах")
    parser.add_argument("--max-pages", type=int, default=50, help="Максимум страниц для краулинга")
    parser.add_argument("--max-depth", type=int, default=2, help="Максимальная глубина краулинга")
    parser.add_argument("--rate", type=float, default=2.0, help="Ограничение частоты (запросов в секунду)")
    parser.add_argument("--user-agent", default="SecurityAuditAssistant/1.0", help="Пользовательский User-Agent")
    parser.add_argument("--parallelism", type=int, default=4, help="Параллелизм краулинга")
    parser.add_argument("--disable-crawl", action="store_true", help="Отключить краулинг")
    parser.add_argument("--disable-tls", action="store_true", help="Отключить проверки TLS")
    parser.add_argument("--disable-headers", action="store_true", help="Отключить проверку HTTP заголовков")
    parser.add_argument("--disable-misconfig", action="store_true", help="Отключить проверки конфигурации")
    parser.add_argument("--disable-code", action="store_true", help="Отключить анализ кода")
    parser.add_argument("--dry-run", action="store_true", help="Не выполнять сетевые запросы")
    parser.add_argument("--log-level", default="INFO", help="Уровень логирования")
    return parser.parse_args(argv)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def run_audit(args: argparse.Namespace) -> AuditReport:
    findings: List[Finding] = []
    stats: Dict[str, object] = {"Страниц просканировано": 0, "Наблюдений": 0}

    session = requests.Session()
    session.headers.update({"User-Agent": args.user_agent})

    if not args.dry_run and not args.disable_crawl:
        crawler = Crawler(
            args.url,
            CrawlConfig(
                max_pages=args.max_pages,
                max_depth=args.max_depth,
                rate_limit=args.rate,
                timeout=args.timeout,
                user_agent=args.user_agent,
                parallelism=args.parallelism,
            ),
        )
        pages = crawler.crawl()
        stats["Страниц просканировано"] = len(pages)

        if not args.disable_headers:
            header_result = check_headers([page.headers for page in pages])
            findings.extend(header_result.findings)
    else:
        pages = []

    if not args.dry_run and not args.disable_misconfig:
        findings.extend(run_misconfig_checks(args.url, session, args.timeout).findings)

    if not args.dry_run and not args.disable_headers:
        https_finding = check_https_redirect(args.url, session, args.timeout)
        if https_finding:
            findings.append(https_finding)

    parsed = urlparse(args.url)
    if not args.dry_run and not args.disable_tls and parsed.hostname:
        tls_result = check_tls(parsed.hostname)
        findings.extend(tls_result.findings)
        stats["Поддерживаемые версии TLS"] = ", ".join(tls_result.supported_versions)

    if args.code and not args.disable_code:
        root = Path(args.code).expanduser().resolve()
        if root.exists():
            findings.extend(scan_python_code(root))
            findings.extend(scan_secrets(root))
            findings.extend(audit_python_deps(root))
            findings.extend(audit_node_deps(root))
        else:
            findings.append(
                Finding(
                    id="code-path-missing",
                    title="Путь к коду не найден",
                    severity="Инфо",
                    confidence="Высокая",
                    evidence=[Evidence(description="Некорректный путь", location=str(root))],
                    remediation="Проверьте значение --code и повторите запуск.",
                    references=[],
                )
            )

    stats["Наблюдений"] = len(findings)

    return build_report(args.url, findings, stats)


def print_report(report: AuditReport) -> None:
    if importlib.util.find_spec("rich"):
        from rich.console import Console
        from rich.table import Table

        console = Console()
        console.print(f"\n[bold]Отчет по безопасности для {report.target}[/bold]")
        console.print(f"Сформировано: {report.generated_at}\n")

        table = Table(title="Наблюдения")
        table.add_column("Серьезность")
        table.add_column("Описание")
        table.add_column("Уверенность")
        table.add_column("Доказательства")

        for finding in report.findings:
            evidence_text = "; ".join(ev.location for ev in finding.evidence)
            table.add_row(finding.severity, finding.title, finding.confidence, evidence_text)
        console.print(table)
    else:
        print(f"Отчет по безопасности для {report.target}")
        print(f"Сформировано: {report.generated_at}")
        for finding in report.findings:
            print(f"- [{finding.severity}] {finding.title} ({finding.confidence})")
            for ev in finding.evidence:
                print(f"  * {ev.description}: {ev.location}")


def write_outputs(report: AuditReport, args: argparse.Namespace) -> None:
    if args.out:
        Path(args.out).write_text(report.to_json(), encoding="utf-8")
        logger.info("JSON отчет сохранен в %s", args.out)
    if args.html:
        Path(args.html).write_text(report.to_html(), encoding="utf-8")
        logger.info("HTML отчет сохранен в %s", args.html)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    if not args.url:
        try:
            args.url = input("Введите URL для аудита (например https://example.com): ").strip()
        except EOFError:
            args.url = ""
        if not args.url:
            print("Ошибка: URL не указан. Используйте --url или введите ссылку при запуске.")
            return 2
    configure_logging(args.log_level)
    report = run_audit(args)
    print_report(report)
    write_outputs(report, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
