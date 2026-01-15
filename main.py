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


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Security Audit Assistant (passive checks)")
    parser.add_argument("--url", required=True, help="Target URL (https://example.com)")
    parser.add_argument("--code", help="Path to source code for static analysis")
    parser.add_argument("--out", help="JSON report output path")
    parser.add_argument("--html", help="HTML report output path")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("--rate", type=float, default=2.0, help="Rate limit (requests per second)")
    parser.add_argument("--user-agent", default="SecurityAuditAssistant/1.0", help="Custom user agent")
    parser.add_argument("--parallelism", type=int, default=4, help="Parallelism for crawling")
    parser.add_argument("--disable-crawl", action="store_true", help="Disable crawling")
    parser.add_argument("--disable-tls", action="store_true", help="Disable TLS checks")
    parser.add_argument("--disable-headers", action="store_true", help="Disable HTTP header checks")
    parser.add_argument("--disable-misconfig", action="store_true", help="Disable misconfiguration checks")
    parser.add_argument("--disable-code", action="store_true", help="Disable code scanning")
    parser.add_argument("--dry-run", action="store_true", help="Do not perform network requests")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    return parser.parse_args(argv)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def run_audit(args: argparse.Namespace) -> AuditReport:
    findings: List[Finding] = []
    stats: Dict[str, int] = {"pages_crawled": 0, "findings": 0}

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
        stats["pages_crawled"] = len(pages)

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
        stats["tls_versions"] = ", ".join(tls_result.supported_versions)

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
                    title="Code path not found",
                    severity="Info",
                    confidence="High",
                    evidence=[Evidence(description="Invalid path", location=str(root))],
                    remediation="Verify the --code path and re-run the scan.",
                    references=[],
                )
            )

    stats["findings"] = len(findings)

    return build_report(args.url, findings, stats)


def print_report(report: AuditReport) -> None:
    if importlib.util.find_spec("rich"):
        from rich.console import Console
        from rich.table import Table

        console = Console()
        console.print(f"\n[bold]Security Audit Report for {report.target}[/bold]")
        console.print(f"Generated at: {report.generated_at}\n")

        table = Table(title="Findings")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Confidence")
        table.add_column("Evidence")

        for finding in report.findings:
            evidence_text = "; ".join(ev.location for ev in finding.evidence)
            table.add_row(finding.severity, finding.title, finding.confidence, evidence_text)
        console.print(table)
    else:
        print(f"Security Audit Report for {report.target}")
        print(f"Generated at: {report.generated_at}")
        for finding in report.findings:
            print(f"- [{finding.severity}] {finding.title} ({finding.confidence})")
            for ev in finding.evidence:
                print(f"  * {ev.description}: {ev.location}")


def write_outputs(report: AuditReport, args: argparse.Namespace) -> None:
    if args.out:
        Path(args.out).write_text(report.to_json(), encoding="utf-8")
        logger.info("Wrote JSON report to %s", args.out)
    if args.html:
        Path(args.html).write_text(report.to_html(), encoding="utf-8")
        logger.info("Wrote HTML report to %s", args.html)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    configure_logging(args.log_level)
    report = run_audit(args)
    print_report(report)
    write_outputs(report, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
