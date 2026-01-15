# Security Audit Assistant

**Security Audit Assistant** is a production-quality Python 3.11+ tool for **legal and non-intrusive** security auditing of websites you own or have explicit permission to test. It focuses on safe configuration checks, passive analysis, and optional static code review.

> ⚠️ **Ethics & legality**: Use only on assets you own or have explicit permission to audit. This tool does **not** perform intrusive attacks or active exploitation.

## Features

- **CLI-first** workflow with JSON and HTML reporting.
- **Passive crawling**: sitemap.xml, robots.txt, internal links only (same host).
- **HTTP/TLS checks**: HTTPS redirect, HSTS, CSP, X-Frame-Options, and more.
- **CORS & cookie checks** for dangerous configurations.
- **Misconfiguration checks** for directory listing and common sensitive paths (limited set, no brute-force).
- **Static code scan** (optional): Python anti-patterns, secret scanning, dependency audits.
- **Rate limiting** and **dry-run** support.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python audit.py --url https://example.com
python audit.py --url https://example.com --code ./repo --out report.json --html report.html
```

### CLI Options

- `--url` **(required)** Target URL.
- `--code` Path to source code for static analysis.
- `--out` JSON output file.
- `--html` HTML report file.
- `--timeout` HTTP timeout in seconds.
- `--max-pages` Crawl limit.
- `--max-depth` Crawl depth.
- `--rate` Rate limit (requests/sec).
- `--user-agent` Custom user agent.
- `--parallelism` Parallelism (reserved for future use).
- `--dry-run` Do not perform network requests.
- `--disable-*` Disable specific checks: crawl, tls, headers, misconfig, code.

## Output

The tool generates:

- Console report (human-readable).
- JSON report (`--out`).
- HTML report (`--html`).

## Static Analysis Notes

- **Python**: Checks for `eval/exec`, unsafe deserialization, `shell=True`, weak randomness for secrets.
- **Secrets**: Regex-based detection with **redaction** in output.
- **Dependencies**:
  - `pip-audit` if available.
  - `npm audit` if `package-lock.json` exists and npm is installed.

## Limitations

This tool performs **non-intrusive** checks only. It cannot confirm real exploitability without active testing. Findings include confidence levels and evidence, but you should validate them responsibly.

## License

MIT
