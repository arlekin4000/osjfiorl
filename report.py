from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from html import escape
from typing import Any, Dict, Iterable, List, Optional


SEVERITY_CLASS_MAP = {
    "Критическая": "critical",
    "Высокая": "high",
    "Средняя": "medium",
    "Низкая": "low",
    "Инфо": "info",
}


@dataclass
class Evidence:
    description: str
    location: str
    snippet: Optional[str] = None


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    evidence: List[Evidence]
    remediation: str
    references: List[str] = field(default_factory=list)


@dataclass
class AuditReport:
    target: str
    generated_at: str
    findings: List[Finding]
    stats: Dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)

    def to_html(self) -> str:
        def badge(text: str) -> str:
            cls = SEVERITY_CLASS_MAP.get(text, "info")
            return f"<span class='badge {cls}'>{escape(text)}</span>"

        findings_html = "".join(
            f"""
            <div class="finding">
              <h3>{escape(finding.title)} {badge(finding.severity)}</h3>
              <div class="meta">Идентификатор: {escape(finding.id)} · Уверенность: {escape(finding.confidence)}</div>
              <p>{escape(finding.remediation)}</p>
              <ul>
                {''.join(f"<li><strong>{escape(ev.description)}</strong>: {escape(ev.location)}<pre>{escape(ev.snippet or '')}</pre></li>" for ev in finding.evidence)}
              </ul>
              <div class="refs">
                {' '.join(f"<a href='{escape(ref)}' target='_blank' rel='noreferrer'>{escape(ref)}</a>" for ref in finding.references)}
              </div>
            </div>
            """
            for finding in self.findings
        )

        stats_html = "".join(
            f"<li><strong>{escape(str(key))}</strong>: {escape(str(value))}</li>"
            for key, value in self.stats.items()
        )

        return f"""
        <!doctype html>
        <html lang="ru">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <title>Отчет по безопасности</title>
            <style>
              body {{ font-family: Arial, sans-serif; background: #f6f7fb; color: #1f2937; margin: 0; }}
              header {{ background: #111827; color: white; padding: 24px; }}
              .container {{ max-width: 960px; margin: 0 auto; padding: 24px; }}
              .finding {{ background: white; padding: 16px 20px; border-radius: 8px; margin-bottom: 16px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); }}
              .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; margin-left: 8px; color: white; }}
              .critical {{ background: #b91c1c; }}
              .high {{ background: #dc2626; }}
              .medium {{ background: #f59e0b; }}
              .low {{ background: #2563eb; }}
              .info {{ background: #6b7280; }}
              .meta {{ color: #6b7280; font-size: 13px; }}
              pre {{ background: #f3f4f6; padding: 8px; border-radius: 6px; overflow-x: auto; }}
              .refs a {{ margin-right: 8px; font-size: 12px; }}
            </style>
          </head>
          <body>
            <header>
              <h1>Отчет по безопасности</h1>
              <div>Цель: {escape(self.target)}</div>
              <div>Сформировано: {escape(self.generated_at)}</div>
            </header>
            <div class="container">
              <h2>Сводка</h2>
              <ul>{stats_html}</ul>
              <h2>Наблюдения</h2>
              {findings_html or '<p>Наблюдений не найдено.</p>'}
            </div>
          </body>
        </html>
        """


def build_report(target: str, findings: Iterable[Finding], stats: Dict[str, Any]) -> AuditReport:
    return AuditReport(
        target=target,
        generated_at=datetime.utcnow().isoformat(timespec="seconds") + "Z",
        findings=list(findings),
        stats=stats,
    )
