"""
LLM Service v01
----------------
Pluggable report generation backend for the scan/engagement reports.

Supported providers
-------------------
  anthropic  Claude Haiku / Sonnet / Opus via the Anthropic Messages API.
  openai     GPT-4o / GPT-4 Turbo via the OpenAI Chat Completions API.
  none       Deterministic, knowledge-base report with no external API calls.

Configuration
-------------
Set ``LLM_PROVIDER`` in ``.env`` (or the Vercel env UI) to one of the above.
When ``none`` is selected the service is entirely offline and never opens a
network connection or imports a provider SDK at module load time — which is
what makes the Vercel deployment path survivable without an LLM key configured.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Callable, Optional

from app.config import get_settings
from app.models.schemas import (
    EngagementSummary,
    NormalizedFinding,
    Severity,
    ScanReport,
)

logger = logging.getLogger(__name__)
settings = get_settings()


# =============================================================================
# Provider instantiation — lazy, so ``LLM_PROVIDER=none`` never touches a
# provider SDK at import time. ``None`` is fine on Vercel when you only use
# the deterministic path.
# =============================================================================


def _build_anthropic_client() -> Any:
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError(
            "LLM_PROVIDER is set to 'anthropic' but the 'anthropic' package is not installed."
        ) from exc
    api_key = os.getenv("LLM_API_KEY")
    if not api_key:
        raise RuntimeError(
            "LLM_API_KEY is empty; configure it in .env or the Vercel env UI before using the Anthropic provider."
        )
    return anthropic.Anthropic(api_key=api_key)


def _build_openai_client() -> Any:
    try:
        import openai
    except ImportError as exc:
        raise RuntimeError(
            "LLM_PROVIDER is set to 'openai' but the 'openai' package is not installed."
        ) from exc
    api_key = os.getenv("LLM_API_KEY")
    if not api_key:
        raise RuntimeError(
            "LLM_API_KEY is empty; configure it in .env or the Vercel env UI before using the OpenAI provider."
        )
    return openai.OpenAI(api_key=api_key)


def get_client() -> Any:
    provider = os.getenv("LLM_PROVIDER", "none").lower()
    if provider == "anthropic":
        return _build_anthropic_client()
    if provider == "openai":
        return _build_openai_client()
    return None


def provider_is_available() -> bool:
    return get_client() is not None


# =============================================================================
# Deterministic / knowledge-base report — no LLM required.
# =============================================================================


def generate_report(
    findings: list[NormalizedFinding],
    target: TargetInfo,
    config: dict[str, Any],
    engine: str = "deterministic",
) -> dict[str, Any]:
    """Build a report dict without calling any LLM provider.

    Parameters
    ----------
    findings:
        Normalized findings from the scanner normalizer.
    target:
        Target metadata attached to the scan.
    config:
        Provider/model config dict; ignored by the deterministic path except
        for logging purposes.
    engine:
        Which engine produced the findings; used only for the report summary.
    """
    total = len(findings)
    start_time = time.time()

    logger.info(
        "generate_report(deterministic) target=%s findings=%d",
        target.host,
        total,
    )

    report = {
        "target": target.model_dump(),
        "generated_at": datetime.utcnow().isoformat(),
        "total_findings": total,
        "findings": [f.model_dump() for f in findings],
        "provider": "deterministic",
        "engine": engine,
    }

    logger.info(
        "generate_report(deterministic) completed target=%s duration_ms=%.0f",
        target.host,
        (time.time() - start_time) * 1000.0,
    )
    return report


def _parse_tool_call(text: str) -> Optional[ToolCall]:
    """Extract a single tool call from a provider message if present."""
    if not text:
        return None
    m = re.search(r"<tool_call>(.*?)</tool_call>", text, re.DOTALL)
    if not m:
        return None
    try:
        payload = json.loads(m.group(1))
    except json.JSONDecodeError:
        return None
    return ToolCall.model_validate(payload)


# =============================================================================
# LLM-backed opinionated report (optional, provider-gated).
# =============================================================================


def build_markdown(report: EngagementReport) -> str:
    """Render an engagement/scan report as Markdown.

    This path is provider-agnostic and uses only the data already present in
    the report object, so it works whether or not an LLM provider is enabled.
    """
    lines: list[str] = []
    target = report.target
    lines.append(f"# Security Review — {target.host}")
    lines.append("")
    lines.append(f"- **Target:** {target.url or target.host}")
    lines.append(f"- **Generated:** {report.generated_at}")
    lines.append(f"- **Provider:** {report.provider}")
    lines.append(f"- **Engine:** {report.engine}")
    lines.append(f"- **Total findings:** {report.total_findings}")
    lines.append("")

    if report.summary:
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(report.summary)
        lines.append("")

    if report.finding_count:
        lines.append("## Findings by severity")
        lines.append("")
        for severity, count in report.finding_count.items():
            lines.append(f"- {severity.value}: {count}")
        lines.append("")

    if report.findings:
        lines.append("## Findings")
        lines.append("")
        for finding in report.findings:
            sev = finding.severity or Severity.INFO
            lines.append(f"### {sev.value} — {finding.title or 'Unnamed finding'}")
            lines.append("")
            if finding.description:
                lines.append(finding.description)
                lines.append("")
            if finding.remediation:
                lines.append("**Remediation**")
                lines.append("")
                lines.append(finding.remediation)
                lines.append("")
            if finding.location:
                lines.append(f"- **Location:** {finding.location}")
            lines.append("---")
            lines.append("")

    if report.tool_calls:
        lines.append("## Tool calls")
        lines.append("")
        for tc in report.tool_calls:
            lines.append(f"- **{tc.tool}:** {tc.arguments}")
        lines.append("")

    lines.append("## Metadata")
    lines.append("")
    lines.append(f"- **Report ID:** {report.id}")
    lines.append(f"- **Engagement ID:** {report.engagement_id or 'n/a'}")
    lines.append(f"- **Scan ID:** {report.scan_id or 'n/a'}")
    lines.append("")
    return "\n".join(lines)


def build_html(report: EngagementReport) -> str:
    """Render an engagement/scan report as a standalone HTML page.

    Provider-agnostic; uses only the data in the report object so it works
    with or without an LLM provider enabled.
    """
    findings_html = ""
    if report.findings:
        items: list[str] = []
        for f in report.findings:
            sev = f.severity or Severity.INFO
            title = (f.title or "Unnamed finding").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            desc = (f.description or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            rem = (f.remediation or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            loc = (f.location or "")
            items.append(
                f'<div class="finding finding-{sev.value.lower()}">'
                f'<div class="finding-head"><span class="finding-sev">{sev.value}</span> '
                f'<strong class="finding-title">{title}</strong>'
                + (f'<span class="finding-loc">{loc}</span>' if loc else "")
                + "</div>"
                + (f'<div class="finding-desc">{desc}</div>' if desc else "")
                + (f'<div class="finding-rem"><strong>Remediation:</strong> {rem}</div>' if rem else "")
                + "</div>"
            )
        findings_html = "\n".join(items)

    tool_calls_html = ""
    if report.tool_calls:
        rows = "".join(
            f'<tr><td class="tc-tool">{tc.tool}</td><td class="tc-args">{json.dumps(tc.arguments)}</td></tr>'
            for tc in report.tool_calls
        )
        tool_calls_html = f'<table class="tc-table"><thead><tr><th>Tool</th><th>Arguments</th></tr></thead><tbody>{rows}</tbody></table>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Security Review — {report.target.host}</title>
  <style>
    :root {{
      --bg: #0b0d10;
      --panel: #111318;
      --line: #1c212a;
      --fg: #e9edf3;
      --muted: #8a93a1;
      --danger: #f8a8a8;
      --high: #f4c97a;
      --med: #b4c7e7;
      --low: #8a93a1;
      --info: #7e9cd4;
    }}
    * {{ box-sizing: border-box; }}
    html, body {{ margin: 0; padding: 0; background: var(--bg); color: var(--fg); font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace; }}
    .wrap {{ max-width: 920px; margin: 0 auto; padding: 2rem 1.5rem; }}
    header {{ border-bottom: 1px solid var(--line); padding-bottom: 1rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: flex-end; }}
    h1 {{ margin: 0; font-size: 1.6rem; letter-spacing: 0.02em; }}
    .meta {{ color: var(--muted); font-size: 0.8rem; text-align: right; line-height: 1.5; }}
    .meta strong {{ color: var(--fg); }}
    h2 {{ margin: 2rem 0 0.6rem; font-size: 1rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); border-bottom: 1px solid var(--line); padding-bottom: 0.3rem; }}
    .sev {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}
    .sev.critical {{ background: rgba(248,168,168,0.18); color: var(--danger); }}
    .sev.high {{ background: rgba(244,201,122,0.16); color: var(--high); }}
    .sev.medium {{ background: rgba(180,199,231,0.14); color: var(--med); }}
    .sev.low {{ background: rgba(138,147,161,0.16); color: var(--low); }}
    .sev.info {{ background: rgba(126,156,212,0.16); color: var(--info); }}
    .finding {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 1rem 1.1rem; margin-bottom: 0.9rem; }}
    .finding-head {{ display: flex; align-items: baseline; gap: 0.6rem; flex-wrap: wrap; }}
    .finding-sev {{ font-size: 0.65rem; padding: 0.1rem 0.4rem; border-radius: 4px; }}
    .finding-title {{ font-size: 1rem; }}
    .finding-loc {{ margin-left: auto; color: var(--muted); font-size: 0.75rem; }}
    .finding-desc {{ color: var(--fg); margin-top: 0.5rem; line-height: 1.5; }}
    .finding-rem {{ color: var(--high); margin-top: 0.5rem; }}
    .tc-table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.8rem; }}
    .tc-table th, .tc-table td {{ text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--line); }}
    .tc-table th {{ color: var(--muted); text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; }}
    .tc-tool {{ font-weight: 600; }}
    .tc-args {{ color: var(--muted); font-family: ui-monospace, monospace; word-break: break-word; }}
    .footer {{ margin-top: 3rem; border-top: 1px solid var(--line); padding-top: 1rem; color: var(--muted); font-size: 0.75rem; }}
    .empty {{ color: var(--muted); font-style: italic; padding: 1rem 0; }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div>
        <h1>Security Review — {report.target.host}</h1>
        <div class="meta">
          <strong>Target:</strong> {report.target.url or report.target.host}<br />
          <strong>Generated:</strong> {report.generated_at}<br />
          <strong>Provider:</strong> {report.provider}<br />
          <strong>Engine:</strong> {report.engine}<br />
          <strong>Total findings:</strong> {report.total_findings}
        </div>
      </div>
    </header>

    {"<h2>Executive Summary</h2>" + report.summary.replace("\n", "<br />") if report.summary else '<div class="empty">No executive summary available.</div>'}

    {"<h2>Findings by severity</h2>" + "".join(f"<div><span class='sev sev-{sev.value.lower()}'>{sev.value}</span> <strong>{count}</strong></div>" for sev, count in report.finding_count.items()) if report.finding_count else '<div class="empty">No findings recorded.</div>'}

    {"<h2>Findings</h2>" + findings_html if findings_html else '<div class="empty">No findings recorded.</div>'}

    {"<h2>Tool calls</h2>" + tool_calls_html if tool_calls_html else ''}

    <div class="footer">
      <strong>Report ID:</strong> {report.id}<br />
      <strong>Engagement ID:</strong> {report.engagement_id or 'n/a'}<br />
      <strong>Scan ID:</strong> {report.scan_id or 'n/a'}
    </div>
  </div>
</body>
</html>"""


def generate_report_opinionated(
    findings: list[NormalizedFinding],
    target: TargetInfo,
    config: dict[str, Any],
    scanner_engine: str = "scanner",
    client: Optional[Any] = None,
) -> EngagementReport:
    raise NotImplementedError('stub')


def _to_engagement_report(raw: dict[str, Any], target: TargetInfo) -> EngagementReport:
    raise NotImplementedError('stub')


def _call_llm_for_summary(client: Any, findings: list[NormalizedFinding], target: TargetInfo, config: dict[str, Any]) -> Optional[str]:
    """Ask the LLM provider for a short executive summary.

    Returns ``None`` when the provider did not return usable text.
    """
    payload = _build_summary_prompt(findings, target)
    try:
        if hasattr(client, "messages"):
            resp = client.messages.create(
                model=os.getenv("LLM_MODEL", "claude-3-haiku-20240307"),
                max_tokens=1024,
                messages=[{"role": "user", "content": payload}],
            )
            if resp.content:
                return resp.content[0].text or None
            return None
        if hasattr(client, "chat"):
            resp = client.chat.completions.create(
                model=os.getenv("LLM_MODEL", "gpt-4o"),
                max_tokens=1024,
                messages=[{"role": "user", "content": payload}],
            )
            if resp.choices:
                return resp.choices[0].message.content or None
            return None
        return None
    except Exception as exc:
        logger.exception("generate_report_opinionated: LLM call failed: %s", exc)
        return None


def _build_summary_prompt(findings: list[NormalizedFinding], target: TargetInfo) -> str:
    finding_lines = []
    for f in findings:
        sev = f.severity.value if f.severity else "info"
        loc = f" at {f.location}" if f.location else ""
        finding_lines.append(f"- [{sev}] {f.title or 'Unnamed'}{loc}")
    body = "\n".join(finding_lines) if finding_lines else "No findings."
    return (
        "You are a senior application security analyst producing a concise executive summary.\n"
        "Target: " + (target.url or target.host) + "\n"
        "Findings:\n" + body + "\n\n"
        "Write a short executive summary (3-6 sentences). Include:\n"
        "- overall risk posture and the most important issue(s)\n"
        "- likely impact if exploited\n"
        "- recommended remediation priorities\n"
        "Do not repeat the finding list verbatim."
    )


def _fallback_summary(findings: list[Finding], target: TargetInfo) -> str:
    high = [f for f in findings if f.severity and f.severity.value in {"CRITICAL", "HIGH"}]
    if high:
        titles = "; ".join(f"{f.severity.value}: {f.title or 'Unnamed'}" for f in high[:5])
        return (
            f"Target {target.host} has {len(findings)} findings. "
            f"Highest severity issues: {titles}. "
            "Manual verification is required before acting on any finding."
        )
    if findings:
        return (
            f"Target {target.host} has {len(findings)} findings. "
            "No critical or high severity issues were detected by the automated scan, "
            "but results still require manual review."
        )
    return f"No automated findings were recorded for {target.host}."


def _count_by_severity(findings: list[NormalizedFinding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {}
    for f in findings:
        sev = f.severity or Severity.INFO
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _count_by_severity_from_findings(findings: list[Finding]) -> dict[Severity, int]:
    return _count_by_severity(findings)


def _report_id() -> str:
    now = int(time.time())
    h = hashlib.sha256(f"report-{now}-{os.urandom(8).hex()}".encode()).hexdigest()[:12]
    return f"rr-{now}-{h}"


def format_finding_for_llm(finding: NormalizedFinding) -> str:
    """Serialize a single normalized finding into a compact LLM-friendly string."""
    sev = finding.severity.value if finding.severity else "info"
    parts = [f"[{sev}] {finding.title or 'Unnamed finding'}"]
    if finding.location:
        parts.append(f"Location: {finding.location}")
    if finding.description:
        parts.append(finding.description)
    if finding.remediation:
        parts.append(f"Remediation: {finding.remediation}")
    if finding.references:
        parts.append("References: " + "; ".join(finding.references))
    return "\n".join(parts)
