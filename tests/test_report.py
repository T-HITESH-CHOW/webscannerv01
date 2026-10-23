"""
Tests for the report generator and the built-in HTTP assessment.

Run with: pytest tests/
"""

import httpx
import pytest

from app.models.schemas import NormalizedFinding, ScanType, ScannerName, Severity
from app.services.llm_service import (
    build_finding,
    build_markdown,
    dedupe_findings,
    generate_report,
    sort_findings,
)
from app.services.scanner import assess_http_target, engines_used


def make_finding(title, severity, location="http://lab.test/", scanner=ScannerName.HTTP,
                 description="", rule_id="test-rule"):
    return NormalizedFinding(
        title=title,
        severity=severity,
        location=location,
        evidence="evidence line",
        source_scanner=scanner,
        description=description,
        rule_id=rule_id,
    )


MIXED = [
    make_finding("Info thing", Severity.INFO),
    make_finding("Low thing", Severity.LOW),
    make_finding("Critical thing", Severity.CRITICAL),
    make_finding("Medium thing", Severity.MEDIUM),
    make_finding("High thing", Severity.HIGH),
]


# --- Ordering -------------------------------------------------------------

def test_sort_findings_is_worst_first():
    ordered = sort_findings(MIXED)
    assert [f.severity for f in ordered] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]


def test_sort_findings_uses_cvss_within_same_severity():
    low_cvss = make_finding("A", Severity.HIGH, location="http://lab.test/a")
    high_cvss = make_finding("B", Severity.HIGH, location="http://lab.test/b")
    low_cvss.cvss = 5.0
    high_cvss.cvss = 9.8
    ordered = sort_findings([low_cvss, high_cvss])
    assert ordered[0].title == "B"


def test_dedupe_merges_engine_overlap():
    a = make_finding("Missing security header: X-Frame-Options", Severity.LOW)
    b = make_finding("missing security header: x-frame-options", Severity.MEDIUM)
    assert len(dedupe_findings([a, b])) == 1
    # the worse severity survives
    assert dedupe_findings([a, b])[0].severity == Severity.MEDIUM


def test_dedupe_keeps_different_locations():
    a = make_finding("Open port tcp/22", Severity.MEDIUM, location="host-a:22")
    b = make_finding("Open port tcp/22", Severity.MEDIUM, location="host-b:22")
    assert len(dedupe_findings([a, b])) == 2


# --- Report ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_generate_report_orders_and_counts():
    report = await generate_report("abc123", "http://lab.test", ScanType.URL, MIXED)

    assert report.total_findings == 5
    assert report.risk_rating == "critical"
    assert report.findings_by_severity[Severity.CRITICAL] == 1
    assert report.findings_by_severity[Severity.INFO] == 1
    assert [f.severity for f in report.findings][0] == Severity.CRITICAL
    assert report.findings[0].priority == 1
    assert report.summary
    assert "critical" in report.summary.lower()


@pytest.mark.asyncio
async def test_generate_report_empty():
    report = await generate_report("empty", "http://lab.test", ScanType.URL, [])
    assert report.total_findings == 0
    assert report.risk_rating == "informational"
    assert report.findings == []
    assert "no findings" in report.summary.lower() or "without producing" in report.summary.lower()


@pytest.mark.asyncio
async def test_generate_report_uses_knowledge_base():
    sql = make_finding(
        "SQL injection in login handler",
        Severity.HIGH,
        location="app/db.py:42",
        scanner=ScannerName.SEMGREP,
    )
    report = await generate_report("sql", "upload://app.zip", ScanType.UPLOAD, [sql])
    finding = report.findings[0]
    assert "parameteris" in finding.suggested_fix.lower()
    assert finding.explanation
    assert finding.impact
    assert finding.owasp == "A03:2021 Injection"
    assert report.scan_type == ScanType.UPLOAD


def test_build_finding_keeps_evidence_and_cve():
    f = make_finding("Vulnerable dependency", Severity.CRITICAL, location="requirements.txt")
    f.cve = "CVE-2024-0001"
    built = build_finding(f, priority=1)
    assert built.cve == "CVE-2024-0001"
    assert any("CVE-2024-0001" in r for r in built.references)
    assert built.evidence == "evidence line"


def test_engines_used_is_unique_and_labelled():
    used = engines_used(
        [
            make_finding("A", Severity.LOW, scanner=ScannerName.HTTP),
            make_finding("B", Severity.LOW, scanner=ScannerName.HTTP),
            make_finding("C", Severity.HIGH, scanner=ScannerName.TRIVY),
        ]
    )
    assert len(used) == 2
    assert any("Trivy" in u for u in used)


@pytest.mark.asyncio
async def test_markdown_export_contains_sections():
    report = await generate_report("md", "http://lab.test", ScanType.URL, MIXED)
    markdown = build_markdown(report)
    assert "# Security Assessment Report" in markdown
    assert "## Findings by severity" in markdown
    assert "## Detailed findings" in markdown
    assert "CRITICAL" in markdown
    assert report.disclaimer.split(":")[0] in markdown


# --- Built-in HTTP assessment --------------------------------------------

def lab_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/.git/HEAD":
        return httpx.Response(200, text="ref: refs/heads/main\n")
    if path == "/":
        return httpx.Response(
            200,
            headers={"server": "nginx/1.18.0", "set-cookie": "session=abc123; Path=/"},
            text="<html><body>hello</body></html>",
        )
    return httpx.Response(404, text="not found")


@pytest.mark.asyncio
async def test_assess_http_target_finds_real_issues():
    transport = httpx.MockTransport(lab_handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://lab.test") as client:
        findings = await assess_http_target("http://lab.test", client=client)

    titles = {f.title for f in findings}
    by_title = {f.title: f for f in findings}

    csp = "Missing security header: Content-Security-Policy"
    assert csp in titles
    assert by_title[csp].severity == Severity.MEDIUM

    exposed = "Exposed sensitive resource: /.git/HEAD"
    assert exposed in titles
    assert by_title[exposed].severity == Severity.CRITICAL
    assert "ref: refs/heads/main" in by_title[exposed].evidence

    assert any("Cookie 'session' missing security flags" in t for t in titles)
    assert any("version disclosure" in t.lower() for t in titles)
    # plain HTTP with no redirect is flagged
    assert any("redirect HTTP traffic to HTTPS" in t for t in titles)
    # all findings trace back to the built-in engine
    assert all(f.source_scanner == ScannerName.HTTP for f in findings)


@pytest.mark.asyncio
async def test_assess_http_target_survives_unreachable_host():
    def boom(request):
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(boom)
    async with httpx.AsyncClient(transport=transport, base_url="http://lab.test") as client:
        findings = await assess_http_target("http://lab.test", client=client)

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "did not respond" in findings[0].title
