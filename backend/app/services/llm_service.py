"""
Report Generator v1 — turns raw normalized findings into a detailed English report.

Two layers:

1. **Deterministic** (always runs, no API key needed): sorts every finding
   critical -> high -> medium -> low -> info, de-duplicates engine overlap,
   assigns a fix priority, maps each finding to a plain-English explanation /
   impact / remediation from the knowledge base below, and writes an executive
   summary plus a Markdown export.

2. **LLM enrichment** (optional): when `LLM_API_KEY` is set, the prose for each
   finding is rewritten by Claude. Any failure silently falls back to layer 1 so
   a report is always produced.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from app.config import get_settings
from app.models.schemas import (
    LLMFinding,
    NormalizedFinding,
    ScanReport,
    ScanType,
    Severity,
    severity_rank,
)

settings = get_settings()

SEVERITY_TITLE = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informational",
}

# How fast each severity should be dealt with (used in the roadmap section).
SEVERITY_SLA = {
    Severity.CRITICAL: "Fix now — before the next deploy (24 hours)",
    Severity.HIGH: "Fix within 7 days",
    Severity.MEDIUM: "Fix within 30 days",
    Severity.LOW: "Fix within the next release cycle",
    Severity.INFO: "Review and document; no immediate action",
}


# ---------------------------------------------------------------------------
# Knowledge base: keyword -> plain-English explanation / impact / remediation
# ---------------------------------------------------------------------------

class Topic:
    __slots__ = ("name", "patterns", "summary", "impact", "fix", "owasp")

    def __init__(self, name, patterns, summary, impact, fix, owasp=""):
        self.name = name
        self.patterns = [p.lower() for p in patterns]
        self.summary = summary
        self.impact = impact
        self.fix = fix
        self.owasp = owasp


TOPICS: tuple[Topic, ...] = (
    Topic(
        "SQL injection",
        ["sql injection", "sqli", "formatted-sql", "concat.*query", "sql query"],
        "Application input reaches a database query without parameterisation. The "
        "query text and the data are built from the same string, so whatever the "
        "user sends becomes part of the command the database executes.",
        "An attacker who controls part of a SQL statement can read tables they were "
        "never meant to see, modify or delete rows, bypass login checks with a "
        "crafted condition, and on some database engines read files or run operating "
        "system commands. A single injectable parameter is usually enough for full "
        "data disclosure, so this is treated as a top-priority issue.",
        "1. Replace string concatenation/formatting with parameterised queries or an "
        "ORM binding layer (e.g. `cursor.execute('... WHERE id = ?', (user_id,))`).\n"
        "2. Never build identifiers (table/column names) from user input; map them "
        "through an allowlist.\n"
        "3. Give the application database account only the privileges it needs "
        "(no DROP, no FILE, no cross-schema access).\n"
        "4. Add regression tests that send quotes and boolean logic in every input.",
        "A03:2021 Injection",
    ),
    Topic(
        "Cross-site scripting",
        ["xss", "cross site scripting", "cross-site scripting", "render_template_string", "output encoding"],
        "User-controlled data is written into an HTML response without contextual "
        "output encoding, so the browser treats it as markup or script rather than "
        "text. Template injection variants are worse: the input is evaluated by the "
        "templating engine itself.",
        "Script running in your origin can read cookies and tokens, submit requests "
        "as the victim, rewrite the page (fake login forms), and pivot into internal "
        "APIs the browser can reach. It converts a single crafted link into account "
        "takeover for whoever clicks it.",
        "1. Encode output for the exact context it lands in (HTML body, attribute, "
        "JavaScript, URL) using the framework's auto-escaping.\n"
        "2. Never pass user input to `render_template_string`, `eval`, or raw HTML "
        "insertion APIs; use fixed templates with data parameters.\n"
        "3. Add a Content-Security-Policy that forbids inline script and unexpected "
        "sources as a second layer.\n"
        "4. Mark session cookies HttpOnly so script cannot read them.",
        "A03:2021 Injection",
    ),
    Topic(
        "Server-side template injection",
        ["ssti", "template injection"],
        "User input is compiled as a template expression instead of being treated as "
        "data, so the input can contain template syntax that the server executes.",
        "Template engines usually expose enough of the host language to walk object "
        "attributes, which commonly escalates from information disclosure to remote "
        "code execution on the application server.",
        "1. Pass user input only as template *data*.\n"
        "2. Use a sandboxed template environment and disable dangerous globals.\n"
        "3. Reject or escape template delimiters in user input as defence in depth.",
        "A03:2021 Injection",
    ),
    Topic(
        "Hardcoded secret",
        ["hardcoded", "hard-coded", "api key", "api_key", "secret key", "private key",
         "credential", "password", "leaked key"],
        "A credential was found in source code, configuration or page content. "
        "Anything in the repository or served to a browser is readable by everyone "
        "who can reach it, and it survives in git history after deletion.",
        "Leaked keys allow direct access to the third-party or internal service they "
        "belong to: cloud billing, database contents, email sending, or the "
        "application's own authentication. Automated scanners harvest these from "
        "public repositories within minutes of a push.",
        "1. Revoke and rotate the exposed credential first — assume it is already "
        "compromised.\n"
        "2. Move secrets to environment variables or a secret manager.\n"
        "3. Review provider audit logs for use from unknown IPs.\n"
        "4. Add a pre-commit secret scanner so it cannot happen again.",
        "A07:2021 Identification and Authentication Failures",
    ),
    Topic(
        "Security headers",
        ["missing security header", "content-security-policy", "x-frame-options",
         "x-content-type-options", "referrer-policy", "permissions-policy"],
        "The response is missing one or more headers that tell the browser how to "
        "treat the page. Browsers default to permissive behaviour when a header is "
        "absent, so the absence of a header is itself a weakness.",
        "Without these headers the browser is more willing to run injected script, "
        "frame the page inside an attacker's site (clickjacking), guess content "
        "types, and leak URLs through the Referer header. None of them fix a "
        "vulnerability on their own, but together they remove whole classes of "
        "exploitation and are cheap to add.",
        "1. Set the headers at the reverse proxy or application middleware so every "
        "route inherits them.\n"
        "2. Start CSP in report-only mode, fix what it flags, then enforce.\n"
        "3. Keep a short allowlist of script/style/frame sources.\n"
        "4. Add `X-Content-Type-Options: nosniff` and a restrictive Referrer-Policy "
        "immediately — they are zero-risk.",
        "A05:2021 Security Misconfiguration",
    ),
    Topic(
        "HSTS / TLS",
        ["strict-transport-security", "hsts", "https redirect", "upgrade to https",
         "plain http", "transport security", "ssl", "tls", "certificate"],
        "Transport security is not enforced: either HSTS is missing or plain HTTP is "
        "served without upgrading to HTTPS.",
        "On the first request the browser may speak HTTP. Anyone sharing the network "
        "— public Wi-Fi, a compromised router, a hostile ISP — can intercept or "
        "rewrite that request, steal session cookies, or serve a modified page. This "
        "is the classic SSL-stripping attack.",
        "1. Redirect all HTTP traffic to HTTPS with a 301.\n"
        "2. Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
        "once HTTPS works reliably.\n"
        "3. Mark cookies Secure.\n"
        "4. Renew certificates automatically and monitor expiry.",
        "A02:2021 Cryptographic Failures",
    ),
    Topic(
        "Cookie flags",
        ["cookie", "httponly", "samesite"],
        "A cookie is issued without the Secure, HttpOnly and/or SameSite attributes.",
        "Without Secure it travels over plain HTTP and can be sniffed. Without "
        "HttpOnly any XSS immediately becomes session theft. Without SameSite the "
        "browser attaches it to cross-site requests, weakening CSRF defences.",
        "1. Set `Secure; HttpOnly; SameSite=Lax` (or `Strict`) on all session cookies.\n"
        "2. Never store credentials or tokens in cookies readable by JavaScript.\n"
        "3. Keep session lifetimes short and rotate the session ID on login.",
        "A05:2021 Security Misconfiguration",
    ),
    Topic(
        "CORS",
        ["cors", "access-control-allow-origin"],
        "The cross-origin policy allows more than it should — either a wildcard that "
        "also permits credentials, or an arbitrary Origin reflected back.",
        "If the API trusts any Origin and accepts cookies or bearer credentials, any "
        "website can make the victim's browser read authenticated responses and "
        "exfiltrate them. Effectively the same-origin policy stops protecting the "
        "user's data.",
        "1. Allowlist exact origins that legitimately call the API.\n"
        "2. Never combine `Access-Control-Allow-Origin: *` with credentials.\n"
        "3. Validate the Origin header server-side instead of echoing it.\n"
        "4. Keep cookie-authenticated endpoints same-origin where possible.",
        "A05:2021 Security Misconfiguration",
    ),
    Topic(
        "Exposed sensitive file",
        ["exposed sensitive", ".git", ".env", "backup", "server-status", "actuator", "swagger"],
        "A file or endpoint that should be private is served publicly. Version "
        "control metadata, environment files, backups and management endpoints are "
        "the highest-value targets on a web server.",
        "Repository metadata can reconstruct source code and its deleted secrets. An "
        "environment file typically contains database passwords and API keys. Backups "
        "often hold the whole application plus a data dump. Any of these can end the "
        "engagement on its own — full source and credential disclosure.",
        "1. Block the paths at the web server / CDN and confirm a 404 or 403.\n"
        "2. Move secrets out of files that sit in the web root.\n"
        "3. Rotate anything that was reachable during the exposure window.\n"
        "4. Add deployment-time checks that fail the build if these paths are public.",
        "A05:2021 Security Misconfiguration",
    ),
    Topic(
        "Information disclosure",
        ["disclosure", "server:", "x-powered-by", "version", "banner", "directory listing"],
        "The server reveals product, version or directory information in responses.",
        "Version banners let an attacker look up known CVEs for exactly that build and "
        "choose exploits that are likely to work, without noisy trial and error. It "
        "does not cause a breach by itself, but it shortens the path to one.",
        "1. Remove or genericise `Server`, `X-Powered-By` and framework headers.\n"
        "2. Disable directory listing and verbose error pages in production.\n"
        "3. Keep the stack patched — removing the banner is not a substitute.",
        "A05:2021 Security Misconfiguration",
    ),
    Topic(
        "Exposed service / open port",
        ["open port", "exposed sensitive service", "exposed administrative"],
        "A network port is reachable and running a service. The severity depends on "
        "what that service is and who can reach it.",
        "Every reachable port is an entry point: database and cache ports can bypass "
        "application authorisation entirely, remote-access ports invite brute force, "
        "and admin interfaces assume a trusted network. Attackers map these first and "
        "pick the weakest one.",
        "1. Confirm the port must be reachable from this network position.\n"
        "2. Firewall it to known source IPs, or bind it to localhost only.\n"
        "3. Require authentication with strong credentials and rate limiting on any "
        "management service.\n"
        "4. Patch the running version and monitor it for brute-force attempts.",
        "A05:2021 Security Misconfiguration",
    ),
    Topic(
        "Vulnerable dependency",
        ["cve-", "vulnerab", "dependency", "package", "library"],
        "A third-party package in use has a known vulnerability, matched against the "
        "version installed.",
        "Dependencies inherit the trust of the application. A known CVE in a library "
        "you ship is a documented attack path that any scanner can find, and the "
        "impact ranges from denial of service to remote code execution depending on "
        "the advisory.",
        "1. Upgrade to the fixed version listed in the finding. If no fix exists, "
        "apply vendor mitigations or replace the package.\n"
        "2. Rebuild and redeploy the artefact — patching the manifest without "
        "rebuilding leaves the vulnerable copy in the image.\n"
        "3. Add automated dependency scanning to CI so new CVEs surface on every PR.",
        "A06:2021 Vulnerable and Outdated Components",
    ),
    Topic(
        "Infrastructure-as-code misconfiguration",
        ["iac", "terraform", "kubernetes", "cloudformation", "dockerfile", "misconfig"],
        "An infrastructure definition grants more access than the workload needs — "
        "for example privileged containers, public buckets, or wildcard IAM policies.",
        "A misconfigured template is replicated to every environment it is deployed "
        "to, so one mistake scales into a fleet-wide weakness that no application-"
        "layer control can compensate for.",
        "1. Apply least privilege: scope IAM actions and resources explicitly.\n"
        "2. Keep buckets and volumes private unless they are intentionally public.\n"
        "3. Drop container privileges, run as non-root, and pin base images.\n"
        "4. Add the IaC scan to CI so the gate runs before apply.",
        "A05:2021 Security Misconfiguration",
    ),
    Topic(
        "Command injection / RCE",
        ["command injection", "rce", "remote code execution", "os command", "eval", "deserialization"],
        "Untrusted input can influence a command or code path the server executes.",
        "This is the most severe class of finding: the attacker runs their own code "
        "with the application's privileges, which usually means reading the database, "
        "reaching internal services, and owning the host.",
        "1. Remove the shell: use argument-vector APIs instead of string commands.\n"
        "2. Allowlist accepted values instead of sanitising.\n"
        "3. Never deserialize untrusted data with a format that can construct "
        "objects; prefer signed, schema-validated JSON.\n"
        "4. Run the service with the minimum privileges and egress restrictions so "
        "exploitation is contained.",
        "A03:2021 Injection",
    ),
    Topic(
        "Unreachable target",
        ["did not respond", "unreachable"],
        "The automated checks could not reach the target, so no evidence was "
        "collected either way.",
        "This is not a vulnerability and not a clean bill of health — it means the "
        "assessment did not run. Treat the target as unverified.",
        "1. Confirm DNS, port and TLS reachability from the scanning host.\n"
        "2. Check for a WAF or IP allowlist blocking the scanner.\n"
        "3. Re-run the scan once reachable; do not report the target as verified.",
        "",
    ),
)

DEFAULT_TOPIC = Topic(
    "General security weakness",
    [],
    "The finding is reported by an automated check and needs manual confirmation "
    "before it is treated as a real weakness.",
    "Impact depends on how the affected component is used. Confirm the finding by "
    "hand, then assess what an attacker gains if it is real.",
    "1. Reproduce the finding manually.\n"
    "2. Fix at the source rather than blocking the symptom.\n"
    "3. Add a test or a linter rule so the same defect cannot come back.",
    "",
)


def _find_topic(finding: NormalizedFinding) -> Topic:
    """
    Pick the knowledge-base entry that best matches the finding.

    Title matches are weighted higher than description matches: a scanner title
    is a precise label, while a description can mention several unrelated words
    (an exposed .env file mentions 'password', but it is not a hardcoded secret).
    """
    title = (finding.title or "").lower()
    body = " ".join(
        [finding.description or "", finding.rule_id or "", " ".join(finding.references or [])]
    ).lower()

    def score(topic: Topic, text: str) -> int:
        return sum(1 for pattern in topic.patterns if pattern in text)

    # The title is a precise label, so a title match always wins. Only when no
    # title matches do we look at the description (which mentions many words).
    titled = [t for t in TOPICS if score(t, title) > 0]
    if titled:
        return max(titled, key=lambda t: score(t, title))

    descored = [t for t in TOPICS if score(t, body) > 0]
    if descored:
        return max(descored, key=lambda t: score(t, body))

    return DEFAULT_TOPIC


# ---------------------------------------------------------------------------
# Ordering / de-duplication
# ---------------------------------------------------------------------------

def sort_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Worst first: severity, then CVSS score, then title for stable output."""
    return sorted(
        findings,
        key=lambda f: (severity_rank(f.severity), -(f.cvss or 0.0), f.title.lower()),
    )


def dedupe_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """
    Merge overlaps between engines. Two findings are the same issue when they share
    a normalised title and location; the first (worst, thanks to the sort) wins.
    """
    seen: dict[tuple[str, str], NormalizedFinding] = {}
    ordered = sort_findings(findings)
    for finding in ordered:
        key = (
            " ".join(finding.title.lower().split()),
            " ".join(finding.location.lower().split()),
        )
        existing = seen.get(key)
        if existing is None:
            seen[key] = finding
            continue
        # keep the worse severity / richer evidence
        if severity_rank(finding.severity) < severity_rank(existing.severity):
            seen[key] = finding
        elif len(finding.evidence or "") > len(existing.evidence or ""):
            seen[key] = finding
    return sort_findings(list(seen.values()))


# ---------------------------------------------------------------------------
# Finding -> report entry
# ---------------------------------------------------------------------------

def build_finding(finding: NormalizedFinding, priority: int) -> LLMFinding:
    topic = _find_topic(finding)

    # A scanner's own description is usually specific to this exact target, so
    # prefer it once it carries enough detail; otherwise fall back to the
    # knowledge base, which is written for a general audience.
    description = (finding.description or "").strip()
    if len(description) >= 120:
        explanation = description
    else:
        explanation = topic.summary or description or DEFAULT_TOPIC.summary

    references = list(dict.fromkeys(finding.references or []))
    if finding.cve:
        nvd = f"https://nvd.nist.gov/vuln/detail/{finding.cve}"
        if nvd not in references:
            references.insert(0, nvd)

    return LLMFinding(
        title=finding.title,
        severity=finding.severity,
        explanation=explanation,
        impact=topic.impact,
        suggested_fix=topic.fix,
        references=references,
        location=finding.location or "Not applicable",
        evidence=finding.evidence or "",
        source_scanner=finding.source_scanner,
        cve=finding.cve,
        cvss=finding.cvss,
        owasp=topic.owasp,
        priority=priority,
    )


def _risk_rating(findings: list[LLMFinding]) -> str:
    if not findings:
        return "informational"
    worst = min((f.severity for f in findings), key=severity_rank)
    return SEVERITY_TITLE[worst].lower()


def _counts(findings: list[LLMFinding]) -> dict[Severity, int]:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _executive_summary(target: str, scan_type: ScanType, findings: list[LLMFinding]) -> str:
    counts = _counts(findings)
    scope = "the live web application" if scan_type == ScanType.URL else "the submitted source code"
    total = len(findings)

    if total == 0:
        return (
            f"The automated assessment of {scope} (`{target}`) completed without "
            "producing any findings.\n\n"
            "This does not mean the target is secure. Automated checks only cover "
            "what they know how to look for, and this run only reflects the engines "
            "that were available at the time. Treat the result as 'no issues detected "
            "by these checks', not as a clean bill of health."
        )

    worst = min((f.severity for f in findings), key=severity_rank)
    counts_line = ", ".join(
        f"{counts[s]} {SEVERITY_TITLE[s].lower()}"
        for s in Severity
        if counts[s]
    )

    paragraphs = [
        f"The automated assessment of {scope} (`{target}`) produced **{total} "
        f"finding{'s' if total != 1 else ''}** ({counts_line}). The highest severity "
        f"observed is **{SEVERITY_TITLE[worst]}**, so the overall risk for this "
        f"target is rated **{_risk_rating(findings)}**."
    ]

    top = [
        f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ][:3]
    if top:
        bullets = "\n".join(
            f"- **{SEVERITY_TITLE[f.severity]} — {f.title}**"
            + (f" (`{f.location}`)" if f.location and f.location != "Not applicable" else "")
            for f in top
        )
        paragraphs.append(
            "Address these first — each one is either directly exploitable or removes "
            "a layer of defence that makes the others worse:\n\n" + bullets
        )
    elif counts[Severity.MEDIUM]:
        paragraphs.append(
            "No critical or high severity issues were found. The medium severity "
            "findings below are configuration and hardening gaps that make other "
            "attacks easier; they are worth scheduling rather than ignoring."
        )
    else:
        paragraphs.append(
            "Only low and informational findings were produced. That is a good "
            "result, but it reflects the depth of these automated checks, not a "
            "guarantee that the application is free of exploitable flaws."
        )

    if counts[Severity.CRITICAL] or counts[Severity.HIGH]:
        paragraphs.append(
            f"Remediation order: {SEVERITY_SLA[Severity.CRITICAL]} for anything "
            "critical, then high severity within a week. Fixing one critical issue "
            "reduces risk far more than fixing ten informational ones."
        )

    return "\n\n".join(paragraphs)


# ---------------------------------------------------------------------------
# Optional LLM enrichment
# ---------------------------------------------------------------------------

async def _enrich_with_llm(findings: list[LLMFinding], target: str) -> list[LLMFinding]:
    if not settings.LLM_API_KEY or not findings:
        return findings

    try:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=settings.LLM_API_KEY)

        payload = [
            {
                "index": i,
                "title": f.title,
                "severity": f.severity.value,
                "scanner": str(f.source_scanner),
                "location": f.location,
                "evidence": f.evidence[:400],
                "description": f.explanation[:600],
            }
            for i, f in enumerate(findings[:15])
        ]

        prompt = (
            "You are a senior application security engineer writing one section of a "
            "penetration-test report for a learning exercise.\n"
            f"Target: {target}\n"
            "For each finding, rewrite three fields in clear, professional English for "
            "a developer who is not a security specialist:\n"
            "  explanation: what the issue is and why it exists (2-4 sentences)\n"
            "  impact: what an attacker could actually do (2-3 sentences)\n"
            "  suggested_fix: concrete remediation steps (2-4 numbered steps)\n"
            "Do not invent CVEs, versions or evidence that are not in the input. Keep "
            "each field plain text, no markdown headers.\n"
            "Return ONLY a JSON array of objects with keys: index, explanation, "
            "impact, suggested_fix.\n\n"
            f"Findings:\n{json.dumps(payload, indent=2)}"
        )

        message = await client.messages.create(
            model=settings.LLM_MODEL,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(
            block.text for block in message.content if getattr(block, "type", "") == "text"
        )
        start, end = text.find("["), text.rfind("]")
        if start == -1 or end == -1:
            raise ValueError("LLM response contained no JSON array")

        for item in json.loads(text[start : end + 1]):
            idx = item.get("index")
            if not isinstance(idx, int) or not (0 <= idx < len(findings)):
                continue
            if item.get("explanation"):
                findings[idx].explanation = str(item["explanation"]).strip()
            if item.get("impact"):
                findings[idx].impact = str(item["impact"]).strip()
            if item.get("suggested_fix"):
                findings[idx].suggested_fix = str(item["suggested_fix"]).strip()

        print(f"[llm] enriched {min(len(findings), 15)} finding(s) with {settings.LLM_MODEL}")
    except Exception as exc:  # noqa: BLE001 - enrichment is strictly optional
        print(f"[llm] enrichment skipped ({type(exc).__name__}: {exc}); using built-in prose")

    return findings


# ---------------------------------------------------------------------------
# Markdown export
# ---------------------------------------------------------------------------

def build_markdown(report: ScanReport) -> str:
    counts = report.findings_by_severity
    lines = [
        f"# Security Assessment Report — {report.target}",
        "",
        f"- **Scan ID:** `{report.scan_id}`",
        f"- **Date:** {report.timestamp.strftime('%Y-%m-%d %H:%M')}",
        f"- **Target:** `{report.target}`",
        f"- **Scope:** {report.scan_type.value}",
        f"- **Overall risk:** {report.risk_rating.upper()}",
        f"- **Total findings:** {report.total_findings}",
        "",
        "## Findings by severity",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in Severity:
        lines.append(f"| {SEVERITY_TITLE[sev]} | {counts.get(sev, 0)} |")

    lines += ["", "## Executive summary", "", report.summary, ""]

    if report.methodology:
        lines += ["## Methodology", ""]
        lines += [f"- {m}" for m in report.methodology]
        lines.append("")

    if report.engines:
        lines += ["## Engine availability", "", "| Engine | Role | Status |", "| --- | --- | --- |"]
        for e in report.engines:
            status = f"available ({e.version})" if e.available else "not available"
            lines.append(f"| {e.label} | {e.role.value} | {status} |")
        lines.append("")

    lines += ["## Detailed findings", ""]
    if not report.findings:
        lines.append("_No findings were reported by the engines that ran._")

    for i, f in enumerate(report.findings, start=1):
        lines += [
            f"### {i}. [{SEVERITY_TITLE[f.severity]}] {f.title}",
            "",
            f"- **Priority:** P{f.priority}",
            f"- **Location:** `{f.location}`",
            f"- **Detected by:** {f.source_scanner.value if f.source_scanner else 'n/a'}",
        ]
        if f.cve:
            lines.append(f"- **CVE:** {f.cve}")
        if f.cvss:
            lines.append(f"- **CVSS:** {f.cvss}")
        if f.owasp:
            lines.append(f"- **OWASP:** {f.owasp}")
        lines.append("")
        if f.evidence:
            lines += ["**Evidence**", "", "```", f.evidence, "```", ""]
        lines += [
            "**What this is**",
            "",
            f.explanation,
            "",
            "**Impact**",
            "",
            f.impact,
            "",
            "**How to fix it**",
            "",
            f.suggested_fix,
            "",
        ]
        if f.references:
            lines.append("**References**")
            lines.append("")
            lines += [f"- {r}" for r in f.references]
            lines.append("")

    lines += ["---", "", report.disclaimer, ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def generate_report(
    scan_id: str,
    target: str,
    scan_type: ScanType,
    findings: list[NormalizedFinding],
    engines: Optional[list] = None,
    methodology: Optional[list[str]] = None,
) -> ScanReport:
    """Build a severity-ordered, human-readable report from normalized findings."""
    from app.services.scanner import engines_used  # local import avoids a cycle

    ordered = dedupe_findings(findings or [])
    built = [build_finding(f, priority=min(severity_rank(f.severity) + 1, 5)) for f in ordered]
    built = await _enrich_with_llm(built, target)

    counts = _counts(built)
    methodology = list(methodology) if methodology is not None else engines_used(ordered)

    report = ScanReport(
        scan_id=scan_id,
        timestamp=datetime.now(),
        target=target,
        scan_type=scan_type,
        summary=_executive_summary(target, scan_type, built),
        total_findings=len(built),
        findings_by_severity=counts,
        findings=built,
        risk_rating=_risk_rating(built),
        methodology=methodology,
        engines=engines or [],
    )
    return report
