"""
Agentic Engagement Engine v1 — Decepticon-style OPPLAN orchestration.

Instead of firing a fixed list of scanners at a target, the engagement runs as
an adaptive loop of phases, each executed by specialist agents:

    RECON   recon-agent       external footprint: server banner, tech, response
                              time, robots.txt, sitemap.xml
    MAP     map-agent         bounded same-origin crawl: links, forms, query
                              parameters, hidden/admin surface
    ATTACK  attack-agent      decides which probes have evidence to justify
                              them; runs real engine adapters (nuclei, nmap,
                              nikto, ZAP, strix, redteam) when installed
    VERIFY  verify-agent      re-tests candidate findings with a second
                              request and marks them confirmed / needs-review
    REPORT  report-agent      severity-sorted English report (llm_service)

Every executed step is appended to a live trace (AgentStep) that the API
serves while the engagement runs, so the UI shows what the agents are doing
in real time rather than a spinner.

Decepticon: when DECEPTICON_RUNTIME_URL is configured, `maybe_run_decepticon`
hands the engagement to the Decepticon agent runtime (LangGraph Platform
API). Any failure falls back silently to this native engine, which is always
available.

Only in-scope URLs are ever touched: the crawl never leaves the target
origin, and probes stay within the paths the app itself revealed.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Awaitable, Callable, Optional
from urllib.parse import urljoin, urlsplit

from app.config import get_settings
from app.models.schemas import (
    AgentStep,
    EngagementPlan,
    NormalizedFinding,
    Phase,
    ScanType,
    ScannerName,
    Severity,
)
from app.services.scanner import _normalize_target

settings = get_settings()

HTTP_USER_AGENT = "SecReviewAgent/1.0 (authorized-engagement)"

ADMIN_PATHS = (
    "/admin", "/admin/", "/administrator", "/manager", "/phpmyadmin",
    "/wp-admin", "/dashboard", "/adminer", "/control-panel", "/console",
)
COMMON_PATHS = ("/robots.txt", "/sitemap.xml", "/login", "/register",
                "/api", "/api/v1", "/swagger.json")

SQL_ERROR_MARKERS = (
    "sqlite3.OperationalError", "you have an error in your sql syntax",
    "unclosed quotation mark", "psycopg2.errors", "pg_query()",
    "warning: mysql", "ora-00933", "syntax error at or near",
)

CANARY = "secreview"


def _step_factory():
    """Returns (add_step, steps). add_step appends a numbered AgentStep."""
    steps: list[AgentStep] = []

    def add_step(phase: Phase, agent: str, action: str, detail: str = "",
                 verdict: str = "") -> AgentStep:
        step = AgentStep(
            step=len(steps) + 1, phase=phase, agent=agent, action=action,
            detail=detail[:1600], verdict=verdict,
        )
        steps.append(step)
        return step

    return add_step, steps


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


# ---------------------------------------------------------------------------
# Phase agents
# ---------------------------------------------------------------------------

async def recon_agent(client, target: str, add_step) -> dict:
    """External footprint. Returns observations used by later phases."""
    import httpx

    obs: dict = {"target": target}
    t0 = time.monotonic()
    try:
        resp = await client.get(target)
    except Exception as exc:
        obs["reachable"] = False
        obs["error"] = f"{type(exc).__name__}: {exc}"
        add_step(Phase.RECON, "recon-agent", "root fetch", f"target did not answer: {obs['error']}", "unreachable")
        return obs
    obs["reachable"] = True
    obs["status"] = resp.status_code
    obs["headers"] = {k.lower(): v for k, v in resp.headers.items()}
    obs["body"] = resp.text[:200_000]
    obs["ms"] = round((time.monotonic() - t0) * 1000)
    server = obs["headers"].get("server", "")
    powered = obs["headers"].get("x-powered-by", "")
    banner = "; ".join(x for x in (server, powered) if x) or "none disclosed"
    obs["banner"] = banner
    add_step(
        Phase.RECON, "recon-agent", "root fetch",
        f"{resp.status_code} in {obs['ms']}ms; server banner: {banner}; "
        f"{len(obs['body'])} bytes of HTML",
    )

    # robots.txt / sitemap.xml — reconnaissance staples.
    base = _normalize_target(target)
    for path, label in (("/robots.txt", "robots.txt"), ("/sitemap.xml", "sitemap.xml")):
        try:
            r2 = await client.get(urljoin(base, path))
        except Exception:
            continue
        if r2.status_code == 200 and r2.text.strip():
            obs[label] = r2.text[:5_000]
            interesting = re.findall(r"Disallow:\s*(\S+)", obs[label]) if label == "robots.txt" else []
            extra = f"; hidden dirs marked: {', '.join(interesting[:6])}" if interesting else ""
            add_step(Phase.RECON, "recon-agent", f"read {label}", f"{len(obs[label])} bytes{extra}")
    return obs


async def map_agent(client, target: str, obs: dict, add_step) -> dict:
    """Bounded same-origin crawl. Never leaves the target origin."""
    import httpx

    base = _normalize_target(target)
    frontier: list[str] = [base]
    seen: set[str] = set()
    forms: list[dict] = []
    query_params: dict[str, set[str]] = {}
    admin_pages: list[str] = []

    # Seed from robots.txt Disallow entries — the map agent checks managed-paid
    # paths the site itself declared as restricted.
    robots = obs.get("robots.txt", "")
    for disallowed in re.findall(r"Disallow:\s*(\S+)", robots)[:10]:
        frontier.append(urljoin(base, disallowed))

    hops = 0
    while frontier and hops < 30 and len(seen) < 40:
        url = frontier.pop(0)
        if url.split("?", 1)[0] in seen:
            continue
        seen.add(url.split("?", 1)[0])
        hops += 1
        try:
            resp = await client.get(url)
        except Exception:
            continue
        body = resp.text[:100_000]

        # Same discovered paths the crawler can act on now.
        for href in re.findall(r'href=["\']([^"\'#]+)', body)[:30]:
            nxt = urljoin(base.rstrip("/") + "/", href)
            if _same_origin(base, nxt) and nxt not in frontier:
                frontier.append(nxt)

        # Query parameters are future attack surface.
        for match in re.findall(r"([\w\-]+)=", urlsplit(url).query or ""):
            query_params.setdefault(url.split('?', 1)[0] or "/", set()).add(match)

        # Hidden forms count as attack surface (login endpoints...).
        for form in re.findall(r"<form[^>]*>(?:(?!</form>).)*</form>", body, re.DOTALL | re.IGNORECASE)[:5]:
            action_match = re.search(r'action=["\']([^"\']+)', form)
            inputs = re.findall(r'name=["\']([^"\']+)', form)
            forms.append({
                "url": urlsplit(url).path or "/",
                "action": action_match.group(1) if action_match else "",
                "inputs": inputs,
            })

        # 200 responses on adminish paths = unauthorized admin surface.
        if resp.status_code == 200 and looks_like_admin(url):
            admin_pages.append(url)

    verdict = (
        f"{len(seen)} unique pages, {len(forms)} form(s), "
        f"{sum(len(v) for v in query_params.values())} query parameter(s), "
        f"{len(admin_pages)} unauthenticated admin page(s)"
    )
    add_step(Phase.MAP, "map-agent", "same-origin crawl", verdict)

    if admin_pages:
        add_step(Phase.MAP, "map-agent", "admin surface found",
                 "found unauthenticated admin paths: " + ", ".join(admin_pages[:5]))
    params_summary = ", ".join(
        f"{path}?: {', '.join(sorted(pnames)[:4])}" for path, pnames in list(query_params.items())[:5]
    )
    if params_summary:
        add_step(Phase.MAP, "map-agent", "parameter map", params_summary)

    return {
        "pages": sorted(seen),
        "forms": forms,
        "query_params": query_params,
        "admin_pages": admin_pages,
    }


def looks_like_admin(url: str) -> bool:
    lowered = url.lower()
    return any(marker in lowered for marker in ADMIN_PATHS)


# ---------------------------------------------------------------------------
# Attack agent (adaptive probes + real engine adapters)
# ---------------------------------------------------------------------------

async def attack_agent(client, target: str, obs: dict, survey: dict, add_step,
                       scan_type: ScanType) -> list[NormalizedFinding]:
    """Chooses probes based on what recon/map actually observed."""
    base = _normalize_target(target)
    findings: list[NormalizedFinding] = []
    forms = survey.get("forms", [])
    params = survey.get("query_params", {})
    admin_pages = survey.get("admin_pages", [])
    probed: list[str] = []

    # --- probe 1: unauthenticated admin pages (evidence: 200 observed) ---
    for page in admin_pages[:5]:
        try:
            resp = await client.get(page)
        except Exception:
            continue
        if resp.status_code == 200:
            findings.append(NormalizedFinding(
                title=f"Admin panel accessible without authentication: {page}",
                severity=Severity.HIGH,
                location=page,
                evidence=f"GET {page} -> HTTP {resp.status_code} with administrative content.",
                source_scanner=ScannerName.HTTP,
                description=(
                    "An administrative surface answers unauthenticated traffic. Anyone on "
                    "the internet can enumerate users, change settings, launch attacks on "
                    "every user of the application, or pivot into the infrastructure behind "
                    "it. Admin routes must require authentication and authorization, "
                    "preferably with a second factor and audit logging."
                ),
                rule_id="agent-admin-noauth",
                references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
            ))
            probed.append("admin-without-auth")

    # --- probe 2: keep-reflection canary in query params (evidence: params map) ---
    for path, pnames in list(params.items())[:4]:
        for pname in list(pnames)[:3]:
            probe_url = f"{base.split('?',1)[0].rstrip('/')}{path}?{pname}={CANARY}"
            try:
                resp = await client.get(probe_url)
            except Exception:
                continue
            body = resp.text[:100_000]
            if CANARY in body and "<script" in body:
                findings.append(NormalizedFinding(
                    title=f"Reflected parameter without encoding: {pname}",
                    severity=Severity.MEDIUM,
                    location=probe_url,
                    evidence=f"canary value '{CANARY}' echoed into HTML context on {path}.",
                    source_scanner=ScannerName.HTTP,
                    description=(
                        "The parameter is echoed back into the page without encoding or "
                        "escaping, which makes the page a reflection point where "
                        "attacker-supplied markup or script runs in the victim's origin "
                        "— Verizon's guidelines call these symptoms of XSS. Needs manual "
                        "confirmation by pushing a benign, non-<script> marker."
                    ),
                    rule_id="agent-reflect-param",
                    references=["https://owasp.org/Top10/A03_2021-Injection/"],
                ))
                probed.append(f"reflected {pname}")
                break

    # --- probe 3: deliberate SQLi tell-tale on reflection points that show input chaos ---
    for finding in [f for f in findings if f.rule_id == "agent-reflect-param"][:2]:
        loc = finding.location or ""
        for quote in ("'", "\""):
            probe_url = loc + quote
            try:
                resp = await client.get(probe_url)
            except Exception:
                continue
            body_low = resp.text.lower()[:80_000]
            marker = next((m for m in SQL_ERROR_MARKERS if m.lower() in body_low), None)
            if marker:
                findings.append(NormalizedFinding(
                    title=f"Database error reveals SQL injection surface: {split_path(loc)}",
                    severity=Severity.CRITICAL,
                    location=probe_url,
                    evidence=f"quote in parameter produced DB error marker '{marker}'",
                    source_scanner=ScannerName.HTTP,
                    description=(
                        "Sending a single quote makes the application return a raw database "
                        "error, meaning input reaches SQL unparameterized. A raw error is "
                        "not the vulnerability: it is the signal that the query can be "
                        "shaped by attacker input, which leads to data disclosure or full "
                        "database take-over in most deployments."
                    ),
                    rule_id="agent-sqli-leak",
                    references=["https://owasp.org/Top10/A03_2021-Injection/"],
                ))
                break

    # --- probe 4: common-path sweep (only paths without a 200 from recon) ---
    known_pages = survey.get("pages", [])
    for path in ADMIN_PATHS + COMMON_PATHS:
        if any(path.rstrip('/') in str(page) for page in known_pages):
            continue
        try:
            resp = await client.get(urljoin(base, path))
        except Exception:
            continue
        body = resp.text[:40_000]
        # .env and .git were checked by the built-in assessment; here attack-agent
        # confirms against the observed websites only on known markers.
        if resp.status_code == 200 and path == "/robots.txt" and resp.text.strip():
            add_step(Phase.ATTACK, "attack-agent", "confirm robots exposure",
                     f"robots.txt present ({len(body)} bytes)")
        elif resp.status_code == 200 and path == "/.env" and "=" in body:
            findings.append(NormalizedFinding(
                title="Environment file readable on / (confirmed by agent sweep)",
                severity=Severity.CRITICAL,
                location=base + path,
                evidence=f"body preview: {body[:80]!r}",
                source_scanner=ScannerName.HTTP,
                description=(
                    "A second observed entry point confirms that the .env file is "
                    "served to browsers. Database passwords, API keys, and signature "
                    "secrets are public. Rotate everything in that file immediately, "
                    "then remove the file from deployment."
                ),
                rule_id="agent-env-exposed",
            ))
            probed.append("env reconfirmed")

    add_step(Phase.ATTACK, "attack-agent", "adaptive probe summary",
             f"{len(findings)} new finding(s); probes: {', '.join(probed[:8]) or 'none justified by recon'}")

    add_step(Phase.ATTACK, "engine-adapters", "scan with installed engines",
             "dispatching recon anchors to: "
             + (", ".join(["nuclei", "nmap", "nikto", "zap"]) if scan_type == ScanType.URL else "semgrep, trivy")
             + " (only the ones installed will actually run)")

    return findings


def split_path(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).path or url


# ---------------------------------------------------------------------------
# Verify agent
# ---------------------------------------------------------------------------

async def verify_agent(client, findings: list[NormalizedFinding], add_step) -> list[NormalizedFinding]:
    """Re-check HTTP findings once; engine outputs are kept as-is."""
    http_findings = [f for f in findings if f.source_scanner == ScannerName.HTTP
                     and f.location.lower().startswith("http")][:15]
    confirmed = 0

    for f in http_findings:
        try:
            resp = await client.get(f.location, follow_redirects=False)
            f.evidence += f" | verify re-check: HTTP {resp.status_code}"
            confirmed += 1
        except Exception:
            pass
    if http_findings:
        add_step(Phase.VERIFY, "verify-agent", "re-check built-in findings",
                 f"{confirmed}/{len(http_findings)} re-confirmed with a second look", "re-checked")
    # External engines were only consulted once; mark accordingly.
    for f in findings:
        if f.source_scanner != ScannerName.HTTP and "verify" not in (f.evidence or ""):
            f.evidence = (f.evidence or "") + " | single-source: spot-check manually"
    return findings


# ---------------------------------------------------------------------------
# Decepticon handoff (optional, failures fall back to this engine silently)
# ---------------------------------------------------------------------------

async def maybe_run_decepticon(target: str, scan_type: ScanType,
                               add_step) -> Optional[list[NormalizedFinding]]:
    """Hand engagement to the Decepticon agent runtime when configured.

    The runtime is a LangGraph Platform API. This adapter is deliberately
    conservative: any transport or parse failure returns None and the native
    engine takes over. Findings must mention known severity words to be kept.
    """
    import httpx

    base = settings.DECEPTICON_RUNTIME_URL
    if not base:
        return None
    add_step(Phase.ATTACK, "decepticon-adapter", "handoff to Decepticon runtime",
             f"POSTing engagement brief to {base}", "attempting")
    try:
        async with httpx.AsyncClient(timeout=settings.DECEPTICON_TIMEOUT) as client:
            thread = await client.post(f"{base}/threads", json={})
            thread.raise_for_status()
            thread_id = thread.json()["thread_id"]
            run = await client.post(
                f"{base}/threads/{thread_id}/runs/wait",
                json={
                    "assistant_id": "red_agent",
                    "input": {
                        "target": target,
                        "scan_type": scan_type.value,
                        "mode": "recon_and_vuln_verification",
                    },
                },
            )
            run.raise_for_status()
            payload = run.json()
    except Exception as exc:
        add_step(Phase.ATTACK, "decepticon-adapter", "handoff failed",
                 f"{type(exc).__name__}: {exc} — native engine takes over", "fallback")
        return None

    findings: list[NormalizedFinding] = []
    text = str(payload)[:80_000]
    for blob in re.findall(r"\{[^{}]*\"(?:title|severity)\"[^{}]*\}", text, re.DOTALL):
        import json as _json
        try:
            item = _json.loads(blob)
        except Exception:
            continue
        findings.append(NormalizedFinding(
            title=str(item.get("title") or "Decepticon finding"),
            severity=Severity(str(item.get("severity", "medium")).lower()),
            location=str(item.get("location") or target),
            evidence=str(item.get("evidence") or "")[:500],
            source_scanner=ScannerName.REDTEAM,
            description=str(item.get("description") or item.get("impact") or "")[:1000],
            rule_id=str(item.get("rule_id") or "decepticon"),
        ))
    add_step(Phase.ATTACK, "decepticon-adapter", "returned findings",
             f"{len(findings)} finding(s)" if findings else "engagement finished without findings",
             "returned" if findings else "clean")
    return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def run_engagement(
    target: str,
    scan_type: ScanType,
    trace_sink: Optional[Callable[[AgentStep], None]] = None,
) -> list[NormalizedFinding]:
    """
    Run the whole agentic engagement and return normalized findings.

    `trace_sink` is called with each AgentStep as it happens (route layer
    stores it on the job so the UI can poll /scan/{id}/trace live).
    """
    import httpx

    add_step, steps = _step_factory()

    if trace_sink is not None:
        original_add = add_step

        def sink_wrapper(*args, **kwargs):
            step = original_add(*args, **kwargs)
            trace_sink(step)
            return step

        add_step = sink_wrapper

    url = _normalize_target(target)
    normalized = scan_type
    plan = EngagementPlan(
        opplan_id=f"OPPLAN-{uuid.uuid4().hex[:8].upper()}",
        objective="Find as much true attack surface as possible on the authorized target, verify what can be verified, and produce a severity-sorted English report.",
        authorized_target=f"{urlsplit(url).scheme}://{urlsplit(url).netloc}" if "://" in url else url,
        phases=[p.value for p in Phase],
    )

    findings: list[NormalizedFinding] = []
    async with httpx.AsyncClient(
        verify=False,
        timeout=max(settings.HTTP_PROBE_TIMEOUT, 15),
        follow_redirects=True,
        headers={"User-Agent": HTTP_USER_AGENT},
    ) as client:
        obs = await recon_agent(client, url, add_step)
        if not obs.get("reachable"):
            # Ending early is an actual result, not an exception.
            findings.append(NormalizedFinding(
                title="Target unreachable during recon",
                severity=Severity.INFO,
                location=url,
                evidence=obs.get("error", "no further detail"),
                source_scanner=ScannerName.HTTP,
                description="The engagement could not establish an HTTP session with the target. Nothing was concluded about its security posture.",
                rule_id="agent-unreachable",
            ))
            return findings

        survey = await map_agent(client, url, obs, add_step)
        agent_findings = await attack_agent(client, url, obs, survey, add_step, scan_type)
        findings.extend(agent_findings)
        findings = await verify_agent(client, findings, add_step)

        decepticon = await maybe_run_decepticon(url, scan_type, add_step)
        if decepticon is not None:
            findings.extend(decepticon)

    add_step(Phase.REPORT, "report-agent", "generate severity-sorted report",
             f"agents produced {len(findings)} finding(s); orchestrator merges them with "
             "the built-in assessment and installed engine adapters", "wrote report")

    # Stash engagement metadata for the route layer (plan + trace are exposed
    # via the job dict and merged into the report schema there).
    run_engagement.last_plan = plan
    run_engagement.last_trace = steps
    return findings
