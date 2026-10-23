"""
Scanner Orchestrator v1 — real engines + built-in HTTP assessment.

Every engine is optional. `run_all_scanners()` figures out what is actually
installed on this machine, runs what it can, normalizes all output into a single
list of `NormalizedFinding`, and always returns something useful because the
built-in HTTP assessment is pure Python.

Engines
-------
  built-in HTTP   pure Python/httpx: headers, cookies, CORS, exposed paths,
                  secret leakage, HTTPS redirect. Always available.
  nuclei          DAST / template-based CVE & misconfig checks.
  nmap            recon: open ports and service versions.
  nikto           DAST: legacy web-server misconfiguration scan.
  semgrep         SAST: source code patterns.
  trivy           SCA + IaC + secret scanning on a filesystem.
  zap-cli         DAST: full spider + active scan (slow, needs a ZAP daemon).
  strix           AI pentest agent (needs Docker + LLM key).
  ai-red-teaming  LLM/agent red-team harness (needs Node + LLM key).

Nothing here re-implements exploits: external engines are invoked as CLIs and
their structured output is parsed by `app.services.normalizer`.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from app.config import get_settings
from app.models.schemas import (
    EngineRole,
    EngineStatus,
    NormalizedFinding,
    ScanType,
    ScannerName,
    Severity,
)
from app.services.normalizer import map_severity_str, normalize_all_findings

# Module-level settings object: tests monkeypatch `app.services.scanner.settings`.
settings = get_settings()

HTTP_USER_AGENT = "SecReviewTool/1.0 (authorized-lab-scan)"


# ---------------------------------------------------------------------------
# Engine registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EngineSpec:
    name: ScannerName
    label: str
    role: EngineRole
    commands: tuple[str, ...]
    applies_to: frozenset[ScanType]
    detail: str
    version_flag: tuple[str, ...] = ("--version",)


ENGINE_SPECS: tuple[EngineSpec, ...] = (
    EngineSpec(
        name=ScannerName.NUCLEI,
        label="Nuclei",
        role=EngineRole.DAST,
        commands=("nuclei",),
        applies_to=frozenset({ScanType.URL}),
        detail="Template-based DAST (CVEs, misconfigs, exposed panels). "
               "Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        version_flag=("-version",),
    ),
    EngineSpec(
        name=ScannerName.NMAP,
        label="Nmap",
        role=EngineRole.RECON,
        commands=("nmap",),
        applies_to=frozenset({ScanType.URL}),
        detail="Port / service discovery. Install: https://nmap.org/download",
    ),
    EngineSpec(
        name=ScannerName.NIKTO,
        label="Nikto",
        role=EngineRole.DAST,
        commands=("nikto",),
        applies_to=frozenset({ScanType.URL}),
        detail="Web-server misconfiguration scanner. "
               "Install: git clone https://github.com/sullo/nikto (add to PATH)",
    ),
    EngineSpec(
        name=ScannerName.ZAP,
        label="OWASP ZAP",
        role=EngineRole.DAST,
        commands=("zap-cli", "zap.sh", "zap.bat"),
        applies_to=frozenset({ScanType.URL}),
        detail="Spider + active scan. Needs a running ZAP daemon "
               "(zap.sh -daemon -port 8090) and zap-cli.",
    ),
    EngineSpec(
        name=ScannerName.SEMGREP,
        label="Semgrep",
        role=EngineRole.SAST,
        commands=("semgrep",),
        applies_to=frozenset({ScanType.UPLOAD}),
        detail="Source-code pattern analysis. Install: pip install semgrep",
    ),
    EngineSpec(
        name=ScannerName.TRIVY,
        label="Trivy",
        role=EngineRole.SCA,
        commands=("trivy",),
        applies_to=frozenset({ScanType.UPLOAD}),
        detail="Dependency CVEs, IaC misconfig and secret scanning. "
               "Install: https://trivy.dev/latest/getting-started/installation/",
    ),
    EngineSpec(
        name=ScannerName.STRIX,
        label="Strix (AI pentest)",
        role=EngineRole.AI_PENTEST,
        commands=(settings.STRIX_CMD, "strix"),
        applies_to=frozenset({ScanType.URL}),
        detail="Autonomous AI pentest agent. Needs Docker + an LLM API key. "
               "Install: pipx install strix-agent",
    ),
    EngineSpec(
        name=ScannerName.REDTEAM,
        label="AI Red-Teaming",
        role=EngineRole.AI_REDTEAM,
        commands=("node",),
        applies_to=frozenset({ScanType.URL}),
        detail=f"LLM/agent attack harness (OWASP LLM Top 10). Needs Node + an LLM key "
               f"and a checkout at REDTEAM_DIR ('{settings.REDTEAM_DIR}').",
    ),
)


def _which(*candidates: str) -> Optional[str]:
    for cmd in candidates:
        if not cmd:
            continue
        found = shutil.which(cmd)
        if found:
            return found
    return None


def _probe_version(exe: str, flag: tuple[str, ...]) -> str:
    """Best-effort `--version`; never blocks for more than 5s."""
    import subprocess

    try:
        proc = subprocess.run(
            [exe, *flag],
            capture_output=True,
            timeout=5,
            text=True,
            errors="replace",
        )
    except Exception:
        return ""
    out = (proc.stdout or "") + " " + (proc.stderr or "")
    for line in out.splitlines():
        line = line.strip()
        if line:
            return line[:120]
    return ""


def _redteam_ready() -> tuple[bool, str]:
    node = shutil.which("node")
    if not node:
        return False, "node is not installed"
    base = Path(settings.REDTEAM_DIR)
    if not base.exists():
        return False, f"REDTEAM_DIR not found: {settings.REDTEAM_DIR}"
    return True, ""


def detect_engines() -> list[EngineStatus]:
    """Report which engines exist locally so the UI can explain what really ran."""
    statuses: list[EngineStatus] = [
        EngineStatus(
            name=ScannerName.HTTP,
            label="Built-in HTTP assessment",
            role=EngineRole.BUILTIN,
            available=True,
            version="v1",
            detail="Pure-Python checks: security headers, cookie flags, CORS, "
                   "exposed paths, secret leakage, HTTPS redirect.",
            command="(internal)",
        )
    ]

    for spec in ENGINE_SPECS:
        exe = _which(*spec.commands)
        available = bool(exe)
        detail = spec.detail

        if spec.name is ScannerName.REDTEAM:
            ready, why = _redteam_ready()
            available = available and ready
            if not ready:
                detail = f"{spec.detail} Blocked: {why}."

        statuses.append(
            EngineStatus(
                name=spec.name,
                label=spec.label,
                role=spec.role,
                available=available,
                version=_probe_version(exe, spec.version_flag) if exe else "",
                detail=detail if not available else "Ready.",
                command=exe or spec.commands[0],
            )
        )

    return statuses


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

async def _run(
    cmd: list[str],
    timeout: int,
    cwd: Optional[str] = None,
) -> tuple[int, str, str]:
    """Run a CLI without a shell. Returns (returncode, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
    except (FileNotFoundError, OSError) as exc:
        return 127, "", f"{cmd[0]} could not be started: {exc}"

    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        with suppress(Exception):
            proc.kill()
        with suppress(Exception):
            await proc.wait()
        return 124, "", f"timed out after {timeout}s"
    except Exception as exc:  # pragma: no cover - platform specific
        return 1, "", str(exc)

    return (
        proc.returncode or 0,
        out.decode("utf-8", errors="replace"),
        err.decode("utf-8", errors="replace"),
    )


# ---------------------------------------------------------------------------
# Built-in HTTP assessment (always available)
# ---------------------------------------------------------------------------

# (lowercase header, display name, severity, why it matters)
SECURITY_HEADERS: tuple[tuple[str, str, Severity, str], ...] = (
    (
        "content-security-policy",
        "Content-Security-Policy",
        Severity.MEDIUM,
        "A missing Content-Security-Policy means the browser has no instruction "
        "about which sources of script, style and frame content are trusted. "
        "Any script-injection flaw - reflected XSS, a compromised third-party "
        "script, or an injected inline handler - can then execute in the page.",
    ),
    (
        "x-frame-options",
        "X-Frame-Options",
        Severity.LOW,
        "Without X-Frame-Options (or a frame-ancestors CSP directive) the page can "
        "be embedded in an attacker-controlled iframe, enabling clickjacking: the "
        "victim thinks they are clicking the attacker's page but act on yours.",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        Severity.LOW,
        "Without 'nosniff', browsers may guess a response's content type. A file "
        "upload containing HTML can then be interpreted as a script and run in "
        "the site's origin.",
    ),
    (
        "referrer-policy",
        "Referrer-Policy",
        Severity.LOW,
        "Without a Referrer-Policy the full URL of internal pages (including "
        "tokens or IDs in query strings) leaks to every third-party site the user "
        "navigates to.",
    ),
    (
        "permissions-policy",
        "Permissions-Policy",
        Severity.INFO,
        "Without Permissions-Policy, powerful browser features (camera, "
        "microphone, geolocation) stay available to any embedded frame or "
        "injected script.",
    ),
    (
        "strict-transport-security",
        "Strict-Transport-Security",
        Severity.MEDIUM,
        "Without HSTS, the browser will happily make the first request over plain "
        "HTTP, giving a network attacker a window to downgrade or hijack the "
        "session (SSL stripping).",
    ),
)

# path -> (severity, marker that must appear in the body, description)
SENSITIVE_PATHS: dict[str, tuple[Severity, Optional[str], str]] = {
    "/.git/HEAD": (
        Severity.CRITICAL,
        "ref:",
        "The .git directory is served publicly. An attacker can download the "
        "repository metadata, reconstruct the full source history, and recover "
        "secrets or unreleased code that were committed and later deleted.",
    ),
    "/.env": (
        Severity.CRITICAL,
        "=",
        "An environment file is publicly readable. It typically contains database "
        "passwords, API keys and signing secrets, which is enough for a complete "
        "application takeover.",
    ),
    "/server-status": (
        Severity.HIGH,
        None,
        "Apache server-status is exposed and leaks live request URLs, client IPs "
        "and internal hostnames to anyone who asks.",
    ),
    "/actuator/env": (
        Severity.HIGH,
        None,
        "A Spring Boot actuator endpoint is exposed and can disclose environment "
        "variables and configuration, including credentials.",
    ),
    "/backup.zip": (
        Severity.HIGH,
        None,
        "A backup archive is downloadable. Backups usually contain the source "
        "code, database dumps or configuration from before current hardening.",
    ),
    "/swagger.json": (
        Severity.LOW,
        None,
        "An API specification is public. It maps every endpoint and parameter for "
        "an attacker and often exposes internal or unauthenticated routes.",
    ),
}

SECRET_PATTERNS: tuple[tuple[str, str, Severity], ...] = (
    ("aws-access-key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    ("stripe-live-key", r"sk_live_[0-9a-zA-Z]{16,}", Severity.CRITICAL),
    ("github-token", r"gh[pousr]_[A-Za-z0-9]{20,}", Severity.CRITICAL),
    ("private-key-block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", Severity.CRITICAL),
    ("google-api-key", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH),
    ("slack-token", r"xox[baprs]-[0-9A-Za-z\-]{10,}", Severity.HIGH),
    ("generic-password-assignment", r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]", Severity.HIGH),
)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme:
        return url
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _normalize_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        return target
    if "://" not in target:
        return f"http://{target}"
    return target


def _check_headers(url: str, headers: dict[str, str], is_https: bool) -> list[NormalizedFinding]:
    found: list[NormalizedFinding] = []
    for key, display, severity, why in SECURITY_HEADERS:
        if key == "strict-transport-security" and not is_https:
            continue  # meaningless over plain HTTP
        if headers.get(key, "").strip():
            continue
        found.append(
            NormalizedFinding(
                title=f"Missing security header: {display}",
                severity=severity,
                location=url,
                evidence=f"The response from {url} did not include a '{display}' header.",
                source_scanner=ScannerName.HTTP,
                description=why,
                rule_id=f"http-header-{key}",
                references=["https://owasp.org/www-project-secure-headers/"],
            )
        )
    return found


def _check_cookies(url: str, set_cookie_values: list[str]) -> list[NormalizedFinding]:
    found: list[NormalizedFinding] = []
    for raw in set_cookie_values:
        name = raw.split("=", 1)[0].strip() or "cookie"
        lowered = raw.lower()
        missing = [
            label
            for flag, label in (("secure", "Secure"), ("httponly", "HttpOnly"), ("samesite", "SameSite"))
            if flag not in lowered
        ]
        if not missing:
            continue
        serious = "Secure" in missing or "HttpOnly" in missing
        found.append(
            NormalizedFinding(
                title=f"Cookie '{name}' missing security flags: {', '.join(missing)}",
                severity=Severity.MEDIUM if serious else Severity.LOW,
                location=url,
                evidence=raw[:300],
                source_scanner=ScannerName.HTTP,
                description=(
                    "A cookie without 'Secure' is sent over plain HTTP and can be "
                    "captured on the network. A cookie without 'HttpOnly' is readable "
                    "by JavaScript, so any XSS becomes immediate session theft. "
                    "Without 'SameSite' the cookie is attached to cross-site requests, "
                    "weakening CSRF defences."
                ),
                rule_id=f"http-cookie-{name}",
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            )
        )
    return found


def _check_server_disclosure(url: str, headers: dict[str, str]) -> list[NormalizedFinding]:
    leaks = [
        (key, headers[key])
        for key in ("server", "x-powered-by", "x-aspnet-version", "x-generator")
        if headers.get(key, "").strip()
    ]
    if not leaks:
        return []
    evidence = "; ".join(f"{k}: {v}" for k, v in leaks)
    return [
        NormalizedFinding(
            title="Technology and version disclosure in response headers",
            severity=Severity.LOW,
            location=url,
            evidence=evidence,
            source_scanner=ScannerName.HTTP,
            description=(
                "The server advertises its product, and often its exact version, in "
                "response headers. An attacker can map that version to known CVEs "
                "and pick exploits that are likely to work before sending a single "
                "probe. Remove or genericise these headers."
            ),
            rule_id="http-header-disclosure",
            references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
        )
    ]


def _check_secrets(url: str, body: str) -> list[NormalizedFinding]:
    found: list[NormalizedFinding] = []
    sample = (body or "")[:200_000]
    for name, pattern, severity in SECRET_PATTERNS:
        match = re.search(pattern, sample)
        if not match:
            continue
        raw = match.group(0)
        redacted = raw[:8] + "*" * max(len(raw) - 8, 4)
        found.append(
            NormalizedFinding(
                title=f"Possible secret exposed in page content: {name}",
                severity=severity,
                location=url,
                evidence=f"Matched pattern '{name}': {redacted}",
                source_scanner=ScannerName.HTTP,
                description=(
                    "A credential-shaped string is served to any visitor of this "
                    "page. Anything the browser can read is public: rotate the key "
                    "immediately, then move the secret server-side and check access "
                    "logs for prior use."
                ),
                rule_id=f"http-secret-{name}",
                references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
            )
        )
    return found


async def _check_cors(client, url: str) -> list[NormalizedFinding]:
    probe = "https://evil.example"
    try:
        resp = await client.get(url, headers={"Origin": probe})
    except Exception:
        return []

    allow_origin = resp.headers.get("access-control-allow-origin", "").strip()
    allow_creds = resp.headers.get("access-control-allow-credentials", "").strip().lower()

    if not allow_origin:
        return []

    if allow_origin == "*" and allow_creds == "true":
        severity = Severity.HIGH
        detail = ("Access-Control-Allow-Origin is '*' while credentials are allowed. "
                  "Any website can read authenticated responses from this origin.")
    elif allow_origin == probe:
        severity = Severity.HIGH
        detail = ("The server reflects an arbitrary Origin back in "
                  "Access-Control-Allow-Origin. Any website the victim visits can read "
                  "this origin's authenticated responses.")
    elif allow_origin == "*":
        severity = Severity.INFO
        detail = ("Cross-origin reads are open to every origin. If no endpoint here "
                  "relies on authentication, this is only informational.")
    else:
        return []

    return [
        NormalizedFinding(
            title="Permissive CORS policy",
            severity=severity,
            location=url,
            evidence=f"Origin: {probe} -> Access-Control-Allow-Origin: {allow_origin}"
                     + (f", Access-Control-Allow-Credentials: {allow_creds}" if allow_creds else ""),
            source_scanner=ScannerName.HTTP,
            description=detail,
            rule_id="http-cors-permissive",
            references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
        )
    ]


async def _check_https_redirect(client, url: str) -> list[NormalizedFinding]:
    if urlsplit(url).scheme != "http":
        return []
    try:
        resp = await client.get(url, follow_redirects=False)
    except Exception:
        return []

    location = resp.headers.get("location", "")
    redirected = 300 <= resp.status_code < 400 and location.lower().startswith("https://")
    if redirected:
        return []

    return [
        NormalizedFinding(
            title="Site does not redirect HTTP traffic to HTTPS",
            severity=Severity.MEDIUM,
            location=url,
            evidence=f"GET {url} -> {resp.status_code}"
                     + (f" Location: {location}" if location else " with no redirect"),
            source_scanner=ScannerName.HTTP,
            description=(
                "Plain HTTP is served without forcing an upgrade to HTTPS. Everything "
                "sent before a redirect - cookies, credentials, session tokens - can "
                "be read or modified by anyone on the network path. Serve a permanent "
                "redirect to HTTPS and add an HSTS header."
            ),
            rule_id="http-no-https-redirect",
            references=["https://owasp.org/www-community/attacks/SSL_Strip"],
        )
    ]


async def _check_sensitive_paths(client, url: str) -> list[NormalizedFinding]:
    base = _origin(url)
    found: list[NormalizedFinding] = []
    for path, (severity, marker, why) in SENSITIVE_PATHS.items():
        full = base.rstrip("/") + path
        try:
            resp = await client.get(full, follow_redirects=False)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        body = (resp.text or "")[:20_000]
        if marker and marker not in body:
            continue
        found.append(
            NormalizedFinding(
                title=f"Exposed sensitive resource: {path}",
                severity=severity,
                location=full,
                evidence=f"HTTP 200 for {full} ({len(resp.content)} bytes). Preview: {body[:160]!r}",
                source_scanner=ScannerName.HTTP,
                description=why,
                rule_id=f"http-exposed-{path.strip('/').replace('/', '-').replace('.', '-')}",
                references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
            )
        )
    return found


async def assess_http_target(target: str, client=None) -> list[NormalizedFinding]:
    """
    Built-in HTTP security assessment. Works with no external tools installed.

    `client` may be an httpx.AsyncClient (used by the tests with a mock transport).
    """
    import httpx

    url = _normalize_target(target)
    if not url:
        return []

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(
            verify=False,
            timeout=settings.HTTP_PROBE_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": HTTP_USER_AGENT},
        )

    findings: list[NormalizedFinding] = []
    try:
        try:
            response = await client.get(url)
        except Exception as exc:
            return [
                NormalizedFinding(
                    title="Target did not respond to the HTTP assessment",
                    severity=Severity.INFO,
                    location=url,
                    evidence=f"{type(exc).__name__}: {exc}",
                    source_scanner=ScannerName.HTTP,
                    description=(
                        "The built-in checks could not reach the target. This may be a "
                        "network problem, a firewall, or a URL that only answers on a "
                        "different host/port. No conclusion can be drawn about the "
                        "target's security from this result."
                    ),
                    rule_id="http-unreachable",
                )
            ]

        headers = {k.lower(): v for k, v in response.headers.items()}
        is_https = url.lower().startswith("https://")

        findings.extend(_check_headers(url, headers, is_https))
        findings.extend(_check_cookies(url, response.headers.get_list("set-cookie")))
        findings.extend(_check_server_disclosure(url, headers))
        findings.extend(_check_secrets(url, response.text))
        findings.extend(await _check_cors(client, url))
        findings.extend(await _check_https_redirect(client, url))
        findings.extend(await _check_sensitive_paths(client, url))
    finally:
        if owns_client:
            with suppress(Exception):
                await client.aclose()

    return findings


# ---------------------------------------------------------------------------
# External engine adapters
# ---------------------------------------------------------------------------

async def run_nuclei(target: str) -> Optional[dict]:
    """`nuclei -json` -> {"results": [...]} or None when unavailable."""
    exe = _which("nuclei")
    if not exe:
        return None
    rc, out, err = await _run(
        [exe, "-u", target, "-json", "-silent", "-no-color", "-disable-update-check"],
        settings.FAST_SCANNER_TIMEOUT,
    )
    matches = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        with suppress(json.JSONDecodeError):
            matches.append(json.loads(line))
    if not matches:
        print(f"[nuclei] no matches (rc={rc}) {err[:300]}")
        return None
    return {"results": matches}


async def run_nmap(target: str) -> Optional[str]:
    """`nmap -sV -oX -` -> raw XML or None."""
    exe = _which("nmap")
    if not exe:
        return None
    host = urlsplit(_normalize_target(target)).hostname or target
    rc, out, err = await _run(
        [exe, "-sV", "-Pn", "--top-ports", "200", "-oX", "-", host],
        settings.FAST_SCANNER_TIMEOUT,
    )
    if "<nmaprun" not in out:
        print(f"[nmap] no XML output (rc={rc}) {err[:300]}")
        return None
    return out


async def run_nikto(target: str) -> Optional[dict]:
    """`nikto -Format json` -> parsed dict or None."""
    exe = _which("nikto", "nikto.pl")
    if not exe:
        return None
    tmp = Path(tempfile.mkdtemp(prefix="nikto_")) / "nikto.json"
    rc, out, err = await _run(
        [exe, "-h", target, "-Format", "json", "-output", str(tmp), "-nointeractive"],
        settings.FAST_SCANNER_TIMEOUT,
    )
    if not tmp.exists():
        print(f"[nikto] no output file (rc={rc}) {err[:300]}")
        return None
    raw = tmp.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return None
    with suppress(json.JSONDecodeError):
        return json.loads(raw)
    return None


async def run_semgrep_scan(path: str, scan_type: ScanType = ScanType.UPLOAD) -> Optional[dict]:
    """Semgrep over a file/directory -> {"results": [...]} or None."""
    if settings.SIMULATE_SCANNERS:
        return SIMULATED_SEMGREP
    exe = _which("semgrep")
    if not exe:
        return None
    if not Path(path).exists():
        print(f"[semgrep] path does not exist: {path}")
        return None
    rc, out, err = await _run(
        [exe, "--config", "auto", "--json", "--quiet", "--no-git-ignore", str(path)],
        settings.FAST_SCANNER_TIMEOUT,
    )
    with suppress(json.JSONDecodeError):
        return json.loads(out) if out.strip().startswith("{") else None
    print(f"[semgrep] unparsable output (rc={rc}) {err[:300]}")
    return None


async def run_trivy_scan(path: str, scan_type: ScanType = ScanType.UPLOAD) -> Optional[dict]:
    """Trivy filesystem scan (deps + IaC + secrets) -> parsed JSON or None."""
    if settings.SIMULATE_SCANNERS:
        return SIMULATED_TRIVY
    exe = _which("trivy")
    if not exe:
        return None
    if not Path(path).exists():
        print(f"[trivy] path does not exist: {path}")
        return None
    rc, out, err = await _run(
        [exe, "fs", "--format", "json", "--quiet", "--scanners", "vuln,misconfig,secret", str(path)],
        settings.FAST_SCANNER_TIMEOUT,
    )
    with suppress(json.JSONDecodeError):
        return json.loads(out) if out.strip().startswith("{") else None
    print(f"[trivy] unparsable output (rc={rc}) {err[:300]}")
    return None


async def run_zap_scan(target: str, scan_type: ScanType = ScanType.URL) -> Optional[dict]:
    """zap-cli quick scan -> {"alerts": [...]} or None."""
    if settings.SIMULATE_SCANNERS:
        return SIMULATED_ZAP
    exe = _which("zap-cli", "zap.sh", "zap.bat")
    if not exe:
        return None

    # zap-cli needs a running daemon; fail fast rather than hanging.
    rc, out, err = await _run([exe, "status"], 15)
    if rc != 0 or "zap" not in (out + err).lower():
        print(f"[zap] daemon not reachable (rc={rc}) {(out + err)[:200]}")
        return None

    await _run([exe, "open-url", target], 30)
    await _run([exe, "spider", target], settings.SCANNER_TIMEOUT)
    await _run([exe, "active-scan", target], settings.SCANNER_TIMEOUT)
    rc, out, err = await _run([exe, "alerts", "-f", "json"], 60)
    with suppress(json.JSONDecodeError):
        data = json.loads(out) if out.strip().startswith("[") else None
        if data:
            return {"alerts": data}
    print(f"[zap] no alerts parsed (rc={rc}) {err[:200]}")
    return None


async def run_strix(target: str) -> Optional[list[NormalizedFinding]]:
    """Strix autonomous pentest. Output is mostly prose, so findings are extracted
    from JSON blocks when present and summarized otherwise."""
    exe = _which(settings.STRIX_CMD, "strix")
    if not exe:
        return None
    rc, out, err = await _run(
        [exe, "-n", "-t", target],
        settings.SCANNER_TIMEOUT,
    )
    findings: list[NormalizedFinding] = []
    for blob in re.findall(r"\{[^{}]*\"(?:title|severity)\"[^{}]*\}", out, re.DOTALL):
        with suppress(json.JSONDecodeError):
            item = json.loads(blob)
            findings.append(
                NormalizedFinding(
                    title=str(item.get("title", "Strix finding")),
                    severity=map_severity_str(item.get("severity", "medium")),
                    location=str(item.get("location", target)),
                    evidence=str(item.get("evidence", ""))[:500],
                    source_scanner=ScannerName.STRIX,
                    description=str(item.get("description", ""))[:1000],
                    rule_id=str(item.get("rule_id", "strix")),
                )
            )
    if not findings:
        deep_link = "https://app.strix.ai"
        print(f"[strix] completed (rc={rc}) without machine-readable findings; "
              f"see {deep_link} / local run logs. {err[:200]}")
    return findings or None


async def run_redteam(target: str) -> Optional[list[NormalizedFinding]]:
    """ai-red-teaming harness. Expects `npm run redteam -- --target <url>` in REDTEAM_DIR."""
    ready, _why = _redteam_ready()
    if not ready:
        return None
    rc, out, err = await _run(
        ["npm", "run", "redteam", "--", "--target", target, "--json"],
        settings.SCANNER_TIMEOUT,
        cwd=settings.REDTEAM_DIR,
    )
    findings: list[NormalizedFinding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        with suppress(json.JSONDecodeError):
            item = json.loads(line)
            findings.append(
                NormalizedFinding(
                    title=str(item.get("title") or item.get("attack") or "AI red-team finding"),
                    severity=map_severity_str(item.get("severity", "medium")),
                    location=str(item.get("location", target)),
                    evidence=str(item.get("evidence", ""))[:500],
                    source_scanner=ScannerName.REDTEAM,
                    description=str(item.get("description", ""))[:1000],
                    rule_id=str(item.get("id", "redteam")),
                )
            )
    if not findings:
        print(f"[redteam] completed (rc={rc}) without JSONL findings. {err[:200]}")
    return findings or None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

async def run_all_scanners(
    target: str,
    scan_type: ScanType,
    include_builtin: bool = True,
) -> list[NormalizedFinding]:
    """
    Run every available engine for this scan type and return normalized findings.

    Never raises for a single engine failure: a broken/missing engine is skipped,
    because the built-in assessment and the report must still be produced.
    """
    if settings.SIMULATE_SCANNERS:
        return normalize_all_findings(
            zap_output=SIMULATED_ZAP,
            semgrep_output=SIMULATED_SEMGREP,
            trivy_output=SIMULATED_TRIVY,
        )

    findings: list[NormalizedFinding] = []

    async def safe(coro, label: str):
        """One broken engine must never kill the whole scan."""
        try:
            return await coro
        except Exception as exc:
            print(f"[scanner] {label} failed: {type(exc).__name__}: {exc}")
            return None

    if scan_type == ScanType.URL:
        if include_builtin:
            findings.extend(await safe(assess_http_target(target), "built-in-http") or [])

        nuclei_out = await safe(run_nuclei(target), "nuclei")
        if nuclei_out:
            findings.extend(normalize_all_findings(nuclei_output=nuclei_out))

        nmap_out = await safe(run_nmap(target), "nmap")
        if nmap_out:
            findings.extend(normalize_all_findings(nmap_output=nmap_out))

        nikto_out = await safe(run_nikto(target), "nikto")
        if nikto_out:
            findings.extend(normalize_all_findings(nikto_output=nikto_out))

        zap_out = await safe(run_zap_scan(target, scan_type), "zap")
        if zap_out:
            findings.extend(normalize_all_findings(zap_output=zap_out))

        findings.extend(await safe(run_strix(target), "strix") or [])
        findings.extend(await safe(run_redteam(target), "redteam") or [])
    else:
        semgrep_out = await safe(run_semgrep_scan(target, scan_type), "semgrep")
        if semgrep_out:
            findings.extend(normalize_all_findings(semgrep_output=semgrep_out))

        trivy_out = await safe(run_trivy_scan(target, scan_type), "trivy")
        if trivy_out:
            findings.extend(normalize_all_findings(trivy_output=trivy_out))

    return findings


def engines_used(findings: list[NormalizedFinding]) -> list[str]:
    """Human-readable methodology list derived from what actually produced findings."""
    labels = {
        ScannerName.HTTP: "Built-in HTTP security assessment (headers, cookies, CORS, exposed paths, secrets)",
        ScannerName.NUCLEI: "Nuclei template-based DAST",
        ScannerName.NMAP: "Nmap port and service discovery",
        ScannerName.NIKTO: "Nikto web-server misconfiguration scan",
        ScannerName.ZAP: "OWASP ZAP spider + active scan",
        ScannerName.SEMGREP: "Semgrep static analysis (SAST)",
        ScannerName.TRIVY: "Trivy dependency / IaC / secret scan (SCA)",
        ScannerName.STRIX: "Strix autonomous AI pentest agent",
        ScannerName.REDTEAM: "AI red-teaming harness (LLM attack chains)",
    }
    seen: list[str] = []
    for scanner in {f.source_scanner for f in findings}:
        label = labels.get(scanner, str(scanner))
        if label not in seen:
            seen.append(label)
    return sorted(seen)


# ---------------------------------------------------------------------------
# Simulated fixtures (SIMULATE_SCANNERS=true / tests)
# ---------------------------------------------------------------------------

SIMULATED_ZAP: dict = {
    "alerts": [
        {
            "alert": "Cross Site Scripting (Reflected)",
            "riskcode": "3",
            "desc": "User input is reflected in the response without output encoding.",
            "pluginid": "40012",
            "cweid": "79",
            "reference": "https://owasp.org/www-community/attacks/xss/",
            "instances": [
                {
                    "uri": "http://example.com/search",
                    "param": "q",
                    "attack": "<script>alert(1)</script>",
                    "evidence": "<script>alert(1)</script>",
                }
            ],
        },
        {
            "alert": "Missing Anti-clickjacking Header",
            "riskcode": "2",
            "desc": "The response does not include an X-Frame-Options or frame-ancestors CSP directive.",
            "pluginid": "10020",
            "cweid": "1021",
            "reference": "https://owasp.org/www-project-web-security-testing-guide/",
            "instances": [{"uri": "http://example.com/", "param": "", "attack": "", "evidence": ""}],
        },
        {
            "alert": "Cookie Without Secure Flag",
            "riskcode": "1",
            "desc": "A cookie was set without the Secure attribute.",
            "pluginid": "10011",
            "cweid": "614",
            "reference": "https://owasp.org/www-community/controls/SecureCookieAttribute",
            "instances": [{"uri": "http://example.com/login", "param": "SESSIONID", "attack": "", "evidence": "Set-Cookie: SESSIONID=..."}],
        },
    ]
}

SIMULATED_SEMGREP: dict = {
    "results": [
        {
            "check_id": "python.flask.security.xss.render-template-string",
            "path": "app/views.py",
            "start": {"line": 42, "col": 10},
            "extra": {
                "message": "User input passed to render_template_string (potential SSTI/XSS)",
                "severity": "ERROR",
                "lines": "return render_template_string(user_input)",
                "metadata": {
                    "cwe": "79",
                    "owasp": "A03:2021",
                    "references": ["https://owasp.org/www-community/attacks/xss/"],
                },
            },
        },
        {
            "check_id": "python.lang.security.audit.formatted-sql-query",
            "path": "app/db.py",
            "start": {"line": 88, "col": 4},
            "extra": {
                "message": "SQL query built with string formatting (possible SQL injection)",
                "severity": "ERROR",
                "lines": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                "metadata": {"cwe": "89", "owasp": "A03:2021", "references": []},
            },
        },
        {
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "app/settings.py",
            "start": {"line": 15, "col": 0},
            "extra": {
                "message": "Hardcoded credential in source code",
                "severity": "WARNING",
                "lines": 'DB_PASSWORD = "changeme123"',
                "metadata": {"cwe": "798", "owasp": "A07:2021", "references": []},
            },
        },
    ]
}

SIMULATED_TRIVY: dict = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-32681",
                    "PkgName": "requests",
                    "InstalledVersion": "2.28.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "MEDIUM",
                    "Title": "Requests proxy-authorization header leak",
                    "Description": "Requests forwards the Proxy-Authorization header to destination servers on redirect.",
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"],
                }
            ],
        },
        {
            "Target": "Dockerfile",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "base-image",
                    "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.2",
                    "Severity": "CRITICAL",
                    "Title": "Remote code execution in base image component",
                    "Description": "An unauthenticated attacker can execute code in the container via a crafted request.",
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
                }
            ],
        },
    ]
}
