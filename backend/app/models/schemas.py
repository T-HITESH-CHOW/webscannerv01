from pydantic import BaseModel, HttpUrl, Field
from typing import Literal, Optional
from enum import Enum
from datetime import datetime


class ScanType(str, Enum):
    URL = "url"
    UPLOAD = "upload"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Ordering used to sort a report worst-first (critical -> info).
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def severity_rank(s: "Severity") -> int:
    return SEVERITY_ORDER.get(s, 99)


class ScannerName(str, Enum):
    # Legacy scanners (already modelled in the normalizer)
    ZAP = "zap"
    SEMGREP = "semgrep"
    TRIVY = "trivy"
    # Real infrastructure / web scanning engines
    NUCLEI = "nuclei"
    NIKTO = "nikto"
    NMAP = "nmap"
    HTTP = "http"          # built-in HTTP security assessment (pure Python)
    # AI-driven engines (external CLIs)
    STRIX = "strix"        # strix AI pentest agent
    REDTEAM = "redteam"    # ai-red-teaming framework (LLM/agent targets)


class EngineRole(str, Enum):
    DAST = "DAST"
    SAST = "SAST"
    SCA = "SCA"
    RECON = "Recon"
    BUILTIN = "Built-in"
    AI_PENTEST = "AI Pentest"
    AI_REDTEAM = "AI Red-Team"


class EngineStatus(BaseModel):
    """Availability of a scanner/engine so the UI can explain what ran."""
    name: ScannerName
    label: str
    role: EngineRole
    available: bool
    version: str = ""
    detail: str = ""       # why it is unavailable / how to enable it
    command: str = ""      # executable the adapter looks for


class ScanRequest(BaseModel):
    scan_type: ScanType
    target_url: Optional[HttpUrl] = None
    confirmation_phrase: str = ""


# --- Normalized Finding Format (Common Schema) ---
class NormalizedFinding(BaseModel):
    """Common format for all scanner outputs"""
    title: str
    severity: Severity
    location: str = ""           # file:line or URL/path
    evidence: str = ""           # code snippet, request/response, etc.
    source_scanner: ScannerName
    description: str = ""        # human-readable explanation
    rule_id: str = ""            # original rule/check ID
    references: list[str] = []   # CWE, OWASP, advisory links
    cve: Optional[str] = None
    cvss: Optional[float] = None


class RawFinding(BaseModel):
    """Raw finding from a specific scanner (before normalization)"""
    scanner: ScannerName
    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    references: list[str] = []
    cve: Optional[str] = None
    cvss: Optional[float] = None


# ---------------------------------------------------------------------------
# Agentic engagement (Decepticon-style OPPLAN)
# ---------------------------------------------------------------------------

class Phase(str, Enum):
    RECON = "recon"        # external footprint: server, tech, robots, sitemap
    MAP = "map"            # crawl/app map: links, forms, parameters, surfaces
    ATTACK = "attack"      # engraved probes + real engine adapters
    VERIFY = "verify"      # confirm candidate findings with a second look
    REPORT = "report"      # severity-sorted English report


class AgentStep(BaseModel):
    """One executed step of the agentic engagement, shown live in the UI."""
    step: int
    phase: Phase
    agent: str                 # e.g. "recon-agent", "attack-agent", "nuclei-adapter"
    action: str                # short name of what was done
    detail: str = ""           # human readable summary of the observation
    verdict: str = ""          # e.g. "confirmed", "needs manual review", "gone"


class EngagementPlan(BaseModel):
    """The OPPLAN the orchestrator derived for this target before acting."""
    opplan_id: str
    objective: str
    authorized_target: str
    phases: list[str] = [p.value for p in Phase]
    approvals_required_note: str = (
        "The engagement is restricted to the authorized target; exploration outside "
        "that origin is never attempted."
    )


class LLMFinding(BaseModel):
    """Enhanced finding after report processing"""
    title: str
    severity: Severity
    explanation: str
    impact: str
    suggested_fix: str
    references: list[str] = []
    raw_findings: list[RawFinding] = []  # Traceability to original scanner output
    # Extended reporting metadata
    location: str = ""
    evidence: str = ""
    source_scanner: Optional[ScannerName] = None
    cve: Optional[str] = None
    cvss: Optional[float] = None
    owasp: str = ""
    priority: int = 0          # 1 = fix first (derived from severity)


class ScanReport(BaseModel):
    scan_id: str
    timestamp: datetime
    target: str
    scan_type: ScanType
    summary: str
    total_findings: int
    findings_by_severity: dict[Severity, int]
    # findings are always sorted worst-first (critical -> info)
    findings: list[LLMFinding]
    # New v1 fields
    risk_rating: str = "informational"       # overall risk (e.g. critical/high/...)
    methodology: list[str] = []              # engines that actually ran
    engines: list[EngineStatus] = []         # availability of every engine
    agent_plan: Optional[EngagementPlan] = None
    agent_trace: list[AgentStep] = []        # what the agents actually did, in order
    disclaimer: str = (
        "LEARNING / AUTHORIZED-TESTING ONLY: This report is generated from automated "
        "scanner output and AI analysis. It is NOT a certified penetration test. "
        "Findings may contain false positives/negatives and must be verified manually. "
        "Only scan systems you own or have explicit written permission to test."
    )
