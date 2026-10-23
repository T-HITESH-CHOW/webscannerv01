from datetime import datetime
import traceback
import uuid

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse

from app.config import get_settings
from app.models.schemas import AgentStep, ScanRequest, ScanType, ScannerName
from app.services.scanner import assess_http_target, detect_engines, engines_used, run_all_scanners
from app.services.agent_engine import run_engagement
from app.services.llm_service import build_html, build_markdown, generate_report
from app.db import supabase_db
from app.services.guardrails import (
    ALLOWED_TARGETS,
    REQUIRED_CONFIRMATION,
    get_disclaimer_banner,
    get_disclaimer_full,
    get_disclaimer_short,
    get_report_footer,
)
from app.utils.file_handler import save_upload, extract_archive

router = APIRouter()
settings = get_settings()

# In-memory job cache. Supabase (see app/db/supabase_db.py) keeps the durable
# copy when SUPABASE_URL / SUPABASE_SERVICE_KEY are configured; without them
# everything still works out of memory.
scan_jobs: dict[str, dict] = {}

# Engagement backlog — the list the UI shows on "Scan Backlog" and
# "New Engagement". Each engagement is also surfaced as a region-scoped
# scan in scan_jobs so the existing scan/* endpoints still work.
engagements: dict[str, dict] = {}


ARCHIVE_SUFFIXES = {".zip", ".tar", ".gz", ".tgz"}

# Which engines make sense for each scan type.
URL_ENGINES = {
    ScannerName.HTTP, ScannerName.NUCLEI, ScannerName.NMAP,
    ScannerName.NIKTO, ScannerName.ZAP, ScannerName.STRIX, ScannerName.REDTEAM,
}
UPLOAD_ENGINES = {ScannerName.SEMGREP, ScannerName.TRIVY}


async def _persist(scan_id: str) -> None:
    """Best-effort durable copy to Supabase; no-op when unconfigured."""
    try:
        await supabase_db.upsert_scan(scan_id, scan_jobs.get(scan_id, {}))
    except Exception as exc:  # pragma: no cover
        print(f"[persist] scan {scan_id} failed: {type(exc).__name__}: {exc}")


# ------------------------------------------------------------------------###
# Engine status / history                                                ###
# ------------------------------------------------------------------------###

@router.get("/engines")
async def list_engines():
    """What can actually run on this machine right now."""
    engines = detect_engines()
    return {
        "simulate_scanners": settings.SIMULATE_SCANNERS,
        "decepticon_runtime": settings.DECEPTICON_RUNTIME_URL or None,
        "supabase_configured": supabase_db.configured(),
        "engines": [e.model_dump() for e in engines],
        "note": (
            "Simulation mode is ON: findings are fixtures, not real scan output."
            if settings.SIMULATE_SCANNERS
            else "The built-in HTTP assessment always runs. External engines run only "
                 "when their executable is found on PATH."
        ),
    }


@router.get("/scans")
async def recent_scans(limit: int = 25):
    """Scan history: Supabase when configured, otherwise this process."""
    if supabase_db.configured():
        rows = await supabase_db.list_scans(limit)
        if rows:
            return {"source": "supabase", "scans": rows}
    rows = [
        {
            "scan_id": sid,
            "target": j.get("target", ""),
            "scan_type": j.get("scan_type", ""),
            "status": j.get("status", ""),
            "created_at": j.get("created_at"),
            "completed_at": j.get("completed_at"),
            "simulated": bool(j.get("simulated")),
        }
        for sid, j in sorted(scan_jobs.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)[:limit]
    ]
    return {"source": "memory", "scans": rows}


# ------------------------------------------------------------------------###
# Engagement backlog                                                     ###
# ------------------------------------------------------------------------###

@router.get("/engagements")
async def list_engagements():
    """Current engagement backlog for the Decepticon-style UI.

    Each engagement mirrors scan_jobs so the per-engagement scan endpoints
    (status/trace/report) continue to work.
    """
    rows = [
        {
            "engagement_id": e.get("engagement_id"),
            "target_url": e.get("target_url", ""),
            "target_name": e.get("target_name", ""),
            "status": e.get("status", ""),
            "scan_type": e.get("scan_type", ""),
            "scan_id": e.get("scan_id"),
            "scope": e.get("scope", ""),
            "scoped_targets": e.get("scoped_targets", []),
            "opplan_id": e.get("opplan_id"),
            "created_at": e.get("created_at"),
            "completed_at": e.get("completed_at"),
            "settings": e.get("settings", {}),
            "tools_run": e.get("tools_run", []),
            "findings_count": e.get("findings_count", 0),
        }
        for e in sorted(engagements.values(), key=lambda kv: kv.get("created_at", ""), reverse=True)
    ]
    return {"engagements": rows}


@router.post("/engagements/start")
async def start_engagement(target_url: str = Form(...)):
    """Start a Decepticon-style engagement against an authorized target.

    If the target is already backed by a scan_job, resume it; otherwise
    create a fresh engagement and its backing scan job.
    """
    target_url = target_url.strip() if target_url else ""
    if not target_url:
        raise HTTPException(400, "target_url is required")

    # Preserve any existing scoped targets / settings across runs.
    existing = None
    for e in engagements.values():
        if e.get("target_url") == target_url:
            existing = e
            break

    engagement_id = str(uuid.uuid4())[:8]
    scan_id = str(uuid.uuid4())[:8]

    # Scope the engagement (same-origin only, bounded crawl) — mirrors the
    # agent engine's _same_origin / _normalize_target helpers.
    scope = "same-origin only"
    scoped_targets = [target_url]

    new_eng = {
        "engagement_id": engagement_id,
        "target_url": target_url,
        "target_name": target_url,
        "status": "queued",
        "scan_type": ScanType.URL.value,
        "scan_id": scan_id,
        "scope": scope,
        "scoped_targets": scoped_targets,
        "opplan_id": None,
        "created_at": datetime.now().isoformat(),
        "completed_at": None,
        "settings": {
            "max_crawl_depth": "3",
            "max_targets": "50",
            "timeout_seconds": "30",
            "pause": "false",
            "opplan_style": "decepticon",
        },
        "findings_count": 0,
    }
    if existing:
        new_eng["scoped_targets"] = existing.get("scoped_targets", [target_url])
        new_eng["settings"] = {**existing.get("settings", {}), "pause": "false"}
        new_eng["opplan_id"] = existing.get("opplan_id")
        new_eng["completed_at"] = None
        new_eng["status"] = "queued"

    # Backing scan job so the scan/{scan_id} endpoints keep working.
    scan_jobs[scan_id] = {
        "status": "queued",
        "target": target_url,
        "scan_type": ScanType.URL.value,
        "created_at": datetime.now().isoformat(),
        "progress": "queued",
        "trace": [],
        "scoped_targets": new_eng["scoped_targets"],
        "engagement_id": engagement_id,
    }
    engagements[engagement_id] = new_eng

    await _persist(scan_id)

    # Kick off the actual engagement in the background.
    background_tasks = BackgroundTasks()
    background_tasks.add_task(_run_engagement_worker, engagement_id, scan_id, target_url)

    return {"engagement": {
        "id": new_eng["engagement_id"],
        **new_eng,
    }}


@router.get("/engagements/{engagement_id}/status")
async def engagement_status(engagement_id: str):
    eng = engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    return {
        "engagement": {
            "id": eng.get("engagement_id"),
            "target_url": eng.get("target_url", ""),
            "target_name": eng.get("target_name", ""),
            "status": eng.get("status", ""),
            "scan_type": eng.get("scan_type", ""),
            "scan_id": eng.get("scan_id"),
            "scope": eng.get("scope", ""),
            "scoped_targets": eng.get("scoped_targets", []),
            "opplan_id": eng.get("opplan_id"),
            "created_at": eng.get("created_at"),
            "completed_at": eng.get("completed_at"),
            "settings": eng.get("settings", {}),
            "tools_run": eng.get("tools_run", []),
            "findings_count": eng.get("findings_count", 0),
        }
    }


@router.get("/engagements/{engagement_id}/trace")
async def engagement_trace(engagement_id: str):
    eng = engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    scan_id = eng.get("scan_id")
    job = scan_jobs.get(scan_id)
    steps = [s.model_dump() for s in (job.get("trace", []) if job else [])]
    return {
        "engagement_id": engagement_id,
        "scan_id": scan_id,
        "status": eng.get("status", ""),
        "progress": eng.get("progress", ""),
        "steps": steps,
    }


@router.get("/engagements/{engagement_id}/report")
async def engagement_report(engagement_id: str):
    eng = engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    scan_id = eng.get("scan_id")
    job = scan_jobs.get(scan_id)
    if not job or job.get("status") != "completed":
        raise HTTPException(400, f"Engagement status: {job.get('status') if job else 'unknown'}")
    return job.get("report")


@router.get("/engagements/{engagement_id}/scope")
async def engagement_scope(engagement_id: str):
    eng = engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    return {
        "scope": eng.get("scope", ""),
        "scoped_targets": eng.get("scoped_targets", []),
    }


@router.get("/engagements/{engagement_id}/scoped-targets")
async def scoped_targets(engagement_id: str):
    return await engagement_scope(engagement_id)


@router.post("/engagements/{engagement_id}/set-scope")
async def set_engagement_scope(engagement_id: str, scoped_targets: list[str] = Form(...)):
    """Replace the scoped targets for an engagement (UI-settable)."""
    eng = engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    # Keep only same-origin-ish targets (basic sanity, not enforcement).
    sanitized = [t for t in scoped_targets if t and ("://" in t or t.startswith("."))]
    eng["scoped_targets"] = sanitized
    # Also stamp the backing scan job.
    scan_id = eng.get("scan_id")
    if scan_id in scan_jobs:
        scan_jobs[scan_id]["scoped_targets"] = sanitized
    return {"scoped_targets": sanitized}


@router.post("/engagements/{engagement_id}/settings")
async def set_engagement_setting(engagement_id: str, setting_key: str = Form(...), setting_value: str = Form(...)):
    """Persist a single engagement setting (UI-settable)."""
    eng = engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    eng.setdefault("settings", {})[setting_key] = setting_value
    return {"setting": {setting_key: setting_value}}


@router.post("/engagements/{engagement_id}/run")
async def run_engagement_manual(engagement_id: str):
    """Re-run an existing engagement with its current scoped targets."""
    eng = engagements.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    scan_id = eng.get("scan_id")
    target_url = eng.get("target_url", "")
    # Reset status and re-kick the worker.
    eng["status"] = "queued"
    eng["completed_at"] = None
    eng["opplan_id"] = None
    if scan_id in scan_jobs:
        scan_jobs[scan_id]["status"] = "queued"
        scan_jobs[scan_id]["progress"] = "queued"
        scan_jobs[scan_id]["trace"] = []
        scan_jobs[scan_id]["completed_at"] = None
        scan_jobs[scan_id]["report"] = None
        scan_jobs[scan_id]["markdown"] = None
        scan_jobs[scan_id]["html"] = None
        scan_jobs[scan_id]["error"] = None
    await _persist(scan_id)
    background_tasks = BackgroundTasks()
    background_tasks.add_task(_run_engagement_worker, engagement_id, scan_id, target_url)
    return {"engagement": eng}


@router.post("/engagements/{engagement_id}/delete")
async def delete_engagement(engagement_id: str):
    """Remove an engagement from the backlog."""
    eng = engagements.pop(engagement_id, None)
    if eng:
        scan_id = eng.get("scan_id")
        scan_jobs.pop(scan_id, None)
    return {"ok": True}


# ------------------------------------------------------------------------###
# Scan entry points (kept intact — the engagement engine also uses these) ###
# ------------------------------------------------------------------------###

@router.post("/scan/url")
async def scan_url(
    request: Request,
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
):
    if not scan_request.target_url:
        raise HTTPException(400, "target_url is required")

    target = str(scan_request.target_url)
    # Guardrails intentionally disabled by project owner: any URL/domain allowed.
    # Keep the disclaimer strings — they are still returned by /guardrails/disclaimers.
    scan_id = str(uuid.uuid4())[:8]
    scan_jobs[scan_id] = {
        "status": "queued",
        "target": target,
        "scan_type": ScanType.URL.value,
        "created_at": datetime.now().isoformat(),
        "progress": "queued",
        "trace": [],
    }
    await _persist(scan_id)
    background_tasks.add_task(process_scan, scan_id, target, target, ScanType.URL)
    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "Engagement started (authorized lab use only)",
        "engines": [e.model_dump() for e in detect_engines()],
    }


@router.post("/scan/upload")
async def scan_upload(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    confirmation_phrase: str = Form(""),
):
    if not file.filename:
        raise HTTPException(400, "No file provided")

    file_path = await save_upload(file)

    scan_target = file_path
    suffix = "." + file.filename.lower().rsplit(".", 1)[-1] if "." in file.filename else ""
    if suffix in ARCHIVE_SUFFIXES:
        scan_target = extract_archive(file_path)

    display_target = f"upload://{file.filename}"
    scan_id = str(uuid.uuid4())[:8]
    scan_jobs[scan_id] = {
        "status": "queued",
        "target": display_target,
        "scan_type": ScanType.UPLOAD.value,
        "created_at": datetime.now().isoformat(),
        "progress": "queued",
        "trace": [],
    }
    await _persist(scan_id)
    background_tasks.add_task(process_scan, scan_id, scan_target, display_target, ScanType.UPLOAD)
    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "Upload scan started (authorized lab use only)",
    }


# ------------------------------------------------------------------------###
# Results                                                                ###
# ------------------------------------------------------------------------###

@router.get("/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    job = scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found")
    return {
        "scan_id": scan_id,
        "status": job.get("status"),
        "progress": job.get("progress", ""),
        "target": job.get("target"),
        "scan_type": job.get("scan_type"),
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
        "error": job.get("error"),
        "simulated": job.get("simulated"),
    }


@router.get("/scan/{scan_id}/trace")
async def scan_trace(scan_id: str):
    """Live agentic engagement trace — polled while the scan runs."""
    job = scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(404, "Scan not found")
    return {
        "scan_id": scan_id,
        "status": job.get("status"),
        "progress": job.get("progress", ""),
        "steps": [s.model_dump() for s in job.get("trace", [])],
    }


@router.get("/scan/{scan_id}/report")
async def get_report(scan_id: str, format: str = "json"):
    job = scan_jobs.get(scan_id)
    if not job:
        # Fall back to Supabase: the backend may have restarted since.
        if supabase_db.configured():
            findings_rows = await supabase_db.get_findings(scan_id)
            if findings_rows:
                return {
                    "scan_id": scan_id,
                    "restored_from": "supabase",
                    "findings": findings_rows,
                }
        raise HTTPException(404, "Scan not found")
    if job.get("status") != "completed":
        raise HTTPException(400, f"Scan status: {job.get('status')}")

    report = job.get("report")
    if format == "markdown":
        return PlainTextResponse(job.get("markdown", ""), media_type="text/markdown")
    if format == "html":
        return PlainTextResponse(job.get("html", ""), media_type="text/html")
    return report


# ------------------------------------------------------------------------###
# Guardrails (informational only — enforcement is disabled)               ###
# ------------------------------------------------------------------------###

@router.get("/guardrails/allowed-targets")
async def get_allowed_targets():
    return {
        "allowed_targets": sorted(ALLOWED_TARGETS),
        "enforcement": "disabled",
        "note": "Guardrails are disabled for this deployment; all targets are accepted.",
    }


@router.get("/guardrails/confirmation-phrase")
async def get_confirmation_phrase():
    return {"confirmation_phrase": REQUIRED_CONFIRMATION, "enforced": False}


@router.get("/guardrails/disclaimers")
async def get_disclaimers():
    return {
        "banner": get_disclaimer_banner(),
        "full": get_disclaimer_full(),
        "short": get_disclaimer_short(),
        "report_footer": get_report_footer(),
    }


# ------------------------------------------------------------------------###
# Worker                                                                 ###
# ------------------------------------------------------------------------###

def _trace_sink(job: dict):
    """Returns a callback that appends new AgentSteps to the live job."""
    def sink(step: AgentStep) -> None:
        try:
            job["trace"].append(step)
        except Exception:
            pass
        # Cheap progress update the UI can pick up from the trace endpoint.
        job["progress"] = f"{step.phase.value} \\u00b7 {step.agent}: {step.action}"
    return sink


async def process_scan(scan_id: str, scan_target: str, display_target: str, scan_type: ScanType):
    job = scan_jobs[scan_id]
    try:
        job["status"] = "running"
        job["progress"] = "detecting engines"

        engines = detect_engines()
        await _persist(scan_id)

        if scan_type == ScanType.URL:
            # Agentic engagement (recon -> map -> attack -> verify) with live
            # trace, handing off to Decepticon when a runtime is configured.
            findings = await run_engagement(
                scan_target, scan_type, trace_sink=_trace_sink(job),
            )
            # The built-in header/cookie/CORS/exposed-path assessment still
            # runs for every URL target on top of the agents' probes.
            findings.extend(await assess_http_target(scan_target))
            # Real engine adapters for extra depth (nuclei/nmap/nikto/zap/
            # strix/redteam — only the installed ones actually run).
            external = await run_all_scanners(scan_target, scan_type, include_builtin=False)
            findings.extend(external)
        else:
            job["progress"] = "upload: engine adapters"
            findings = await run_all_scanners(scan_target, scan_type)

        job["progress"] = f"analyzing {len(findings)} finding(s)"

        # When nothing was found, still explain what ran and what was missing —
        # "0 findings" is only meaningful alongside engine availability.
        applicable = URL_ENGINES if scan_type == ScanType.URL else UPLOAD_ENGINES
        methodology = engines_used(findings) or []
        if not methodology:
            for engine in engines:
                if engine.name not in applicable:
                    state = "not applicable to this scan type"
                elif engine.available:
                    state = "ran, reported nothing"
                else:
                    state = "not installed on this host"
                methodology.append(f"{engine.label} ({engine.role.value}): {state}")

        started_at = datetime.fromisoformat(job["created_at"])
        completed_at = datetime.now()
        tools_run = [
            f"{e.label} {e.version}".strip()
            for e in engines
            if e.available and e.name in applicable
        ]

        report = await generate_report(
            scan_id,
            display_target,
            scan_type,
            findings,
            engines=engines,
            methodology=methodology,
            engagement={
                "target": display_target,
                "scan_type": scan_type,
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": (completed_at - started_at).total_seconds(),
                "tools_run": tools_run,
            },
        )

        # Attach the OPPLAN and the full step trace so the report is
        # self-contained when exported or read through the API.
        report.agent_plan = getattr(run_engagement, "last_plan", None)
        trace = job.get("trace", [])
        if not trace:
            trace = list(getattr(run_engagement, "last_trace", []) or [])
            job["trace"] = trace
        report.agent_trace = trace

        job["report"] = report
        job["markdown"] = build_markdown(report)
        job["html"] = build_html(report)
        job["status"] = "completed"
        job["progress"] = "completed"
        job["completed_at"] = datetime.now().isoformat()
        job["simulated"] = settings.SIMULATE_SCANNERS

        await _persist(scan_id)
        try:
            await supabase_db.insert_findings(scan_id, report)
        except Exception as exc:
            print(f"[persist] findings {scan_id}: {type(exc).__name__}: {exc}")

    except Exception as exc:  # noqa: BLE001 - surface the error in the job status
        job["status"] = "failed"
        job["progress"] = "failed"
        job["error"] = f"{type(exc).__name__}: {exc}"
        job["traceback"] = traceback.format_exc()[-2000:]
        print(f"[scan {scan_id}] failed: {job['error']}")
        await _persist(scan_id)


async def _run_engagement_worker(engagement_id: str, scan_id: str, target_url: str):
    """Background task that drives one engagement through the OPPLAN loop."""
    eng = engagements.get(engagement_id)
    job = scan_jobs.get(scan_id)

    try:
        eng["status"] = "running"
        job["status"] = "running"
        job["progress"] = "recon"

        engines = detect_engines()
        await _persist(scan_id)

        # Agentic engagement with a live trace sink, handing off to Decepticon
        # when DECEPTICON_RUNTIME_URL is configured (fail-open to this engine).
        findings = await run_engagement(
            target_url, ScanType.URL, trace_sink=_trace_sink(job),
        )
        # Built-in HTTP assessment on top of the agents' probes.
        findings.extend(await assess_http_target(target_url))
        # Real engine adapters for extra depth.
        external = await run_all_scanners(target_url, ScanType.URL, include_builtin=False)
        findings.extend(external)

        job["progress"] = f"analyzing {len(findings)} finding(s)"
        applicable = URL_ENGINES
        methodology = engines_used(findings) or []
        if not methodology:
            for engine in engines:
                if engine.name not in applicable:
                    state = "not applicable to this scan type"
                elif engine.available:
                    state = "ran, reported nothing"
                else:
                    state = "not installed on this host"
                methodology.append(f"{engine.label} ({engine.role.value}): {state}")

        started_at = datetime.fromisoformat(job["created_at"])
        completed_at = datetime.now()
        tools_run = [
            f"{e.label} {e.version}".strip()
            for e in engines
            if e.available and e.name in applicable
        ]

        report = await generate_report(
            scan_id,
            target_url,
            ScanType.URL,
            findings,
            engines=engines,
            methodology=methodology,
            engagement={
                "target": target_url,
                "scan_type": ScanType.URL.value,
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": (completed_at - started_at).total_seconds(),
                "tools_run": tools_run,
            },
        )
        report.agent_plan = getattr(run_engagement, "last_plan", None)
        trace = job.get("trace", [])
        if not trace:
            trace = list(getattr(run_engagement, "last_trace", []) or [])
            job["trace"] = trace
        report.agent_trace = trace

        job["report"] = report
        job["markdown"] = build_markdown(report)
        job["html"] = build_html(report)
        job["status"] = "completed"
        job["completed_at"] = datetime.now().isoformat()
        job["findings_count"] = len(report.findings)

        # Mark the engagement done too.
        eng["status"] = "completed"
        eng["completed_at"] = datetime.now().isoformat()
        eng["opplan_id"] = getattr(report, "agent_plan", {}).get("opplan_id")
        eng["tools_run"] = tools_run
        eng["findings_count"] = len(report.findings)

        await _persist(scan_id)
        try:
            await supabase_db.insert_findings(scan_id, report)
        except Exception as exc:
            print(f"[persist] findings {scan_id}: {type(exc).__name__}: {exc}")

    except Exception as exc:  # noqa: BLE001
        msg = f"{type(exc).__name__}: {exc}"
        eng["status"] = "failed"
        eng["error"] = msg
        eng["completed_at"] = datetime.now().isoformat()
        job["status"] = "failed"
        job["progress"] = "failed"
        job["error"] = msg
        job["traceback"] = traceback.format_exc()[-2000:]
        print(f"[engagement {engagement_id}] failed: {msg}")
        await _persist(scan_id)
