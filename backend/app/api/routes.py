from datetime import datetime
import traceback
import uuid

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse

from app.config import get_settings
from app.models.schemas import AgentStep, ScanRequest, ScanType, ScannerName
from app.services.scanner import assess_http_target, detect_engines, engines_used, run_all_scanners
from app.services.agent_engine import run_engagement
from app.services.llm_service import build_markdown, generate_report
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


# ---------------------------------------------------------------------------
# Engine status / history
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Scan entry points
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

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
    return report


# ---------------------------------------------------------------------------
# Guardrails (informational only — enforcement is disabled)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def _trace_sink(job: dict):
    """Returns a callback that appends new AgentSteps to the live job."""
    def sink(step: AgentStep) -> None:
        try:
            job["trace"].append(step)
        except Exception:
            pass
        # Cheap progress update the UI can pick up from the trace endpoint.
        job["progress"] = f"{step.phase.value} · {step.agent}: {step.action}"
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

        report = await generate_report(
            scan_id,
            display_target,
            scan_type,
            findings,
            engines=engines,
            methodology=methodology,
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
