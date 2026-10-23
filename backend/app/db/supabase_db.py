"""
Supabase persistence (PostgREST) for scan history — zero new dependencies.

`scan_jobs` in routes.py stays the runtime cache so scans work even before
Supabase is configured. When SUPABASE_URL + SUPABASE_SERVICE_KEY are set,

  * every scan create/update/complete/fail is upserted into the `scans` table,
  * findings are inserted into `findings` when the report completes,
  * GET /scans reads history from Supabase instead of memory,

so history survives backend restarts and is visible to the deployed frontend.
Set your project's URL and service-role key in .env (see .env.example) and run
supabase_schema.sql in the Supabase SQL editor once.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from app.config import get_settings

settings = get_settings()


def configured() -> bool:
    return bool(settings.SUPABASE_URL and settings.SUPABASE_SERVICE_KEY)


def _client():
    """httpx client with PostgREST auth headers. Caller closes it."""
    import httpx

    return httpx.AsyncClient(
        base_url=f"{settings.SUPABASE_URL.rstrip('/')}/rest/v1",
        headers={
            "apikey": settings.SUPABASE_SERVICE_KEY,
            "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        },
        timeout=15,
    )


async def _request(client, method: str, path: str, **kwargs) -> tuple[int, Any]:
    resp = await client.request(method, path, **kwargs)
    if resp.status_code >= 400:
        # Never crash a scan because the database is down: log and continue.
        print(f"[supabase] {method} {path} -> {resp.status_code}: {resp.text[:300]}")
        return resp.status_code, None
    try:
        return resp.status_code, resp.json() if resp.text else None
    except json.JSONDecodeError:
        return resp.status_code, None


# ---------------------------------------------------------------------------
# Scans table
# ---------------------------------------------------------------------------

def _scan_row(scan_id: str, job: dict) -> dict:
    return {
        "scan_id": scan_id,
        "target": job.get("target", ""),
        "scan_type": job.get("scan_type", "url"),
        "status": job.get("status", "queued"),
        "progress": job.get("progress", ""),
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
        "error": job.get("error"),
        "simulated": bool(job.get("simulated", False)),
    }


async def upsert_scan(scan_id: str, job: dict) -> None:
    if not configured():
        return
    try:
        async with _client() as client:
            await _request(client, "POST", "/scans",
                           json=_scan_row(scan_id, job),
                           # upsert on scan_id primary key
                           headers={"Prefer": "resolution=merge-duplicates,return=minimal"})
    except Exception as exc:
        print(f"[supabase] upsert_scan failed: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------

def _finding_rows(scan_id: str, report) -> list[dict]:
    rows = []
    for f in report.findings:
        rows.append({
            "scan_id": scan_id,
            "severity": f.severity.value,
            "priority": f.priority,
            "title": f.title,
            "explanation": f.explanation,
            "impact": f.impact,
            "suggested_fix": f.suggested_fix,
            "location": f.location,
            "evidence": f.evidence,
            "source_scanner": f.source_scanner.value if f.source_scanner else None,
            "cve": f.cve,
            "cvss": f.cvss,
            "owasp": f.owasp,
            "references_": f.references,
        })
    return rows


async def insert_findings(scan_id: str, report) -> None:
    if not configured() or not report.findings:
        return
    rows = _finding_rows(scan_id, report)
    try:
        async with _client() as client:
            # Delete old rows for idempotent re-runs, then insert.
            await _request(client, "DELETE", "/findings", params={"scan_id": f"eq.{scan_id}"})
            chunk = 100
            for i in range(0, len(rows), chunk):
                await _request(client, "POST", "/findings", json=rows[i:i + chunk])
    except Exception as exc:
        print(f"[supabase] insert_findings failed: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# History reads
# ---------------------------------------------------------------------------

async def list_scans(limit: int = 25) -> list[dict]:
    """Recent scans, newest first. Empty list when Supabase is unconfigured."""
    if not configured():
        return []
    try:
        async with _client() as client:
            code, rows = await _request(
                client, "GET", "/scans",
                params={"select": "scan_id,target,scan_type,status,created_at,completed_at,simulated",
                        "order": "created_at.desc", "limit": str(limit)},
            )
            return rows or []
    except Exception as exc:
        print(f"[supabase] list_scans failed: {type(exc).__name__}: {exc}")
        return []


async def get_findings(scan_id: str) -> list[dict]:
    if not configured():
        return []
    try:
        async with _client() as client:
            code, rows = await _request(
                client, "GET", "/findings",
                params={"select": "*", "scan_id": f"eq.{scan_id}",
                        "order": "priority.asc"},
            )
            return rows or []
    except Exception as exc:
        print(f"[supabase] get_findings failed: {type(exc).__name__}: {exc}")
        return []
