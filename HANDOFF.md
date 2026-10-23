# HANDOFF / RESUME NOTES — AI Security Review Tool (v1)

> Last updated: 2026-10-22 (after the scanner + report rewrite landed).
> The core is now **real and verified**, not mock. Read "WHERE THINGS STAND" first.

## TL;DR

The mock scanner is gone. The tool now runs a **real built-in HTTP assessment**
(always), plus any of nuclei / nmap / nikto / ZAP / semgrep / trivy / strix /
ai-red-teaming that happen to be installed, normalizes every output into one
schema, and produces a **severity-ordered English report** (critical → info) with
plain-English explanation, impact and remediation per finding.

Verified end-to-end on this machine: scan of the bundled weak local target
`http://127.0.0.1:8899` → 10 findings, risk **critical**, correctly ordered,
rendered in the Streamlit UI with counts, summary, grouped findings and exports.

## WHERE THINGS STAND

### Done and verified

| Area | File | State |
|---|---|---|
| Engine registry + adapters + HTTP assessment + simulation fallback | `backend/app/services/scanner.py` | rewritten |
| Report: sorting, dedupe, knowledge base, summary, markdown, LLM upgrade | `backend/app/services/llm_service.py` | rewritten |
| Endpoints: `/engines`, fixed guardrail imports, archive extraction, job progress | `backend/app/api/routes.py` | rewritten |
| UI: engine status, severity bars, grouped findings, downloads | `frontend/streamlit_app.py` | rewritten |
| Settings: `REDTEAM_DIR`, `SCANNER_TIMEOUT`, `FAST_SCANNER_TIMEOUT`, `HTTP_PROBE_TIMEOUT` | `backend/app/config.py` | rewritten |
| Severity ordering, engine enums, extended report fields | `backend/app/models/schemas.py` | done earlier |
| nuclei / nikto / nmap parsers | `backend/app/services/normalizer.py` | done earlier |
| 30 tests (normalizer, scanner, ordering, dedupe, report, HTTP assessment) | `tests/` | green |
| Weak local verification target | `data/lab_target.py` | new |
| Docs | `README.md` | updated |

`pytest tests -q` → **30 passed**. `python -m pytest` works from the repo root
(`pythonpath = ["backend"]` is set in `pyproject.toml`).

### How it was verified

1. `python data/lab_target.py` (port 8899) — a server with no security headers, an
   exposed `.git/HEAD` and `.env`, an unflag'd cookie and a version banner.
2. `PYTHONPATH=backend python -m uvicorn app.main:app --port 8001`.
3. `POST /api/v1/scan/url {"target_url": "http://127.0.0.1:8899"}` → completed in ~3s.
4. Report: 2 critical, 0 high, 3 medium, 4 low, 1 info; risk `critical`; findings
   ordered exactly critical → high → medium → low → info.
5. Upload path: zip of a deliberately bad `app.py` → archive extracted, no SAST/SCA
   engine installed → 0 findings with an honest methodology list explaining that
   semgrep/trivy are missing (not a fake "clean").
6. Streamlit UI driven through the browser: scan started, report rendered, one
   finding expander opened (evidence + explanation + impact + ordered fix list +
   references all present), download buttons produced the .md/.json artifacts.

## Environment facts (this machine)

- Windows, Python **3.14.6**, no venv in the repo (system site-packages).
- Installed: fastapi 0.141.1, pydantic 2.12.5, httpx 0.28.1, pytest 9.1.0,
  pytest-asyncio 1.4.0, streamlit 1.66.1, node 24.19.
- **pandas is broken here**: `ImportError: DLL load failed while importing
  np_datetime: An Application Control policy has blocked this file.`
  → the frontend must not import pandas (severity bars and the engine table are
  plain HTML/markdown for this reason). Do not reintroduce `st.dataframe`,
  `st.bar_chart` or `st.table` without checking pandas first.
- No scanner binaries: nuclei / nmap / nikto / zap-cli / semgrep / trivy absent.
  No docker, no go, no java → strix and Argus cannot run locally.
- Ports used: 8001 (backend), 8501 (UI), 8899 (lab target). All were free before use.

## DECISIONS ALREADY MADE WITH THE USER (do not re-litigate)

1. **Scanner stack:** user chose "everything" → nuclei + nmap + nikto + ZAP +
   semgrep + trivy + built-in HTTP + strix + ai-red-teaming.
2. **Authorization gate:** user chose "fully open". `enforce_guardrails` stays out;
   `is_target_allowed()` / `validate_confirmation_phrase()` remain permissive. Keep
   the disclaimer strings and the UI "I have permission" checkbox.
3. **Report engine:** deterministic English report always; LLM enrichment only when
   `LLM_API_KEY` is set, and it never invents CVEs/evidence.
4. **Reference repos:** Argus = AI SOC layer, `votal-ai-hq/ai-red-teaming` = LLM
   red-team engine, `usestrix/strix` = AI pentest, `T-HITESH-CHOW/security-tool`
   = **404, unreachable** (private/renamed) — still needs the user.

## NEXT STEPS (in order, for tomorrow)

1. **Install the cheap wins so the tool stops being header-only:**
   `pip install semgrep` and download Trivy — that turns the upload/SAST path from
   "0 findings, engine missing" into real source and dependency findings. Both are
   pure-PATH installs, no Docker.
2. **Nuclei** (single .exe release zip, no Go needed) for real DAST templates.
3. **Persistence**: replace the `scan_jobs` dict in `routes.py` with SQL
   (user asked for Supabase earlier, or SQLite for local). Tables:
   `scans(scan_id PK, target, status, scan_type, created_at, completed_at, risk_rating, summary)`
   and `findings(id, scan_id FK, severity, title, location, cve, cvss, priority, explanation, impact, suggested_fix, references JSONB)`.
   Keep the in-memory dict as a fallback so nothing breaks without a DB.
4. **Deploy the frontend**: user wanted Vercel. Streamlit cannot run there — the
   realistic options are (a) Streamlit Community Cloud for the UI + host the FastAPI
   backend elsewhere, or (b) rebuild the UI as a small React app calling the API.
   Decide with the user before building.
5. **AI SOC integration (Argus)**: it is a Django + Next.js + PostgreSQL platform —
   needs Docker, which this machine does not have. Realistic first slice: add a
   webhook/`POST /alerts` bridge that pushes completed reports to Argus, instead of
   vendoring the whole platform.
6. **Strix / ai-red-teaming**: both need Docker/Node + LLM keys. The adapters exist
   and are availability-gated; wiring them for real needs a machine with Docker.
   `ai-red-teaming` also needs `REDTEAM_DIR` to point at a checkout.
7. **Polish**: per-path impact text for `/.env` vs `/.git/HEAD` (currently one
   shared "exposed sensitive file" paragraph); optional PDF export.

## Known gaps / caveats

- `ScannerName.HTTP` findings are all produced by one engine, so methodology lists
  one entry until another engine is installed.
- `assess_http_target(..., client=...)` exists so tests can inject an httpx
  `MockTransport`; keep that parameter when refactoring.
- The lab target (`data/lab_target.py`) is deliberately insecure — never expose it.
- `frontend` polls `/status` every 2s inside the script run; fine for one user,
  would need st.fragment/auto-refresh for heavier use.
- Reports are in memory: restarting uvicorn loses scan history.

## Commands

```bash
# backend
PYTHONPATH=backend python -m uvicorn app.main:app --port 8001
# frontend
python -m streamlit run frontend/streamlit_app.py --server.port 8501
# deliberately weak local target for verification
python data/lab_target.py
# tests
pytest tests -q
```
