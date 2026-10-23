# CentralScan v1 — Handoff (updated Oct 23, 2026)

GitHub: https://github.com/T-HITESH-CHOW/webscannerv01 (pushed, branch `main`, clean merge over the placeholder initial commit).

## What works right now (verified end-to-end)

- Backend on `127.0.0.1:8001` (PID 18740, log `logs/backend.log`)
- React frontend on `localhost:5173` (PID 17132, log `logs/frontend.log`, Vite proxies /api -> 8001)
- Weak lab target on `127.0.0.1:8899` (PID 16880, `data/lab_target.py`)
- 30/30 tests pass (`python -m pytest tests -q`)
- Verified engagement on the lab target: 13 findings (2 crit / 3 high / 3 med / 4 low / 1 info), OPPLAN id embedded, 9-step live agent trace, screenshots equivalent verified through the real UI.

## Architecture (what changed this session)

1. **Agentic engine** — `backend/app/services/agent_engine.py`
   - Phases RECON → MAP → ATTACK → VERIFY → REPORT with one AgentStep each,
     adaptive probes justified by recon (unauth admin panels, reflected params canary
     `secreview`, SQL-error markers, .env re-confirmation).
   - Same-origin only; robots.txt Disallow entries seed the map.
   - `run_engagement(target, scan_type, trace_sink=...)` — trace_sink appends
     steps live to the job dict; `run_engagement.last_plan/.last_trace` hold
     the OPPLAN + steps; routes attach them to the report.
   - Decepticon handoff: `maybe_run_decepticon()` when `DECEPTICON_RUNTIME_URL`
     is set (LangGraph Platform API: POST /threads → /threads/{id}/runs/wait,
     assistant_id "red_agent"). Fails silently to native engine.
2. **Supabase persistence** — `backend/app/db/supabase_db.py` + `supabase_schema.sql`
   - Tables: `scans`, `findings` (column `references_` — "references" is reserved SQL).
   - Env: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`. Without them, memory fallback.
   - `upsert_scan` on every state change, `insert_findings` on completion,
     `list_scans` powers GET /api/v1/scans, `get_findings` for report restore after restart.
   - NOT tested with real credentials yet (none provided).
3. **React frontend** — `frontend/` (Vite + React 18)
   - `src/App.jsx` (scan form, live trace feed, engine chips, severity bars,
     findings with explain/impact/fix, history, md/json export),
     `src/api.js` (VITE_API_BASE for prod, /proxy in dev).
   - `vercel.json` SPA rewrite. Old Streamlit kept at `frontend/streamlit_app.py`.
   - One bug fixed during e2e: trace poller now accepts `{steps: [...]}`.
4. **routes.py** — URL scans run the engagement + built-in assessment + external
   adapters (`run_all_scanners(..., include_builtin=False)`); upload scans unchanged.
5. **lab target** upgraded: /admin /dashboard open, /login form, /search?q= reflects,
   SQL error marker, robots.txt pointing at /admin/ and /backup.zip.

## Remaining

- **Vercel deploy** — user must import the repo in Vercel (root dir `frontend`,
  auto-detects Vite) and set `VITE_API_BASE` to the backend's public URL.
  Backend must be internet-reachable (tunnel or hosting) for the deployed UI.
- **Supabase** — needs real creds in `.env` + run `supabase_schema.sql`.
- Restart note: uvicorn running stale code caused a confusing NameError; kill the
  listener (netstat -ano | findstr :8001 → taskkill //F //PID <pid>) before re-testing.
- SQLi reflection probe only fires when query params are actually observed (0 on lab home) —
  works when the target exposes `?param=` URLs.
- Engine installs still pending: semgrep, trivy, nuclei, etc.
