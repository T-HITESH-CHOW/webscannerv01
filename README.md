# 🛡️ CentralScan — Agentic Security Review Tool

AI-assisted security review tool: **learning / authorized testing only**.
FastAPI backend + React (Vite) frontend. NOT a professional pentest tool; findings
require manual verification. Only scan systems you own or have permission to test.

## What it does

An engagement runs as a **Decepticon-style agentic loop**, not a fixed scanner list:

| Phase | Agent | What happens |
|---|---|---|
| RECON | recon-agent | banner, tech, response time, robots.txt, sitemap.xml |
| MAP | map-agent | bounded same-origin crawl → pages, forms, query params, admin surface |
| ATTACK | attack-agent + engine adapters | adaptive probes justified by recon (open admin panels, reflected params, SQL-error surfaces) + real engines when installed (nuclei, nmap, nikto, ZAP, semgrep, trivy, strix, ai-red-teaming) + built-in HTTP assessment |
| VERIFY | verify-agent | candidate findings get a second request → confirmed / needs manual review |
| REPORT | report-agent | severity-sorted (critical→info), de-duplicated, P1–P5 priorities, plain-English explanation/impact/fix, executive summary, Markdown/JSON export |

Every executed step is streamed live to the UI as an agent-activity trace, and
the full trace (with the OPPLAN ID) is embedded in the report.

**Decepticon integration:** set `DECEPTICON_RUNTIME_URL` in `.env` and engagements
are handed to the [BitterSecurity/Decepticon](https://github.com/BitterSecurity/Decepticon)
agent runtime (LangGraph Platform API). Any failure falls back silently to this
native engine, which always runs.

## Quickstart

```bash
# 1. Backend (port 8001)
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001     # from backend/

# 2. Frontend (port 5173, proxies /api to the backend)
cd frontend && npm install && npm run dev

# 3. (Optional) a deliberately weak local target to scan
python data/lab_target.py   # -> http://127.0.0.1:8899
```

Tests: `python -m pytest tests -q`

## Supabase history (optional)

1. Run [supabase_schema.sql](supabase_schema.sql) in the Supabase SQL editor.
2. In `.env` set `SUPABASE_URL` and `SUPABASE_SERVICE_KEY`.
Scans and findings are then persisted durably; `GET /api/v1/scans` shows history
and it survives backend restarts. Without it, an in-memory store is used.

## Deploy the frontend to Vercel

1. Push this repo to GitHub.
2. In Vercel, import the repo with **Root Directory = `frontend`** (Vite is auto-detected).
3. Set `VITE_API_BASE` to your backend's public URL (Project → Settings → Environment Variables).

Note: the backend must be reachable from the internet for the deployed UI to
scan — run it locally behind a tunnel, or deploy it to a host of your choice.
CORS is open for learning use.

## Houses engines that install in one line

| Engine | Install | Adds |
|---|---|---|
| semgrep | `pip install semgrep` | SAST on uploads |
| trivy | see trivy.dev | SCA / IaC / secrets |
| nuclei | go install | template DAST |
| nmap / nikto / ZAP | OS packages | recon / DAST |
| strix / decepticon / ai-red-teaming | see their repos | AI pentest agents |

## API

- `POST /api/v1/scan/url` — start an engagement
- `GET /api/v1/scan/{id}/status` / `.../trace` / `.../report` (+ `?format=markdown`)
- `GET /api/v1/scans` — history (Supabase when configured)
- `GET /api/v1/engines` — engine availability
- Swagger: `/docs`

Disclaimer auto-generated per project; guardrails are intentionally disabled by
the owner for lab use.
