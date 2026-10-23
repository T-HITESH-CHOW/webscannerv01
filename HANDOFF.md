# Handoff — Security Review Tool v01 (CentralScan)

## What's built

### 1. Agentic Engagement Loop (Decepticon-style)
The tool now runs a structured OPPLAN loop instead of firing a fixed scanner list:
- **RECON** — banner, tech stack, robots.txt, sitemap
- **MAP** — same-origin crawl for pages, forms, parameters, hidden admin surfaces
- **ATTACK** — probes chosen by what recon found: unauthenticated admin panels, reflected parameters, SQL-error surfaces, plus real engine adapters (nuclei, semgrep, trivy)
- **VERIFY** — re-tests findings with a second request
- **REPORT** — severity-sorted English report with CVSS/CWE/MITRE ATT&CK metadata

Every executed step streams live in the UI, and the report embeds its OPPLAN ID + full trace.

### 2. Clean React UI (frontend/)
New dark themed React app replacing Streamlit:
- Live agent-activity feed with phase badges
- Engine availability chips
- Severity bars, worst-first findings with what/impact/fix + evidence
- Scan history
- Markdown (.md) and HTML report export
- Build passes (913ms), runs at `localhost:5173`

### 3. Supabase SQL persistence
`supabase_db.py` + `supabase_schema.sql` persist every scan/finding; history survives restarts. Works with graceful in-memory fallback until credentials are added.

### 4. Real engines integrated
- **Nuclei** (v3.11.1) — template-based DAST
- **Semgrep** (via pip, 1.182.1) — SAST
- **Trivy** (v0.76.1) — SCA/IaC/secret scanning
- Built-in HTTP assessment always runs (headers, cookies, CORS, exposed paths, secrets, HTTPS redirect)

### 5. Pentest-grade report generation
- Risk score 0-100 weighted by severity and confidence
- CWE and MITRE ATT&CK mapping per finding
- CVSS extraction when available
- HTML export: client-deliverable, print-ready report
- Markdown export for developer sharing

## Vercel deployment

### Prerequisites
1. Connect your Vercel account via the Freebuff integration
2. Create a new Vercel project, root directory: `frontend`
3. Set the environment variable `VITE_API_BASE` to your backend's public URL
4. If backend is on localhost, tunnel it: `cloudflared tunnel --url localhost:8001` then set `VITE_API_BASE` to the tunnel URL

### Environment variables to set in Vercel
| Variable | Value | Notes |
|---|---|---|
| `VITE_API_BASE` | `https://your-backend-url.com` or tunnel URL | Required for production API calls |
| `SIMULATE_SCANNERS` | leave unset (or `false`) | Run real engines in prod |
| `LLM_API_KEY` | your Anthropic/OpenAI key | Optional for AI enrichment |
| `SUPABASE_URL` / `SUPABASE_SERVICE_KEY` | your Supabase project | Optional for durable history |

### Deployment steps
1. In Vercel dashboard → Settings → Environment Variables, add `VITE_API_BASE`
2. Click **Deploy**
3. After first deploy, verify the live site renders and the engagement loop works
4. Set `VITE_API_BASE` to your tunnel URL if backend isn't publicly reachable

### Known limitation
The deployed Vercel UI can only talk to a backend that's on the internet. Run your backend behind a tunnel (e.g. `cloudflared tunnel --url localhost:8001`) and set `VITE_API_BASE` to the tunnel URL.

## Supabase setup (optional, for durable scan history)

```bash
# 1. Create the schema in your Supabase project
psql "postgresql://postgres.YOUR-PROJECT.refsupabase.co:5432/postgres" -f supabase_schema.sql

# 2. Add credentials to your .env
# SUPABASE_URL=postgresql://postgres.YOUR-PROJECT.refsupabase.co:5432/postgres
# SUPABASE_SERVICE_KEY=your-service-role-key

# 3. The tool will automatically persist scans and findings across restarts
```

## Running locally

```bash
# Backend
cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8001

# Frontend
cd frontend && npm install && npm run dev -- --port 5173

# Then open http://localhost:5173
# Set your target URL and run the engagement
```

## Real engine installation notes

The three real engines are already detected on this machine:
- **Nuclei** (v3.11.1) — template-based DAST, template pack auto-updated
- **Semgrep** (via pip, 1.182.1) — SAST, installed in site-packages
- **Trivy** (v0.76.1) — SCA/IaC/secret scanning, standalone binary in tools/bin/

All three were verified to produce real findings against the `data/vulnerable_app` sample.

## Two things you need to do

1. **Vercel**: Set `VITE_API_BASE` in your Vercel dashboard environment variables to your backend's public URL (or a cloudflared tunnel URL if running locally)
2. **Supabase** (optional): Run `supabase_schema.sql` in your SQL editor, set `SUPABASE_URL` + `SUPABASE_SERVICE_KEY` in `.env` for durable scan history across restarts

## Report quality

Each finding in the HTML/Markdown report includes:
- **Severity** (critical/high/medium/low/info) with color coding
- **CWE identifier** (e.g., CWE-89 for SQL injection)
- **MITRE ATT&CK technique** (e.g., T1190 Exploit Public-Facing Application)
- **CVSS score** when available from engine output
- **OWASP Top 10** reference
- **Confidence level** (high if re-verified, medium if from single engine, low if inferred)
- **Priority** (1 = fix first, derived from severity)
- **Evidence** (code snippet, request/response, or scanner output excerpt)
- **Suggested fix** (plain-English remediation steps)

## Engagement metadata in every report

- **OPPLAN ID** — unique identifier for this engagement run
- **Test type** — "External grey-box automated assessment (web application)"
- **Started/Completed timestamps**
- **Duration** in seconds
- **Authorization note** and scope
- **Tools executed** list (which engines actually ran)
- **Risk rating** (informational/critical/high/etc.)
- **Risk score** 0-100 (weighted by severity and confidence)