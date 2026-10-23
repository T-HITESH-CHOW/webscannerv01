import { useEffect, useRef, useState } from 'react'
import { api, ENGAGEMENTS_API } from './api.js'

const SEVS = ['critical', 'high', 'medium', 'low', 'info']
const NAV = { backlog: 'Scan Backlog', new: 'New Engagement', projects: 'Projects', history: 'History' }
const KILL = [
  { key: 'recon', label: 'Recon' },
  { key: 'map', label: 'Map' },
  { key: 'attack', label: 'Attack' },
  { key: 'verify', label: 'Verify' },
  { key: 'report', label: 'Report' },
]

export default function App() {
  // nav
  const [activeNav, setActiveNav] = useState('new')
  function useNav(key) { setActiveNav(key) }

  // scan input
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  // engines
  const [engines, setEngines] = useState(null)

  // engagement
  const [eng, setEng] = useState(null)
  const [engStatus, setEngStatus] = useState(null)
  const [engTrace, setEngTrace] = useState([])
  const [engReport, setEngReport] = useState(null)
  const [pollEngRef, setPollEngRef] = useState(null)

  // backlog
  const [backlog, setBacklog] = useState([])
  const [backlogError, setBacklogError] = useState('')

  // history
  const [history, setHistory] = useState([])

  const fetchEngines = async () => {
    try { setEngines(await api.engines()) } catch { setEngines(null) }
  }
  useEffect(fetchEngines, [])

  const fetchBacklog = async () => {
    try {
      const list = await ENGAGEMENTS_API.list()
      setBacklog(list.engagements ?? [])
      setBacklogError('')
    } catch (e) {
      setBacklog([])
      setBacklogError(String(e.message || e))
    }
  }
  const fetchHistory = async () => {
    try { setHistory(await api.history()) } catch {}
  }
  useEffect(fetchBacklog, [])
  useEffect(fetchHistory, [])

  const startPoll = (setter) => {
    const id = setInterval(async () => {
      if (!eng) { clearInterval(id); return }
      try {
        const st = await ENGAGEMENTS_API.status(eng.id)
        setter(st)
        try {
          const t = await ENGAGEMENTS_API.trace(eng.id)
          setEngTrace(Array.isArray(t?.steps) ? t.steps : Array.isArray(t) ? t : [])
        } catch {}
        if (st.status === 'completed') {
          const r = await ENGAGEMENTS_API.report(eng.id)
          setEngReport(r)
          clearInterval(id)
        } else if (st.status === 'failed') {
          clearInterval(id)
        }
      } catch (_) { clearInterval(id) }
    }, 1500)
    return id
  }

  const startEngagement = async (targetUrl, keepOpen = false) => {
    setError('')
    setBusy(true)
    setEng(null)
    setEngStatus(null)
    setEngTrace([])
    setEngReport(null)
    if (pollEngRef) { clearInterval(pollEngRef); setPollEngRef(null) }
    try {
      const res = await ENGAGEMENTS_API.start(targetUrl)
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      setEng(data.engagement)
      setEngStatus({ status: data.engagement.status ?? 'queued' })
      const id = startPoll(setEngStatus)
      setPollEngRef(id)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const openEng = (e) => {
    if (pollEngRef) { clearInterval(pollEngRef); setPollEngRef(null) }
    setEng(e)
    setEngStatus(null)
    setEngTrace([])
    setEngReport(null)
    const id = startPoll(setEngStatus)
    setPollEngRef(id)
  }

  const runEng = async (e) => {
    try { await ENGAGEMENTS_API.run(e.id); fetchBacklog() } catch (_) {}
  }

  const pauseEng = async (e) => {
    try { await ENGAGEMENTS_API.setting(e.id, 'pause', 'true'); fetchBacklog() } catch (_) {}
  }

  const resumeEng = async (e) => {
    try { await ENGAGEMENTS_API.setting(e.id, 'pause', 'false'); fetchBacklog() } catch (_) {}
  }

  const deleteEng = async (e) => {
    try {
      await ENGAGEMENTS_API.delete(e.id)
      if (eng?.id === e.id) {
        if (pollEngRef) { clearInterval(pollEngRef); setPollEngRef(null) }
        setEng(null); setEngStatus(null); setEngTrace([]); setEngReport(null)
      }
      fetchBacklog()
    } catch (_) {}
  }

  const setScope = async (e, scopeList) => {
    try {
      await ENGAGEMENTS_API.setScope(e.id, scopeList)
      let t = await ENGAGEMENTS_API.scopedTargets(e.id)
      setEng(prev => prev ? { ...prev, scoped_targets: t.scoped_targets ?? [] } : prev)
      fetchBacklog()
    } catch (_) {}
  }

  const setSetting = async (e, key, value) => {
    try {
      await ENGAGEMENTS_API.setting(e.id, key, value)
      fetchBacklog()
    } catch (_) {}
  }

  const downloadMarkdown = async (eid) => {
    const md = await ENGAGEMENTS_API.reportMarkdown(eid)
    const blob = new Blob([md], { type: 'text/markdown' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `report-${eid}.md`
    a.click()
  }

  const downloadHtml = async (eid) => {
    const html = await ENGAGEMENTS_API.reportHtml(eid)
    const blob = new Blob([html], { type: 'text/html' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `report-${eid}.html`
    a.click()
  }

  const downloadJson = (report, eid) => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `report-${eid}.json`
    a.click()
  }

  const bars = engReport
    ? SEVS.map((s) => [s, engReport.findings_by_severity?.[s] || 0])
    : []
  const maxBar = Math.max(...bars.map(b => b[1]), 1)
  const riskLike = engReport?.risk_score != null ? engReport.risk_score : 0

  return (
    <div className="app">
      {/* ── Top bar ── */}
      <header className="topbar">
        <div className="logo">
          <div className="icon">D</div>
          <div>
            <span>Decepticon Scan</span>
            <span className="sub">/ agentic security review</span>
          </div>
        </div>
        <nav className="nav-links">
          <a className={activeNav === 'backlog' ? 'active' : ''} onClick={() => useNav('backlog')}>{NAV.backlog}</a>
          <a className={activeNav === 'new' ? 'active' : ''} onClick={() => useNav('new')}>{NAV.new}</a>
          <a className={activeNav === 'projects' ? 'active' : ''} onClick={() => useNav('projects')}>{NAV.projects}</a>
          <a className={activeNav === 'history' ? 'active' : ''} onClick={() => useNav('history')}>{NAV.history}</a>
        </nav>
      </header>

      <main className="main">
        {/* ── Disclaimer ── */}
        <div className="banner">
          <span className="warn">⚠️</span>
          <span><b>Learning / authorized testing only</b> — not a professional pentest tool. Every finding needs manual verification. Only scan systems you own or have explicit written permission to test.</span>
        </div>

        {/* ══════════════════════════════════════════════════════════ */}
        {/* SCAN INPUT — top of every page */}
        {/* ══════════════════════════════════════════════════════════ */}
        <div className="scanbox">
          <input
            type="text"
            placeholder="https://your-authorized-lab-target"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && url && !busy && handleStartUrl()}
          />
          <button className="btn" disabled={busy || !url.trim()} onClick={handleStartUrl}>
            {busy ? 'Starting…' : 'Run engagement'}
          </button>
          {error && <span className="muted small" style={{ marginLeft: 8 }}>{error}</span>}
        </div>

        {/* ══════════════════════════════════════════════════════════ */}
        {/* NAV: NEW ENGAGEMENT */}
        {/* ══════════════════════════════════════════════════════════ */}
        {activeNav === 'new' && (
          <>
            <div className="killchain">
              {KILL.map((k, i) => (
                <>
                  <div key={k.key + '-step'} className="kc-step">
                    <div className="kc-dot" id={`kc-${k.key}`}>{k.label[0]}</div>
                    <div className="kc-label">{k.label}</div>
                  </div>
                  {i < KILL.length - 1 && (
                    <div key={k.key + '-conn'} className="kc-connector" id={`kc-${k.key}-conn`} />
                  )}
                </>
              ))}
            </div>

            {eng ? (
              <div className="grid-2">
                {/* LEFT: live trace */}
                <div>
                  {/* status card */}
                  <div className="card">
                    <h3>Live engagement</h3>
                    <div className="engagement-meta">
                      <div className="k">ID</div>
                      <div className="v">{eng.id}</div>
                      <div className="k">Status</div>
                      <div className="v">
                        <span className={`status-badge ${engStatus?.status || ''}`}>
                          {engStatus?.status || '—'}
                        </span>
                      </div>
                      <div className="k">Target</div>
                      <div className="v">{eng.target_url || '—'}</div>
                      {eng.target_name && (
                        <>
                          <div className="k">Target name</div>
                          <div className="v">{eng.target_name}</div>
                        </>
                      )}
                      {eng.scope && (
                        <>
                          <div className="k">Scope</div>
                          <div className="v">{eng.scope}</div>
                        </>
                      )}
                      {eng.scoped_targets?.length ? (
                        <>
                          <div className="k">In scope</div>
                          <div className="v">{eng.scoped_targets.length} target(s)</div>
                        </>
                      ) : null}
                      {eng.opplan_id && (
                        <>
                          <div className="k">OPPLAN</div>
                          <div className="v">{eng.opplan_id}</div>
                        </>
                      )}
                    </div>
                  </div>

                  {/* agent trace */}
                  <div className="card">
                    <h3>Agent activity</h3>
                    {!engStatus?.status || engStatus?.status === 'queued' ? (
                      <div className="muted" style={{ padding: 8 }}>Queued — engines always run behind the scenes.</div>
                    ) : engStatus?.status === 'running' && engTrace.length === 0 ? (
                      <div className="muted" style={{ padding: 8 }}>Agents warming up…</div>
                    ) : (
                      <div className="trace-feed" style={{ maxHeight: 520 }}>
                        {engTrace.map((s, i) => {
                          const phase = (s.phase || '').toLowerCase()
                          const phaseClass = ['recon','map','attack','verify','report'].includes(phase) ? phase : ''
                          const verdict = (s.verdict || '').toLowerCase()
                          const verdictClass = ['confirmed','needs-review','gone','attempting','fallback'].includes(verdict) ? verdict : ''
                          const agent = s.agent && s.agent !== 'decepticon' ? s.agent : 'decepticon'
                          return (
                            <div className="trace-step" key={i}>
                              {phaseClass && <span className={`phase-badge ${phaseClass}`}>{phase}</span>}
                              <div className="agent-name">{agent}</div>
                              <div className="step-action"><b>{s.action}</b>{s.detail ? ` — ${s.detail}` : ''}</div>
                              {verdictClass && <span className={`verdict ${verdictClass}`}>{s.verdict}</span>}
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                </div>

                {/* RIGHT: report */}
                <div>
                  {engReport ? (
                    <>
                      {/* meta */}
                      <div className="card">
                        <h3>Engagement summary</h3>
                        <div className="engagement-meta" style={{ gridTemplateColumns: '1fr 1fr 1fr' }}>
                          <div className="k">Risk rating</div>
                          <div className="v"><span className={`sev-${engReport.risk_rating || 'info'}`}>{String(engReport.risk_rating || 'info').toUpperCase()}</span></div>
                          <div className="k">Risk score</div>
                          <div className="v">{engReport.risk_score ?? 0} / 100</div>
                          <div className="k">Total findings</div>
                          <div className="v">{engReport.total_findings}</div>
                          <div className="k">Duration</div>
                          <div className="v">{Math.round(engReport.engagement?.duration_seconds || 0)}s · {engReport.engagement?.tools_run?.length || 0} tool(s)</div>
                          <div className="k">OPPLAN</div>
                          <div className="v">{engReport.agent_plan?.opplan_id || '—'}</div>
                        </div>
                      </div>

                      {/* risk gauge + methodology */}
                      <div className="card">
                        <h3>Risk assessment</h3>
                        <div className="risk-gauge">
                          <div
                            className="gauge-ring"
                            style={{
                              background: `conic-gradient(var(--${riskColor(engReport.risk_rating || 'info')})
                                ${(riskLike / 100) * 360}deg,
                                var(--line) 0deg)`,
                            }}
                          >
                            <span style={{ fontSize: '18px', fontWeight: 800 }}>{riskLike}</span>
                          </div>
                          <div className="gauge-text">
                            <span className="big">{riskRatingLabel(riskLike)}</span>
                            <span className="small">
                              {engReport.risk_explanation ? engReport.risk_explanation : 'No findings — target looks clean.'}
                            </span>
                          </div>
                        </div>
                        <div style={{ marginTop: 12, borderTop: '1px solid var(--line)', paddingTop: 10 }}>
                          <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.1em', color: 'var(--muted)', marginBottom: 6, fontWeight: 600 }}>Methodology</div>
                          <ol className="methodology-list">
                            <li>Reconnaissance: live probe against the in-scope target (with any Decepticon runtime, if reachable)</li>
                            <li>Mapping: bounded same-origin crawl — pages, routes, forms, parameters</li>
                            <li>Attack: adaptive probes justified by recon, plus installed engines (nuclei, semgrep, trivy, nmap, nikto, ZAP) and built-in HTTP assessment</li>
                            <li>Verification: each candidate finding gets a second request → confirmed or needs manual review</li>
                            <li>Report: severity-sorted, de-duplicated, plain-English explanation/report/remediation, CWE + MITRE + CVSS + OWASP where available, HTML/PDF-ready and Markdown/JSON export</li>
                          </ol>
                        </div>
                        <div style={{ borderTop: '1px solid var(--line)', marginTop: 10, paddingTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          <button className="btn" onClick={() => downloadMarkdown(eng.id)}>Download .md</button>
                          <button className="btn" onClick={() => downloadHtml(eng.id)}>Download .html</button>
                          <button className="btn secondary" onClick={() => downloadJson(engReport, eng.id)}>Download .json</button>
                        </div>
                      </div>

                      {/* severity bars */}
                      <div className="card">
                        <h3>Findings by severity</h3>
                        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                          {SEVS.map(s => {
                            const n = engReport.findings_by_severity?.[s] || 0
                            return (
                              <div key={s} className="sevbar">
                                <span className={`sev-${s}`}>{s.toUpperCase()}</span>
                                <span className="bar"><i className={`dotbg-${s}`} style={{ width: `${(n / maxBar) * 100}%` }} /></span>
                                <span>{n}</span>
                              </div>
                            )
                          })}
                        </div>
                      </div>

                      {/* findings */}
                      <div className="card">
                        <h3>Findings (worst first)</h3>
                        {engReport.findings.length === 0 ? (
                          <div className="empty-state">
                            <div className="empty-icon">✓</div>
                            <h4>No findings</h4>
                            <p>No issues were found in the in-scope surface. Every finding below was either confirmed by a second request or flagged for manual review.</p>
                          </div>
                        ) : (
                          engReport.findings.map((f) => <Finding key={f.title + (f.location ?? '')} f={f} />)
                        )}
                      </div>
                    </>
                  ) : !engStatus?.status ? null : (
                    <div className="card">
                      <h3>Report</h3>
                      <div className="empty-state">
                        <div className="empty-icon">⏳</div>
                        <h4>{engStatus?.status === 'running' ? 'Engagement in progress' : 'No report yet'}</h4>
                        <p>The report appears here once the engagement completes. The agents are working through the kill chain right now.</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="card">
                <h3>New engagement</h3>
                <p className="muted">
                  Start a Decepticon-style engagement against an authorized target. The agents recon the target,
                  crawl same-origin only, run adaptive probes, re-verify findings, and produce a
                  severity-sorted English report. When the Decepticon runtime is reachable it takes over the
                  whole engagement; otherwise the native OPPLAN engine drives it.
                </p>
                <div style={{ marginTop: 12, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button className="btn" onClick={handleStartUrl} disabled={!url.trim() || busy}>
                    {busy ? 'Starting…' : 'Start against target above'}
                  </button>
                  <a href="https://github.com/BitterSecurity/Decepticon" target="_blank" rel="noopener noreferrer" className="btn secondary" style={{ textDecoration: 'none' }}>
                    BitterSecurity/Decepticon ↗
                  </a>
                </div>
              </div>
            )}

            {error && (
              <div className="card" style={{ borderColor: 'var(--critical)' }}>
                <h3>Error</h3>
                <div className="muted mono" style={{ fontSize: 12, whiteSpace: 'pre-wrap' }}>{error}</div>
              </div>
            )}
          </>
        )}

        {/* ══════════════════════════════════════════════════════════ */}
        {/* NAV: SCAN BACKLOG */}
        {/* ══════════════════════════════════════════════════════════ */}
        {activeNav === 'backlog' && (
          <>
            <div className="card">
              <h3>Engagement backlog</h3>
              {backlogError ? (
                <div className="muted mono" style={{ fontSize: 12 }}>{backlogError}</div>
              ) : backlog.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">📋</div>
                  <h4>No engagements</h4>
                  <p>Run an engagement from New Engagement to see it here.</p>
                </div>
              ) : (
                <div className="engagement-grid">
                  {backlog.map(e => (
                    <div className="engagement-card" key={e.id} onClick={() => openEng(e)}>
                      <div className="ec-header">
                        <span className="ec-id">{e.id}</span>
                        <span className={`status-badge ${e.status}`}>{e.status}</span>
                      </div>
                      <div className="ec-target">{e.target_url || e.target}</div>
                      <div className="ec-stats">
                        <div>Findings <span className="num">{e.findings?.length ?? '?'}</span></div>
                        <div>Tools <span className="num">{e.tools?.length ?? '?'}</span></div>
                        {e.completed_at && <div>Finished <span className="num">{new Date(e.completed_at).toLocaleString()}</span></div>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}

        {/* ══════════════════════════════════════════════════════════ */}
        {/* NAV: PROJECTS */}
        {/* ══════════════════════════════════════════════════════════ */}
        {activeNav === 'projects' && (
          <>
            <div className="grid-2">
              <div className="card">
                <h3>This project</h3>
                <div className="project-card" style={{ padding: 0, border: 'none', background: 'none', marginBottom: 8 }}>
                  <div className="pc-name" style={{ padding: '14px 16px' }}>webscannerv01</div>
                  <div className="pc-desc" style={{ padding: '0 16px 14px' }}>
                    Agentic security review tool — FastAPI backend + React (Vite) frontend.
                    Built for authorized learning/testing, powered by a Decepticon-style kill-chain engine.
                  </div>
                  <div className="pc-meta" style={{ padding: '0 16px 14px' }}>
                    <span>FastAPI · React</span>
                    <span>30 tests</span>
                  </div>
                </div>
                <div className="opplan-box">
                  <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.1em', color: 'var(--muted)', marginBottom: 6, fontWeight: 600 }}>OPPLAN — engagement runbook</div>
                  <div style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12 }}>
                    <div>OPPLAN-001 · target URL / upload</div>
                    <div>RECON → MAP → ATTACK → VERIFY → REPORT</div>
                    <div style={{ color: 'var(--muted)', marginTop: 4 }}>Every step is streamed to the agent activity feed and embedded in the report.</div>
                  </div>
                </div>
              </div>

              <div className="card">
                <h3>Integrations</h3>
                <div className="project-grid" style={{ marginTop: 8 }}>
                  <div className="project-card">
                    <div className="pc-name">Decepticon</div>
                    <div className="pc-desc">
                      If DECEPTICON_RUNTIME_URL is set, engagements are handed to the
                      BitterSecurity/Decepticon agent runtime (LangGraph Platform API).
                      Any failure falls back silently to this native engine, which always runs.
                    </div>
                    <div className="pc-meta" style={{ marginTop: 4 }}>
                      {eng?.opplan_id ? `active · ${eng.opplan_id}` : 'optional'}
                    </div>
                  </div>
                  <div className="project-card">
                    <div className="pc-name">Supabase</div>
                    <div className="pc-desc">Durable scan history and scoped-target persistence. Set SUPABASE_URL + SUPABASE_SERVICE_KEY.</div>
                    <div className="pc-meta" style={{ marginTop: 4 }}>
                      {engines?.supabase_configured ? 'configured ✓' : 'optional'}
                    </div>
                  </div>
                  <div className="project-card">
                    <div className="pc-name">Freebuff Sites</div>
                    <div className="pc-desc">Frontend hosted at https://webscannerv01.vercel.app with Sign in with Freebuff.</div>
                    <div className="pc-meta" style={{ marginTop: 4 }}>
                      deployed ✓
                    </div>
                  </div>
                  <div className="project-card">
                    <div className="pc-name">External engines</div>
                    <div className="pc-desc">
                      Semgrep (SAST), Nuclei (DAST), Trivy (SCA/IaC/secrets), plus built-in HTTP assessment.
                      Plus nmap, nikto, ZAP when installed.
                    </div>
                    <div className="pc-meta" style={{ marginTop: 4 }}>
                      {engines ? `${engines.engines.filter(e => e.available).length}/${engines.engines.length} ready` : 'checking…'}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {/* ══════════════════════════════════════════════════════════ */}
        {/* NAV: HISTORY */}
        {/* ══════════════════════════════════════════════════════════ */}
        {activeNav === 'history' && (
          <div className="card">
            <h3>Recent scans</h3>
            {history.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">📅</div>
                <h4>No history yet</h4>
                <p>Completed/queued scans show up here. History is stored in memory unless Supabase is configured.</p>
              </div>
            ) : (
              <div className="history">
                {history.slice(0, 25).map(h => (
                  <div className="history-item" key={h.scan_id} onClick={() => openEng({ id: h.scan_id, target_url: h.target, status: h.status, target: h.target, findings: h.findings ?? [], completed_at: h.completed_at, opplan_id: h.opplan_id, tools_run: h.tools_run ?? [] })}>
                    <span className="sid">{h.scan_id}</span>
                    <span className="target">{h.target}</span>
                    <span className={`status-badge ${h.status}`}>{h.status}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )

  // ── inline helpers ──
  function handleStartUrl() {
    const t = url.trim()
    if (!t) return
    setError('')
    startEngagement(t, true)
    setUrl('')
  }

  function riskColor(rating) {
    if (!rating) return 'low'
    const m = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' }
    return m[rating] || 'info'
  }

  function riskRatingLabel(score) {
    if (score >= 80) return 'Critical — act now'
    if (score >= 60) return 'High — fix soon'
    if (score >= 30) return 'Medium — schedule'
    if (score > 0) return 'Low — watch'
    return 'Clean'
  }
}

/* ── Finding component ── */
function Finding({ f }) {
  const [open, setOpen] = useState(f.severity === 'critical' || f.severity === 'high')
  return (
    <div className={`finding finding-left-${f.severity}`}>
      <div className="head" onClick={() => setOpen(!open)}>
        <span className={`sev sev-${f.severity}`}>{f.severity}</span>
        <span className="title">{f.title}</span>
        <div className="meta">
          <span>P{f.priority}</span>
          {f.cvss != null && <span>CVSS {f.cvss}</span>}
          {f.cwe && <span>{f.cwe}</span>}
          {f.mitre && <span>{f.mitre}</span>}
          {f.cve && <span>CVE {f.cve}</span>}
        </div>
      </div>
      {open && (
        <div className="body">
          <p><b>What is it:</b> {f.explanation}</p>
          <p><b>Impact:</b> {f.impact}</p>
          <p><b>Fix:</b> <span style={{ whiteSpace: 'pre-line' }}>{f.suggested_fix}</span></p>
          {f.evidence && <div className="evidence">{f.evidence}</div>}
          <div className="meta-line" style={{ marginTop: 6, borderTop: '1px solid var(--line)', paddingTop: 6 }}>
            {f.source_scanner && <span>source: {f.source_scanner}</span>}
            {f.owasp && <span>OWASP: {f.owasp}</span>}
            {f.confidence && <span>confidence: {f.confidence}{f.verified ? ' (verified)' : ''}</span>}
            {f.location && <span>location: {f.location}</span>}
          </div>
        </div>
      )}
    </div>
  )
}
