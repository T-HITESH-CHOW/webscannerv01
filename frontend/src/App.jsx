import { useEffect, useRef, useState } from 'react'
import { api } from './api.js'

export const SEVS = ['critical', 'high', 'medium', 'low', 'info']

export default function App() {
  const [url, setUrl] = useState('')
  const [scanId, setScanId] = useState(() => localStorage.getItem('lastScanId') || null)
  const [trace, setTrace] = useState([])
  const [status, setStatus] = useState(null)
  const [report, setReport] = useState(null)
  const [engines, setEngines] = useState(null)
  const [history, setHistory] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [showTrace, setShowTrace] = useState(true)
  const pollRef = useRef(null)

  const refreshStatic = async () => {
    try {
      setEngines(await api.engines())
    } catch { /* backend down */ }
    try {
      setHistory((await api.history()).scans)
    } catch { /* backend down */ }
  }

  useEffect(() => { refreshStatic() }, [])

  const poll = async () => {
    if (!scanId) return
    try {
      const st = await api.status(scanId)
      setStatus(st)
      try {
        const t = await api.trace(scanId)
        setTrace(Array.isArray(t?.steps) ? t.steps : Array.isArray(t) ? t : [])
      } catch { /* ignore */ }
      if (st.status === 'completed') {
        setReport(await api.report(scanId))
        stopPolling()
        refreshStatic()
      } else if (st.status === 'failed') {
        stopPolling()
      }
    } catch (e) { stopPolling(); setError(String(e.message || e)) }
  }

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
  }

  useEffect(() => {
    if (scanId) poll()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId])

  const startScan = async () => {
    setError('')
    setBusy(true)
    setReport(null)
    setTrace([])
    try {
      const res = await api.startUrlScan(url.trim())
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      localStorage.setItem('lastScanId', data.scan_id)
      setScanId(data.scan_id)
      setStatus({ status: 'queued' })
      stopPolling()
      pollRef.current = setInterval(poll, 1500)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  const openScan = async (sid) => {
    stopPolling()
    setReport(null)
    setTrace([])
    setScanId(sid)
    pollRef.current = setInterval(poll, 1500)
  }

  const bars = report
    ? SEVS.map((s) => [s, report.findings_by_severity?.[s] || 0])
    : []
  const maxBar = Math.max(...bars.map(b => b[1]), 1)

  return (
    <div className="app">
      <div className="disclaimer">
        ⚠️ Learning / authorized testing only — not a professional pentest tool.
        Only scan apps you own or have explicit written permission to test.
      </div>

      <header className="hero">
        <h1>🛡️ CentralScan <span className="muted">— agentic security review</span></h1>
        <p>Decepticon-style engagement: recon → map → attack → verify → report.</p>
      </header>

      <div className="scanbox">
        <div className="scanrow">
          <input
            type="text"
            placeholder="https://your-lab-target (authorized only)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && url && !busy && startScan()}
          />
          <button className="btn" disabled={busy || !url.trim()} onClick={startScan}>
            {busy ? 'Starting…' : 'Run engagement'}
          </button>
        </div>
        {error && <p className="sev-high" style={{ marginBottom: 0 }}>Error: {error}</p>}
      </div>

      <div className="grid">
        <div>
          {/* Status */}
          <div className="card">
            <h3>Status</h3>
            {status ? (
              <>
                <div className="kv"><span>Scan</span><span className="mono">{scanId}</span></div>
                <div className="kv"><span>State</span><span className="mono">{status.status}</span></div>
                <div className="kv"><span>Now</span><span className="mono" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{status.progress || '—'}</span></div>
                <div className="kv"><span>Target</span><span className="mono" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{status.target || '—'}</span></div>
              </>
            ) : <span className="muted">Ready. No engagement running.</span>}
          </div>

          {/* Agent trace */}
          {scanId && (
            <div className="card">
              <h3 style={{ display: 'flex', justifyContent: 'space-between', cursor: 'pointer' }}
                  onClick={() => setShowTrace(!showTrace)}>
                <span>Agent activity</span><span>{showTrace ? '▾' : '▸'}</span>
              </h3>
              {showTrace && (
                <div className="trace-feed">
                  {trace.length === 0 && <span className="muted">Waiting for agents…</span>}
                  {trace.map((s, i) => (
                    <div className="trace-step" key={i}>
                      <span className={`phase ${s.phase}`}>{s.phase}</span>
                      <span className="agent">{s.agent}</span>
                      <span><b>{s.action}</b>{s.detail ? ` — ${s.detail}` : ''}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Engines */}
          <div className="card">
            <h3>Engines</h3>
            {!engines && <span className="muted">Backend offline.</span>}
            {engines && (
              <div className="engine-grid">
                {engines.engines.map((e) => (
                  <div className="engine" key={e.name} title={e.detail}>
                    <span className={`dot ${e.available ? 'ok' : 'off'}`} />
                    <span>{e.label}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* History */}
          {history.length > 0 && (
            <div className="card">
              <h3>Recent scans (Supabase{engines && engines.supabase_configured ? ' ✓' : ' unconfigured — memory only'})</h3>
              {history.slice(0, 10).map((h) => (
                <div className="history-item" key={h.scan_id}>
                  <span className="sid" onClick={() => openScan(h.scan_id)}>{h.scan_id}</span>
                  <span className="mono muted" style={{ fontSize: 11 }}>{h.target}</span>
                  <span className="status">{h.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div>
          {/* Report */}
          {report ? (
            <>
              <div className="card">
                <h3>Executive summary</h3>
                <div className="summary-box"><p style={{ marginTop: 0 }}>{report.summary}</p></div>
                <div className="kv"><span>Risk rating</span><span className={`sev-${report.risk_rating}`}>{String(report.risk_rating).toUpperCase()}</span></div>
                <div className="kv"><span>Total findings</span><span>{report.total_findings}</span></div>
                <div className="kv"><span>OPPLAN</span><span className="mono">{report.agent_plan?.opplan_id || '—'}</span></div>
                <div className="spacer" />
                <div className="severity-bars">
                  {bars.map(([s, n]) => (
                    <div className="sevbar" key={s}>
                      <span className={`sev-${s}`}>{s.toUpperCase()}</span>
                      <span className="bar"><i className={`dotbg-${s}`} style={{ width: `${(n / maxBar) * 100}%` }} /></span>
                      <span>{n}</span>
                    </div>
                  ))}
                </div>
                <div className="spacer" />
                <div className="actions-row">
                  <button className="btn secondary" onClick={async () => {
                    const md = await api.reportMarkdown(scanId)
                    const blob = new Blob([md], { type: 'text/markdown' })
                    const a = document.createElement('a')
                    a.href = URL.createObjectURL(blob)
                    a.download = `report-${scanId}.md`
                    a.click()
                  }}>Download .md</button>
                  <button className="btn secondary" onClick={() => downloadJson(report, scanId)}>Download .json</button>
                </div>
              </div>

              <div className="card">
                <h3>Findings (worst first)</h3>
                {report.findings.map((f) => <Finding key={f.title + f.location} f={f} />)}
              </div>
            </>
          ) : (
            <div className="card">
              <h3>{scanId ? 'Report' : 'Get started'}</h3>
              {!scanId && (
                <p className="muted">
                  Enter an authorized target URL above and run the engagement. The agents recon the
                  target, crawl same-origin only, run adaptive probes, re-verify findings, and produce
                  a severity-sorted English report.
                </p>
              )}
              {scanId && !report && status?.status !== 'failed' && (
                <p className="muted">Engagement running — the agent activity feed shows progress live.</p>
              )}
            </div>
          )}

          {status?.status === 'failed' && (
            <div className="card">
              <h3>Engagement failed</h3>
              <div className="summary-box sev-high mono" style={{ fontSize: 12, whiteSpace: 'pre-wrap' }}>{status.error}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function downloadJson(report, scanId) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `report-${scanId || report.scan_id}.json`
  a.click()
}

function Finding({ f }) {
  const [open, setOpen] = useState(f.severity === 'critical' || f.severity === 'high')
  return (
    <div className={`finding finding-left-${f.severity}`}>
      <div className="head" onClick={() => setOpen(!open)}>
        <span className={`sev dotbg-${f.severity}`} style={{ color: '#0b0f17' }}>{f.severity}</span>
        <span className="title">{f.title}</span>
        <span className="right">P{f.priority}{f.cve ? ` · ${f.cve}` : ''}{f.cvss ? ` · CVSS ${f.cvss}` : ''}</span>
      </div>
      {open && (
        <div className="body">
          <p><b>What is it:</b> {f.explanation}</p>
          <p><b>Impact:</b> {f.impact}</p>
          <p><b>Fix:</b> <span style={{ whiteSpace: 'pre-line' }}>{f.suggested_fix}</span></p>
          {f.evidence && <div className="evidence">{f.evidence}</div>}
          <p className="muted" style={{ fontSize: 12 }}>
            {f.source_scanner ? `source: ${f.source_scanner} · ` : ''}
            {f.owasp ? `OWASP ${f.owasp}` : ''}
            {f.location ? ` · ${f.location}` : ''}
          </p>
        </div>
      )}
    </div>
  )
}
