const RAW_BASE = import.meta.env.VITE_API_BASE || ''
const BASE = RAW_BASE.replace(/\/$/, '')

function apiBaseUrl() {
  const candidate = BASE || ''
  if (candidate) return candidate
  if (typeof window !== 'undefined') {
    if (window.__API_BASE__) return window.__API_BASE__
    try {
      const p = new URLSearchParams(window.location.search)
      const envBase = p.get('apiBase')
      if (envBase) return envBase.replace(/\/$/, '')
    } catch {}
    return window.location.origin
  }
  return 'http://127.0.0.1:8001'
}

async function get(path) {
  const base = apiBaseUrl()
  const res = await fetch(`${base}/api/v1${path}`)
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(text)
  }
  return res.json()
}

async function post(path, body) {
  const base = apiBaseUrl()
  const res = await fetch(`${base}/api/v1${path}`, {
    method: 'POST',
    headers:
      body instanceof FormData ? undefined : { 'Content-Type': 'application/json' },
    body:
      body instanceof FormData ? body : JSON.stringify(body),
  })
  return res
}

export const api = {
  engines: () => get('/engines'),
  startUrlScan: (url) => post('/scan/url', { scan_type: 'url', target_url: url }),
  startUploadScan: (file) => {
    const form = new FormData()
    form.append('file', file)
    return post('/scan/upload', form)
  },
  status: (scanId) => get(`/scan/${scanId}/status`),
  trace: (scanId) => get(`/scan/${scanId}/trace`),
  report: (scanId) => get(`/scan/${scanId}/report`),
  reportMarkdown: async (scanId) => {
    const base = apiBaseUrl()
    const res = await fetch(`${base}/api/v1/scan/${scanId}/report?format=markdown`)
    return res.text()
  },
  reportHtml: async (scanId) => {
    const base = apiBaseUrl()
    const res = await fetch(`${base}/api/v1/scan/${scanId}/report?format=html`)
    return res.text()
  },
  history: () => get('/scans'),
}

export const ENGAGEMENTS_API = {
  list: () => get('/engagements'),
  start: (targetUrl) => post('/engagements/start', { target_url: targetUrl }),
  status: (eid) => get(`/engagements/${eid}/status`),
  trace: (eid) => get(`/engagements/${eid}/trace`),
  report: (eid) => get(`/engagements/${eid}/report`),
  reportMarkdown: async (eid) => {
    const base = apiBaseUrl()
    const res = await fetch(`${base}/api/v1/engagements/${eid}/report?format=markdown`)
    return res.text()
  },
  reportHtml: async (eid) => {
    const base = apiBaseUrl()
    const res = await fetch(`${base}/api/v1/engagements/${eid}/report?format=html`)
    return res.text()
  },
  scope: (eid) => get(`/engagements/${eid}/scope`),
  scopedTargets: (eid) => get(`/engagements/${eid}/scoped-targets`),
  setScope: (eid, scopedTargets) => post(`/engagements/${eid}/set-scope`, { scoped_targets: scopedTargets }),
  setting: (eid, key, value) => post(`/engagements/${eid}/settings`, { setting_key: key, setting_value: value }),
  delete: (eid) => post(`/engagements/${eid}/delete`),
  run: (eid) => post(`/engagements/${eid}/run`),
}
