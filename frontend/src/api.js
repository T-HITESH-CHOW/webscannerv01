// Thin API client for the backend.
// Local dev: Vite proxies /api -> localhost:8001, so the base is empty.
// Production (Vercel): VITE_API_BASE must point at the backend host.
const BASE = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '')

async function get(path) {
  const res = await fetch(`${BASE}/api/v1${path}`)
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(text)
  }
  return res.json()
}

async function post(path, body) {
  const res = await fetch(`${BASE}/api/v1${path}`, {
    method: 'POST',
    headers: body instanceof FormData ? undefined : { 'Content-Type': 'application/json' },
    body: body instanceof FormData ? body : JSON.stringify(body),
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
    const res = await fetch(`${BASE}/api/v1/scan/${scanId}/report?format=markdown`)
    return res.text()
  },
  history: () => get('/scans'),
}
