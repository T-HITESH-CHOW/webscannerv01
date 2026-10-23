"""
AI Security Review Tool — Streamlit frontend.

Talks to the FastAPI backend (default http://localhost:8001).
"""

import json
import os
import time

import requests
import streamlit as st

API_BASE = os.environ.get("SECREVIEW_API", "http://localhost:8001/api/v1")

SEVERITY_COLORS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_BAR_COLORS = {
    "critical": "#d62728",
    "high": "#ff7f0e",
    "medium": "#e6c700",
    "low": "#1f77b4",
    "info": "#9e9e9e",
}

st.set_page_config(page_title="AI Sec Review v01", page_icon="🛡️", layout="wide")


@st.cache_data(ttl=30)
def fetch_engines():
    try:
        return requests.get(f"{API_BASE}/engines", timeout=5).json()
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def poll_scan(scan_id: str, timeout: int = 900):
    """Poll status until the job finishes; returns the final status dict."""
    deadline = time.time() + timeout
    placeholder = st.empty()
    while time.time() < deadline:
        try:
            status = requests.get(f"{API_BASE}/scan/{scan_id}/status", timeout=10).json()
        except Exception as exc:  # noqa: BLE001
            placeholder.warning(f"Backend not reachable: {exc}")
            return {"status": "unreachable", "error": str(exc)}

        if status.get("status") in ("completed", "failed"):
            placeholder.empty()
            return status
        placeholder.info(f"⏳ {status.get('status', 'running')} — {status.get('progress', '')}")
        time.sleep(2)
    placeholder.empty()
    return {"status": "timeout"}


def render_severity_bars(counts: dict):
    """Plain-HTML severity bars (avoids a pandas dependency in the UI)."""
    peak = max(counts.values()) or 1
    blocks = ['<div style="margin:6px 0 14px 0;">']
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        width = int(count / peak * 100)
        blocks.append(
            '<div style="display:flex;align-items:center;gap:10px;margin:3px 0;">'
            f'<span style="width:80px;font-size:13px;text-transform:capitalize;">{sev}</span>'
            '<div style="flex:1;background:rgba(128,128,128,0.18);border-radius:4px;height:16px;">'
            f'<div style="width:{width}%;background:{SEVERITY_BAR_COLORS[sev]};height:16px;border-radius:4px;"></div>'
            "</div>"
            f'<span style="width:26px;text-align:right;font-size:13px;">{count}</span>'
            "</div>"
        )
    blocks.append("</div>")
    st.markdown("".join(blocks), unsafe_allow_html=True)


def render_report(report: dict, key_prefix: str = "main"):
    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for sev, count in (report.get("findings_by_severity") or {}).items():
        severity_counts[str(sev).lower()] = count

    st.markdown(f"## Assessment of `{report.get('target')}`")
    st.caption(
        f"Scan `{report.get('scan_id')}` · {report.get('timestamp', '')[:19].replace('T', ' ')} "
        f"· scope: {report.get('scan_type')}"
    )

    cols = st.columns(6)
    cols[0].metric("Overall risk", str(report.get("risk_rating", "?")).upper())
    cols[1].metric("Total", report.get("total_findings", 0))
    for col, sev in zip(cols[2:], ["critical", "high", "medium"]):
        col.metric(sev.title(), severity_counts.get(sev, 0))

    render_severity_bars(severity_counts)

    st.markdown("### Executive summary")
    st.markdown(report.get("summary", ""))

    methodology = report.get("methodology") or []
    if methodology:
        with st.expander("Methodology — what actually ran"):
            for item in methodology:
                st.markdown(f"- {item}")
            engines = report.get("engines") or []
            if engines:
                rows = ["| Engine | Role | Status | Version | Notes |", "| --- | --- | --- | --- | --- |"]
                for e in engines:
                    role = e.get("role")
                    role = role.get("value") if isinstance(role, dict) else role
                    status = "✅ available" if e.get("available") else "❌ missing"
                    rows.append(
                        f"| {e.get('label')} | {role} | {status} | {e.get('version') or '—'} | {e.get('detail') or ''} |"
                    )
                st.markdown("\n".join(rows))

    st.markdown("### Threats by severity")
    findings = report.get("findings", [])
    if not findings:
        st.success("No findings were reported by the engines that ran. That is not proof the target is secure.")

    for sev in SEVERITY_ORDER:
        group = [f for f in findings if str(f.get("severity")).lower() == sev]
        if not group:
            continue
        st.markdown(f"#### {SEVERITY_COLORS[sev]} {sev.upper()} — {len(group)} finding(s)")
        for f in group:
            label = f"P{f.get('priority', '?')} · {f.get('title')}"
            if f.get("location") and f.get("location") != "Not applicable":
                label += f"  —  {f['location']}"
            with st.expander(label):
                meta = st.columns(4)
                meta[0].caption(f"**Detected by:** {f.get('source_scanner') or '—'}")
                meta[1].caption(f"**CVE:** {f.get('cve') or '—'}")
                meta[2].caption(f"**CVSS:** {f.get('cvss') or '—'}")
                meta[3].caption(f"**OWASP:** {f.get('owasp') or '—'}")

                if f.get("evidence"):
                    st.code(f["evidence"], language=None)
                st.markdown("**What this is**")
                st.markdown(f.get("explanation", ""))
                st.markdown("**Impact**")
                st.markdown(f.get("impact", ""))
                st.markdown("**How to fix it**")
                st.markdown(f.get("suggested_fix", ""))
                refs = f.get("references") or []
                if refs:
                    st.markdown("**References**")
                    for ref in refs[:8]:
                        st.markdown(f"- {ref}")

    st.divider()
    st.caption(report.get("disclaimer", ""))

    left, right = st.columns(2)
    try:
        markdown = requests.get(
            f"{API_BASE}/scan/{report.get('scan_id')}/report",
            params={"format": "markdown"},
            timeout=15,
        ).text
        left.download_button(
            "⬇️ Download Markdown report",
            data=markdown,
            file_name=f"security-report-{report.get('scan_id')}.md",
            mime="text/markdown",
            key=f"{key_prefix}-md",
        )
    except Exception:  # noqa: BLE001
        pass
    right.download_button(
        "⬇️ Download JSON report",
        data=json.dumps(report, indent=2, default=str),
        file_name=f"security-report-{report.get('scan_id')}.json",
        mime="application/json",
        key=f"{key_prefix}-json",
    )


# ---------------------------------------------------------------------------
# Sidebar: backend + engine status
# ---------------------------------------------------------------------------

st.sidebar.title("🛡️ Sec Review v01")

engine_data = fetch_engines()
if "error" in engine_data:
    st.sidebar.error("Backend unreachable")
    st.sidebar.caption(f"{API_BASE}\n\n{engine_data['error']}")
else:
    st.sidebar.success("Backend connected")
    if engine_data.get("simulate_scanners"):
        st.sidebar.warning("SIMULATION MODE — findings are fixtures, not real output")
    st.sidebar.markdown("**Engines**")
    for e in engine_data.get("engines", []):
        icon = "✅" if e.get("available") else "❌"
        role = e.get("role")
        role_value = role.get("value") if isinstance(role, dict) else role
        st.sidebar.markdown(f"{icon} **{e.get('label')}** · {role_value}")
st.sidebar.divider()
st.sidebar.caption(f"API: {API_BASE}")

# ---------------------------------------------------------------------------
# Safety banner
# ---------------------------------------------------------------------------

st.markdown(
    """
> ### ⚠️ AUTHORIZED TESTING ONLY
> Automated scanning sends real traffic to the target. Only scan systems you own or
> have explicit written permission to test. Findings are produced by automated checks
> and must be verified manually — this is not a certified penetration test.
"""
)

st.title("AI Security Review Tool")

tabs = st.tabs(["🌐 URL Scan", "📁 Upload Code", "📊 Last Report"])

with tabs[0]:
    url = st.text_input("Target URL", placeholder="https://example.com or http://localhost:8000")
    authorized = st.checkbox("I own this system or have written permission to test it")

    if st.button("Start scan", type="primary", disabled=not authorized):
        if not url.strip():
            st.error("Please enter a URL.")
        else:
            with st.spinner("Queuing scan..."):
                try:
                    resp = requests.post(
                        f"{API_BASE}/scan/url",
                        json={"scan_type": "url", "target_url": url.strip()},
                        timeout=30,
                    )
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Could not reach the backend: {exc}")
                else:
                    if resp.status_code == 200:
                        scan_id = resp.json()["scan_id"]
                        st.success(f"Scan started: `{scan_id}`")
                        st.session_state["current_scan"] = scan_id
                    else:
                        st.error(resp.text)

with tabs[1]:
    uploaded = st.file_uploader(
        "Source archive or single file", type=["zip", "tar", "gz", "tgz", "py", "js", "ts", "java", "go"]
    )
    authorized_upload = st.checkbox("I own this code / have permission to scan it", key="auth_upload")

    if st.button("Start code scan", type="primary", disabled=not authorized_upload):
        if not uploaded:
            st.error("Please upload a file.")
        else:
            with st.spinner("Uploading..."):
                try:
                    resp = requests.post(
                        f"{API_BASE}/scan/upload",
                        files={"file": (uploaded.name, uploaded.getvalue())},
                        data={"confirmation_phrase": ""},
                        timeout=120,
                    )
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Upload failed: {exc}")
                else:
                    if resp.status_code == 200:
                        scan_id = resp.json()["scan_id"]
                        st.success(f"Scan started: `{scan_id}`")
                        st.session_state["current_scan"] = scan_id
                    else:
                        st.error(resp.text)

scan_id = st.session_state.get("current_scan")
if scan_id:
    status = poll_scan(scan_id)
    if status.get("status") == "completed":
        try:
            report = requests.get(f"{API_BASE}/scan/{scan_id}/report", timeout=30).json()
        except Exception as exc:  # noqa: BLE001
            st.error(f"Could not load the report: {exc}")
        else:
            st.session_state["last_report"] = report
            st.divider()
            render_report(report)
    elif status.get("status") == "failed":
        st.error(f"Scan failed: {status.get('error')}")
    elif status.get("status") == "timeout":
        st.warning("Scan is still running. Refresh the page to check again.")

with tabs[2]:
    last = st.session_state.get("last_report")
    if not last:
        st.info("No report yet in this session. Run a scan first.")
    else:
        render_report(last, key_prefix="last")
