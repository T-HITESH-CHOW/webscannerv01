"""
Scanner Output Normalizer v01

Converts raw JSON from OWASP ZAP, Semgrep, and Trivy into a common format:
{
    "title": "",
    "severity": "",
    "location": "",
    "evidence": "",
    "source_scanner": "",
    "description": "",
    "rule_id": "",
    "references": []
}
"""

import json
import re
from typing import Any
from app.models.schemas import NormalizedFinding, Severity, ScannerName


# --- Severity Mapping ---

ZAP_RISK_TO_SEVERITY = {
    3: Severity.HIGH,
    2: Severity.MEDIUM,
    1: Severity.LOW,
    0: Severity.INFO,
}

SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
}

TRIVY_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def map_zap_severity(risk_code: int | str) -> Severity:
    """Map ZAP risk code (0-3) to our Severity enum"""
    try:
        return ZAP_RISK_TO_SEVERITY.get(int(risk_code), Severity.INFO)
    except (ValueError, TypeError):
        return Severity.INFO


def map_semgrep_severity(level: str) -> Severity:
    """Map Semgrep severity level to our Severity enum"""
    return SEMGREP_SEVERITY_MAP.get(level.upper(), Severity.INFO)


def map_trivy_severity(level: str) -> Severity:
    """Map Trivy severity to our Severity enum"""
    return TRIVY_SEVERITY_MAP.get(level.upper(), Severity.INFO)


# --- Helper Functions ---

def safe_get(obj: dict, *keys, default="") -> Any:
    """Safely navigate nested dict with fallback"""
    current = obj
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current if current != default else default


def truncate(text: str, max_len: int = 500) -> str:
    """Truncate long strings for evidence field"""
    if not text:
        return ""
    return text[:max_len] + ("..." if len(text) > max_len else "")


# --- ZAP Normalization ---

def normalize_zap_alert(alert: dict) -> NormalizedFinding:
    """
    Convert a single ZAP alert to NormalizedFinding.

    ZAP Alert Structure (from /JSON/alerts/):
    {
        "alert": "Cross Site Scripting (Reflected)",
        "riskcode": "3",
        "riskdesc": "High",
        "confidence": "Medium",
        "desc": "...",
        "instances": [
            {
                "uri": "http://example.com/search?q=test",
                "method": "GET",
                "param": "q",
                "attack": "<script>alert(1)</script>",
                "evidence": "<script>alert(1)</script>"
            }
        ],
        "cweid": "79",
        "wascid": "8",
        "sourceid": "3",
        "reference": "https://owasp.org/www-community/attacks/xss/"
    }
    """
    # Extract first instance for location/evidence
    instances = safe_get(alert, "instances", default=[])
    first_instance = instances[0] if instances else {}

    uri = safe_get(first_instance, "uri", default="")
    param = safe_get(first_instance, "param", default="")
    attack = safe_get(first_instance, "attack", default="")
    evidence = safe_get(first_instance, "evidence", default="")

    # Build location
    location_parts = []
    if uri:
        location_parts.append(uri)
    if param:
        location_parts.append(f"param: {param}")
    location = " | ".join(location_parts) if location_parts else "Unknown"

    # Build evidence (prefer attack payload, fallback to evidence)
    evidence_text = attack or evidence

    # References
    refs = []
    cwe = safe_get(alert, "cweid")
    if cwe and cwe != "-1":
        refs.append(f"CWE-{cwe}")
    ref = safe_get(alert, "reference")
    if ref:
        refs.append(ref)

    return NormalizedFinding(
        title=safe_get(alert, "alert", default="ZAP Alert"),
        severity=map_zap_severity(safe_get(alert, "riskcode", default=0)),
        location=location,
        evidence=truncate(evidence_text),
        source_scanner=ScannerName.ZAP,
        description=truncate(safe_get(alert, "desc", default="")),
        rule_id=safe_get(alert, "pluginid", default=""),
        references=refs,
    )


def parse_zap_output(raw_json: str | dict) -> list[NormalizedFinding]:
    """
    Parse ZAP JSON output (from API or report export).
    Handles both single alert list and full report format.
    """
    data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json

    # Handle different ZAP output formats
    alerts = []
    if isinstance(data, dict):
        # Full report format: {"alerts": [...], ...}
        alerts = safe_get(data, "alerts", default=[])
        # Or direct list format
        if not alerts and "alert" in data:
            alerts = [data]
    elif isinstance(data, list):
        alerts = data

    findings = []
    for alert in alerts:
        try:
            findings.append(normalize_zap_alert(alert))
        except Exception as e:
            # Log and continue - don't let one bad alert break everything
            print(f"[WARN] Failed to parse ZAP alert: {e}")
            continue

    return findings


# --- Semgrep Normalization ---

def normalize_semgrep_finding(finding: dict) -> NormalizedFinding:
    """
    Convert a single Semgrep finding to NormalizedFinding.

    Semgrep Finding Structure (from --json output):
    {
        "check_id": "python.lang.security.audit.xss.flask-xss.flask-xss",
        "path": "app.py",
        "start": {"line": 42, "col": 5},
        "end": {"line": 42, "col": 30},
        "extra": {
            "message": "Potential XSS via render_template_string",
            "severity": "ERROR",
            "metadata": {
                "cwe": "CWE-79",
                "owasp": "A03:2021",
                "references": ["https://owasp.org/www-community/attacks/xss/"]
            },
            "lines": "return render_template_string(user_input)"
        }
    }
    """
    extra = safe_get(finding, "extra", default={})
    metadata = safe_get(extra, "metadata", default={})

    # Location: file:line
    path = safe_get(finding, "path", default="")
    start_line = safe_get(finding, "start", "line", default=0)
    location = f"{path}:{start_line}" if path else "Unknown"

    # Evidence: code snippet
    evidence = safe_get(extra, "lines", default="")

    # References
    refs = []
    cwe = safe_get(metadata, "cwe")
    if cwe:
        refs.append(cwe if cwe.startswith("CWE-") else f"CWE-{cwe}")
    owasp = safe_get(metadata, "owasp")
    if owasp:
        refs.append(f"OWASP-{owasp}")
    for ref in safe_get(metadata, "references", default=[]):
        refs.append(ref)

    return NormalizedFinding(
        title=safe_get(extra, "message", default=safe_get(finding, "check_id", default="Semgrep Finding")),
        severity=map_semgrep_severity(safe_get(extra, "severity", default="INFO")),
        location=location,
        evidence=truncate(evidence),
        source_scanner=ScannerName.SEMGREP,
        description=truncate(safe_get(extra, "message", default="")),
        rule_id=safe_get(finding, "check_id", default=""),
        references=refs,
    )


def parse_semgrep_output(raw_json: str | dict) -> list[NormalizedFinding]:
    """Parse Semgrep JSON output (from `semgrep --json`)"""
    data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json

    # Semgrep outputs: {"results": [...], "errors": [...], "skipped": [...]}
    findings_list = safe_get(data, "results", default=[])

    findings = []
    for finding in findings_list:
        try:
            findings.append(normalize_semgrep_finding(finding))
        except Exception as e:
            print(f"[WARN] Failed to parse Semgrep finding: {e}")
            continue

    return findings


# --- Trivy Normalization ---

def normalize_trivy_result(result: dict) -> list[NormalizedFinding]:
    """
    Convert Trivy scan result to NormalizedFinding(s).

    Trivy Result Structure (from `trivy fs --format json`):
    {
        "Target": "requirements.txt",
        "Class": "lang-pkgs",
        "Type": "python",
        "Vulnerabilities": [
            {
                "VulnerabilityID": "CVE-2023-12345",
                "PkgName": "requests",
                "InstalledVersion": "2.28.0",
                "FixedVersion": "2.31.0",
                "Severity": "HIGH",
                "Title": "Request smuggling vulnerability",
                "Description": "...",
                "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"]
            }
        ]
    }
    """
    target = safe_get(result, "Target", default="")
    vulns = safe_get(result, "Vulnerabilities", default=[])

    findings = []
    for vuln in vulns:
        try:
            pkg = safe_get(vuln, "PkgName", default="")
            version = safe_get(vuln, "InstalledVersion", default="")
            fixed = safe_get(vuln, "FixedVersion", default="")
            vuln_id = safe_get(vuln, "VulnerabilityID", default="")

            # Location: target file + package
            location = f"{target} ({pkg}@{version})" if target else f"{pkg}@{version}"

            # Evidence: version info
            evidence_parts = [f"Installed: {version}"]
            if fixed:
                evidence_parts.append(f"Fixed: {fixed}")
            evidence = " | ".join(evidence_parts)

            # References
            refs = safe_get(vuln, "References", default=[])
            if vuln_id and not any(vuln_id in r for r in refs):
                refs.insert(0, vuln_id)

            findings.append(NormalizedFinding(
                title=safe_get(vuln, "Title", default=vuln_id or "Trivy Vulnerability"),
                severity=map_trivy_severity(safe_get(vuln, "Severity", default="UNKNOWN")),
                location=location,
                evidence=truncate(evidence),
                source_scanner=ScannerName.TRIVY,
                description=truncate(safe_get(vuln, "Description", default="")),
                rule_id=vuln_id,
                references=refs,
            ))
        except Exception as e:
            print(f"[WARN] Failed to parse Trivy vulnerability: {e}")
            continue

    return findings


def parse_trivy_output(raw_json: str | dict) -> list[NormalizedFinding]:
    """Parse Trivy JSON output (from `trivy fs --format json`)"""
    data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json

    # Trivy outputs: {"Results": [...], "Metadata": {...}}
    results = safe_get(data, "Results", default=[])

    findings = []
    for result in results:
        try:
            findings.extend(normalize_trivy_result(result))
        except Exception as e:
            print(f"[WARN] Failed to parse Trivy result: {e}")
            continue

    return findings# --- Generic severity string mapping (nuclei / strix / redteam) ---

SEVERITY_STR_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "INFORMATIONAL": Severity.INFO,
    "UNKNOWN": Severity.INFO,
}


def map_severity_str(value) -> Severity:
    """Map a free-form severity string (nuclei/strix/redteam) to Severity."""
    if value is None:
        return Severity.INFO
    return SEVERITY_STR_MAP.get(str(value).strip().upper(), Severity.INFO)


# --- Nuclei Normalization ---

def normalize_nuclei_match(match: dict) -> NormalizedFinding:
    """
    Convert one nuclei JSON match (nuclei -json) to NormalizedFinding.

    {
      "template-id": "cve-2021-44228",
      "info": {
        "name": "Log4j RCE",
        "severity": "critical",
        "description": "...",
        "reference": ["https://..."] ,
        "classification": {"cve-id": "CVE-2021-44228", "cvss-score": 10.0, "cwe-id": "CWE-502"}
      },
      "matched-at": "https://target/path",
      "extracted-results": ["..."],
      "curl-command": "curl ..."
    }
    """
    info = safe_get(match, "info", default={}) or {}
    classification = safe_get(info, "classification", default={}) or {}

    cve = safe_get(classification, "cve-id", default="")
    if isinstance(cve, list):
        cve = cve[0] if cve else ""
    cve = str(cve).strip() or None

    try:
        raw_cvss = safe_get(classification, "cvss-score", default=None)
        cvss = float(raw_cvss) if raw_cvss not in (None, "", "n/a") else None
    except (TypeError, ValueError):
        cvss = None

    refs: list[str] = []
    for r in safe_get(info, "reference", default=[], ) or []:
        if r and r not in refs:
            refs.append(str(r))
    if cve:
        nvd = f"https://nvd.nist.gov/vuln/detail/{cve}"
        if nvd not in refs:
            refs.insert(0, nvd)
    cwe = safe_get(classification, "cwe-id", default="")
    if cwe:
        cwe_s = str(cwe)
        refs.append(cwe_s if cwe_s.upper().startswith("CWE") else f"CWE-{cwe_s}")

    matched = safe_get(match, "matched-at", default="") or safe_get(match, "host", default="")
    extracted = safe_get(match, "extracted-results", default="")
    if isinstance(extracted, list):
        extracted = "; ".join(str(x) for x in extracted)
    evidence = extracted or safe_get(match, "matcher-name", default="") or safe_get(
        match, "curl-command", default=""
    )

    title = safe_get(info, "name", default="") or safe_get(match, "template-id", default="Nuclei Finding")
    description = safe_get(info, "description", default="") or safe_get(match, "template-id", default="")

    return NormalizedFinding(
        title=title,
        severity=map_severity_str(safe_get(info, "severity", default="info")),
        location=matched or "Unknown",
        evidence=truncate(str(evidence)),
        source_scanner=ScannerName.NUCLEI,
        description=truncate(str(description)),
        rule_id=safe_get(match, "template-id", default=""),
        references=refs,
        cve=cve,
        cvss=cvss,
    )


def parse_nuclei_output(raw_json: str | dict | list) -> list[NormalizedFinding]:
    """Parse `nuclei -json` output (a list, or {\"results\": [...]})."""
    data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
    if isinstance(data, dict):
        matches = safe_get(data, "results", default=[])
    elif isinstance(data, list):
        matches = data
    else:
        matches = []

    findings = []
    for match in matches:
        try:
            findings.append(normalize_nuclei_match(match))
        except Exception as e:
            print(f"[WARN] Failed to parse nuclei match: {e}")
            continue
    return findings


# --- Nikto Normalization ---

NIKTO_HIGH_KEYWORDS = [
    "remote code", "arbitrary file", "arbitrary command", "sql injection",
    "cross-site scripting", "command injection", "os command", "file inclusion",
    "directory traversal", "authentication bypass", "credentials", "rce",
    "shell command", "php code execution",
]
NIKTO_LOW_KEYWORDS = [
    "retrieved x-", "allows", "supports", "started", "the following cookies",
    "options", "allowed http methods", "supports ssl", "may allow",
]


def classify_nikto(msg: str) -> Severity:
    """Heuristic severity for Nikto findings (Nikto does not emit a severity)."""
    m = (msg or "").lower()
    if any(k in m for k in NIKTO_HIGH_KEYWORDS):
        return Severity.HIGH
    if any(k in m for k in NIKTO_LOW_KEYWORDS):
        return Severity.LOW
    return Severity.MEDIUM


def normalize_nikto_item(item: dict, host: str = "", port: str = "") -> NormalizedFinding:
    msg = safe_get(item, "msg", default="") or safe_get(item, "message", default="")
    url = safe_get(item, "url", default="")
    osvdb = safe_get(item, "OSVDB", default="") or safe_get(item, "id", default="")

    location = url or (f"{host}:{port}" if host else "Unknown")
    refs = ["https://cwe.mitre.org/", "https://owasp.org/www-project-web-security-testing-guide/"]
    if osvdb and str(osvdb) not in ("0", ""):
        refs.insert(0, f"OSVDB-{osvdb}")

    return NormalizedFinding(
        title=truncate(str(msg), 160) or "Nikto Finding",
        severity=classify_nikto(str(msg)),
        location=location,
        evidence=truncate(str(msg)),
        source_scanner=ScannerName.NIKTO,
        description=truncate(str(msg)),
        rule_id=str(osvdb or "nikto"),
        references=refs,
    )


def parse_nikto_output(raw_json: str | dict | list) -> list[NormalizedFinding]:
    """Parse `nikto -Format json` output."""
    data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json

    hosts = []
    if isinstance(data, list):
        hosts = data
    elif isinstance(data, dict):
        hosts = [data]

    findings = []
    for host_block in hosts:
        if not isinstance(host_block, dict):
            continue
        host = safe_get(host_block, "host", default="")
        port = safe_get(host_block, "port", default="")
        items = safe_get(host_block, "vulnerabilities", default=[]) or []
        for item in items:
            try:
                findings.append(normalize_nikto_item(item, host, port))
            except Exception as e:
                print(f"[WARN] Failed to parse Nikto item: {e}")
                continue
    return findings


# --- Nmap Normalization (XML) ---

NMAP_HIGH_RISK_PORTS = {
    "21", "22", "23", "25", "110", "143", "139", "445", "3389",
    "3306", "5432", "6379", "27017", "11211", "5984", "9200",
    "2375", "2376", "5900", "1433",
}
NMAP_MED_RISK_PORTS = {
    "8080", "8443", "8000", "8001", "8888", "9090", "9000", "5000",
    "161", "162", "512", "513", "514", "873", "2049",
}


def parse_nmap_xml(xml_text: str) -> list[NormalizedFinding]:
    """Parse `nmap -oX -` XML into exposed-service findings."""
    import xml.etree.ElementTree as ET

    findings: list[NormalizedFinding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        print(f"[WARN] Failed to parse nmap XML: {e}")
        return findings

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue

        address = ""
        addr_el = host.find("address")
        if addr_el is not None:
            address = addr_el.get("addr", "")

        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            first = hostnames.find("hostname")
            if first is not None:
                hostname = first.get("name", "")
        target = hostname or address or "unknown-host"

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid = port.get("portid", "")
            protocol = port.get("protocol", "tcp")
            service = port.find("service")
            svc_name = service.get("name", "") if service is not None else ""
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            extrainfo = service.get("extrainfo", "") if service is not None else ""
            version_str = " ".join(x for x in [product, version, extrainfo] if x).strip()

            label = f"{protocol}/{portid}"
            if portid in NMAP_HIGH_RISK_PORTS:
                severity = Severity.MEDIUM
                title = f"Exposed sensitive service on {label}"
            elif portid in NMAP_MED_RISK_PORTS:
                severity = Severity.LOW
                title = f"Exposed administrative/web service on {label}"
            else:
                severity = Severity.INFO
                title = f"Open port {label}"

            evidence = f"{label} open"
            if version_str:
                evidence += f" - {version_str}"
            elif svc_name:
                evidence += f" - {svc_name}"

            description = (
                f"Port {portid}/{protocol} is reachable on {target}"
                + (f" running {version_str}." if version_str else ".")
                + " Open services expand the attack surface; confirm each is required, "
                  "patched, and not exposed beyond its intended scope."
            )

            findings.append(NormalizedFinding(
                title=title,
                severity=severity,
                location=f"{target}:{portid}",
                evidence=evidence,
                source_scanner=ScannerName.NMAP,
                description=description,
                rule_id=f"nmap-{protocol}-{portid}",
                references=["https://attack.mitre.org/techniques/T1046/"],
            ))

    return findings


# --- Main Entry Point ---
def normalize_all_findings(
    zap_output: str | dict | None = None,
    semgrep_output: str | dict | None = None,
    trivy_output: str | dict | None = None,
    nuclei_output: str | dict | list | None = None,
    nikto_output: str | dict | list | None = None,
    nmap_output: str | None = None,
) -> list[NormalizedFinding]:
    """
    Normalize outputs from every scanner into a single list.

    Usage:
        findings = normalize_all_findings(
            zap_output=zap_json,
            semgrep_output=semgrep_json,
            trivy_output=trivy_json,
            nuclei_output=nuclei_json,
            nikto_output=nikto_json,
            nmap_output=nmap_xml,
        )
    """
    all_findings: list[NormalizedFinding] = []

    if zap_output:
        all_findings.extend(parse_zap_output(zap_output))

    if semgrep_output:
        all_findings.extend(parse_semgrep_output(semgrep_output))

    if trivy_output:
        all_findings.extend(parse_trivy_output(trivy_output))

    if nuclei_output:
        all_findings.extend(parse_nuclei_output(nuclei_output))

    if nikto_output:
        all_findings.extend(parse_nikto_output(nikto_output))

    if nmap_output:
        all_findings.extend(parse_nmap_xml(nmap_output))

    return all_findings


# --- Example Usage & Test Data ---

if __name__ == "__main__":
    # Example ZAP alert
    zap_example = {
        "alert": "Cross Site Scripting (Reflected)",
        "riskcode": "3",
        "desc": "Cross-site scripting vulnerability detected",
        "instances": [{
            "uri": "http://localhost:8080/search",
            "param": "q",
            "attack": "<script>alert('xss')</script>",
            "evidence": "<script>alert('xss')</script>"
        }],
        "cweid": "79",
        "reference": "https://owasp.org/www-community/attacks/xss/",
        "pluginid": "40012"
    }

    # Example Semgrep finding
    semgrep_example = {
        "check_id": "python.flask.security.xss.render-template-string",
        "path": "app/views.py",
        "start": {"line": 42, "col": 10},
        "extra": {
            "message": "User input passed to render_template_string - potential XSS",
            "severity": "ERROR",
            "lines": "return render_template_string(user_input)",
            "metadata": {
                "cwe": "79",
                "owasp": "A03:2021",
                "references": ["https://owasp.org/www-community/attacks/xss/"]
            }
        }
    }

    # Example Trivy vulnerability
    trivy_example = {
        "Target": "requirements.txt",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2023-12345",
            "PkgName": "requests",
            "InstalledVersion": "2.28.0",
            "FixedVersion": "2.31.0",
            "Severity": "HIGH",
            "Title": "Request smuggling in requests library",
            "Description": "A vulnerability in the requests library allows...",
            "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"]
        }]
    }

    # Test normalization
    print("=== ZAP Normalization ===")
    zap_findings = parse_zap_output(zap_example)
    for f in zap_findings:
        print(f.model_dump_json(indent=2))

    print("\n=== Semgrep Normalization ===")
    semgrep_findings = parse_semgrep_output({"results": [semgrep_example]})
    for f in semgrep_findings:
        print(f.model_dump_json(indent=2))

    print("\n=== Trivy Normalization ===")
    trivy_findings = parse_trivy_output({"Results": [trivy_example]})
    for f in trivy_findings:
        print(f.model_dump_json(indent=2))

    print("\n=== Combined ===")
    all_findings = normalize_all_findings(
        zap_output=zap_example,
        semgrep_output={"results": [semgrep_example]},
        trivy_output={"Results": [trivy_example]},
    )
    print(f"Total findings: {len(all_findings)}")