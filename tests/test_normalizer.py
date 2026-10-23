"""
Tests for the Scanner Normalizer
Run with: pytest tests/
"""

import pytest
from app.services.normalizer import (
    parse_zap_output,
    parse_semgrep_output,
    parse_trivy_output,
    normalize_all_findings,
    map_zap_severity,
    map_semgrep_severity,
    map_trivy_severity,
)
from app.models.schemas import Severity, ScannerName


# --- Test Data ---

ZAP_ALERT = {
    "alert": "Cross Site Scripting (Reflected)",
    "riskcode": "3",
    "desc": "XSS vulnerability",
    "instances": [{
        "uri": "http://example.com/search",
        "param": "q",
        "attack": "<script>alert(1)</script>",
        "evidence": "<script>alert(1)</script>"
    }],
    "cweid": "79",
    "reference": "https://owasp.org/www-community/attacks/xss/",
    "pluginid": "40012"
}

SEMGREP_FINDING = {
    "check_id": "python.flask.security.xss.render-template-string",
    "path": "app/views.py",
    "start": {"line": 42, "col": 10},
    "extra": {
        "message": "User input in render_template_string",
        "severity": "ERROR",
        "lines": "return render_template_string(user_input)",
        "metadata": {
            "cwe": "79",
            "owasp": "A03:2021",
            "references": ["https://owasp.org/www-community/attacks/xss/"]
        }
    }
}

TRIVY_RESULT = {
    "Target": "requirements.txt",
    "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2023-12345",
        "PkgName": "requests",
        "InstalledVersion": "2.28.0",
        "FixedVersion": "2.31.0",
        "Severity": "HIGH",
        "Title": "Request smuggling",
        "Description": "HTTP request smuggling in requests",
        "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"]
    }]
}


# --- Severity Mapping Tests ---

def test_map_zap_severity():
    assert map_zap_severity(3) == Severity.HIGH
    assert map_zap_severity(2) == Severity.MEDIUM
    assert map_zap_severity(1) == Severity.LOW
    assert map_zap_severity(0) == Severity.INFO
    assert map_zap_severity("3") == Severity.HIGH
    assert map_zap_severity("invalid") == Severity.INFO


def test_map_semgrep_severity():
    assert map_semgrep_severity("ERROR") == Severity.HIGH
    assert map_semgrep_severity("WARNING") == Severity.MEDIUM
    assert map_semgrep_severity("INFO") == Severity.INFO
    assert map_semgrep_severity("unknown") == Severity.INFO


def test_map_trivy_severity():
    assert map_trivy_severity("CRITICAL") == Severity.CRITICAL
    assert map_trivy_severity("HIGH") == Severity.HIGH
    assert map_trivy_severity("MEDIUM") == Severity.MEDIUM
    assert map_trivy_severity("LOW") == Severity.LOW
    assert map_trivy_severity("UNKNOWN") == Severity.INFO
    assert map_trivy_severity("unknown") == Severity.INFO


# --- ZAP Parsing Tests ---

def test_parse_zap_single_alert():
    findings = parse_zap_output(ZAP_ALERT)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Cross Site Scripting (Reflected)"
    assert f.severity == Severity.HIGH
    assert f.source_scanner == ScannerName.ZAP
    assert "search" in f.location
    assert "q" in f.location
    assert "<script>" in f.evidence
    assert "CWE-79" in f.references


def test_parse_zap_alerts_list():
    zap_data = {"alerts": [ZAP_ALERT, ZAP_ALERT]}
    findings = parse_zap_output(zap_data)
    assert len(findings) == 2


def test_parse_zap_missing_fields():
    """Test handling of missing/empty fields"""
    minimal_alert = {"alert": "Test", "riskcode": "1"}
    findings = parse_zap_output(minimal_alert)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Test"
    assert f.severity == Severity.LOW
    assert f.location == "Unknown"
    assert f.evidence == ""


# --- Semgrep Parsing Tests ---

def test_parse_semgrep_finding():
    semgrep_data = {"results": [SEMGREP_FINDING]}
    findings = parse_semgrep_output(semgrep_data)
    assert len(findings) == 1
    f = findings[0]
    assert "render_template_string" in f.title or "XSS" in f.title
    assert f.severity == Severity.HIGH
    assert f.source_scanner == ScannerName.SEMGREP
    assert "app/views.py:42" == f.location
    assert "render_template_string" in f.evidence
    assert "CWE-79" in f.references


def test_parse_semgrep_missing_fields():
    minimal = {"check_id": "test.rule", "path": "test.py", "start": {"line": 1}, "extra": {"severity": "INFO"}}
    findings = parse_semgrep_output({"results": [minimal]})
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "test.rule"
    assert f.location == "test.py:1"


# --- Trivy Parsing Tests ---

def test_parse_trivy_vulnerability():
    trivy_data = {"Results": [TRIVY_RESULT]}
    findings = parse_trivy_output(trivy_data)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Request smuggling"
    assert f.severity == Severity.HIGH
    assert f.source_scanner == ScannerName.TRIVY
    assert "requirements.txt" in f.location
    assert "requests@2.28.0" in f.location
    assert "Installed: 2.28.0" in f.evidence
    assert "Fixed: 2.31.0" in f.evidence
    assert f.rule_id == "CVE-2023-12345"
    assert "CVE-2023-12345" in f.references[0]  # CVE ID is in the reference URL


def test_parse_trivy_multiple_vulns():
    multi = {
        "Results": [{
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "PkgName": "pkg1", "InstalledVersion": "1.0", "Severity": "HIGH", "Title": "Vuln 1"},
                {"VulnerabilityID": "CVE-2", "PkgName": "pkg2", "InstalledVersion": "2.0", "Severity": "MEDIUM", "Title": "Vuln 2"},
            ]
        }]
    }
    findings = parse_trivy_output(multi)
    assert len(findings) == 2


# --- Combined Normalization Tests ---

def test_normalize_all_findings():
    findings = normalize_all_findings(
        zap_output={"alerts": [ZAP_ALERT]},
        semgrep_output={"results": [SEMGREP_FINDING]},
        trivy_output={"Results": [TRIVY_RESULT]},
    )
    assert len(findings) == 3
    scanners = {f.source_scanner for f in findings}
    assert ScannerName.ZAP in scanners
    assert ScannerName.SEMGREP in scanners
    assert ScannerName.TRIVY in scanners


def test_normalize_all_with_none():
    """Test that None inputs are handled gracefully"""
    findings = normalize_all_findings(
        zap_output=None,
        semgrep_output={"results": [SEMGREP_FINDING]},
        trivy_output=None,
    )
    assert len(findings) == 1
    assert findings[0].source_scanner == ScannerName.SEMGREP


if __name__ == "__main__":
    pytest.main([__file__, "-v"])