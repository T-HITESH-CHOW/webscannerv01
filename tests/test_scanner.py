"""
Tests for Scanner Orchestrator
Run with: pytest tests/
"""

import pytest
from unittest.mock import AsyncMock, patch

from app.services.scanner import (
    run_all_scanners,
    run_zap_scan,
    run_semgrep_scan,
    run_trivy_scan,
    SIMULATED_ZAP,
    SIMULATED_SEMGREP,
    SIMULATED_TRIVY,
)
from app.models.schemas import ScanType, NormalizedFinding, ScannerName
from app.config import Settings


# --- Test Settings Override ---

@pytest.fixture
def mock_settings(monkeypatch):
    """Override settings for testing"""
    test_settings = Settings(
        SIMULATE_SCANNERS=True,
        LLM_API_KEY="",
        UPLOAD_DIR="data/uploads",
        REPORTS_DIR="data/reports",
    )
    monkeypatch.setattr("app.services.scanner.settings", test_settings)
    return test_settings


# --- Scanner Tests (Simulation Mode) ---

@pytest.mark.asyncio
async def test_run_zap_scan_simulation(mock_settings):
    result = await run_zap_scan("http://example.com", ScanType.URL)
    assert "alerts" in result
    assert len(result["alerts"]) == 3
    assert result["alerts"][0]["alert"] == "Cross Site Scripting (Reflected)"


@pytest.mark.asyncio
async def test_run_semgrep_scan_simulation(mock_settings):
    result = await run_semgrep_scan("/fake/path", ScanType.UPLOAD)
    assert "results" in result
    assert len(result["results"]) == 3
    assert "render_template_string" in result["results"][0]["extra"]["message"]


@pytest.mark.asyncio
async def test_run_trivy_scan_simulation(mock_settings):
    result = await run_trivy_scan("/fake/path", ScanType.UPLOAD)
    assert "Results" in result
    assert len(result["Results"]) == 2
    assert result["Results"][0]["Target"] == "requirements.txt"


# --- Full Pipeline Test ---

@pytest.mark.asyncio
async def test_run_all_scanners_integration(mock_settings):
    """Test the full scanner pipeline returns normalized findings"""
    findings = await run_all_scanners("test-target", ScanType.UPLOAD)

    # Should have findings from all three scanners
    assert len(findings) > 0

    # Check all three scanners represented
    scanners = {f.source_scanner for f in findings}
    assert ScannerName.ZAP in scanners
    assert ScannerName.SEMGREP in scanners
    assert ScannerName.TRIVY in scanners

    # Check all findings are NormalizedFinding
    for f in findings:
        assert isinstance(f, NormalizedFinding)
        assert f.title
        assert f.severity
        assert f.source_scanner


@pytest.mark.asyncio
async def test_run_all_scanners_url_type(mock_settings):
    """URL scans should still work (ZAP only in simulation)"""
    findings = await run_all_scanners("http://example.com", ScanType.URL)
    assert len(findings) > 0
    # In simulation mode, all three return data
    # In real mode, only ZAP would run for URL scans


# --- Test NormalizedFinding Structure ---

def test_normalized_finding_has_required_fields():
    """Verify NormalizedFinding has all required fields from spec"""
    # This is more of a schema validation test
    from app.models.schemas import NormalizedFinding, Severity, ScannerName

    finding = NormalizedFinding(
        title="Test Finding",
        severity=Severity.HIGH,
        location="test.py:10",
        evidence="bad_code()",
        source_scanner=ScannerName.SEMGREP,
        description="A test finding",
        rule_id="test.rule.001",
        references=["CWE-123"],
    )

    # All fields from the spec should be present
    assert finding.title == "Test Finding"
    assert finding.severity == Severity.HIGH
    assert finding.location == "test.py:10"
    assert finding.evidence == "bad_code()"
    assert finding.source_scanner == ScannerName.SEMGREP
    assert finding.description == "A test finding"
    assert finding.rule_id == "test.rule.001"
    assert finding.references == ["CWE-123"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])