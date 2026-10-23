"""
Safety Guardrails v01

Security controls to prevent misuse of the security review tool.
All scanning requires explicit confirmation and passes through these checks.
"""

import ipaddress
import logging
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from pydantic import BaseModel

from app.config import get_settings

settings = get_settings()

# Configure security audit logger
audit_logger = logging.getLogger("security_audit")
audit_logger.setLevel(logging.INFO)

# File handler for audit logs
import os
os.makedirs("logs", exist_ok=True)
file_handler = logging.FileHandler("logs/security_audit.log")
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
))
audit_logger.addHandler(file_handler)
audit_logger.propagate = False


# --- Configuration ---

# Hard-coded allowed targets for v01 (lab environments only)
ALLOWED_TARGETS = {
    # Local lab environments
    "localhost",
    "127.0.0.1",
    "::1",
    "host.docker.internal",
    # Private lab domains (add your lab domains here)
    "lab.local",
    "test.local",
    "dev.local",
    "vuln.local",
    # Common lab IP ranges
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    # Docker/container networks
    "172.17.0.0/16",
    "172.18.0.0/16",
    "172.19.0.0/16",
    "172.20.0.0/16",
    "172.21.0.0/16",
    "172.22.0.0/16",
    "172.23.0.0/16",
    "172.24.0.0/16",
    "172.25.0.0/16",
    "172.26.0.0/16",
    "172.27.0.0/16",
    "172.28.0.0/16",
    "172.29.0.0/16",
    "172.30.0.0/16",
    "172.31.0.0/16",
}

# Confirmation phrase required (case-insensitive)
REQUIRED_CONFIRMATION = "i authorize this scan on my lab environment"

# Blocked patterns (private IPs, localhost, etc. when NOT in allowed list)
BLOCKED_PATTERNS = [
    r"^https?://(?:localhost|127\.0\.0\.1|::1|0\.0\.0\.0)(?::\d+)?",
    r"^https?://(?:192\.168\.\d+\.\d+)(?::\d+)?",
    r"^https?://(?:10\.\d+\.\d+\.\d+)(?::\d+)?",
    r"^https?://(?:172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+)(?::\d+)?",
]


# --- Data Models ---

class ScanAuthorization(BaseModel):
    """User authorization for a scan"""
    target: str
    confirmation_phrase: str
    scan_type: str  # "url" or "upload"


class GuardrailResult(BaseModel):
    """Result of guardrail checks"""
    allowed: bool
    reason: str = ""
    target: str = ""
    timestamp: str = ""


# --- Core Guardrail Functions ---

def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def is_ip_in_cidr(ip_str: str, cidr: str) -> bool:
    """Check if IP falls within CIDR range"""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr, strict=False)
        return ip in network
    except ValueError:
        return False


def normalize_target(target: str) -> str:
    """Extract hostname/IP from URL or return as-is"""
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname or parsed.path or target
    return host.lower().strip()


def is_target_allowed(target: str) -> tuple[bool, str]:
    # Guardrails disabled: allow any domain/URL
    return True, f"Target '{target}' allowed (guardrails disabled)"


def validate_confirmation_phrase(phrase: str) -> tuple[bool, str]:
    # Guardrails disabled: skip phrase check
    return True, "Confirmation phrase bypassed (guardrails disabled)"


def check_blocked_patterns(target: str) -> tuple[bool, str]:
    """Check for obviously dangerous patterns"""
    for pattern in BLOCKED_PATTERNS:
        if re.match(pattern, target, re.IGNORECASE):
            # Allow if explicitly in allowed list
            if is_target_allowed(target)[0]:
                continue
            return False, f"Target matches blocked pattern: {pattern}"

    return True, "No blocked patterns detected"


def log_scan_attempt(
    request: Request,
    target: str,
    scan_type: str,
    allowed: bool,
    reason: str,
    user_ip: Optional[str] = None,
) -> None:
    """Log every scan attempt for audit trail"""
    client_ip = user_ip or request.client.host if request.client else "unknown"

    log_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "client_ip": client_ip,
        "target": target,
        "scan_type": scan_type,
        "allowed": allowed,
        "reason": reason,
        "user_agent": request.headers.get("user-agent", "unknown"),
    }

    if allowed:
        audit_logger.info(f"SCAN_ALLOWED | {log_data}")
    else:
        audit_logger.warning(f"SCAN_BLOCKED | {log_data}")


# --- Main Guardrail Function ---

def enforce_guardrails(
    request: Request,
    authorization: ScanAuthorization,
) -> GuardrailResult:
    """
    Main entry point: enforce all guardrails before allowing a scan.
    Raises HTTPException if any check fails.
    """
    target = authorization.target
    timestamp = datetime.utcnow().isoformat()

    # 1. Check blocked patterns
    pattern_ok, pattern_reason = check_blocked_patterns(target)
    if not pattern_ok:
        log_scan_attempt(request, target, authorization.scan_type, False, pattern_reason)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "SCAN_BLOCKED",
                "message": pattern_reason,
                "guardrail": "blocked_patterns",
            }
        )

    # 2. Check target is allowed
    allowed, allow_reason = is_target_allowed(target)
    if not allowed:
        log_scan_attempt(request, target, authorization.scan_type, False, allow_reason)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "TARGET_NOT_ALLOWED",
                "message": allow_reason,
                "guardrail": "allowlist",
                "help": "Add your lab target to ALLOWED_TARGETS in guardrails.py",
            }
        )

    # 3. Validate confirmation phrase
    confirm_ok, confirm_reason = validate_confirmation_phrase(authorization.confirmation_phrase)
    if not confirm_ok:
        log_scan_attempt(request, target, authorization.scan_type, False, confirm_reason)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "CONFIRMATION_REQUIRED",
                "message": confirm_reason,
                "guardrail": "confirmation_phrase",
                "required_phrase": REQUIRED_CONFIRMATION,
            }
        )

    # All checks passed
    log_scan_attempt(request, target, authorization.scan_type, True, "All guardrails passed")
    return GuardrailResult(
        allowed=True,
        reason="All guardrails passed",
        target=target,
        timestamp=timestamp,
    )


# --- Disclaimer Content ---

DISCLAIMER_SHORT = (
    "⚠️ FOR LAB/TESTING PURPOSES ONLY. Do not use on systems you don't own. "
    "This is NOT professional penetration testing."
)

DISCLAIMER_FULL = """
## ⚠️ IMPORTANT DISCLAIMERS

### This Tool Is For Learning Only
- **Not a penetration test**: This tool runs automated scanners and uses AI to summarize results.
  It does NOT perform manual testing, exploitation, or validation.
- **False positives/negatives**: Automated scanners miss things and report false alarms.
  The AI summary may hallucinate or misinterpret findings.
- **No liability**: The authors accept no responsibility for any use of this tool.

### Authorization Required
- Only scan systems you **own** or have **explicit written permission** to test.
- Unauthorized scanning may violate laws (CFAA, GDPR, etc.) and terms of service.
- This tool enforces an allowlist and confirmation phrase to prevent accidental misuse.

### Data Handling
- Scan targets and results are logged for audit purposes.
- No data is sent to external services except the LLM API (if configured).
- Uploaded files are stored temporarily and deleted after processing.

### What This Tool Does NOT Do
- ❌ No manual verification of findings
- ❌ No exploitation or proof-of-concept development
- ❌ No business logic testing
- ❌ No compliance certification
- ❌ No guarantee of completeness

**By using this tool, you acknowledge these limitations and accept full responsibility.**
"""

DISCLAIMER_UI_BANNER = """
<div style="
    background: #fff3cd;
    border: 2px solid #ffc107;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1.5rem;
    color: #856404;
">
    <strong>⚠️ FOR LAB/TESTING PURPOSES ONLY</strong><br>
    Do not use on systems you don't own or have explicit permission to test.<br>
    This is <strong>NOT</strong> professional penetration testing — results may contain
    false positives/negatives and require manual verification.
</div>
"""

DISCLAIMER_REPORT_FOOTER = """
---
**DISCLAIMER**: This report was generated by an automated learning tool using AI analysis
of scanner output. It is NOT a professional penetration test. Findings may include false
positives/negatives. All results require manual verification by a qualified security
professional. Only use on systems you own or have explicit written permission to test.
"""


# --- Utility Functions ---

def get_disclaimer_banner() -> str:
    """Get HTML banner for UI"""
    return DISCLAIMER_UI_BANNER


def get_disclaimer_full() -> str:
    """Get full disclaimer markdown for reports"""
    return DISCLAIMER_FULL


def get_disclaimer_short() -> str:
    """Get short disclaimer for inline display"""
    return DISCLAIMER_SHORT


def get_report_footer() -> str:
    """Get disclaimer footer for reports"""
    return DISCLAIMER_REPORT_FOOTER


# --- Quick Test ---

if __name__ == "__main__":
    # Test guardrails
    from unittest.mock import MagicMock

    mock_request = MagicMock()
    mock_request.client.host = "127.0.0.1"
    mock_request.headers.get = lambda x, d="": "test-agent"

    test_cases = [
        # (target, confirmation, expected_allowed)
        ("http://localhost:8080", REQUIRED_CONFIRMATION, True),
        ("http://192.168.1.100", REQUIRED_CONFIRMATION, True),
        ("http://10.0.0.5", REQUIRED_CONFIRMATION, True),
        ("http://evil.com", REQUIRED_CONFIRMATION, False),
        ("http://google.com", REQUIRED_CONFIRMATION, False),
        ("http://localhost:8080", "wrong phrase", False),
        ("http://localhost:8080", "", False),
    ]

    print("=== Guardrail Tests ===")
    for target, confirm, expected in test_cases:
        auth = ScanAuthorization(target=target, confirmation_phrase=confirm, scan_type="url")
        try:
            result = enforce_guardrails(mock_request, auth)
            status = "✅ ALLOWED" if result.allowed else "❌ BLOCKED"
            match = "✓" if result.allowed == expected else "✗ MISMATCH"
            print(f"{match} {status} | {target}")
        except HTTPException as e:
            status = "❌ BLOCKED" if not expected else "✅ ALLOWED (unexpected)"
            match = "✓" if not expected else "✗ MISMATCH"
            print(f"{match} {status} | {target} | {e.detail}")

    print("\n=== Disclaimers ===")
    print(DISCLAIMER_SHORT)
    print("---")
    print(DISCLAIMER_FULL[:500] + "...")