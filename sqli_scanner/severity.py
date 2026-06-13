"""
severity.py
===========

Severity scoring and OWASP Top 10 (2021) mapping shared by all detectors.

Severity is a five-level scale (Critical / High / Medium / Low / Info) derived
from the finding's intrinsic risk and whether it was confirmed. This keeps
severity consistent across every check without each detector re-implementing the
logic. A coarse CVSS-style base band is also provided for reporting.

This module performs no I/O and has no side effects.
"""

from __future__ import annotations

from typing import Dict, Tuple

# Ordered most-severe first; used for sorting findings in reports.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}

# Approximate CVSS v3.1 base-score bands per severity (for reporting only).
_CVSS_BANDS: Dict[str, str] = {
    "Critical": "9.0-10.0",
    "High": "7.0-8.9",
    "Medium": "4.0-6.9",
    "Low": "0.1-3.9",
    "Info": "0.0",
}

# OWASP Top 10 (2021) reference strings, keyed by short code.
OWASP_2021: Dict[str, str] = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery (SSRF)",
}


def rank(severity: str) -> int:
    """Return a sort rank for a severity label (lower = more severe)."""
    return _SEVERITY_RANK.get(severity, len(SEVERITY_ORDER))


def cvss_band(severity: str) -> str:
    """Return the approximate CVSS base-score band for a severity label."""
    return _CVSS_BANDS.get(severity, "0.0")


def derive(risk: str, confidence: str, confirmed: bool) -> str:
    """Map (risk, confidence, confirmed) to a five-level severity label.

    Policy:
        * risk "Critical"                      -> Critical
        * risk "High" + confirmed              -> High
        * risk "High" (unconfirmed)            -> Medium
        * risk "Medium" + confirmed/High conf  -> Medium
        * risk "Medium" (low confidence)       -> Low
        * risk "Informational"/anything else   -> Info
    """
    r = (risk or "").lower()
    c = (confidence or "").lower()
    if r == "critical":
        return "Critical"
    if r == "high":
        return "High" if confirmed else "Medium"
    if r == "medium":
        if confirmed or c == "high":
            return "Medium"
        return "Low"
    if r in ("low",):
        return "Low"
    return "Info"


def summarize(severity: str) -> Tuple[str, str]:
    """Return (severity, cvss_band) tuple for convenience."""
    return severity, cvss_band(severity)
