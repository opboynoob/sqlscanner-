"""
headers_detector.py
===================

Security header and cookie-flag inspection - PASSIVE and SAFE.

Issues a single GET to the target and reports missing/weak HTTP security
controls. These are low-severity hardening findings (mostly OWASP A05:2021 -
Security Misconfiguration) but are valuable in a VAPT report.

Checks:
    * Content-Security-Policy (CSP)
    * X-Frame-Options / CSP frame-ancestors (clickjacking)
    * Strict-Transport-Security (HSTS, for HTTPS targets)
    * X-Content-Type-Options: nosniff
    * Referrer-Policy
    * Permissions-Policy
    * Set-Cookie flags: Secure, HttpOnly, SameSite

No requests beyond one GET; nothing is modified.
"""

from __future__ import annotations

import logging
from typing import List, Optional
from urllib.parse import urlparse

from . import severity
from .scanner import Finding, RequestBudgetError, Scanner

logger = logging.getLogger("sqli_scanner.headers")

CWE_HEADERS = "CWE-693: Protection Mechanism Failure"
CWE_COOKIE = "CWE-1004/CWE-614: Sensitive Cookie Without HttpOnly/Secure flag"
OWASP_MISCONFIG = severity.OWASP_2021["A05"]

# (header-name, friendly-name, severity-if-missing, remediation)
_EXPECTED_HEADERS = [
    ("content-security-policy", "Content-Security-Policy",
     "Define a Content-Security-Policy to mitigate XSS and data injection."),
    ("x-content-type-options", "X-Content-Type-Options",
     "Set 'X-Content-Type-Options: nosniff' to prevent MIME sniffing."),
    ("referrer-policy", "Referrer-Policy",
     "Set a Referrer-Policy (e.g. strict-origin-when-cross-origin)."),
    ("permissions-policy", "Permissions-Policy",
     "Set a Permissions-Policy to restrict powerful browser features."),
]


def _finding(url: str, vuln_type: str, evidence: List[str], cwe: str,
             remediation: str, sev: str, technique: str) -> Finding:
    return Finding(
        vuln_type=vuln_type,
        url=url,
        param="(response headers)",
        method="GET",
        location="header",
        confidence="High",
        risk="Low" if sev in ("Low", "Info") else sev,
        category="SecurityHeaders",
        evidence=evidence,
        matched_techniques=[technique],
        reproduction=[
            f"Target: GET {url}",
            "Inspect the HTTP response headers (and Set-Cookie) for the missing "
            "or weak control described above.",
        ],
        remediation=remediation,
        cwe=cwe,
        owasp=OWASP_MISCONFIG,
        confirmed=True,  # header presence/absence is directly observable
        severity=sev,
    )


def run(scanner: Scanner, target_url: str) -> List[Finding]:
    """Inspect security headers and cookie flags for a single target URL."""
    findings: List[Finding] = []
    try:
        resp = scanner.send_full("GET", target_url, allow_redirects=False)
    except RequestBudgetError:
        logger.warning("Request budget exhausted during headers scan.")
        return findings
    if resp is None:
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    is_https = urlparse(target_url).scheme == "https"

    # Generic expected headers.
    for key, friendly, remediation in _EXPECTED_HEADERS:
        if key not in headers:
            findings.append(_finding(
                target_url, f"Missing security header: {friendly}",
                [f"Response does not set the '{friendly}' header."],
                CWE_HEADERS, remediation, "Low", f"missing-{key}",
            ))

    # Clickjacking: X-Frame-Options OR CSP frame-ancestors.
    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        findings.append(_finding(
            target_url, "Clickjacking protection missing",
            ["Neither 'X-Frame-Options' nor CSP 'frame-ancestors' is set; the "
             "page may be framed by other sites."],
            CWE_HEADERS,
            "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or a CSP "
            "'frame-ancestors' directive.",
            "Low", "missing-clickjacking-protection",
        ))

    # HSTS (only meaningful over HTTPS).
    if is_https and "strict-transport-security" not in headers:
        findings.append(_finding(
            target_url, "Missing HSTS (Strict-Transport-Security)",
            ["HTTPS response does not set Strict-Transport-Security."],
            CWE_HEADERS,
            "Set 'Strict-Transport-Security' with a long max-age (and "
            "includeSubDomains/preload where appropriate).",
            "Low", "missing-hsts",
        ))

    # Cookie flags.
    set_cookie = resp.headers.get("Set-Cookie") or resp.headers.get("set-cookie")
    if set_cookie:
        lc = set_cookie.lower()
        weak = []
        if "httponly" not in lc:
            weak.append("HttpOnly")
        if is_https and "secure" not in lc:
            weak.append("Secure")
        if "samesite" not in lc:
            weak.append("SameSite")
        if weak:
            findings.append(_finding(
                target_url, "Cookie set without recommended flags",
                [f"Set-Cookie is missing flag(s): {', '.join(weak)}.",
                 "Missing HttpOnly exposes cookies to XSS; missing Secure allows "
                 "transmission over HTTP; missing SameSite weakens CSRF defenses."],
                CWE_COOKIE,
                "Set session cookies with HttpOnly, Secure (over HTTPS), and an "
                "appropriate SameSite attribute.",
                "Low", "weak-cookie-flags",
            ))

    for f in findings:
        scanner.note_finding(f)
    return findings
