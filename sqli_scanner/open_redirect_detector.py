"""
open_redirect_detector.py
==========================

Open Redirect detection - DETECTION ONLY and SAFE.

A parameter is flagged when supplying an external, attacker-style destination
causes the application to redirect off-site (via an HTTP 3xx ``Location``
header, an HTML ``<meta http-equiv="refresh">``, or a clear client-side
``location=`` assignment). We never follow the redirect and never use an
internal/metadata target - only a benign, clearly-external RFC2606 example
domain is used as the canary so the test is harmless.

CWE-601 (URL Redirection to Untrusted Site) / OWASP A01:2021.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional
from urllib.parse import urlparse

from . import parser, severity
from .parser import InjectionPoint, RequestTemplate
from .scanner import Finding, RequestBudgetError, Scanner

logger = logging.getLogger("sqli_scanner.openredirect")

CWE_OPEN_REDIRECT = "CWE-601: URL Redirection to Untrusted Site (Open Redirect)"
OWASP_OPEN_REDIRECT = severity.OWASP_2021["A01"]

REMEDIATION = (
    "Do not build redirects from raw user input. Use an allow-list of permitted "
    "destinations (or relative paths only), map user-facing tokens to known "
    "internal URLs server-side, and reject absolute/external URLs. If external "
    "redirects are required, show an interstitial confirmation page."
)

# Benign, clearly-external canary using a reserved example domain (RFC 2606).
_CANARY_HOST = "redirect-check.example"
_CANARY_URL = f"https://{_CANARY_HOST}/oob"

# Parameter names that commonly drive redirects.
_REDIRECT_NAMES = {
    "redirect", "redirect_uri", "redirect_url", "redirecturl", "return",
    "returnurl", "return_url", "returnto", "return_to", "next", "url", "dest",
    "destination", "continue", "goto", "go", "out", "target", "to", "forward",
    "callback", "checkout_url", "rurl", "u",
}

_META_REFRESH_RE = re.compile(
    r"<meta[^>]+http-equiv=['\"]?refresh['\"]?[^>]*url=([^'\"> ]+)", re.IGNORECASE
)
_JS_LOCATION_RE = re.compile(
    r"(?:location\.(?:href|replace|assign)\s*=?\s*\(?|window\.location\s*=)\s*['\"]([^'\"]+)",
    re.IGNORECASE,
)


def _is_redirect_param(point: InjectionPoint) -> bool:
    name = (point.param_name or "").lower()
    if name in _REDIRECT_NAMES or any(t in name for t in ("redirect", "return", "url", "next", "goto")):
        return True
    val = (point.original_value or "").strip()
    return val.startswith(("http://", "https://", "//", "/"))


def _redirects_to_canary(resp) -> Optional[str]:
    """Return the detection mechanism if the response redirects to the canary."""
    # 1) HTTP Location header (3xx).
    location = resp.headers.get("Location") or resp.headers.get("location")
    if location and _CANARY_HOST in location:
        if urlparse(location if "//" in location else f"//{location}").hostname == _CANARY_HOST \
                or _CANARY_HOST in location:
            return f"HTTP {resp.status} Location header -> {location}"
    # 2) Meta refresh.
    m = _META_REFRESH_RE.search(resp.text or "")
    if m and _CANARY_HOST in m.group(1):
        return f"meta refresh -> {m.group(1)}"
    # 3) Client-side location assignment.
    j = _JS_LOCATION_RE.search(resp.text or "")
    if j and _CANARY_HOST in j.group(1):
        return f"JavaScript redirect -> {j.group(1)}"
    return None


def test_point(scanner: Scanner, point: InjectionPoint) -> Optional[Finding]:
    if point.location not in ("query", "body"):
        return None
    if point.template.is_unsafe():
        return None
    if not _is_redirect_param(point):
        return None

    # Inject the external canary; do NOT follow the redirect.
    resp = scanner.probe_point(point, _CANARY_URL, allow_redirects=False)
    if resp is None:
        return None
    mechanism = _redirects_to_canary(resp)
    if not mechanism:
        return None

    # Confirm with a repeat.
    confirm = scanner.probe_point(point, _CANARY_URL, allow_redirects=False)
    confirmed = confirm is not None and _redirects_to_canary(confirm) is not None

    method, url, _, _, _ = parser.materialize(point, point.original_value)
    risk = "High"
    sev = severity.derive(risk, "High" if confirmed else "Medium", confirmed)

    return Finding(
        vuln_type="Open Redirect",
        url=url,
        param=point.param_name,
        method=method,
        location=point.location,
        confidence="High" if confirmed else "Medium",
        risk=risk,
        category="OpenRedirect",
        evidence=[
            f"Supplying an external URL caused an off-site redirect ({mechanism}).",
            "A benign reserved example domain was used as the canary; the "
            "redirect was not followed.",
        ],
        matched_techniques=["external-redirect"],
        reproduction=[
            f"Target: {method} {url}",
            f"Set '{point.param_name}' to an absolute external URL "
            f"(e.g. https://{_CANARY_HOST}/...).",
            "Observe the application redirect to the external host instead of "
            "rejecting it or keeping the user on-site.",
        ],
        remediation=REMEDIATION,
        cwe=CWE_OPEN_REDIRECT,
        owasp=OWASP_OPEN_REDIRECT,
        confirmed=confirmed,
        severity=sev,
    )


def run(scanner: Scanner, templates: List[RequestTemplate]) -> List[Finding]:
    found: List[Finding] = []
    seen = set()
    for template in templates:
        if template.is_unsafe():
            continue
        for point in parser.enumerate_injection_points(template, include_path=False):
            key = (point.template.method, point.template.url, point.param_name, point.location)
            if key in seen:
                continue
            seen.add(key)
            try:
                finding = test_point(scanner, point)
            except RequestBudgetError:
                logger.warning("Request budget exhausted during open-redirect scan.")
                return found
            if finding is not None:
                scanner.note_finding(finding)
                found.append(finding)
    return found
