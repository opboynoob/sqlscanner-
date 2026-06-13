"""
ssrf_detector.py
================

Server-Side Request Forgery (SSRF) detection - SAFE and DETECTION ONLY.

SSRF cannot be confirmed reliably in-band without an out-of-band (OAST)
listener, and actively forcing a server to fetch internal resources (cloud
metadata, localhost, RFC1918 ranges) would be exploitation. This module
therefore:

    1. **Passively** identifies parameters that accept URLs/hosts (by name or by
       value shape) and reports them as *potential* SSRF surface (Low
       confidence). No requests are required for this.

    2. **Optionally** (only when the operator supplies their OWN canary domain
       via ``--ssrf-canary``) injects that benign, externally-controlled URL and
       sends the request, so the operator can confirm a server-side fetch by
       checking their listener logs. The canary MUST be a public host; this tool
       refuses internal/loopback/metadata targets and never crafts such payloads
       itself.

We never point the target at 169.254.169.254, localhost, or private IP ranges.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import List, Optional
from urllib.parse import urlparse

from . import parser
from .parser import InjectionPoint, RequestTemplate
from .scanner import Finding, RequestBudgetError, Scanner

logger = logging.getLogger("sqli_scanner.ssrf")

CWE_SSRF = "CWE-918: Server-Side Request Forgery (SSRF)"
OWASP_SSRF = "OWASP A10:2021 - Server-Side Request Forgery (SSRF)"

REMEDIATION_SSRF = (
    "Validate and allow-list permitted destinations (scheme, host, port) for "
    "any server-side fetch. Resolve and verify the target is not an internal/"
    "loopback/link-local/private address, disable unused URL schemes, block "
    "redirects to internal hosts, and isolate egress with network controls. "
    "Do not send credentials or cloud-metadata-accessible requests based on "
    "user input."
)

# Parameter names that commonly carry URLs/hosts the server may fetch.
_URL_PARAM_NAMES = {
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "redirecturl", "return", "returnurl", "return_url", "next",
    "continue", "callback", "webhook", "feed", "rss", "host", "domain",
    "server", "proxy", "fetch", "load", "open", "site", "target", "image",
    "imageurl", "image_url", "img", "avatar", "document", "out", "forward",
    "remote", "endpoint", "api", "data",
}

_URL_VALUE_RE = re.compile(r"^(https?:)?//|^https?://|^[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)


def _looks_like_url_param(point: InjectionPoint) -> bool:
    """Heuristic: does this parameter accept a URL/host?"""
    name = (point.param_name or "").lower()
    if name in _URL_PARAM_NAMES:
        return True
    if any(tok in name for tok in ("url", "uri", "href", "link", "redirect", "callback", "webhook")):
        return True
    if point.original_value and _URL_VALUE_RE.match(point.original_value.strip()):
        return True
    return False


def is_safe_public_canary(canary: str) -> bool:
    """Reject canaries that resolve to internal/loopback/metadata targets.

    We only allow ordinary public hostnames. Bare IPs and known-internal targets
    are rejected so the tool can never be pointed at an internal service.
    """
    if not canary:
        return False
    parsed = urlparse(canary if "://" in canary else f"http://{canary}")
    host = parsed.hostname or ""
    if not host:
        return False
    # Block the cloud metadata IP explicitly.
    if host in ("169.254.169.254", "metadata.google.internal", "localhost"):
        return False
    # Reject anything that is a literal IP in a private/reserved range.
    try:
        ip = ipaddress.ip_address(host)
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
        # A public literal IP is allowed but discouraged; still permit it.
        return True
    except ValueError:
        # Not an IP literal -> a hostname. Require it to look like a real domain.
        return bool(re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", host, re.IGNORECASE))


def _passive_finding(point: InjectionPoint) -> Finding:
    method, url, _, _, _ = parser.materialize(point, point.original_value)
    return Finding(
        vuln_type="Potential SSRF surface (URL-accepting parameter)",
        url=url,
        param=point.param_name,
        method=method,
        location=point.location,
        confidence="Low",
        risk="Medium",
        category="SSRF",
        evidence=[
            f"Parameter '{point.param_name}' appears to accept a URL/host and "
            "could be abused for SSRF if the server fetches it without "
            "allow-listing.",
            "Reported passively (no server-side fetch was induced). Use a "
            "controlled OAST canary (--ssrf-canary) to confirm safely.",
        ],
        matched_techniques=["url-parameter-heuristic"],
        reproduction=[
            f"Target: {method} {url}",
            f"Review how the server handles the '{point.param_name}' parameter; "
            "determine whether it performs a server-side request to the value.",
            "Confirm only with an external canary you control - never point the "
            "server at internal, loopback, or cloud-metadata addresses.",
        ],
        remediation=REMEDIATION_SSRF,
        cwe=CWE_SSRF,
        owasp=OWASP_SSRF,
        confirmed=False,
    )


def _canary_finding(point: InjectionPoint, canary: str, observed_change: bool) -> Finding:
    method, url, _, _, _ = parser.materialize(point, point.original_value)
    confidence = "Medium" if observed_change else "Low"
    evidence = [
        f"Injected operator-controlled canary URL into '{point.param_name}'.",
        "Check your canary/OAST listener logs for an inbound request from the "
        "target's server IP to confirm SSRF (out-of-band confirmation).",
    ]
    if observed_change:
        evidence.append("Response changed versus baseline, consistent with the "
                        "server processing the supplied URL.")
    return Finding(
        vuln_type="SSRF candidate (canary injected - verify via listener)",
        url=url,
        param=point.param_name,
        method=method,
        location=point.location,
        confidence=confidence,
        risk="High",
        category="SSRF",
        evidence=evidence,
        matched_techniques=["oast-canary-injected"]
        + (["response-differential"] if observed_change else []),
        reproduction=[
            f"Target: {method} {url}",
            f"Set '{point.param_name}' to your public canary URL.",
            "Inspect your canary listener for a callback originating from the "
            "server. A callback confirms SSRF.",
            "Safety: canary is a public host you control; internal/metadata "
            "targets are never used.",
        ],
        remediation=REMEDIATION_SSRF,
        cwe=CWE_SSRF,
        owasp=OWASP_SSRF,
        confirmed=False,  # in-band tool cannot see the OAST callback
    )


def run(scanner: Scanner, templates: List[RequestTemplate],
        canary: Optional[str] = None) -> List[Finding]:
    """Identify URL-accepting params; optionally inject a safe operator canary."""
    findings: List[Finding] = []
    seen = set()

    canary_ok = False
    if canary:
        canary_ok = is_safe_public_canary(canary)
        if not canary_ok:
            logger.warning(
                "Refusing SSRF canary '%s': must be a public hostname (no "
                "internal/loopback/metadata targets). Falling back to passive.",
                canary,
            )

    for template in templates:
        if template.is_unsafe():
            continue
        for point in parser.enumerate_injection_points(template, include_path=False):
            if not _looks_like_url_param(point):
                continue
            key = (point.template.method, point.template.url,
                   point.param_name, point.location)
            if key in seen:
                continue
            seen.add(key)

            if canary_ok:
                # Active (opt-in) safe canary injection with a differential check.
                try:
                    baseline = scanner.probe_point(point, point.original_value)
                    injected = scanner.probe_point(point, canary)
                except RequestBudgetError:
                    logger.warning("Request budget exhausted during SSRF scan.")
                    return findings
                observed_change = bool(
                    baseline and injected
                    and not baseline.metrics.is_similar_to(injected.metrics)
                )
                finding = _canary_finding(point, canary, observed_change)
            else:
                finding = _passive_finding(point)

            findings.append(finding)
            scanner.note_finding(finding)
    return findings
