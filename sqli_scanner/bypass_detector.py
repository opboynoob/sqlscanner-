"""
bypass_detector.py
==================

403 / 404 Access-Control Bypass detection - DETECTION ONLY.

When a path returns 401/403/404, web servers and proxies sometimes serve the
restricted resource if the request is lightly mutated (path-normalization
tricks, alternate casing, or rewrite/override headers). This module checks
whether such a bypass is *possible* and reports it so the owner can fix their
access control - it does NOT harvest or dump the protected content (only status
code and response size are compared).

Techniques attempted (all benign GET/HEAD variations):
    * Path tweaks: trailing slash, /./, //, %2e, trailing %20/%09/.json/;/#/?
    * Case variation of the final segment
    * Override headers: X-Original-URL, X-Rewrite-URL, X-Forwarded-For,
      X-Forwarded-Host, X-Custom-IP-Authorization, Referer

A bypass is flagged only when a variant returns a clearly "allowed" response
(2xx) and a meaningfully different body size than the blocked baseline,
confirmed by a repeat.

CWE-284 (Improper Access Control) / OWASP A01:2021.
"""

from __future__ import annotations

import logging
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from . import severity
from .scanner import Finding, RequestBudgetError, Scanner

logger = logging.getLogger("sqli_scanner.bypass")

CWE_BYPASS = "CWE-284: Improper Access Control (403/404 bypass)"
OWASP_BYPASS = severity.OWASP_2021["A01"]

REMEDIATION = (
    "Enforce authorization in the application layer, not only at the proxy/URL "
    "level. Normalize and canonicalize paths before authorization checks, ignore "
    "client-supplied rewrite/override headers (X-Original-URL, X-Rewrite-URL) "
    "unless explicitly trusted, and apply consistent access control across "
    "methods and path variants."
)

# Commonly access-controlled paths to probe (kept small; same host only).
CANDIDATE_PATHS = [
    "/admin", "/admin/", "/administrator", "/manager", "/dashboard",
    "/internal", "/private", "/config", "/api/admin", "/actuator/env",
    "/server-status", "/.git/config", "/user/settings",
]

# Path-based mutations applied to a blocked path.
def _path_variants(path: str) -> List[str]:
    p = path.rstrip("/")
    variants = [
        path + "/", path + "/.", path + "//", "/." + path, path + "/..;/",
        path + "%20", path + "%09", path + "%2e", path + ".json", path + "..;/",
        path + ";/", path + "/~", path + "?", path + "#",
        p.upper() if p else path, p + "/.//",
    ]
    # De-dup while preserving order.
    seen, out = set(), []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


# Header-based bypass attempts (value -> headers dict).
def _header_variants(path: str) -> List[dict]:
    return [
        {"X-Original-URL": path},
        {"X-Rewrite-URL": path},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "127.0.0.1"},
        {"Referer": "/"},
    ]


def _base(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _allowed(resp) -> bool:
    return resp is not None and 200 <= resp.status < 300


def _get(scanner: Scanner, url: str, headers: Optional[dict] = None):
    """A header-capable GET that respects the budget (uses the session directly)."""
    if scanner.stats.requests_sent >= scanner.config.max_requests:
        scanner.stats.budget_exhausted = True
        raise RequestBudgetError("Global request budget exhausted.")
    scanner._reserve_request()
    import time
    time.sleep(scanner.config.delay)
    try:
        resp = scanner.session.get(
            url, timeout=scanner.config.timeout, allow_redirects=False,
            headers=headers or None,
        )
    except Exception as exc:
        logger.debug("bypass GET failed for %s: %s", url, exc)
        return None
    text = resp.text or ""

    class _R:
        status = resp.status_code
        length = len(text)
    return _R()


def _check_path(scanner: Scanner, base: str, path: str) -> Optional[Finding]:
    full = urljoin(base + "/", path.lstrip("/"))
    baseline = _get(scanner, full)
    if baseline is None:
        return None
    # Only meaningful when the resource is actually blocked.
    if baseline.status not in (401, 403, 404):
        return None

    # Try path variants (GET to mutated URL).
    for variant in _path_variants(path):
        vurl = urljoin(base + "/", variant.lstrip("/"))
        r = _get(scanner, vurl)
        if _allowed(r) and r.length != baseline.length:
            confirm = _get(scanner, vurl)
            if _allowed(confirm):
                return _finding(full, baseline, "path-variant", variant, r)

    # Try override/spoof headers against the original path.
    for headers in _header_variants(path):
        r = _get(scanner, full, headers=headers)
        if _allowed(r) and r.length != baseline.length:
            confirm = _get(scanner, full, headers=headers)
            if _allowed(confirm):
                hdr = ", ".join(f"{k}: {v}" for k, v in headers.items())
                return _finding(full, baseline, "override-header", hdr, r)
    return None


def _finding(url, baseline, technique, detail, variant_resp) -> Finding:
    return Finding(
        vuln_type="Access-control bypass (403/404 bypass)",
        url=url,
        param="(path/headers)",
        method="GET",
        location="path",
        confidence="High",
        risk="High",
        category="AccessControlBypass",
        evidence=[
            f"Blocked resource (HTTP {baseline.status}, {baseline.length} bytes) "
            f"became accessible (HTTP {variant_resp.status}, "
            f"{variant_resp.length} bytes) via {technique}: {detail}.",
            "Only status/size were compared; protected content was not read.",
        ],
        matched_techniques=[technique],
        reproduction=[
            f"Baseline: GET {url} -> HTTP {baseline.status} (blocked).",
            f"Bypass: apply {technique} ({detail}) and observe an allowed (2xx) "
            "response for the same resource.",
        ],
        remediation=REMEDIATION,
        cwe=CWE_BYPASS,
        owasp=OWASP_BYPASS,
        confirmed=True,
        severity=severity.derive("High", "High", True),
    )


def run(scanner: Scanner, target_url: str,
        candidate_paths: Optional[List[str]] = None) -> List[Finding]:
    """Probe candidate access-controlled paths for 403/404 bypasses."""
    found: List[Finding] = []
    base = _base(target_url)
    paths = list(dict.fromkeys((candidate_paths or []) + CANDIDATE_PATHS))

    def _worker(path):
        try:
            f = _check_path(scanner, base, path)
        except RequestBudgetError:
            raise
        if f is not None:
            scanner.note_finding(f)
            found.append(f)
        return None

    scanner.parallel_map(paths, _worker)
    return found
