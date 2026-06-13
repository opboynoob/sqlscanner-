"""
cors_detector.py
================

Cross-Origin Resource Sharing (CORS) misconfiguration detection - SAFE.

Sends a request with a crafted, attacker-style ``Origin`` header (a benign
reserved example domain) and inspects the CORS response headers. It flags:

    * Reflected arbitrary origin in ``Access-Control-Allow-Origin`` (ACAO)
      together with ``Access-Control-Allow-Credentials: true`` (the most
      dangerous combination).
    * ACAO reflecting an arbitrary origin without credentials.
    * Wildcard ``ACAO: *`` combined with credentials (invalid but sometimes
      mishandled).
    * ``null`` origin acceptance.

No data is read and no cross-origin request is actually performed by a victim;
this only inspects how the server *advertises* its CORS policy.

CWE-942 (Permissive Cross-domain Policy) / OWASP A05:2021.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from . import severity
from .parser import RequestTemplate
from .scanner import Finding, RequestBudgetError, Scanner

logger = logging.getLogger("sqli_scanner.cors")

CWE_CORS = "CWE-942: Permissive Cross-domain Policy with Untrusted Domains"
OWASP_CORS = severity.OWASP_2021["A05"]

REMEDIATION = (
    "Do not reflect the Origin header into Access-Control-Allow-Origin. Maintain "
    "a strict server-side allow-list of trusted origins, avoid combining "
    "credentialed responses with a wildcard, never trust the 'null' origin, and "
    "scope CORS narrowly to endpoints that require it."
)

_EVIL_ORIGIN = "https://cors-check.example"


def _evaluate(scanner: Scanner, url: str) -> Optional[Finding]:
    """Issue an Origin-bearing GET via the session and evaluate CORS headers."""
    if scanner.stats.requests_sent >= scanner.config.max_requests:
        scanner.stats.budget_exhausted = True
        raise RequestBudgetError("Global request budget exhausted.")
    try:
        import time
        time.sleep(scanner.config.delay)
        resp = scanner.session.get(
            url, timeout=scanner.config.timeout, allow_redirects=False,
            headers={"Origin": _EVIL_ORIGIN},
        )
    except Exception as exc:
        logger.debug("CORS request failed for %s: %s", url, exc)
        scanner.stats.requests_sent += 1
        return None
    scanner.stats.requests_sent += 1

    headers = {k.lower(): v for k, v in getattr(resp, "headers", {}).items()}
    acao = headers.get("access-control-allow-origin")
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    if not acao:
        return None

    creds = acac == "true"
    risk = "Low"
    confidence = "High"
    technique = None
    detail = None

    if acao.strip() == _EVIL_ORIGIN and creds:
        technique, detail = "reflected-origin-with-credentials", (
            "Server reflected an arbitrary Origin into ACAO AND allows "
            "credentials - cross-origin reading of authenticated responses.")
        risk = "High"
    elif acao.strip() == _EVIL_ORIGIN:
        technique, detail = "reflected-origin", (
            "Server reflected an arbitrary Origin into ACAO (no credentials).")
        risk = "Medium"
    elif acao.strip() == "null":
        technique, detail = "null-origin-allowed", (
            "Server allows the 'null' origin, abusable from sandboxed iframes/"
            "redirects.")
        risk = "Medium"
    elif acao.strip() == "*" and creds:
        technique, detail = "wildcard-with-credentials", (
            "Wildcard ACAO combined with credentials (mishandled permissive "
            "policy).")
        risk = "Medium"
    else:
        return None

    confirmed = risk in ("High", "Medium") and technique in (
        "reflected-origin-with-credentials", "reflected-origin")
    sev = severity.derive(risk, confidence, confirmed)

    return Finding(
        vuln_type="CORS Misconfiguration",
        url=url,
        param="(Origin header)",
        method="GET",
        location="header",
        confidence=confidence,
        risk=risk,
        category="CORS",
        evidence=[
            detail,
            f"Observed Access-Control-Allow-Origin: {acao}"
            + (f"; Access-Control-Allow-Credentials: {acac}" if acac else ""),
        ],
        matched_techniques=[technique],
        reproduction=[
            f"Target: GET {url}",
            f"Send header 'Origin: {_EVIL_ORIGIN}'.",
            "Inspect the Access-Control-Allow-Origin / -Allow-Credentials "
            "response headers reflecting/permitting the untrusted origin.",
        ],
        remediation=REMEDIATION,
        cwe=CWE_CORS,
        owasp=OWASP_CORS,
        confirmed=confirmed,
        severity=sev,
    )


def run(scanner: Scanner, templates: List[RequestTemplate]) -> List[Finding]:
    found: List[Finding] = []
    seen = set()
    for template in templates:
        url = template.url
        if url in seen:
            continue
        seen.add(url)
        try:
            finding = _evaluate(scanner, url)
        except RequestBudgetError:
            logger.warning("Request budget exhausted during CORS scan.")
            return found
        if finding is not None:
            scanner.note_finding(finding)
            found.append(finding)
    return found
