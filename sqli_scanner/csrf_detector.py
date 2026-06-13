"""
csrf_detector.py
================

Cross-Site Request Forgery (CSRF) detection - PASSIVE and DETECTION ONLY.

This check never submits forms or performs state-changing actions. It inspects
the structure of discovered state-changing requests (HTML POST forms) and flags
those that lack a recognizable anti-CSRF token field. Optionally, when a
``Scanner`` is supplied, it can do a single lightweight GET to inspect cookie
``SameSite`` attributes for additional context.

Findings are reported conservatively (the absence of a token field is a strong
indicator but not absolute proof, since protections such as SameSite cookies or
custom-header requirements may exist), so results are marked for manual
verification.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

from .parser import RequestTemplate
from .scanner import Finding, Scanner

logger = logging.getLogger("sqli_scanner.csrf")

CWE_CSRF = "CWE-352: Cross-Site Request Forgery (CSRF)"
OWASP_CSRF = "OWASP A01:2021 - Broken Access Control (CSRF)"

REMEDIATION_CSRF = (
    "Protect state-changing requests with anti-CSRF tokens (synchronizer token "
    "or double-submit cookie) that are validated server-side. Set session "
    "cookies with SameSite=Lax or Strict, require a custom header for sensitive "
    "actions, and re-authenticate for high-impact operations. Use framework "
    "built-in CSRF protection where available."
)

# Field-name patterns that typically indicate an anti-CSRF token.
_TOKEN_NAME_RE = re.compile(
    r"(csrf|xsrf|_token\b|authenticity_token|requestverificationtoken|"
    r"nonce|anti.?forgery|form.?key|csrfmiddlewaretoken)",
    re.IGNORECASE,
)


def _has_csrf_token(template: RequestTemplate) -> bool:
    """Return True if any body field name looks like an anti-CSRF token."""
    for name in template.body_params:
        if _TOKEN_NAME_RE.search(name or ""):
            return True
    return False


def _cookie_samesite_note(scanner: Optional[Scanner], url: str) -> Optional[str]:
    """Best-effort: GET the URL once and report missing SameSite on cookies."""
    if scanner is None:
        return None
    try:
        resp = scanner.send_full("GET", url, allow_redirects=False)
    except Exception:
        return None
    if resp is None:
        return None
    set_cookie = resp.headers.get("Set-Cookie") or resp.headers.get("set-cookie")
    if not set_cookie:
        return None
    if "samesite" not in set_cookie.lower():
        return "Response set cookies without a SameSite attribute."
    return None


def run(scanner: Optional[Scanner], templates: List[RequestTemplate],
        check_cookies: bool = False) -> List[Finding]:
    """Inspect POST form templates for missing anti-CSRF protections."""
    findings: List[Finding] = []
    seen = set()

    for template in templates:
        # Only state-changing HTML form POSTs are CSRF-relevant. JSON APIs that
        # require a custom content-type are generally not CSRF-able via forms.
        if template.method != "POST":
            continue
        if template.body_type != "urlencoded":
            continue
        if template.is_unsafe():
            # Destructive forms are skipped from active testing elsewhere; we
            # still note them as high-value CSRF targets if missing a token.
            pass

        key = (template.url, tuple(sorted(template.body_params)))
        if key in seen:
            continue
        seen.add(key)

        if _has_csrf_token(template):
            logger.debug("Form at %s appears to include an anti-CSRF token.", template.url)
            continue

        evidence = [
            "State-changing POST form does not contain a recognizable anti-CSRF "
            "token field (e.g. csrf_token, authenticity_token, __RequestVerificationToken).",
            f"Form fields observed: {', '.join(template.body_params) or '(none)'}.",
        ]
        cookie_note = _cookie_samesite_note(scanner, template.url) if check_cookies else None
        confidence = "Medium"
        if cookie_note:
            evidence.append(cookie_note)
            confidence = "High"

        finding = Finding(
            vuln_type="Potential Cross-Site Request Forgery (CSRF)",
            url=template.url,
            param="(form)",
            method="POST",
            location="form",
            confidence=confidence,
            risk="Medium",
            category="CSRF",
            evidence=evidence,
            matched_techniques=["missing-anti-csrf-token"]
            + (["cookie-missing-samesite"] if cookie_note else []),
            reproduction=[
                f"Target: POST {template.url}",
                "Inspect the form markup; note the absence of a server-validated "
                "anti-CSRF token among its fields.",
                "Verify manually that submitting the form cross-origin is not "
                "rejected (do NOT perform a real state-changing submission against "
                "production; use a controlled test account/environment).",
            ],
            remediation=REMEDIATION_CSRF,
            cwe=CWE_CSRF,
            owasp=OWASP_CSRF,
            confirmed=False,  # conservative: requires manual confirmation
        )
        findings.append(finding)
        if scanner is not None:
            scanner.note_finding(finding)
    return findings
