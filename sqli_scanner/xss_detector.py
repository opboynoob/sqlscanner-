"""
xss_detector.py
===============

Reflected Cross-Site Scripting (XSS) detection - DETECTION ONLY.

Approach (non-destructive, no browser, no script execution):
    1. Inject a unique benign marker into a parameter and check whether it is
       reflected in the response at all. If not reflected, the parameter is not
       a reflected-XSS candidate and is skipped (keeps false positives low).
    2. If reflected, inject a benign probe that includes HTML-significant
       characters ( < > " ' ) wrapped around the marker and inspect whether
       those characters survive *unencoded* next to the marker. Unencoded
       reflection of angle brackets or the context-relevant quote is the
       standard, reliable signal that the output is not being encoded.
    3. Classify the reflection context (HTML text / attribute / script / comment)
       for the evidence and remediation guidance.
    4. Confirm by repeating the probe.

We deliberately use harmless probe markers (e.g. ``<kxNNN>`` style tags and bare
quotes) - never real script payloads, event handlers, or anything that would
execute. The goal is to prove output encoding is missing, not to run code.
"""

from __future__ import annotations

import logging
import re
import secrets
from typing import List, Optional, Tuple

from . import parser
from .parser import InjectionPoint, RequestTemplate
from .scanner import Finding, RequestBudgetError, Scanner

logger = logging.getLogger("sqli_scanner.xss")

CWE_XSS = "CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)"
OWASP_XSS = "OWASP A03:2021 - Injection"

REMEDIATION_XSS = (
    "Apply context-aware output encoding for all untrusted data (HTML entity "
    "encoding for HTML text, attribute encoding inside attributes, JavaScript "
    "string encoding inside scripts, URL encoding in URLs). Prefer auto-escaping "
    "template engines, set a strong Content-Security-Policy, use the HttpOnly "
    "flag on session cookies, and validate/allow-list input where possible."
)


def _new_marker() -> str:
    """Return a unique, benign alphanumeric marker token."""
    return "kx" + secrets.token_hex(4)


def _classify_context(body: str, index: int) -> str:
    """Best-effort classification of where the marker was reflected.

    Returns one of: 'script', 'attribute', 'comment', 'html_text'.
    """
    before = body[:index]
    # Inside a <script> block?
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open != -1 and last_script_open > last_script_close:
        return "script"
    # Inside an HTML comment?
    last_comment_open = before.rfind("<!--")
    last_comment_close = before.rfind("-->")
    if last_comment_open != -1 and last_comment_open > last_comment_close:
        return "comment"
    # Inside a tag attribute? (an unclosed '<' tag before the marker)
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt != -1 and last_lt > last_gt:
        return "attribute"
    return "html_text"


def _analyze_reflection(body: str, marker: str) -> Tuple[bool, str]:
    """Return (reflected, context) for a bare marker in the response body."""
    idx = body.find(marker)
    if idx == -1:
        return False, ""
    return True, _classify_context(body, idx)


def test_point(scanner: Scanner, point: InjectionPoint) -> Optional[Finding]:
    """Run reflected-XSS detection against a single injection point."""
    # Only test text-reflective locations (query/body). Path segments are rarely
    # reflected verbatim and add noise.
    if point.location not in ("query", "body"):
        return None
    if point.template.is_unsafe():
        return None

    marker = _new_marker()

    # Step 1: is the marker reflected at all?
    resp = scanner.probe_point(point, f"{point.original_value}{marker}")
    if resp is None:
        return None
    reflected, context = _analyze_reflection(resp.text, marker)
    if not reflected:
        return None

    # Step 2: probe with HTML-significant characters around a benign tag marker.
    # Benign tag <m{marker}> would never appear naturally; bare quotes test
    # attribute/script breakout. No executable payload is used.
    angle_tag = f"<m{marker}>"
    probe_value = f"{point.original_value}{marker}{angle_tag}\"'"
    resp2 = scanner.probe_point(point, probe_value)
    if resp2 is None:
        return None
    body2 = resp2.text

    angle_unencoded = angle_tag in body2          # can introduce new tags
    dquote_unencoded = (marker + angle_tag + "\"") in body2 or f'{angle_tag}"' in body2
    squote_unencoded = f"{angle_tag}'" in body2

    # Re-classify context at the reflection of our probe marker.
    idx2 = body2.find(marker)
    ctx = _classify_context(body2, idx2) if idx2 != -1 else context

    # Decide significance based on context + which characters survived.
    signal = None
    confidence = "Low"
    risk = "Medium"
    confirmed = False

    if angle_unencoded:
        # Unencoded angle brackets => attacker can inject arbitrary tags.
        signal = "unencoded-angle-brackets"
        confidence, risk, confirmed = "High", "High", True
    elif ctx == "attribute" and dquote_unencoded:
        signal = "attribute-quote-breakout"
        confidence, risk, confirmed = "High", "High", True
    elif ctx == "script" and (dquote_unencoded or squote_unencoded):
        signal = "script-context-quote-breakout"
        confidence, risk, confirmed = "High", "High", True
    else:
        # Reflected but special characters appear encoded/neutralized.
        # Report only as a low-confidence possibility (likely safe output
        # encoding); keeps false positives down.
        logger.debug("Param '%s' reflects input but encodes special chars (%s context).",
                     point.param_name, ctx)
        return None

    # Step 3: confirm by repeating the decisive probe.
    confirm_resp = scanner.probe_point(point, probe_value)
    if confirm_resp is None or (angle_tag not in confirm_resp.text
                                and signal == "unencoded-angle-brackets"):
        # Could not reproduce the unencoded reflection; downgrade to possible.
        confirmed = False
        confidence = "Medium" if confidence == "High" else confidence

    method, url, _, _, _ = parser.materialize(point, point.original_value)

    evidence = [
        f"Input reflected unsanitized in '{ctx}' context (signal: {signal}).",
        "Benign probe characters ( < > \" ' ) were returned without HTML/"
        "attribute encoding, indicating missing output encoding.",
    ]
    reproduction = [
        f"Target: {method} {url}",
        f"Parameter: '{point.param_name}' ({point.location}).",
        "Submit a unique marker followed by benign HTML-significant characters "
        "(angle brackets and quotes).",
        f"Observe the marker reflected in the response within a {ctx} context "
        "with those characters left unencoded.",
        "Note: a benign, non-executing probe is used. Do NOT escalate to a "
        "working script payload; report to the application owner for fixing.",
    ]

    return Finding(
        vuln_type="Reflected Cross-Site Scripting (XSS)",
        url=url,
        param=point.param_name,
        method=method,
        location=point.location,
        confidence=confidence,
        risk=risk,
        category="XSS",
        evidence=evidence,
        matched_techniques=["reflection", signal],
        reproduction=reproduction,
        remediation=REMEDIATION_XSS,
        cwe=CWE_XSS,
        owasp=OWASP_XSS,
        confirmed=confirmed,
    )


def run(scanner: Scanner, templates: List[RequestTemplate]) -> List[Finding]:
    """Run reflected-XSS detection across all templates' injection points."""
    found: List[Finding] = []
    seen = set()
    for template in templates:
        if template.is_unsafe():
            continue
        for point in parser.enumerate_injection_points(template, include_path=False):
            key = (point.template.method, point.template.url,
                   point.param_name, point.location)
            if key in seen:
                continue
            seen.add(key)
            try:
                finding = test_point(scanner, point)
            except RequestBudgetError:
                logger.warning("Request budget exhausted during XSS scan.")
                return found
            if finding is not None:
                scanner.note_finding(finding)
                found.append(finding)
    return found
