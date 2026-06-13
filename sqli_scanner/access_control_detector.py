"""
access_control_detector.py
==========================

Broken Access Control / IDOR *surface* identification - INFORMATIONAL and SAFE.

True Insecure Direct Object Reference (IDOR) confirmation requires comparing
responses across multiple authenticated identities, which cannot be done safely
or reliably by an unattended scanner without risking unauthorized data access.
Therefore this module does NOT attempt to access other users' objects.

Instead it passively flags object-reference parameters (numeric IDs, UUID/hash
-like values in query, body, or path) as candidates that a tester should review
manually for authorization enforcement. Findings are reported at Info severity.

CWE-639 (Authorization Bypass Through User-Controlled Key) / OWASP A01:2021.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

from . import parser, severity
from .parser import InjectionPoint, RequestTemplate
from .scanner import Finding, Scanner

logger = logging.getLogger("sqli_scanner.idor")

CWE_IDOR = "CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)"
OWASP_IDOR = severity.OWASP_2021["A01"]

REMEDIATION = (
    "Enforce object-level authorization on every request: verify the "
    "authenticated principal owns or may access the referenced object before "
    "returning it. Prefer unguessable identifiers, but never rely on them as the "
    "sole control. Add automated access-control tests."
)

_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HASHLIKE_RE = re.compile(r"^[0-9a-f]{16,64}$", re.I)
# Parameter names that often reference objects.
_ID_NAME_RE = re.compile(r"(^id$|_id$|^uid$|user|account|order|invoice|doc|file|"
                         r"object|record|item|profile|customer|ticket|msg|message)",
                         re.IGNORECASE)


def _looks_like_object_ref(point: InjectionPoint) -> Optional[str]:
    """Return a short reason string if the point looks like an object reference."""
    name = point.param_name or ""
    value = (point.original_value or "").strip()
    if point.location == "path" and (_NUMERIC_RE.match(value) or _UUID_RE.match(value)):
        return "numeric/UUID path segment"
    if _ID_NAME_RE.search(name):
        return f"identifier-like parameter name '{name}'"
    if _NUMERIC_RE.match(value):
        return "numeric value"
    if _UUID_RE.match(value):
        return "UUID value"
    if _HASHLIKE_RE.match(value):
        return "hash-like value"
    return None


def run(scanner: Scanner, templates: List[RequestTemplate]) -> List[Finding]:
    found: List[Finding] = []
    seen = set()
    for template in templates:
        if template.is_unsafe():
            continue
        for point in parser.enumerate_injection_points(template, include_path=True):
            reason = _looks_like_object_ref(point)
            if not reason:
                continue
            key = (point.template.method, point.template.url, point.param_name, point.location)
            if key in seen:
                continue
            seen.add(key)

            method, url, _, _, _ = parser.materialize(point, point.original_value)
            finding = Finding(
                vuln_type="Access-control review candidate (potential IDOR)",
                url=url,
                param=point.param_name,
                method=method,
                location=point.location,
                confidence="Low",
                risk="Informational",
                category="IDOR",
                evidence=[
                    f"Parameter '{point.param_name}' references an object "
                    f"({reason}); verify server-side authorization.",
                    "Reported as informational only - no other identity's data "
                    "was accessed. Confirm manually with multiple test accounts.",
                ],
                matched_techniques=["object-reference-heuristic"],
                reproduction=[
                    f"Target: {method} {url}",
                    f"As an authorized tester with two accounts, change "
                    f"'{point.param_name}' to an object owned by another account "
                    "and verify the request is denied.",
                    "Do NOT access data you are not authorized to view.",
                ],
                remediation=REMEDIATION,
                cwe=CWE_IDOR,
                owasp=OWASP_IDOR,
                confirmed=False,
                severity="Info",
            )
            found.append(finding)
            scanner.note_finding(finding)
    return found
