"""
ssti_detector.py
================

Server-Side Template Injection (SSTI) detection - DETECTION ONLY and SAFE.

Approach (no code execution): inject benign arithmetic wrapped in common
template-expression syntaxes and check whether the *evaluated* result appears in
the response while the raw expression does not. A correct multiplication result
that the attacker did not send is strong evidence the input is rendered by a
server-side template engine.

We use ONLY arithmetic (e.g. ``{{1337*7}}``) bracketed by a unique marker. We do
NOT attempt object traversal, sandbox escapes, config/secret access, or any
code/command execution payloads - those would be exploitation and are excluded.

CWE-1336 / CWE-94 / OWASP A03:2021 (Injection).
"""

from __future__ import annotations

import logging
import secrets
from typing import List, Optional, Tuple

from . import parser, severity
from .parser import InjectionPoint, RequestTemplate
from .scanner import Finding, RequestBudgetError, Scanner

logger = logging.getLogger("sqli_scanner.ssti")

CWE_SSTI = "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine"
OWASP_SSTI = severity.OWASP_2021["A03"]

REMEDIATION = (
    "Never render user input as part of a template. Pass untrusted data only as "
    "template variables/parameters (logic-less context), use auto-escaping, run "
    "templates in a sandboxed engine where possible, and validate/allow-list "
    "input. Keep template libraries patched."
)

# Two factors -> distinctive product that is unlikely to occur by chance.
_A, _B = 1337, 7
_EXPECTED = _A * _B  # 9359

# Common template-expression syntaxes (arithmetic only).
def _payloads(marker: str) -> List[Tuple[str, str]]:
    expr = f"{_A}*{_B}"
    return [
        (f"{marker}{{{{{expr}}}}}{marker}", "Jinja2/Twig/Nunjucks {{ }}"),
        (f"{marker}${{{expr}}}{marker}", "JSP/Freemarker/Thymeleaf ${ }"),
        (f"{marker}#{{{expr}}}{marker}", "Ruby/Thymeleaf #{ }"),
        (f"{marker}<%= {expr} %>{marker}", "ERB/EJS <%= %>"),
        (f"{marker}*{{{expr}}}{marker}", "Thymeleaf *{ }"),
        (f"{marker}@({expr}){marker}", "Razor @( )"),
    ]


def test_point(scanner: Scanner, point: InjectionPoint) -> Optional[Finding]:
    if point.location not in ("query", "body"):
        return None
    if point.template.is_unsafe():
        return None

    marker = "kx" + secrets.token_hex(3)
    expected_str = f"{marker}{_EXPECTED}{marker}"

    for payload, engine_hint in _payloads(marker):
        resp = scanner.probe_point(point, f"{point.original_value}{payload}")
        if resp is None:
            continue
        body = resp.text or ""
        # Evaluated: the product appears between markers AND the raw expression
        # (e.g. "1337*7") is gone -> the engine computed it.
        if expected_str in body and f"{_A}*{_B}" not in body:
            # Confirm by repeating.
            confirm = scanner.probe_point(point, f"{point.original_value}{payload}")
            confirmed = confirm is not None and expected_str in (confirm.text or "")

            method, url, _, _, _ = parser.materialize(point, point.original_value)
            risk = "High"
            sev = severity.derive(risk, "High" if confirmed else "Medium", confirmed)
            return Finding(
                vuln_type="Server-Side Template Injection (SSTI)",
                url=url,
                param=point.param_name,
                method=method,
                location=point.location,
                confidence="High" if confirmed else "Medium",
                risk=risk,
                category="SSTI",
                evidence=[
                    f"A benign template arithmetic expression was evaluated "
                    f"server-side ({_A}*{_B} returned {_EXPECTED}).",
                    f"Likely engine family: {engine_hint}.",
                    "Only arithmetic was used; no code/command execution was "
                    "attempted.",
                ],
                matched_techniques=["template-expression-evaluated"],
                reproduction=[
                    f"Target: {method} {url}",
                    f"Set '{point.param_name}' to a unique marker wrapping a "
                    f"template arithmetic expression (e.g. {{{{{_A}*{_B}}}}}).",
                    f"Observe the response contains the computed product "
                    f"({_EXPECTED}) between the markers, proving template "
                    "evaluation. Stop here; do not escalate to code execution.",
                ],
                remediation=REMEDIATION,
                cwe=CWE_SSTI,
                owasp=OWASP_SSTI,
                confirmed=confirmed,
                severity=sev,
            )
    return None


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
                logger.warning("Request budget exhausted during SSTI scan.")
                return found
            if finding is not None:
                scanner.note_finding(finding)
                found.append(finding)
    return found
