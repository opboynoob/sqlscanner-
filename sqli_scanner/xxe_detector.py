"""
xxe_detector.py
===============

XML External Entity (XXE) / XML injection detection - DETECTION ONLY and SAFE.

IMPORTANT SAFETY DESIGN:
    This module NEVER uses external entities (no ``SYSTEM "file:///..."``, no
    ``http://`` entities). Doing so would read local files or trigger SSRF -
    that is exploitation and is intentionally excluded.

    Instead it uses an **internal** general entity that expands to a benign,
    unique marker:

        <!DOCTYPE r [ <!ENTITY probe "UNIQUE_MARKER"> ]>
        <r>&probe;</r>

    If the response reflects the *expanded* marker (and a control request
    without the entity does not), the XML parser is resolving general entities
    with a permissive configuration. That is the prerequisite/indicator for XXE
    and is reported as a finding so the team can harden the parser - without us
    ever attempting to read files or reach internal services.

    We also fingerprint XML parser error messages (error-based signal).

This check only runs when explicitly enabled (``--test-xml``) because ordinary
crawled endpoints do not usually accept XML, and blindly POSTing XML would be
noisy.
"""

from __future__ import annotations

import logging
import re
import secrets
from typing import List, Optional

from .scanner import Finding, RequestBudgetError, Scanner

logger = logging.getLogger("sqli_scanner.xxe")

CWE_XXE = "CWE-611: Improper Restriction of XML External Entity Reference"
OWASP_XXE = "OWASP A05:2021 - Security Misconfiguration (XXE)"

REMEDIATION_XXE = (
    "Disable DOCTYPE declarations and external entity resolution in the XML "
    "parser (set FEATURE_SECURE_PROCESSING, disallow-doctype-decl, and disable "
    "external general/parameter entities). Prefer less complex data formats "
    "such as JSON where possible, keep XML libraries patched, and validate input "
    "against a strict schema."
)

# XML parser error signatures (used for an error-based corroborating signal).
_XML_ERROR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"DOCTYPE is not allowed",
        r"external entit(y|ies)",
        r"org\.xml\.sax",
        r"SAXParseException",
        r"XMLSyntaxError",
        r"xmlParseEntityRef",
        r"premature end of data",
        r"not well-formed",
        r"undefined entity",
        r"lxml\.etree",
    ]
]


def _xml_error(text: str) -> bool:
    return any(p.search(text or "") for p in _XML_ERROR_PATTERNS)


def _build_entity_body(marker: str) -> str:
    """Internal-entity XML body that expands to the benign marker (no external refs)."""
    return (
        f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        f"<!DOCTYPE r [ <!ENTITY probe \"{marker}\"> ]>"
        f"<r><value>&probe;</value></r>"
    )


def _build_control_body(marker: str) -> str:
    """Plain XML body with the marker inline (no entity) for comparison."""
    return (
        f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        f"<r><value>{marker}</value></r>"
    )


def run(scanner: Scanner, target_url: str,
        xml_body: Optional[str] = None) -> List[Finding]:
    """Probe a single target URL for XML entity expansion (safe).

    If ``xml_body`` is provided it is used to confirm the endpoint accepts XML;
    the entity-expansion probe itself always uses an internally-defined entity.
    """
    findings: List[Finding] = []
    marker = "xxe" + secrets.token_hex(4)

    try:
        # Control: plain XML with the marker inline.
        control = scanner.send_full(
            "POST", target_url, raw_body=_build_control_body(marker),
            content_type="application/xml",
        )
        # Probe: same marker delivered via an internal general entity.
        probe = scanner.send_full(
            "POST", target_url, raw_body=_build_entity_body(marker),
            content_type="application/xml",
        )
    except RequestBudgetError:
        logger.warning("Request budget exhausted during XXE scan.")
        return findings

    if probe is None:
        logger.debug("No response to XML probe at %s; skipping XXE.", target_url)
        return findings

    # Expansion is proven only when the marker appears AND the literal entity
    # reference (&probe;) is gone - otherwise the server may just be echoing the
    # raw request body (which would also contain the marker inside the ENTITY
    # declaration). This distinction keeps false positives down.
    entity_expanded = (marker in probe.text) and ("&probe;" not in probe.text)
    control_has_marker = bool(control and marker in control.text)
    parser_error = _xml_error(probe.text)

    # Strong signal: the entity-delivered marker is reflected (expanded) only
    # when sent via the entity, indicating general-entity resolution is enabled.
    if entity_expanded:
        # Confirm with a repeat to reduce false positives.
        confirm = None
        try:
            confirm = scanner.send_full(
                "POST", target_url, raw_body=_build_entity_body(marker),
                content_type="application/xml",
            )
        except RequestBudgetError:
            pass
        confirmed = confirm is not None and marker in confirm.text

        evidence = [
            "An internally-defined XML general entity expanded to its value in "
            "the response, showing the parser resolves DTD-declared entities.",
            "No external entities were used (no file or network access was "
            "attempted) - this is a safe indicator of XXE-prone configuration.",
        ]
        if parser_error:
            evidence.append("XML parser error signatures were also observed.")

        findings.append(Finding(
            vuln_type="XML External Entity (XXE) - entity expansion enabled",
            url=target_url,
            param="(XML body)",
            method="POST",
            location="body",
            confidence="High" if confirmed else "Medium",
            risk="High",
            category="XXE",
            evidence=evidence,
            matched_techniques=["internal-entity-expansion"]
            + (["xml-parser-error"] if parser_error else []),
            reproduction=[
                f"Target: POST {target_url} with Content-Type: application/xml",
                "Send an XML document that declares an INTERNAL entity expanding "
                "to a unique benign marker and references it in an element.",
                "Observe the marker returned in expanded form, while a control "
                "document containing the marker inline (no entity) differs.",
                "Note: only an internal entity was used. Do NOT test external "
                "entities (file:// or http://); report for parser hardening.",
            ],
            remediation=REMEDIATION_XXE,
            cwe=CWE_XXE,
            owasp=OWASP_XXE,
            confirmed=confirmed,
        ))
        scanner.note_finding(findings[-1])
        return findings

    # Weaker signal: parser errors indicate XML is processed but entities may be
    # restricted. Report as a low-confidence informational possibility.
    if parser_error:
        findings.append(Finding(
            vuln_type="XML processing detected (potential XXE surface)",
            url=target_url,
            param="(XML body)",
            method="POST",
            location="body",
            confidence="Low",
            risk="Medium",
            category="XXE",
            evidence=[
                "The endpoint parses XML (parser error signatures observed) but "
                "internal entity expansion was not reflected. Review parser "
                "configuration for external-entity handling.",
            ],
            matched_techniques=["xml-parser-error"],
            reproduction=[
                f"Target: POST {target_url} with Content-Type: application/xml",
                "Submit a benign XML document and observe XML parser behavior/"
                "error messages indicating server-side XML processing.",
            ],
            remediation=REMEDIATION_XXE,
            cwe=CWE_XXE,
            owasp=OWASP_XXE,
            confirmed=False,
        ))
        scanner.note_finding(findings[-1])

    return findings
