"""
info_disclosure_detector.py
===========================

Information Disclosure / Exposed Sensitive Path detection - DETECTION ONLY.

This module helps a site owner find data that should not be publicly reachable:

    1. **Exposed sensitive paths** - probes a bounded list of commonly-leaked
       files/endpoints (e.g. /.env, /.git/config, /server-status, backups) on
       the SAME host and reports any that are reachable.
    2. **Sensitive content patterns** - scans response bodies/headers for
       indicators such as stack traces, directory listings, server banners, and
       secret-looking tokens (AWS keys, private keys, JWTs, api_key=...).

Safety / ethics:
    * Same-host only; GET requests only.
    * It reports *that* something is exposed - it does NOT exfiltrate data.
      Any matched secret is REDACTED in the evidence (only a short, masked hint
      is shown) so the report itself does not leak the secret.
    * Subject to the global request budget and delay.

CWE-200 (Exposure of Sensitive Information) / OWASP A05:2021.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from . import severity
from .scanner import Finding, RequestBudgetError, Scanner

logger = logging.getLogger("sqli_scanner.infodisc")

CWE_INFO = "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
OWASP_INFO = severity.OWASP_2021["A05"]

REMEDIATION_PATH = (
    "Remove or block public access to sensitive files and management endpoints. "
    "Do not deploy VCS metadata (.git/.svn), environment files, backups, or "
    "debug/status endpoints to production. Enforce authentication and restrict "
    "by network where appropriate, and return 404 for non-public resources."
)
REMEDIATION_CONTENT = (
    "Disable verbose error pages/stack traces and directory listing in "
    "production, strip server/version banners, and never embed secrets (keys, "
    "tokens, credentials) in responses or client-side code. Rotate any exposed "
    "secret immediately."
)

# Bounded list of commonly-exposed sensitive paths.
SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.backup", "/.git/config", "/.git/HEAD",
    "/.gitignore", "/.svn/entries", "/.hg/", "/.DS_Store",
    "/config.php.bak", "/config.bak", "/wp-config.php.bak", "/web.config",
    "/composer.json", "/composer.lock", "/package.json", "/yarn.lock",
    "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/database.sql", "/dump.sql",
    "/server-status", "/server-info", "/phpinfo.php", "/info.php",
    "/actuator", "/actuator/health", "/actuator/env", "/metrics",
    "/debug", "/trace", "/.well-known/security.txt",
    "/admin/", "/administrator/", "/.htaccess", "/.htpasswd",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/.aws/credentials",
    "/id_rsa", "/.ssh/id_rsa", "/credentials.json", "/secrets.yaml",
]

# Content-pattern signatures (compiled). Each: (name, regex, severity).
_CONTENT_SIGNATURES = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "High"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"), "High"),
    ("JSON Web Token", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "Medium"),
    ("Generic API key/secret assignment",
     re.compile(r"(?i)(api[_-]?key|secret|access[_-]?token|client[_-]?secret)['\"]?\s*[:=]\s*['\"][^'\"]{8,}"), "Medium"),
    ("Directory listing", re.compile(r"<title>Index of /|Directory listing for /"), "Medium"),
    ("Stack trace / debug",
     re.compile(r"Traceback \(most recent call last\)|Exception in thread|"
                r"java\.lang\.[A-Za-z.]+Exception|at [\w.$]+\([\w.]+\.java:\d+\)|"
                r"Whoops, looks like something went wrong|Warning: .* in .* on line \d+"), "Medium"),
    ("Private IP address", re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"), "Low"),
]


def _redact(secret: str) -> str:
    """Mask a matched secret so the report does not itself leak it."""
    s = secret.strip()
    if len(s) <= 8:
        return s[:2] + "***"
    return f"{s[:4]}...{s[-2:]} (len {len(s)}, redacted)"


def _base(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _looks_present(resp) -> bool:
    """A path is 'exposed' if it returns 2xx with non-trivial, non-error body."""
    if resp is None:
        return False
    if resp.status not in (200, 206):
        return False
    # Avoid generic SPA/200 catch-alls: require some content and not an obvious
    # "not found" page rendered with status 200.
    body = (resp.text or "")
    if len(body) < 1 and resp.status != 200:
        return False
    lowered = body.lower()
    if "not found" in lowered and len(body) < 600:
        return False
    return True


def _path_finding(base_url: str, path: str, resp) -> Finding:
    full = urljoin(base_url, path)
    sev = "Medium"
    # Elevate clearly-sensitive items.
    if any(t in path for t in (".env", ".git", "id_rsa", ".ssh", "credentials",
                               ".aws", ".htpasswd", "dump.sql", "database.sql",
                               "db.sql", "actuator/env")):
        sev = "High"
    elif path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        sev = "Info"
    return Finding(
        vuln_type=f"Exposed sensitive path: {path}",
        url=full,
        param="(path)",
        method="GET",
        location="path",
        confidence="High",
        risk=sev,
        category="InfoDisclosure",
        evidence=[
            f"Path '{path}' is publicly reachable (HTTP {resp.status}, "
            f"{resp.metrics.length} bytes).",
            "Existence is reported; contents were not exfiltrated.",
        ],
        matched_techniques=["exposed-path"],
        reproduction=[
            f"Request: GET {full}",
            f"Observe an accessible response (HTTP {resp.status}) for a resource "
            "that should not be publicly served.",
        ],
        remediation=REMEDIATION_PATH,
        cwe=CWE_INFO,
        owasp=OWASP_INFO,
        confirmed=(sev in ("High", "Medium")),
        severity=severity.derive(sev, "High", sev in ("High", "Medium")),
    )


def _scan_content(scanner: Scanner, url: str, resp) -> List[Finding]:
    findings: List[Finding] = []
    haystack = (resp.text or "")
    header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    # Server/version banner disclosure.
    server = resp.headers.get("Server") or resp.headers.get("server")
    powered = resp.headers.get("X-Powered-By") or resp.headers.get("x-powered-by")
    if server and re.search(r"\d", server or ""):
        findings.append(_content_finding(
            url, "Verbose Server banner", f"Server: {server}", "Low"))
    if powered:
        findings.append(_content_finding(
            url, "X-Powered-By technology disclosure", f"X-Powered-By: {powered}", "Low"))

    for name, pattern, sev in _CONTENT_SIGNATURES:
        m = pattern.search(haystack) or pattern.search(header_blob)
        if m:
            sample = _redact(m.group(0))
            findings.append(_content_finding(url, name, sample, sev))
    return findings


def _content_finding(url: str, name: str, sample: str, sev: str) -> Finding:
    is_secret = sev == "High"
    return Finding(
        vuln_type=f"Information disclosure: {name}",
        url=url,
        param="(response body/headers)",
        method="GET",
        location="header" if "banner" in name.lower() or "Powered" in name else "body",
        confidence="High",
        risk=sev,
        category="InfoDisclosure",
        evidence=[
            f"Response exposes {name}.",
            f"Indicator (redacted): {sample}",
        ],
        matched_techniques=[f"content:{name.lower().replace(' ', '-')}"],
        reproduction=[
            f"Request: GET {url}",
            f"Observe {name} present in the response (redacted in this report).",
        ],
        remediation=REMEDIATION_CONTENT,
        cwe=CWE_INFO,
        owasp=OWASP_INFO,
        confirmed=is_secret or sev == "Medium",
        severity=severity.derive(sev, "High", is_secret or sev == "Medium"),
    )


def run(scanner: Scanner, target_url: str,
        extra_urls: Optional[List[str]] = None) -> List[Finding]:
    """Probe sensitive paths and scan content for disclosure indicators."""
    found: List[Finding] = []
    base = _base(target_url)

    # 1) Content scan of the target (and any extra URLs already in scope).
    content_targets = [target_url] + list(extra_urls or [])
    seen_ct = set()

    def _content_worker(u):
        if u in seen_ct:
            return None
        seen_ct.add(u)
        try:
            resp = scanner.send_full("GET", u, allow_redirects=False)
        except RequestBudgetError:
            raise
        if resp is None:
            return None
        for f in _scan_content(scanner, u, resp):
            scanner.note_finding(f)
            found.append(f)
        return None

    scanner.parallel_map(content_targets, _content_worker)

    # 2) Sensitive path probing.
    def _path_worker(path):
        full = urljoin(base + "/", path.lstrip("/"))
        try:
            resp = scanner.send_full("GET", full, allow_redirects=False)
        except RequestBudgetError:
            raise
        if _looks_present(resp):
            f = _path_finding(base + "/", path, resp)
            scanner.note_finding(f)
            found.append(f)
            # Also content-scan exposed files for secrets.
            for cf in _scan_content(scanner, full, resp):
                scanner.note_finding(cf)
                found.append(cf)
        return None

    scanner.parallel_map(SENSITIVE_PATHS, _path_worker)
    return found
