"""
selftest.py
===========

Offline self-test / demonstration that exercises the full detection pipeline
WITHOUT any network access or third-party packages. It uses small in-memory
"fake" HTTP sessions that simulate deliberately vulnerable (and safe) endpoints,
then runs the real detectors and reporter against them.

Run:
    python3 -m sqli_scanner.selftest

Covers: SQLi, reflected XSS, CSRF, SSRF, and XXE - plus false-positive checks
on safe endpoints. Useful for verifying logic where ``requests`` is unavailable
or there is no authorized live target handy.
"""

from __future__ import annotations

import html as html_lib
import re
import time
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from . import (
    access_control_detector,
    cors_detector,
    csrf_detector,
    headers_detector,
    open_redirect_detector,
    parser,
    reporter,
    ssrf_detector,
    ssti_detector,
    xss_detector,
    xxe_detector,
)
from .parser import RequestTemplate
from .scanner import ScanConfig, Scanner


# ---------------------------------------------------------------------------
# Fake HTTP primitives
# ---------------------------------------------------------------------------
class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, text: str, status_code: int = 200,
                 headers: Optional[Dict[str, str]] = None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}


def _params_from(url, data):
    """Merge query-string and POST body (dict) into a flat param dict."""
    parsed = urlparse(url)
    params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    if data and isinstance(data, dict):
        params.update(data)
    return params


# ---------------------------------------------------------------------------
# SQLi mock
# ---------------------------------------------------------------------------
class FakeSQLiSession:
    """Simulates an app where the 'id' parameter is SQL-injectable."""

    def get(self, url, timeout=None, allow_redirects=False, **kwargs):
        return self._handle(url)

    def post(self, url, data=None, timeout=None, allow_redirects=False, **kwargs):
        return self._handle(url, data)

    def _handle(self, url, data=None) -> FakeResponse:
        value = _params_from(url, data).get("id", "")
        m = re.search(r"SLEEP\((\d+)\)", value, re.IGNORECASE)
        if m:
            time.sleep(min(int(m.group(1)), 6))
            return FakeResponse(self._page("Product 1", rows=1))
        if value.count("'") % 2 == 1 or value.endswith('"'):
            return FakeResponse(
                "<html><body><h1>Error</h1><p>You have an error in your SQL "
                "syntax; check the manual that corresponds to your MySQL server "
                "version for the right syntax near '''' at line 1</p></body></html>",
                status_code=500,
            )
        if re.search(r"1=2", value):
            return FakeResponse(self._page("No products found", rows=0))
        if re.search(r"1=1", value):
            return FakeResponse(self._page("Product 1", rows=1))
        return FakeResponse(self._page("Product 1", rows=1))

    @staticmethod
    def _page(title: str, rows: int) -> str:
        items = "".join(f"<li>Item {i}</li>" for i in range(rows))
        return (f"<html><body><h1>{title}</h1><ul>{items}</ul>"
                f"<p>Static catalog footer content for stability.</p></body></html>")


class FakeSafeSession:
    """A session that always returns the same stable page (no vulnerabilities)."""

    def get(self, url, timeout=None, allow_redirects=False, **kwargs):
        return FakeResponse("<html><body><h1>Welcome</h1>"
                            "<p>Static page.</p></body></html>")

    def post(self, url, data=None, timeout=None, allow_redirects=False, **kwargs):
        return self.get(url)


# ---------------------------------------------------------------------------
# XSS mocks
# ---------------------------------------------------------------------------
class FakeXSSSession:
    """Reflects the 'q' parameter UNENCODED into the HTML body (vulnerable)."""

    def get(self, url, timeout=None, allow_redirects=False, **kwargs):
        return self._handle(url)

    def post(self, url, data=None, timeout=None, allow_redirects=False, **kwargs):
        return self._handle(url, data)

    def _handle(self, url, data=None) -> FakeResponse:
        q = _params_from(url, data).get("q", "")
        return FakeResponse(
            f"<html><body><h1>Search</h1>"
            f"<p>Results for: {q}</p></body></html>"  # raw, unencoded reflection
        )


class FakeSafeXSSSession:
    """Reflects 'q' but HTML-encodes it (safe; should NOT be flagged)."""

    def get(self, url, timeout=None, allow_redirects=False, **kwargs):
        return self._handle(url)

    def post(self, url, data=None, timeout=None, allow_redirects=False, **kwargs):
        return self._handle(url, data)

    def _handle(self, url, data=None) -> FakeResponse:
        q = html_lib.escape(_params_from(url, data).get("q", ""))
        return FakeResponse(f"<html><body><p>Results for: {q}</p></body></html>")


# ---------------------------------------------------------------------------
# XXE mock
# ---------------------------------------------------------------------------
class FakeXXESession:
    """Simulates a permissive XML parser that expands internal entities."""

    def get(self, url, timeout=None, allow_redirects=False, **kwargs):
        return FakeResponse("<r/>")

    def post(self, url, data=None, timeout=None, allow_redirects=False, **kwargs):
        body = data if isinstance(data, str) else ""
        m = re.search(r'<!ENTITY\s+probe\s+"([^"]*)"\s*>', body)
        if m and "&probe;" in body:
            # Expand the entity (parser resolves &probe; to its value) and
            # re-serialize WITHOUT the literal reference.
            value = m.group(1)
            return FakeResponse(f"<r><value>{value}</value></r>")
        # Echo inline marker for the control request.
        m2 = re.search(r"<value>([^<]*)</value>", body)
        if m2:
            return FakeResponse(f"<r><value>{m2.group(1)}</value></r>")
        return FakeResponse("<r/>")


# ---------------------------------------------------------------------------
# Open redirect mock
# ---------------------------------------------------------------------------
class FakeOpenRedirectSession:
    """Redirects (302) to whatever the 'next' parameter says (vulnerable)."""

    def get(self, url, timeout=None, allow_redirects=False, **kwargs):
        params = _params_from(url, None)
        target = params.get("next", "")
        if target.startswith("http") or target.startswith("//"):
            return FakeResponse("", status_code=302, headers={"Location": target})
        return FakeResponse("<html><body>home</body></html>")

    def post(self, url, data=None, timeout=None, allow_redirects=False, **kwargs):
        return self.get(url)


# ---------------------------------------------------------------------------
# SSTI mock
# ---------------------------------------------------------------------------
class FakeSSTISession:
    """Evaluates a {{a*b}} expression in the 'name' parameter (vulnerable)."""

    def get(self, url, timeout=None, allow_redirects=False, **kwargs):
        return self._handle(url)

    def post(self, url, data=None, timeout=None, allow_redirects=False, **kwargs):
        return self._handle(url, data)

    def _handle(self, url, data=None) -> FakeResponse:
        name = _params_from(url, data).get("name", "")
        # Evaluate any {{<int>*<int>}} expression (simulating a template engine).
        rendered = re.sub(r"\{\{(\d+)\*(\d+)\}\}",
                          lambda m: str(int(m.group(1)) * int(m.group(2))), name)
        return FakeResponse(f"<html><body><h1>Hi {rendered}</h1></body></html>")


# ---------------------------------------------------------------------------
# CORS + security-headers mocks
# ---------------------------------------------------------------------------
class FakeCORSSession:
    """Reflects the Origin header and allows credentials (misconfigured)."""

    def get(self, url, timeout=None, allow_redirects=False, headers=None, **kwargs):
        origin = (headers or {}).get("Origin", "")
        return FakeResponse(
            "<html><body>api</body></html>",
            headers={
                "Content-Type": "text/html",
                "Access-Control-Allow-Origin": origin or "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )

    def post(self, url, data=None, timeout=None, allow_redirects=False, **kwargs):
        return self.get(url)


class FakeNoHeadersSession:
    """Returns a page with NO security headers and a weak cookie (vulnerable)."""

    def get(self, url, timeout=None, allow_redirects=False, **kwargs):
        return FakeResponse(
            "<html><body>home</body></html>",
            headers={"Content-Type": "text/html", "Set-Cookie": "session=abc; Path=/"},
        )

    def post(self, url, data=None, timeout=None, allow_redirects=False, **kwargs):
        return self.get(url)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _new_scanner(session) -> Scanner:
    return Scanner(session, ScanConfig(delay=0.0, timeout=8.0, time_delay=2,
                                       confirm_repeats=1, baseline_samples=2))


def _print(name: str, scanner: Scanner, target: str) -> None:
    reporter.print_console_summary(
        target, scanner.findings, scanner.stats,
        {"urls_crawled": 1, "unsafe_skipped": 0}, use_color=False,
    )


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
def main() -> int:  # noqa: C901 - linear test script
    results = []

    # 1) SQLi vulnerable -------------------------------------------------
    print("\n=== Case: SQLi (vulnerable 'id') ===")
    s = _new_scanner(FakeSQLiSession())
    s.scan_templates([parser.build_request_from_url("http://app.local/product?id=1")])
    _print("sqli", s, "http://app.local/product?id=1")
    sqli_ok = any(f.category == "SQLi" and f.confirmed for f in s.findings)
    results.append(("SQLi confirmed on vulnerable app", sqli_ok))

    # 2) SQLi safe (false-positive check) --------------------------------
    print("\n=== Case: SQLi (safe app) ===")
    s = _new_scanner(FakeSafeSession())
    s.scan_templates([parser.build_request_from_url("http://app.local/product?id=1")])
    results.append(("No SQLi on safe app", not any(f.category == "SQLi" for f in s.findings)))

    # 3) XSS vulnerable --------------------------------------------------
    print("\n=== Case: Reflected XSS (vulnerable 'q') ===")
    s = _new_scanner(FakeXSSSession())
    xss_detector.run(s, [parser.build_request_from_url("http://app.local/search?q=hello")])
    _print("xss", s, "http://app.local/search?q=hello")
    results.append(("XSS confirmed on vulnerable app",
                    any(f.category == "XSS" and f.confirmed for f in s.findings)))

    # 4) XSS safe (encoded reflection) -----------------------------------
    print("\n=== Case: Reflected XSS (safe, encoded) ===")
    s = _new_scanner(FakeSafeXSSSession())
    xss_detector.run(s, [parser.build_request_from_url("http://app.local/search?q=hello")])
    results.append(("No XSS when output is encoded",
                    not any(f.category == "XSS" for f in s.findings)))

    # 5) CSRF: form without token ---------------------------------------
    print("\n=== Case: CSRF (POST form missing token) ===")
    s = _new_scanner(FakeSafeSession())
    no_token = RequestTemplate(
        url="http://app.local/comment", method="POST",
        body_params={"comment": "", "author": ""},
        body_type="urlencoded", source="html-form-post",
    )
    csrf_detector.run(s, [no_token])
    _print("csrf", s, "http://app.local/comment")
    results.append(("CSRF flagged on token-less form",
                    any(f.category == "CSRF" for f in s.findings)))

    # 6) CSRF: form WITH token (no finding) ------------------------------
    print("\n=== Case: CSRF (POST form with token) ===")
    s = _new_scanner(FakeSafeSession())
    with_token = RequestTemplate(
        url="http://app.local/comment", method="POST",
        body_params={"comment": "", "csrf_token": "abc123"},
        body_type="urlencoded", source="html-form-post",
    )
    csrf_detector.run(s, [with_token])
    results.append(("No CSRF when token present",
                    not any(f.category == "CSRF" for f in s.findings)))

    # 7) SSRF: passive URL-param identification --------------------------
    print("\n=== Case: SSRF (passive URL parameter) ===")
    s = _new_scanner(FakeSafeSession())
    ssrf_detector.run(
        s, [parser.build_request_from_url("http://app.local/fetch?url=http://example.com/a")]
    )
    _print("ssrf", s, "http://app.local/fetch?url=...")
    results.append(("SSRF surface identified passively",
                    any(f.category == "SSRF" for f in s.findings)))

    # 8) SSRF canary safety: internal targets must be refused ------------
    internal_rejected = (
        not ssrf_detector.is_safe_public_canary("http://169.254.169.254/latest")
        and not ssrf_detector.is_safe_public_canary("http://127.0.0.1:8080")
        and not ssrf_detector.is_safe_public_canary("http://10.0.0.5/")
        and ssrf_detector.is_safe_public_canary("http://canary.example.com/abc")
    )
    results.append(("SSRF canary rejects internal/metadata, allows public", internal_rejected))

    # 9) XXE: internal entity expansion ----------------------------------
    print("\n=== Case: XXE (internal entity expansion) ===")
    s = _new_scanner(FakeXXESession())
    xxe_detector.run(s, "http://app.local/xmlapi")
    _print("xxe", s, "http://app.local/xmlapi")
    results.append(("XXE entity expansion detected",
                    any(f.category == "XXE" and f.confirmed for f in s.findings)))

    # 10) Open redirect --------------------------------------------------
    print("\n=== Case: Open Redirect (vulnerable 'next') ===")
    s = _new_scanner(FakeOpenRedirectSession())
    open_redirect_detector.run(
        s, [parser.build_request_from_url("http://app.local/login?next=/home")])
    _print("openredirect", s, "http://app.local/login?next=/home")
    results.append(("Open redirect detected",
                    any(f.category == "OpenRedirect" and f.confirmed for f in s.findings)))

    # 11) SSTI -----------------------------------------------------------
    print("\n=== Case: SSTI (template eval in 'name') ===")
    s = _new_scanner(FakeSSTISession())
    ssti_detector.run(
        s, [parser.build_request_from_url("http://app.local/greet?name=bob")])
    _print("ssti", s, "http://app.local/greet?name=bob")
    results.append(("SSTI detected",
                    any(f.category == "SSTI" and f.confirmed for f in s.findings)))

    # 12) SSTI safe (no template engine) ---------------------------------
    s = _new_scanner(FakeSafeSession())
    ssti_detector.run(
        s, [parser.build_request_from_url("http://app.local/greet?name=bob")])
    results.append(("No SSTI on non-template app",
                    not any(f.category == "SSTI" for f in s.findings)))

    # 13) CORS misconfiguration ------------------------------------------
    print("\n=== Case: CORS (reflected origin + credentials) ===")
    s = _new_scanner(FakeCORSSession())
    cors_detector.run(s, [parser.build_request_from_url("http://app.local/api")])
    _print("cors", s, "http://app.local/api")
    results.append(("CORS misconfiguration detected",
                    any(f.category == "CORS" for f in s.findings)))

    # 14) Security headers / cookie flags --------------------------------
    print("\n=== Case: Missing security headers ===")
    s = _new_scanner(FakeNoHeadersSession())
    headers_detector.run(s, "http://app.local/")
    _print("headers", s, "http://app.local/")
    results.append(("Missing security headers reported",
                    any(f.category == "SecurityHeaders" for f in s.findings)))

    # 15) IDOR surface (informational) -----------------------------------
    print("\n=== Case: IDOR surface (numeric id) ===")
    s = _new_scanner(FakeSafeSession())
    access_control_detector.run(
        s, [parser.build_request_from_url("http://app.local/account?id=5")])
    _print("idor", s, "http://app.local/account?id=5")
    results.append(("IDOR surface flagged (Info)",
                    any(f.category == "IDOR" for f in s.findings)))

    # --- Summary --------------------------------------------------------
    print("\n" + "=" * 60)
    print("SELF-TEST RESULTS")
    print("=" * 60)
    all_ok = True
    for label, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        all_ok = all_ok and ok
    print("=" * 60)
    print("OVERALL:", "PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
