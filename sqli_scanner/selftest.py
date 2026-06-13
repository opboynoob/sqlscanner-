"""
selftest.py
===========

Offline self-test / demonstration that exercises the detection pipeline WITHOUT
any network access or third-party packages. It uses a small in-memory "fake"
HTTP server (a mock session) that simulates a deliberately vulnerable endpoint,
then runs the real Scanner and Reporter against it.

Run:
    python3 -m sqli_scanner.selftest

This is useful for verifying the tool's logic in environments where ``requests``
is unavailable or where there is no authorized live target handy.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from . import detector, parser, reporter
from .parser import RequestTemplate
from .scanner import ScanConfig, Scanner


# ---------------------------------------------------------------------------
# A tiny fake HTTP response / session
# ---------------------------------------------------------------------------
class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, text: str, status_code: int = 200,
                 headers: Optional[Dict[str, str]] = None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}


class FakeVulnerableSession:
    """Simulates an app where the 'id' query parameter is SQL-injectable.

    Behavior:
      * Baseline (numeric id) -> normal product page.
      * A single quote -> MySQL error message (error-based signal).
      * ' AND 1=1 (true) -> normal page; ' AND 1=2 (false) -> empty results
        (boolean-based signal).
      * SLEEP(n) -> sleeps n seconds (time-based signal).
    Other parameters behave normally (no injection) to verify low false
    positives.
    """

    def get(self, url, timeout=None, allow_redirects=False, **kwargs):
        return self._handle(url)

    def post(self, url, data=None, timeout=None, allow_redirects=False, **kwargs):
        # Fold POST body into the same handler for simplicity.
        return self._handle(url, data)

    # -- internal ------------------------------------------------------
    def _handle(self, url, data=None) -> FakeResponse:
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        if data and isinstance(data, dict):
            params.update(data)

        value = params.get("id", "")

        # Time-based: honor a SLEEP(n) payload with a bounded real sleep.
        m = re.search(r"SLEEP\((\d+)\)", value, re.IGNORECASE)
        if m:
            time.sleep(min(int(m.group(1)), 6))
            return FakeResponse(self._page("Product 1", rows=1))

        # Error-based: an unbalanced quote triggers a DB error.
        if value.count("'") % 2 == 1 or value.endswith("\""):
            body = (
                "<html><body><h1>Error</h1>"
                "<p>You have an error in your SQL syntax; check the manual that "
                "corresponds to your MySQL server version for the right syntax "
                "near '''' at line 1</p></body></html>"
            )
            return FakeResponse(body, status_code=500)

        # Boolean-based: TRUE keeps rows, FALSE empties them.
        if re.search(r"1=2", value):
            return FakeResponse(self._page("No products found", rows=0))
        if re.search(r"1=1", value):
            return FakeResponse(self._page("Product 1", rows=1))

        # Default baseline page (stable).
        return FakeResponse(self._page("Product 1", rows=1))

    @staticmethod
    def _page(title: str, rows: int) -> str:
        items = "".join(f"<li>Item {i}</li>" for i in range(rows))
        return (
            f"<html><body><h1>{title}</h1><ul>{items}</ul>"
            f"<p>Static catalog footer content for stability.</p></body></html>"
        )


class FakeSafeSession(FakeVulnerableSession):
    """A session that is NOT injectable (used to confirm no false positives)."""

    def _handle(self, url, data=None) -> FakeResponse:
        # Always return the same stable page regardless of input.
        return FakeResponse(self._page("Product 1", rows=1))


def _run_case(name: str, session, template: RequestTemplate) -> int:
    print(f"\n=== Self-test case: {name} ===")
    scanner = Scanner(
        session,
        ScanConfig(delay=0.0, timeout=8.0, time_delay=2, confirm_repeats=1,
                   baseline_samples=2),
    )
    findings = scanner.scan_templates([template])
    crawl_info = {"urls_crawled": 1, "unsafe_skipped": 0}
    reporter.print_console_summary(
        template.url, findings, scanner.stats, crawl_info, use_color=False
    )
    return len([f for f in findings if f.confirmed])


def main() -> int:
    # Case 1: vulnerable 'id' parameter -> expect at least one confirmed finding.
    vuln_template = parser.build_request_from_url("http://testapp.local/product?id=1")
    confirmed = _run_case("Vulnerable endpoint (id)", FakeVulnerableSession(), vuln_template)

    # Case 2: safe endpoint -> expect zero findings (false-positive check).
    safe_template = parser.build_request_from_url("http://testapp.local/product?id=1")
    safe_confirmed = _run_case("Safe endpoint (no SQLi)", FakeSafeSession(), safe_template)

    print("\n----------------------------------------------------------")
    ok = confirmed >= 1 and safe_confirmed == 0
    print(f"Vulnerable case confirmed findings : {confirmed} (expected >= 1)")
    print(f"Safe case confirmed findings       : {safe_confirmed} (expected 0)")
    print("SELF-TEST RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
