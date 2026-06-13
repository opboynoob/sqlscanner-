"""
main.py
=======

Command-line entry point for the defensive web vulnerability detection scanner.

Usage:
    python3 -m sqli_scanner.main "https://target.example.com/page?id=1"

The user supplies ONE target URL; the tool discovers and tests parameters
automatically (query string, forms, JSON body if provided, path-like values),
crawling the same host within a safe depth limit, and runs detection-only checks
for SQL injection, reflected XSS, CSRF, SSRF, and (opt-in) XXE.

AUTHORIZED USE ONLY. Only run against systems you own or are explicitly
permitted to test.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Dict, List, Optional
from urllib.parse import urlparse

from . import parser as param_parser
from . import reporter
from . import xss_detector, xxe_detector, csrf_detector, ssrf_detector
from . import (
    open_redirect_detector,
    ssti_detector,
    cors_detector,
    headers_detector,
    access_control_detector,
)
from .crawler import Crawler, CrawlConfig
from .scanner import Scanner, ScanConfig

LOG = logging.getLogger("sqli_scanner")

ALL_CHECKS = ("sqli", "xss", "csrf", "ssrf", "xxe", "openredirect", "ssti",
              "cors", "headers", "idor")
# xxe and idor are opt-in (XXE needs an XML endpoint; IDOR is informational).
DEFAULT_CHECKS = ("sqli", "xss", "csrf", "ssrf", "openredirect", "ssti",
                  "cors", "headers")

BANNER = r"""
  __        __   _    ____                  _   _      _
  \ \      / /__| |__/ ___|  ___ __ _ _ __ | \ | | ___| |_
   \ \ /\ / / _ \ '_ \___ \ / __/ _` | '_ \|  \| |/ _ \ __|
    \ V  V /  __/ |_) |__) | (_| (_| | | | | |\  |  __/ |_
     \_/\_/ \___|_.__/____/ \___\__,_|_| |_|_| \_|\___|\__|
   Defensive Web Vulnerability Detection Scanner v3.0
   SQLi | XSS | XXE | CSRF | SSRF | Open Redirect | SSTI
        | CORS | Security Headers | IDOR surface
   ---------------------------------------------------
   AUTHORIZED SECURITY TESTING ONLY. Detection-only:
   no data extraction, no exploitation, no WAF bypass.
"""


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    p = argparse.ArgumentParser(
        prog="sqli_scanner",
        description="Defensive, detection-only web vulnerability scanner for "
                    "authorized VAPT. Discovers and safely tests parameters for "
                    "a single target URL across SQLi, XSS, XXE, CSRF and SSRF.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="AUTHORIZED USE ONLY. You are responsible for ensuring you have "
               "permission to test the target.",
    )
    p.add_argument("url", help="Single target URL (include scheme, e.g. https://...)")

    # Check selection
    p.add_argument("--checks", default=None,
                   help="Comma-separated subset of checks to run (choices: "
                        "sqli,xss,csrf,ssrf,xxe,openredirect,ssti,cors,headers,idor). "
                        "Default: sqli,xss,csrf,ssrf,openredirect,ssti,cors,headers "
                        "(xxe and idor are opt-in).")
    p.add_argument("--ssrf-canary", default=None,
                   help="Your OWN public OAST/canary URL for safe SSRF "
                        "confirmation. Internal/loopback/metadata targets are "
                        "refused. Without this, SSRF is reported passively.")
    p.add_argument("--test-xml", action="store_true",
                   help="Enable the XXE check (POSTs benign XML with an internal "
                        "entity). Only meaningful for XML-accepting endpoints.")
    p.add_argument("--idor", action="store_true",
                   help="Enable IDOR / access-control surface identification "
                        "(informational only).")
    p.add_argument("--xml-body", default=None,
                   help="Optional raw XML body used to confirm an XML endpoint "
                        "(the XXE probe always uses a safe internal entity).")
    p.add_argument("--csrf-cookie-check", action="store_true",
                   help="For CSRF, also issue one GET to inspect Set-Cookie "
                        "SameSite attributes.")

    # Crawling / scope
    p.add_argument("--max-depth", type=int, default=2,
                   help="Maximum crawl depth on the same host.")
    p.add_argument("--max-pages", type=int, default=50,
                   help="Maximum number of pages to crawl.")
    p.add_argument("--no-crawl", action="store_true",
                   help="Disable crawling; only test the supplied URL.")
    p.add_argument("--no-path-test", action="store_true",
                   help="Disable testing of path-like (ID) segments.")
    p.add_argument("--no-robots", action="store_true",
                   help="Do not fetch/respect robots.txt (still same-host only).")

    # Safety controls
    p.add_argument("--delay", type=float, default=0.3,
                   help="Delay between requests in seconds.")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="Per-request timeout in seconds.")
    p.add_argument("--max-requests", type=int, default=500,
                   help="Hard cap on total HTTP requests (safety budget).")
    p.add_argument("--time-delay", type=int, default=5,
                   help="Requested delay (s) for time-based probes (clamped 2-10).")
    p.add_argument("--no-time-based", action="store_true",
                   help="Disable time-based detection probes entirely.")
    p.add_argument("--allow-destructive-methods", action="store_true",
                   help="Explicitly allow non GET/POST methods (NOT recommended).")

    # Auth / request shaping
    p.add_argument("--cookie", action="append", default=[],
                   help="Cookie 'name=value' (repeatable) for authenticated tests.")
    p.add_argument("--header", action="append", default=[],
                   help="Custom header 'Name: Value' (repeatable).")
    p.add_argument("--user-agent",
                   default="SQLiDetect-DefensiveScanner/1.0 (authorized-testing)",
                   help="User-Agent header to send.")
    p.add_argument("--json-body", default=None,
                   help="Raw JSON body to test as POST parameters (object only).")
    p.add_argument("--json-method", default="POST",
                   help="HTTP method used with --json-body.")

    # Reporting
    p.add_argument("--json-report", default=None,
                   help="Path to write the JSON report.")
    p.add_argument("--html-report", default=None,
                   help="Path to write the HTML report.")
    p.add_argument("--no-color", action="store_true",
                   help="Disable colored console output.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable verbose (DEBUG) logging.")
    p.add_argument("--yes-i-am-authorized", action="store_true",
                   help="Acknowledge you are authorized to test the target "
                        "(skips the interactive confirmation prompt).")
    return p


def configure_logging(verbose: bool) -> None:
    """Set up logging format and level."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_headers(raw_headers: List[str]) -> Dict[str, str]:
    """Parse 'Name: Value' header strings into a dict."""
    headers: Dict[str, str] = {}
    for item in raw_headers:
        if ":" not in item:
            LOG.warning("Ignoring malformed header (missing ':'): %s", item)
            continue
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def parse_cookies(raw_cookies: List[str]) -> Dict[str, str]:
    """Parse 'name=value' cookie strings into a dict."""
    cookies: Dict[str, str] = {}
    for item in raw_cookies:
        # Allow a single string with multiple '; '-separated cookies too.
        for piece in item.split(";"):
            piece = piece.strip()
            if not piece:
                continue
            if "=" not in piece:
                LOG.warning("Ignoring malformed cookie (missing '='): %s", piece)
                continue
            name, _, value = piece.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


def build_session(args) -> "requests.Session":
    """Create a configured requests.Session with headers and cookies."""
    try:
        import requests  # imported lazily so --help works without the dependency
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "ERROR: the 'requests' package is required to run a scan. Install "
            "dependencies with: pip install -r requirements.txt"
        ) from exc
    session = requests.Session()
    session.headers.update({"User-Agent": args.user_agent})
    session.headers.update(parse_headers(args.header))
    for name, value in parse_cookies(args.cookie).items():
        session.cookies.set(name, value)
    return session


def confirm_authorization(url: str, pre_acknowledged: bool) -> bool:
    """Ensure the operator confirms authorization before scanning."""
    if pre_acknowledged:
        return True
    if not sys.stdin.isatty():
        # Non-interactive without explicit flag: refuse to proceed safely.
        LOG.error(
            "Authorization not confirmed. Re-run with --yes-i-am-authorized to "
            "confirm you are permitted to test %s.", url
        )
        return False
    print(f"\nYou are about to scan: {url}")
    print("Confirm you are AUTHORIZED to test this target.")
    answer = input("Type 'yes' to continue: ").strip().lower()
    return answer in ("y", "yes")


def validate_url(url: str) -> bool:
    """Basic URL validation: must have http/https scheme and a host."""
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def resolve_checks(args) -> set:
    """Determine the enabled set of checks from CLI options."""
    if args.checks:
        requested = {c.strip().lower() for c in args.checks.split(",") if c.strip()}
        unknown = requested - set(ALL_CHECKS)
        if unknown:
            LOG.warning("Ignoring unknown checks: %s", ", ".join(sorted(unknown)))
        enabled = requested & set(ALL_CHECKS)
    else:
        enabled = set(DEFAULT_CHECKS)
    # --test-xml is a convenience switch for enabling XXE.
    if args.test_xml:
        enabled.add("xxe")
    if args.idor:
        enabled.add("idor")
    if not enabled:
        LOG.warning("No valid checks selected; defaulting to: %s", ", ".join(DEFAULT_CHECKS))
        enabled = set(DEFAULT_CHECKS)
    return enabled


def run(args) -> int:
    """Execute the full scan workflow. Returns a process exit code."""
    if not args.no_color:
        print(BANNER)

    if not validate_url(args.url):
        LOG.error("Invalid URL '%s'. Include a scheme, e.g. https://host/path", args.url)
        return 2

    if not confirm_authorization(args.url, args.yes_i_am_authorized):
        LOG.error("Aborting: authorization not confirmed.")
        return 3

    session = build_session(args)

    # --- Crawl phase ---------------------------------------------------
    crawl_config = CrawlConfig(
        max_depth=0 if args.no_crawl else args.max_depth,
        max_pages=1 if args.no_crawl else args.max_pages,
        delay=args.delay,
        timeout=args.timeout,
        respect_robots=not args.no_robots,
        user_agent=args.user_agent,
    )
    crawler = Crawler(session, crawl_config)
    try:
        crawl_result = crawler.crawl(args.url)
    except Exception as exc:
        LOG.error("Crawl failed: %s", exc)
        crawl_result = None

    templates = list(crawl_result.templates) if crawl_result else []
    visited = list(crawl_result.visited_urls) if crawl_result else [args.url]
    unsafe_skipped = len(crawl_result.skipped_unsafe) if crawl_result else 0

    # Always ensure the start URL's query template is present.
    start_template = param_parser.build_request_from_url(args.url)
    if start_template.query_params and not start_template.is_unsafe():
        if not any(t.url == start_template.url and
                   set(t.query_params) == set(start_template.query_params)
                   for t in templates):
            templates.append(start_template)

    # Add an explicit JSON body template if provided.
    if args.json_body:
        try:
            json_template = param_parser.build_request_from_json(
                args.url, args.json_body, args.json_method
            )
            templates.append(json_template)
        except ValueError as exc:
            LOG.error("Ignoring --json-body: %s", exc)

    if not templates:
        LOG.warning(
            "No testable parameters discovered. Provide a URL with query "
            "parameters, a JSON body (--json-body), or a page containing forms."
        )

    # --- Scan phase ----------------------------------------------------
    enabled_checks = resolve_checks(args)
    LOG.info("Enabled checks: %s", ", ".join(sorted(enabled_checks)))

    scan_config = ScanConfig(
        delay=args.delay,
        timeout=args.timeout,
        max_requests=args.max_requests,
        time_delay=args.time_delay,
        enable_time_based=not args.no_time_based,
        allow_destructive_methods=args.allow_destructive_methods,
        test_path_params=not args.no_path_test,
        enable_sqli="sqli" in enabled_checks,
        enable_xss="xss" in enabled_checks,
        enable_csrf="csrf" in enabled_checks,
        enable_ssrf="ssrf" in enabled_checks,
        enable_xxe="xxe" in enabled_checks,
        ssrf_canary=args.ssrf_canary,
        xml_body=args.xml_body,
    )
    scanner = Scanner(session, scan_config)

    # Each detector appends its findings to the shared scanner via note_finding
    # (SQLi appends internally), so we collect from scanner.findings at the end.
    # Modules catch their own budget-exhaustion and return early.
    if scan_config.enable_sqli:
        LOG.info("Running SQL injection checks...")
        scanner.scan_templates(templates)
    if scan_config.enable_xss:
        LOG.info("Running reflected XSS checks...")
        xss_detector.run(scanner, templates)
    if scan_config.enable_csrf:
        LOG.info("Running CSRF checks (passive)...")
        csrf_detector.run(scanner, templates, check_cookies=args.csrf_cookie_check)
    if scan_config.enable_ssrf:
        LOG.info("Running SSRF checks...")
        ssrf_detector.run(scanner, templates, canary=scan_config.ssrf_canary)
    if scan_config.enable_xxe:
        LOG.info("Running XXE checks (safe internal-entity probe)...")
        xxe_detector.run(scanner, args.url, xml_body=scan_config.xml_body)
    if "openredirect" in enabled_checks:
        LOG.info("Running open redirect checks...")
        open_redirect_detector.run(scanner, templates)
    if "ssti" in enabled_checks:
        LOG.info("Running SSTI checks (arithmetic marker only)...")
        ssti_detector.run(scanner, templates)
    if "cors" in enabled_checks:
        LOG.info("Running CORS misconfiguration checks...")
        cors_detector.run(scanner, templates)
    if "headers" in enabled_checks:
        LOG.info("Running security header / cookie checks...")
        headers_detector.run(scanner, args.url)
    if "idor" in enabled_checks:
        LOG.info("Running IDOR/access-control surface checks (informational)...")
        access_control_detector.run(scanner, templates)

    findings = scanner.findings

    # --- Report phase --------------------------------------------------
    crawl_info = {"urls_crawled": len(visited), "unsafe_skipped": unsafe_skipped}
    report = reporter.build_report_dict(args.url, findings, scanner.stats, crawl_info)

    report_paths: Dict[str, str] = {}
    if args.json_report:
        try:
            report_paths["json"] = reporter.write_json_report(args.json_report, report)
        except OSError:
            LOG.error("Could not write JSON report.")
    if args.html_report:
        try:
            report_paths["html"] = reporter.write_html_report(args.html_report, report)
        except OSError:
            LOG.error("Could not write HTML report.")

    reporter.print_console_summary(
        args.url, findings, scanner.stats, crawl_info,
        report_paths=report_paths, use_color=not args.no_color,
    )

    # Exit code: 1 if any confirmed finding (useful for CI gating), else 0.
    return 1 if any(f.confirmed for f in findings) else 0


def main(argv: Optional[List[str]] = None) -> int:
    """Parse arguments and run. Returns process exit code."""
    arg_parser = build_arg_parser()
    args = arg_parser.parse_args(argv)
    configure_logging(args.verbose)
    try:
        return run(args)
    except KeyboardInterrupt:
        LOG.warning("Interrupted by user.")
        return 130
    except Exception as exc:  # last-resort guard
        LOG.exception("Unexpected error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
