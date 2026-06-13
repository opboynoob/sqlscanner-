"""
crawler.py
==========

Safe, same-host crawler used to discover pages, links, and forms within a
strict budget. Safety is the priority:

    * Same host only (never leaves the target's netloc).
    * Bounded depth and a hard cap on total pages fetched.
    * Per-request timeout and inter-request delay.
    * Skips destructive/sensitive actions (logout, delete, payment, ...).
    * Optional robots.txt awareness for polite, in-scope crawling.

The crawler only issues GET requests. It returns the set of discovered
``RequestTemplate`` objects (from URLs with query strings and from HTML forms).
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib import robotparser
from urllib.parse import urljoin, urlparse

from . import parser
from .parser import RequestTemplate

logger = logging.getLogger("sqli_scanner.crawler")


@dataclass
class CrawlConfig:
    """Tunable, safety-focused crawl parameters."""

    max_depth: int = 2
    max_pages: int = 50
    delay: float = 0.3            # seconds between requests
    timeout: float = 10.0         # per-request timeout (seconds)
    respect_robots: bool = True
    user_agent: str = "SQLiDetect-DefensiveScanner/1.0 (authorized-testing)"


@dataclass
class CrawlResult:
    """Aggregate output of a crawl."""

    visited_urls: List[str] = field(default_factory=list)
    templates: List[RequestTemplate] = field(default_factory=list)
    skipped_unsafe: List[str] = field(default_factory=list)


class Crawler:
    """Breadth-first, same-host crawler with strict safety limits."""

    def __init__(self, session, config: Optional[CrawlConfig] = None):
        """
        Args:
            session: a ``requests.Session`` (or compatible) used for all GETs.
            config:  crawl tuning / safety configuration.
        """
        self.session = session
        self.config = config or CrawlConfig()
        self._robots: Optional[robotparser.RobotFileParser] = None
        self._robots_host: Optional[str] = None

    # ------------------------------------------------------------------
    # robots.txt handling
    # ------------------------------------------------------------------
    def _load_robots(self, start_url: str) -> None:
        """Fetch and parse robots.txt for the start host (best-effort)."""
        if not self.config.respect_robots:
            return
        parsed = urlparse(start_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        rp = robotparser.RobotFileParser()
        try:
            resp = self.session.get(robots_url, timeout=self.config.timeout)
            if resp.status_code == 200 and resp.text:
                rp.parse(resp.text.splitlines())
            else:
                rp.parse([])  # treat as allow-all if not present
            self._robots = rp
            self._robots_host = parsed.netloc
            logger.debug("Loaded robots.txt from %s (status %s)", robots_url, resp.status_code)
        except Exception as exc:  # network errors are non-fatal
            logger.debug("Could not fetch robots.txt (%s); proceeding allow-all.", exc)
            self._robots = None

    def _allowed_by_robots(self, url: str) -> bool:
        """Return True if robots.txt permits crawling ``url`` (or no robots)."""
        if not self.config.respect_robots or self._robots is None:
            return True
        try:
            return self._robots.can_fetch(self.config.user_agent, url)
        except Exception:
            return True

    # ------------------------------------------------------------------
    # Main crawl loop
    # ------------------------------------------------------------------
    def crawl(self, start_url: str) -> CrawlResult:
        """Crawl from ``start_url`` and return discovered templates.

        Uses BFS bounded by ``max_depth`` and ``max_pages``. Always includes the
        start URL's own query parameters as a template even if nothing is
        crawled.
        """
        result = CrawlResult()
        self._load_robots(start_url)

        # Always seed with the start URL's query template (it is in scope).
        start_template = parser.build_request_from_url(start_url)
        if start_template.query_params and not start_template.is_unsafe():
            result.templates.append(start_template)

        visited: Set[str] = set()
        seen_template_keys: Set[str] = set()
        if start_template.query_params:
            seen_template_keys.add(self._template_key(start_template))

        queue: "deque[tuple[str, int]]" = deque()
        queue.append((start_url, 0))

        while queue and len(visited) < self.config.max_pages:
            url, depth = queue.popleft()
            norm = self._normalize(url)
            if norm in visited:
                continue
            if not parser.same_host(start_url, url):
                continue
            if parser.is_unsafe_target(url):
                result.skipped_unsafe.append(url)
                logger.info("Skipping unsafe URL: %s", url)
                continue
            if not self._allowed_by_robots(url):
                logger.info("robots.txt disallows: %s", url)
                continue

            html = self._fetch(url)
            visited.add(norm)
            result.visited_urls.append(url)
            if html is None:
                continue

            # Discover forms on this page.
            try:
                for tmpl in parser.extract_forms(html, url):
                    key = self._template_key(tmpl)
                    if key not in seen_template_keys:
                        seen_template_keys.add(key)
                        result.templates.append(tmpl)
            except Exception as exc:
                logger.debug("Form parse error on %s: %s", url, exc)

            # Discover links (and any with query strings become templates).
            if depth < self.config.max_depth:
                for link in parser.extract_links(html, url):
                    if not parser.same_host(start_url, link):
                        continue
                    if parser.is_unsafe_target(link):
                        result.skipped_unsafe.append(link)
                        continue
                    link_tmpl = parser.build_request_from_url(link)
                    if link_tmpl.query_params:
                        key = self._template_key(link_tmpl)
                        if key not in seen_template_keys:
                            seen_template_keys.add(key)
                            result.templates.append(link_tmpl)
                    nlink = self._normalize(link)
                    if nlink not in visited:
                        queue.append((link, depth + 1))

        logger.info(
            "Crawl complete: %d pages visited, %d templates discovered, %d unsafe skipped.",
            len(result.visited_urls), len(result.templates), len(result.skipped_unsafe),
        )
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _fetch(self, url: str) -> Optional[str]:
        """GET a URL with timeout + delay; return text or None on failure."""
        try:
            time.sleep(self.config.delay)
            resp = self.session.get(
                url,
                timeout=self.config.timeout,
                allow_redirects=True,
            )
            content_type = resp.headers.get("Content-Type", "")
            # Only parse HTML-ish documents for links/forms.
            if "html" not in content_type.lower() and content_type:
                logger.debug("Skipping non-HTML content (%s) at %s", content_type, url)
                return None
            return resp.text
        except Exception as exc:
            logger.warning("Fetch failed for %s: %s", url, exc)
            return None

    @staticmethod
    def _normalize(url: str) -> str:
        """Normalize a URL for visited-set comparison (drop fragment)."""
        parsed = urlparse(url)
        return parsed._replace(fragment="").geturl()

    @staticmethod
    def _template_key(template: RequestTemplate) -> str:
        """Stable dedup key for a request template."""
        params = sorted(set(template.query_params) | set(template.body_params))
        return f"{template.method}|{template.url}|{','.join(params)}"
