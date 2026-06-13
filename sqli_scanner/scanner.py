"""
scanner.py
==========

Scan orchestration and false-positive reduction. For every discovered
``InjectionPoint`` the scanner:

    1. Establishes a stable *baseline* (multiple requests) and rejects unstable
       or highly dynamic endpoints to avoid false positives.
    2. Runs non-destructive detection probes (error / boolean / time).
    3. Confirms each candidate signal with repeated requests.
    4. Requires at least two independent signals to mark a finding "confirmed".

Safety controls enforced here:
    * Global request budget (hard cap).
    * Per-request timeout and inter-request delay.
    * Refusal to send destructive HTTP methods unless explicitly enabled.
    * Skips parameters belonging to unsafe (destructive) actions.

Only HTTP GET/POST are used. No data is extracted; probes only seek to observe
behavioral differences indicative of injection.
"""

from __future__ import annotations

import hashlib
import logging
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import detector, parser
from .detector import ResponseMetrics, SignalResult
from .parser import InjectionPoint, RequestTemplate

logger = logging.getLogger("sqli_scanner.scanner")

# CWE / OWASP references reused in findings.
CWE_SQLI = "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
OWASP_SQLI = "OWASP A03:2021 - Injection"

REMEDIATION = (
    "Use parameterized queries / prepared statements (bind variables) for all "
    "database access. Never concatenate untrusted input into SQL. Apply strict "
    "server-side input validation and allow-listing, enforce least-privilege DB "
    "accounts, and use a vetted ORM or query builder. Disable detailed database "
    "error messages in production."
)


@dataclass
class ScanConfig:
    """Safety-focused scan configuration."""

    delay: float = 0.3                 # seconds between requests
    timeout: float = 10.0              # per-request timeout (seconds)
    max_requests: int = 500            # hard global budget
    baseline_samples: int = 3          # baseline repeats for stability
    confirm_repeats: int = 2           # repeats to confirm a candidate signal
    time_delay: int = 5                # requested SLEEP seconds for time probes
    similarity_threshold: float = 0.95 # body-length similarity ratio
    enable_time_based: bool = True
    allow_destructive_methods: bool = False  # gate on non GET/POST methods
    test_path_params: bool = True
    # Which checks to run. SQLi/XSS are active param tests; CSRF is passive;
    # XXE and the active SSRF canary are opt-in.
    enable_sqli: bool = True
    enable_xss: bool = True
    enable_csrf: bool = True
    enable_ssrf: bool = True
    enable_xxe: bool = False           # opt-in (needs an XML-accepting endpoint)
    ssrf_canary: Optional[str] = None  # user-controlled OAST domain for SSRF
    xml_body: Optional[str] = None     # optional raw XML body for XXE probing
    concurrency: int = 1               # parallel workers for independent checks


@dataclass
class FullResponse:
    """A richer response wrapper exposing headers/status for non-SQLi checks."""

    metrics: "ResponseMetrics"
    text: str
    headers: Dict[str, str]
    status: int
    elapsed: float


@dataclass
class Finding:
    """A single reported (candidate or confirmed) vulnerability.

    Generalized to cover multiple categories (SQLi, XSS, XXE, CSRF, SSRF). The
    ``category`` field identifies the vulnerability class; ``confirmed`` is set
    explicitly by each detector according to its own confirmation policy.
    """

    vuln_type: str
    url: str
    param: str
    method: str
    location: str
    confidence: str
    risk: str
    category: str = "SQLi"
    dbms: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    matched_techniques: List[str] = field(default_factory=list)
    reproduction: List[str] = field(default_factory=list)
    remediation: str = REMEDIATION
    cwe: str = CWE_SQLI
    owasp: str = OWASP_SQLI
    confirmed: bool = False
    severity: str = ""  # Critical/High/Medium/Low/Info; derived if left blank


@dataclass
class ScanStats:
    """Counters surfaced in the final summary."""

    params_tested: int = 0
    requests_sent: int = 0
    confirmed: int = 0
    possible: int = 0
    false_positive_filtered: int = 0
    unstable_skipped: int = 0
    budget_exhausted: bool = False


class RequestBudgetError(Exception):
    """Raised internally when the global request budget is exhausted."""


class Scanner:
    """Runs detection against discovered injection points."""

    def __init__(self, session, config: Optional[ScanConfig] = None):
        self.session = session
        self.config = config or ScanConfig()
        self.stats = ScanStats()
        self.findings: List[Finding] = []
        # Thread-safety for concurrent checks + a live-finding callback hook.
        self._lock = threading.RLock()
        self.on_finding: Optional[Callable[["Finding"], None]] = None

    def _reserve_request(self) -> None:
        """Atomically check the budget and reserve one request slot.

        Raises RequestBudgetError if the global budget is exhausted. Counting at
        reservation time keeps the cap correct even under concurrency.
        """
        with self._lock:
            if self.stats.requests_sent >= self.config.max_requests:
                self.stats.budget_exhausted = True
                raise RequestBudgetError("Global request budget exhausted.")
            self.stats.requests_sent += 1

    def parallel_map(self, items, worker):
        """Run ``worker(item)`` over items, concurrently when configured.

        Workers are responsible for recording their own findings via
        ``note_finding`` (which is thread-safe). RequestBudgetError from a worker
        is swallowed so the pool drains cleanly. Returns the list of results.
        """
        items = list(items)
        workers = max(1, int(self.config.concurrency))
        if workers == 1 or len(items) <= 1:
            results = []
            for it in items:
                try:
                    results.append(worker(it))
                except RequestBudgetError:
                    break
            return results

        def _safe(it):
            try:
                return worker(it)
            except RequestBudgetError:
                return None

        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(_safe, items))

    # ------------------------------------------------------------------
    # Low-level request with budget + safety enforcement
    # ------------------------------------------------------------------
    def _send(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, str]] = None,
        json_body: Optional[str] = None,
    ) -> Optional[Tuple[ResponseMetrics, str]]:
        """Send one HTTP request and return (metrics, text), or None on error.

        Enforces the request budget, delay, timeout, and the destructive-method
        guard.
        """
        method = method.upper()
        if method not in ("GET", "POST") and not self.config.allow_destructive_methods:
            logger.warning("Refusing non-GET/POST method %s (destructive guard).", method)
            return None

        self._reserve_request()  # atomic budget check + count

        time.sleep(self.config.delay)
        start = time.perf_counter()
        try:
            if method == "POST":
                if json_body is not None:
                    resp = self.session.post(
                        url, data=json_body, timeout=self.config.timeout,
                        headers={"Content-Type": "application/json"},
                        allow_redirects=False,
                    )
                else:
                    resp = self.session.post(
                        url, data=data or {}, timeout=self.config.timeout,
                        allow_redirects=False,
                    )
            else:
                resp = self.session.get(
                    url, timeout=self.config.timeout, allow_redirects=False,
                )
        except Exception as exc:
            # A timeout on a time-based probe is meaningful; report elapsed.
            elapsed = time.perf_counter() - start
            logger.debug("Request error (%s) for %s after %.2fs", exc, url, elapsed)
            return None

        elapsed = time.perf_counter() - start
        text = resp.text or ""
        metrics = ResponseMetrics(
            status=resp.status_code,
            length=len(text),
            elapsed=elapsed,
            content_hash=hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest(),
            dbms_error=detector.fingerprint_dbms(text),
        )
        return metrics, text

    # ------------------------------------------------------------------
    # Header-exposing probe (used by XSS / XXE / CSRF / SSRF detectors)
    # ------------------------------------------------------------------
    def send_full(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, str]] = None,
        json_body: Optional[str] = None,
        raw_body: Optional[str] = None,
        content_type: Optional[str] = None,
        allow_redirects: bool = False,
    ) -> Optional["FullResponse"]:
        """Send a request and return a ``FullResponse`` (metrics + text + headers).

        Mirrors ``_send`` safety (budget, delay, timeout, method guard) but also
        exposes response headers and status, which the non-SQLi detectors need
        (e.g. redirect ``Location`` for SSRF, ``Set-Cookie`` for CSRF). Supports
        a ``raw_body`` with an explicit ``content_type`` (used for XML probes).
        """
        method = method.upper()
        if method not in ("GET", "POST") and not self.config.allow_destructive_methods:
            logger.warning("Refusing non-GET/POST method %s (destructive guard).", method)
            return None

        headers: Dict[str, str] = {}
        if content_type:
            headers["Content-Type"] = content_type

        self._reserve_request()  # atomic budget check + count
        time.sleep(self.config.delay)
        start = time.perf_counter()
        try:
            if method == "POST":
                if raw_body is not None:
                    resp = self.session.post(
                        url, data=raw_body, timeout=self.config.timeout,
                        headers=headers or None, allow_redirects=allow_redirects,
                    )
                elif json_body is not None:
                    resp = self.session.post(
                        url, data=json_body, timeout=self.config.timeout,
                        headers={"Content-Type": "application/json"},
                        allow_redirects=allow_redirects,
                    )
                else:
                    resp = self.session.post(
                        url, data=data or {}, timeout=self.config.timeout,
                        headers=headers or None, allow_redirects=allow_redirects,
                    )
            else:
                resp = self.session.get(
                    url, timeout=self.config.timeout, headers=headers or None,
                    allow_redirects=allow_redirects,
                )
        except Exception as exc:
            logger.debug("send_full error (%s) for %s", exc, url)
            return None

        elapsed = time.perf_counter() - start
        text = resp.text or ""
        metrics = ResponseMetrics(
            status=resp.status_code,
            length=len(text),
            elapsed=elapsed,
            content_hash=hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest(),
            dbms_error=detector.fingerprint_dbms(text),
        )
        # Normalize headers into a plain dict (case-insensitive lookups by caller).
        resp_headers = {k: v for k, v in getattr(resp, "headers", {}).items()}
        return FullResponse(metrics=metrics, text=text, headers=resp_headers,
                            status=resp.status_code, elapsed=elapsed)

    def probe_point(
        self, point: InjectionPoint, injected_value: str,
        allow_redirects: bool = False,
    ) -> Optional["FullResponse"]:
        """Materialize an injection point with a value and send it (full response)."""
        method, url, data, json_body, _ = parser.materialize(point, injected_value)
        return self.send_full(method, url, data=data, json_body=json_body,
                              allow_redirects=allow_redirects)

    def note_finding(self, finding: "Finding") -> None:
        """Record a finding (thread-safe) and fire the live-finding callback."""
        with self._lock:
            self.findings.append(finding)
            if finding.confirmed:
                self.stats.confirmed += 1
            else:
                self.stats.possible += 1
            logger.info("Finding: %s param='%s' confidence=%s",
                        finding.vuln_type, finding.param, finding.confidence)
            callback = self.on_finding
        # Invoke callback outside the structural mutation but still serialized by
        # the RLock to keep live console output from interleaving.
        if callback is not None:
            with self._lock:
                try:
                    callback(finding)
                except Exception:  # never let reporting break the scan
                    logger.debug("on_finding callback raised", exc_info=True)

    # ------------------------------------------------------------------
    # Baseline & stability
    # ------------------------------------------------------------------
    def _baseline(self, point: InjectionPoint) -> Optional[Dict[str, object]]:
        """Build a stable baseline for a point using its original value.

        Returns a dict with baseline metrics, representative text, and the list
        of observed response times. Returns None if the endpoint is too unstable
        to test reliably (false-positive guard).
        """
        method, url, data, json_body, _ = parser.materialize(point, point.original_value)

        samples: List[ResponseMetrics] = []
        texts: List[str] = []
        for _ in range(max(2, self.config.baseline_samples)):
            sent = self._send(method, url, data, json_body)
            if sent is None:
                continue
            metrics, text = sent
            samples.append(metrics)
            texts.append(text)

        if len(samples) < 2:
            logger.debug("Insufficient baseline samples for %s", point.param_name)
            return None

        # Stability: all baseline responses should be similar to the first.
        ref = samples[0]
        stable = all(
            ref.is_similar_to(s, self.config.similarity_threshold) for s in samples[1:]
        )
        # Detect a dynamic page (same length, different hash => rotating tokens).
        dynamic = len({s.content_hash for s in samples}) > 1 and all(
            ref.is_similar_to(s, self.config.similarity_threshold) for s in samples[1:]
        )

        if not stable:
            logger.info(
                "Endpoint unstable for param '%s' at %s; skipping to avoid false positives.",
                point.param_name, url,
            )
            self.stats.unstable_skipped += 1
            return None

        return {
            "metrics": ref,
            "text": texts[0],
            "times": [s.elapsed for s in samples],
            "dynamic": dynamic,
            "method": method,
            "url": url,
        }

    # ------------------------------------------------------------------
    # Per-point scanning
    # ------------------------------------------------------------------
    def scan_point(self, point: InjectionPoint) -> Optional[Finding]:
        """Test a single injection point and return a Finding (or None)."""
        # Never test parameters of an unsafe action.
        if point.template.is_unsafe():
            logger.info("Skipping unsafe target param '%s'.", point.param_name)
            return None

        self.stats.params_tested += 1
        baseline = self._baseline(point)
        if baseline is None:
            return None

        baseline_metrics: ResponseMetrics = baseline["metrics"]  # type: ignore
        baseline_text: str = baseline["text"]                     # type: ignore
        baseline_times: List[float] = baseline["times"]           # type: ignore
        is_dynamic: bool = baseline["dynamic"]                     # type: ignore

        matched: List[SignalResult] = []

        # --- 1) Error-based ------------------------------------------------
        err_signal = self._test_error_based(point, baseline_text)
        if err_signal and err_signal.matched:
            matched.append(err_signal)

        # --- 2) Boolean-based ---------------------------------------------
        # On highly dynamic pages, boolean comparison is unreliable; weight down.
        if not is_dynamic:
            bool_signal = self._test_boolean_based(point, baseline_metrics)
            if bool_signal and bool_signal.matched:
                matched.append(bool_signal)
        else:
            logger.debug("Skipping boolean test on dynamic page for '%s'.", point.param_name)

        # --- 3) Time-based -------------------------------------------------
        if self.config.enable_time_based:
            time_signal = self._test_time_based(point, baseline_times)
            if time_signal and time_signal.matched:
                matched.append(time_signal)

        if not matched:
            return None

        return self._build_finding(point, matched, baseline)

    # ------------------------------------------------------------------
    # Technique: error-based
    # ------------------------------------------------------------------
    def _test_error_based(
        self, point: InjectionPoint, baseline_text: str
    ) -> Optional[SignalResult]:
        """Inject malformed fragments and look for DB error signatures."""
        for payload in detector.ERROR_PAYLOADS:
            injected = f"{point.original_value}{payload}"
            sent = self._materialize_and_send(point, injected)
            if sent is None:
                continue
            _, text = sent
            signal = detector.detect_error_signal(baseline_text, text, payload)
            if signal.matched:
                # Confirm with a repeat to avoid transient errors.
                if self._confirm_error(point, injected, baseline_text):
                    return signal
        return None

    def _confirm_error(self, point: InjectionPoint, injected: str, baseline_text: str) -> bool:
        """Repeat an error-triggering request to confirm consistency."""
        confirmations = 0
        for _ in range(self.config.confirm_repeats):
            sent = self._materialize_and_send(point, injected)
            if sent is None:
                continue
            _, text = sent
            if detector.detect_error_signal(baseline_text, text, injected).matched:
                confirmations += 1
        return confirmations >= 1

    # ------------------------------------------------------------------
    # Technique: boolean-based
    # ------------------------------------------------------------------
    def _test_boolean_based(
        self, point: InjectionPoint, baseline_metrics: ResponseMetrics
    ) -> Optional[SignalResult]:
        """Compare logically TRUE vs FALSE payloads against the baseline."""
        pairs = [
            p for p in detector.BOOLEAN_PAIRS
            if p.context == ("numeric" if point.numeric_context else "string")
        ] or detector.BOOLEAN_PAIRS

        for pair in pairs:
            true_val = f"{point.original_value}{pair.true_payload}"
            false_val = f"{point.original_value}{pair.false_payload}"

            true_sent = self._materialize_and_send(point, true_val)
            false_sent = self._materialize_and_send(point, false_val)
            if true_sent is None or false_sent is None:
                continue

            true_metrics, _ = true_sent
            false_metrics, _ = false_sent
            signal = detector.evaluate_boolean_signal(
                baseline_metrics, true_metrics, false_metrics, pair,
                self.config.similarity_threshold,
            )
            if signal.matched and self._confirm_boolean(point, pair, baseline_metrics):
                return signal
        return None

    def _confirm_boolean(
        self, point: InjectionPoint, pair, baseline_metrics: ResponseMetrics
    ) -> bool:
        """Repeat the TRUE/FALSE comparison to confirm a stable difference."""
        confirmations = 0
        for _ in range(self.config.confirm_repeats):
            true_val = f"{point.original_value}{pair.true_payload}"
            false_val = f"{point.original_value}{pair.false_payload}"
            true_sent = self._materialize_and_send(point, true_val)
            false_sent = self._materialize_and_send(point, false_val)
            if true_sent is None or false_sent is None:
                continue
            true_metrics, _ = true_sent
            false_metrics, _ = false_sent
            signal = detector.evaluate_boolean_signal(
                baseline_metrics, true_metrics, false_metrics, pair,
                self.config.similarity_threshold,
            )
            if signal.matched:
                confirmations += 1
        return confirmations >= 1

    # ------------------------------------------------------------------
    # Technique: time-based
    # ------------------------------------------------------------------
    def _test_time_based(
        self, point: InjectionPoint, baseline_times: List[float]
    ) -> Optional[SignalResult]:
        """Send bounded delay probes; confirm a reproducible time difference."""
        payloads = [
            tp for tp in detector.build_time_payloads(self.config.time_delay)
            if tp.context == ("numeric" if point.numeric_context else "string")
        ]
        # Always include a couple of generic ones as fallback.
        if not payloads:
            payloads = detector.build_time_payloads(self.config.time_delay)

        for tp in payloads:
            injected = f"{point.original_value}{tp.template}"
            sent = self._materialize_and_send(point, injected)
            if sent is None:
                # Could be a genuine timeout from a long delay; treat cautiously.
                continue
            metrics, _ = sent
            signal = detector.evaluate_time_signal(
                baseline_times, metrics.elapsed, float(tp.delay_seconds), tp.template,
            )
            if signal.matched and self._confirm_time(point, tp, baseline_times):
                return signal
        return None

    def _confirm_time(self, point: InjectionPoint, tp, baseline_times: List[float]) -> bool:
        """Confirm a time delay reproduces (guards against one-off latency)."""
        confirmations = 0
        for _ in range(self.config.confirm_repeats):
            injected = f"{point.original_value}{tp.template}"
            sent = self._materialize_and_send(point, injected)
            if sent is None:
                continue
            metrics, _ = sent
            signal = detector.evaluate_time_signal(
                baseline_times, metrics.elapsed, float(tp.delay_seconds), tp.template,
            )
            if signal.matched:
                confirmations += 1
        # Require all confirmation repeats to agree for time-based (noisy signal).
        return confirmations >= max(1, self.config.confirm_repeats - 1)

    # ------------------------------------------------------------------
    # Shared send helper
    # ------------------------------------------------------------------
    def _materialize_and_send(
        self, point: InjectionPoint, injected_value: str
    ) -> Optional[Tuple[ResponseMetrics, str]]:
        method, url, data, json_body, _ = parser.materialize(point, injected_value)
        return self._send(method, url, data, json_body)

    # ------------------------------------------------------------------
    # Finding assembly
    # ------------------------------------------------------------------
    def _build_finding(
        self, point: InjectionPoint, matched: List[SignalResult], baseline: Dict[str, object]
    ) -> Finding:
        confidence, risk = detector.score_confidence(matched)
        techniques = sorted({s.technique for s in matched})
        dbms = next((s.dbms for s in matched if s.dbms), None)

        evidence = [s.detail for s in matched if s.detail]
        for s in matched:
            if s.evidence:
                kv = ", ".join(f"{k}={v}" for k, v in s.evidence.items())
                evidence.append(f"[{s.technique}] {kv}")

        method = str(baseline["method"])
        url = str(baseline["url"])

        repro = self._safe_reproduction(point, matched, method, url)

        vuln_type = "SQL Injection ({})".format(
            ", ".join(t + "-based" for t in techniques)
        )

        finding = Finding(
            vuln_type=vuln_type,
            url=url,
            param=point.param_name,
            method=method,
            location=point.location,
            confidence=confidence,
            risk=risk,
            category="SQLi",
            dbms=dbms,
            evidence=evidence,
            matched_techniques=techniques,
            reproduction=repro,
            confirmed=len(set(techniques)) >= 2,
        )
        return finding

    @staticmethod
    def _safe_reproduction(
        point: InjectionPoint, matched: List[SignalResult], method: str, url: str
    ) -> List[str]:
        """Produce safe, high-level reproduction steps (no data extraction)."""
        steps = [
            f"Target: {method} {url}",
            f"Parameter: '{point.param_name}' (location: {point.location}, "
            f"original value: '{point.original_value}').",
        ]
        for s in matched:
            if s.technique == "error":
                steps.append(
                    "Append a single quote (') to the parameter value and observe "
                    "a database error message in the response."
                )
            elif s.technique == "boolean":
                steps.append(
                    "Submit a logically TRUE condition vs. a FALSE condition and "
                    "observe that the response content changes only for FALSE, "
                    "confirming the input is evaluated in SQL."
                )
            elif s.technique == "time":
                steps.append(
                    "Submit a bounded time-delay condition and observe the response "
                    "time increases by approximately the requested delay, confirming "
                    "the input reaches the SQL engine. (Delay probe only; no data "
                    "is read or modified.)"
                )
        steps.append(
            "Note: Stop here. Do not attempt data extraction; report to the "
            "application owner for remediation."
        )
        return steps

    # ------------------------------------------------------------------
    # Top-level driver
    # ------------------------------------------------------------------
    def scan_templates(self, templates: List[RequestTemplate]) -> List[Finding]:
        """Enumerate and scan all injection points across templates."""
        # De-duplicate points across templates by (method,url,param,location).
        seen: set = set()
        for template in templates:
            if template.is_unsafe():
                continue
            points = parser.enumerate_injection_points(
                template, include_path=self.config.test_path_params
            )
            for point in points:
                key = (point.template.method, point.template.url,
                       point.param_name, point.location)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    finding = self.scan_point(point)
                except RequestBudgetError:
                    logger.warning("Request budget exhausted; stopping scan.")
                    return self.findings
                if finding is not None:
                    self.note_finding(finding)
        return self.findings
