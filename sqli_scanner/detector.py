"""
detector.py
===========

Core detection knowledge base and signal evaluation for the defensive SQLi
scanner. This module is intentionally *passive*: it only describes what an
injectable parameter looks like and evaluates evidence. It performs no network
I/O and no exploitation.

Responsibilities:
    * Hold safe, bounded payload sets (error / boolean / time probes).
    * Fingerprint database engines from error messages.
    * Evaluate response signals to decide if a parameter looks injectable.
    * Compute a confidence score (Low / Medium / High).

NOTE: No data-extraction, UNION-dump, stacked-query, or WAF-bypass payloads are
included. Time probes use a single, short, bounded delay only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple


# ---------------------------------------------------------------------------
# Database error fingerprints
# ---------------------------------------------------------------------------
# Each engine maps to a list of regular expressions that strongly indicate a
# SQL error surfaced in the HTTP response body. These are used for error-based
# detection and for fingerprinting the backend DBMS.
_DB_ERROR_PATTERNS: Dict[str, List[str]] = {
    "MySQL": [
        r"SQL syntax.*MySQL",
        r"Warning.*\bmysqli?_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"Unknown column '[^']+' in 'field list'",
        r"MariaDB server version for the right syntax",
        r"com\.mysql\.jdbc",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\bpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"unterminated quoted string at or near",
        r"syntax error at or near",
    ],
    "Microsoft SQL Server": [
        r"Driver.* SQL[\-\_ ]*Server",
        r"OLE DB.* SQL Server",
        r"\bSQL Server[^&<]+Driver",
        r"Warning.*\b(mssql|sqlsrv)_",
        r"Microsoft SQL Native Client error",
        r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark after the character string",
        r"Incorrect syntax near",
    ],
    "Oracle": [
        r"\bORA-\d{4,5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\boci_",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*\bsqlite_",
        r"\[SQLITE_ERROR\]",
        r"sqlite3\.OperationalError",
        r"unrecognized token:",
        r"near \".*\": syntax error",
    ],
}

# Pre-compile the patterns once for performance and reuse.
_COMPILED_DB_PATTERNS: Dict[str, List[Pattern[str]]] = {
    engine: [re.compile(p, re.IGNORECASE) for p in patterns]
    for engine, patterns in _DB_ERROR_PATTERNS.items()
}


# ---------------------------------------------------------------------------
# Payload definitions
# ---------------------------------------------------------------------------
# These payloads are crafted ONLY to trigger detectable behavior (errors,
# boolean differences, or a short time delay). They never attempt to read or
# modify data.

# Error-based probes: malformed fragments meant to provoke a SQL parser error.
ERROR_PAYLOADS: List[str] = [
    "'",
    "\"",
    "')",
    "\")",
    "`",
    "'\"",
]


@dataclass(frozen=True)
class BooleanPair:
    """A pair of payloads that should be logically TRUE vs. FALSE.

    If the application is injectable, the TRUE payload should behave like the
    original/baseline response while the FALSE payload differs (or vice versa).
    """

    true_payload: str
    false_payload: str
    context: str  # "string" or "numeric"


# Boolean-based probes for both string and numeric contexts. Suffixed with a
# trailing comment to neutralize the remainder of the original query safely.
BOOLEAN_PAIRS: List[BooleanPair] = [
    BooleanPair("' AND '1'='1", "' AND '1'='2", "string"),
    BooleanPair("' AND '1'='1' -- ", "' AND '1'='2' -- ", "string"),
    BooleanPair(" AND 1=1", " AND 1=2", "numeric"),
    BooleanPair(" AND 1=1 -- ", " AND 1=2 -- ", "numeric"),
    BooleanPair("\" AND \"1\"=\"1", "\" AND \"1\"=\"2", "string"),
]


@dataclass(frozen=True)
class TimePayload:
    """A single bounded time-delay probe.

    ``delay_seconds`` is the requested delay used to size detection thresholds.
    Kept intentionally short to remain non-disruptive.
    """

    template: str
    delay_seconds: int
    context: str


# Time-based probes. We use a single short delay (default 5s) per engine family.
# The scanner enforces a strict per-request timeout independently.
def build_time_payloads(delay_seconds: int = 5) -> List[TimePayload]:
    """Construct bounded time-delay payloads for the given delay.

    The delay is clamped to a safe range to avoid long-running / disruptive
    requests even if a caller passes an extreme value.
    """
    d = max(2, min(int(delay_seconds), 10))  # clamp 2..10 seconds
    return [
        # MySQL / MariaDB
        TimePayload(f"' AND SLEEP({d}) -- ", d, "string"),
        TimePayload(f" AND SLEEP({d}) -- ", d, "numeric"),
        TimePayload(f"' AND SLEEP({d}) AND '1'='1", d, "string"),
        # PostgreSQL
        TimePayload(f"' AND pg_sleep({d}) -- ", d, "string"),
        TimePayload(f" AND pg_sleep({d}) -- ", d, "numeric"),
        # Microsoft SQL Server
        TimePayload(f"'; WAITFOR DELAY '0:0:{d}' -- ", d, "string"),
        TimePayload(f" WAITFOR DELAY '0:0:{d}' -- ", d, "numeric"),
    ]


# ---------------------------------------------------------------------------
# Detection result container
# ---------------------------------------------------------------------------
@dataclass
class SignalResult:
    """The outcome of evaluating one detection technique against a parameter."""

    technique: str            # "error", "boolean", or "time"
    matched: bool
    detail: str = ""
    dbms: Optional[str] = None
    payload: str = ""
    evidence: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Fingerprinting & error detection
# ---------------------------------------------------------------------------
def fingerprint_dbms(text: str) -> Optional[str]:
    """Return the DBMS name if a known error signature is present, else None."""
    if not text:
        return None
    for engine, patterns in _COMPILED_DB_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(text):
                return engine
    return None


def detect_error_signal(
    baseline_text: str,
    response_text: str,
    payload: str,
) -> SignalResult:
    """Error-based detection.

    A signal fires only when a DB error signature appears in the *response* but
    not in the *baseline* (so we don't flag pages that always echo SQL-looking
    text).
    """
    response_dbms = fingerprint_dbms(response_text)
    baseline_dbms = fingerprint_dbms(baseline_text)

    if response_dbms and not baseline_dbms:
        return SignalResult(
            technique="error",
            matched=True,
            detail=f"Database error signature for {response_dbms} appeared "
            f"after injecting payload but was absent in baseline.",
            dbms=response_dbms,
            payload=payload,
            evidence={"dbms": response_dbms},
        )
    return SignalResult(technique="error", matched=False, payload=payload)


# ---------------------------------------------------------------------------
# Boolean-based evaluation
# ---------------------------------------------------------------------------
def evaluate_boolean_signal(
    baseline_metrics: "ResponseMetrics",
    true_metrics: "ResponseMetrics",
    false_metrics: "ResponseMetrics",
    pair: BooleanPair,
    similarity_threshold: float = 0.95,
) -> SignalResult:
    """Boolean-based detection.

    Injectable behavior: the TRUE payload response closely resembles the
    baseline while the FALSE payload response differs meaningfully. Comparisons
    use content length ratio and status code rather than exact equality to
    tolerate minor dynamic content.
    """
    # The TRUE response should look like the baseline.
    true_like_baseline = baseline_metrics.is_similar_to(
        true_metrics, similarity_threshold
    )
    # The FALSE response should differ from both the baseline and the TRUE one.
    false_differs_baseline = not baseline_metrics.is_similar_to(
        false_metrics, similarity_threshold
    )
    false_differs_true = not true_metrics.is_similar_to(
        false_metrics, similarity_threshold
    )

    matched = true_like_baseline and false_differs_baseline and false_differs_true

    detail = (
        "TRUE payload response matched baseline while FALSE payload diverged, "
        "indicating the parameter is evaluated inside a SQL boolean context."
    )
    return SignalResult(
        technique="boolean",
        matched=matched,
        detail=detail if matched else "",
        payload=f"TRUE={pair.true_payload!r} FALSE={pair.false_payload!r}",
        evidence={
            "baseline_len": str(baseline_metrics.length),
            "true_len": str(true_metrics.length),
            "false_len": str(false_metrics.length),
            "true_status": str(true_metrics.status),
            "false_status": str(false_metrics.status),
        },
    )


# ---------------------------------------------------------------------------
# Time-based evaluation
# ---------------------------------------------------------------------------
def evaluate_time_signal(
    baseline_times: List[float],
    injected_time: float,
    expected_delay: float,
    payload: str,
    tolerance: float = 0.7,
) -> SignalResult:
    """Time-based detection.

    Injectable behavior: the injected request takes at least ~``expected_delay``
    longer than the typical baseline response time. ``tolerance`` (0..1) scales
    how much of the expected delay must be observed to count, reducing false
    positives from normal jitter.
    """
    if not baseline_times:
        return SignalResult(technique="time", matched=False, payload=payload)

    # Use the maximum observed baseline time as a conservative reference so that
    # natural latency spikes do not trigger a false positive.
    baseline_ref = max(baseline_times)
    threshold = baseline_ref + (expected_delay * tolerance)
    matched = injected_time >= threshold

    detail = (
        f"Injected request responded in {injected_time:.2f}s vs. baseline max "
        f"{baseline_ref:.2f}s (threshold {threshold:.2f}s for a {expected_delay:.0f}s "
        f"delay probe), consistent with a time-based SQL delay."
    )
    return SignalResult(
        technique="time",
        matched=matched,
        detail=detail if matched else "",
        payload=payload,
        evidence={
            "baseline_max_s": f"{baseline_ref:.3f}",
            "injected_s": f"{injected_time:.3f}",
            "threshold_s": f"{threshold:.3f}",
        },
    )


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------
def score_confidence(matched_signals: List[SignalResult]) -> Tuple[str, str]:
    """Map a set of matched signals to a confidence label and risk level.

    Policy (low false positives):
        * 0 matched signals -> not a finding (handled by caller).
        * 1 matched signal  -> "Low" (possible / unconfirmed).
        * 2 matched signals -> "Medium" (confirmed by independent signals).
        * 3+ matched signals -> "High".
    Error-based signals are weighted slightly higher because a real DB error
    string is a very strong indicator.
    """
    techniques = {s.technique for s in matched_signals if s.matched}
    count = len(techniques)

    if count == 0:
        return "None", "Informational"
    if count == 1:
        # A lone error-based hit is more trustworthy than a lone boolean/time.
        if "error" in techniques:
            return "Medium", "High"
        return "Low", "Medium"
    if count == 2:
        return "Medium", "High"
    return "High", "Critical"


# ---------------------------------------------------------------------------
# Lightweight response metrics (shared with scanner)
# ---------------------------------------------------------------------------
@dataclass
class ResponseMetrics:
    """Compact, comparable fingerprint of an HTTP response.

    Used for false-positive reduction: comparing status, length, content hash
    and timing instead of raw bodies.
    """

    status: int
    length: int
    elapsed: float
    content_hash: str
    dbms_error: Optional[str] = None

    def is_similar_to(self, other: "ResponseMetrics", threshold: float = 0.95) -> bool:
        """Return True if two responses are 'similar enough'.

        Similarity requires the same status code and a content-length ratio
        within ``threshold``. Exact hash match is treated as fully similar.
        """
        if self.status != other.status:
            return False
        if self.content_hash and self.content_hash == other.content_hash:
            return True
        longer = max(self.length, other.length)
        if longer == 0:
            return True  # both empty -> identical
        shorter = min(self.length, other.length)
        ratio = shorter / longer
        return ratio >= threshold
