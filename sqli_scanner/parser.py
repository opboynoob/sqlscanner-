"""
parser.py
=========

Parameter discovery and request modeling.

This module extracts everything the scanner can safely test from a page:
    * Query-string parameters
    * HTML form fields (including hidden fields), POST and GET forms
    * JSON body keys (when a JSON request is supplied)
    * Path-like values (numeric or short string path segments that look like IDs)

It also models requests as ``RequestTemplate`` objects and enumerates
``InjectionPoint`` objects (one per testable parameter). No network I/O happens
here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

try:
    from bs4 import BeautifulSoup  # type: ignore
except ImportError:  # pragma: no cover - dependency guidance
    BeautifulSoup = None  # noqa: N816


# Keywords in a URL/form action that suggest a destructive or sensitive action.
# We never inject payloads into these to avoid side effects.
UNSAFE_ACTION_KEYWORDS = (
    "logout", "signout", "sign-out", "delete", "remove", "destroy", "drop",
    "payment", "pay", "checkout", "purchase", "buy", "order", "transfer",
    "withdraw", "refund", "reset", "deactivate", "disable", "ban",
    "unsubscribe", "subscribe", "register", "password", "credit", "card",
    "admin/delete", "wipe", "purge", "shutdown",
)

# Path segments that look like opaque IDs and are good path-injection candidates.
_NUMERIC_RE = re.compile(r"^\d+$")
_SHORT_SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
# File-like or known non-id segments we should not treat as injectable IDs.
_FILE_LIKE_RE = re.compile(r".+\.[A-Za-z0-9]{1,5}$")
_NON_ID_SEGMENTS = {
    "api", "v1", "v2", "v3", "static", "assets", "css", "js", "img",
    "images", "fonts", "public", "www",
}


@dataclass
class RequestTemplate:
    """A discoverable, testable request.

    Attributes:
        url:        Target URL (for GET this includes the path; query is in
                    ``query_params``).
        method:     "GET" or "POST".
        query_params: Parameters carried in the URL query string.
        body_params:  Parameters carried in the body (POST).
        body_type:    "none", "urlencoded", or "json".
        source:       Human-readable description of where this came from.
    """

    url: str
    method: str = "GET"
    query_params: Dict[str, str] = field(default_factory=dict)
    body_params: Dict[str, str] = field(default_factory=dict)
    body_type: str = "none"  # none | urlencoded | json
    source: str = "url"

    def is_unsafe(self) -> bool:
        """Return True if this request targets a destructive/sensitive action."""
        return is_unsafe_target(self.url, {**self.query_params, **self.body_params})


@dataclass
class InjectionPoint:
    """A single parameter (within a RequestTemplate) to test for SQLi.

    Attributes:
        template:   The owning request template.
        param_name: Name of the parameter to fuzz.
        location:   "query", "body", or "path".
        original_value: The unmodified value (used to build TRUE/baseline cases).
        path_index: For path injection, the index of the path segment to mutate.
    """

    template: RequestTemplate
    param_name: str
    location: str  # query | body | path
    original_value: str = ""
    path_index: Optional[int] = None

    @property
    def numeric_context(self) -> bool:
        """Whether the original value looks numeric (affects payload choice)."""
        return bool(_NUMERIC_RE.match(self.original_value or ""))


# ---------------------------------------------------------------------------
# Safety helpers
# ---------------------------------------------------------------------------
def is_unsafe_target(url: str, params: Optional[Dict[str, str]] = None) -> bool:
    """Heuristically decide whether a URL/params represent an unsafe action."""
    haystack = (url or "").lower()
    if any(keyword in haystack for keyword in UNSAFE_ACTION_KEYWORDS):
        return True
    if params:
        joined = " ".join(f"{k} {v}" for k, v in params.items()).lower()
        if any(keyword in joined for keyword in UNSAFE_ACTION_KEYWORDS):
            return True
    return False


def same_host(url_a: str, url_b: str) -> bool:
    """Return True if both URLs share the same network location (host:port)."""
    a, b = urlparse(url_a), urlparse(url_b)
    return (a.scheme in ("http", "https")
            and b.scheme in ("http", "https")
            and a.netloc.lower() == b.netloc.lower())


# ---------------------------------------------------------------------------
# Query string parsing
# ---------------------------------------------------------------------------
def split_url(url: str) -> "tuple[str, Dict[str, str]]":
    """Split a URL into its base (without query) and a dict of query params."""
    parsed = urlparse(url)
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    base = urlunparse(parsed._replace(query=""))
    return base, query_params


def build_request_from_url(url: str) -> RequestTemplate:
    """Create a GET RequestTemplate from a raw URL."""
    base, query_params = split_url(url)
    return RequestTemplate(
        url=base,
        method="GET",
        query_params=query_params,
        body_type="none",
        source="url-query",
    )


# ---------------------------------------------------------------------------
# JSON body parsing
# ---------------------------------------------------------------------------
def build_request_from_json(url: str, raw_json: str, method: str = "POST") -> RequestTemplate:
    """Create a POST RequestTemplate from a raw JSON string.

    Only top-level string/number keys are treated as testable parameters to keep
    behavior predictable and avoid mutating nested structures destructively.
    """
    base, query_params = split_url(url)
    try:
        data = json.loads(raw_json)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid JSON body: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("JSON body must be an object at the top level.")

    body_params = {
        key: ("" if value is None else str(value))
        for key, value in data.items()
        if isinstance(value, (str, int, float, bool)) or value is None
    }
    return RequestTemplate(
        url=base,
        method=method.upper(),
        query_params=query_params,
        body_params=body_params,
        body_type="json",
        source="json-body",
    )


# ---------------------------------------------------------------------------
# HTML form parsing
# ---------------------------------------------------------------------------
def extract_forms(html: str, page_url: str) -> List[RequestTemplate]:
    """Parse all HTML forms on a page into RequestTemplate objects.

    Captures input/textarea/select fields, including hidden fields, and resolves
    the form action relative to the page URL. Unsafe forms are skipped.
    """
    if BeautifulSoup is None:
        raise RuntimeError(
            "beautifulsoup4 is required for form parsing. Install with "
            "`pip install beautifulsoup4`."
        )

    templates: List[RequestTemplate] = []
    soup = BeautifulSoup(html or "", "html.parser")

    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        action_url = urljoin(page_url, action)
        method = (form.get("method") or "GET").strip().upper()
        if method not in ("GET", "POST"):
            method = "GET"

        fields: Dict[str, str] = {}
        for field_tag in form.find_all(["input", "textarea", "select"]):
            name = field_tag.get("name")
            if not name:
                continue
            input_type = (field_tag.get("type") or "text").lower()
            # Skip controls that should not be fuzzed.
            if input_type in ("submit", "button", "image", "reset", "file"):
                continue
            # Capture default value (covers hidden fields too).
            value = field_tag.get("value") or ""
            if field_tag.name == "select":
                option = field_tag.find("option")
                value = (option.get("value") if option else "") or ""
            fields[name] = value

        if not fields:
            continue

        # Honor the declared content type semantics.
        if method == "POST":
            template = RequestTemplate(
                url=urljoin(page_url, urlparse(action_url)._replace(query="").geturl()),
                method="POST",
                body_params=fields,
                body_type="urlencoded",
                source="html-form-post",
            )
        else:
            base, existing_q = split_url(action_url)
            existing_q.update(fields)
            template = RequestTemplate(
                url=base,
                method="GET",
                query_params=existing_q,
                body_type="none",
                source="html-form-get",
            )

        if template.is_unsafe():
            continue
        templates.append(template)

    return templates


# ---------------------------------------------------------------------------
# Link extraction (used by crawler)
# ---------------------------------------------------------------------------
def extract_links(html: str, page_url: str) -> List[str]:
    """Extract absolute hyperlinks from anchor tags on a page."""
    if BeautifulSoup is None:
        return []
    soup = BeautifulSoup(html or "", "html.parser")
    links: List[str] = []
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        links.append(urljoin(page_url, href))
    return links


# ---------------------------------------------------------------------------
# Path-like parameter discovery
# ---------------------------------------------------------------------------
def discover_path_injection_points(template: RequestTemplate) -> List[InjectionPoint]:
    """Identify path segments that look like IDs and model them as test points.

    Example: ``/products/42/reviews`` -> the ``42`` segment is a candidate.
    """
    points: List[InjectionPoint] = []
    parsed = urlparse(template.url)
    segments = [s for s in parsed.path.split("/")]

    for index, segment in enumerate(segments):
        if not segment:
            continue
        if segment.lower() in _NON_ID_SEGMENTS:
            continue
        if _FILE_LIKE_RE.match(segment):
            continue
        is_numeric = bool(_NUMERIC_RE.match(segment))
        is_slug = bool(_SHORT_SLUG_RE.match(segment))
        # Prefer numeric IDs; also allow short slugs that are not obvious words
        # by requiring they contain a digit (reduces noise on /about, /home).
        if is_numeric or (is_slug and any(ch.isdigit() for ch in segment)):
            points.append(
                InjectionPoint(
                    template=template,
                    param_name=f"path[{index}]",
                    location="path",
                    original_value=segment,
                    path_index=index,
                )
            )
    return points


# ---------------------------------------------------------------------------
# Top-level: enumerate all injection points for a template
# ---------------------------------------------------------------------------
def enumerate_injection_points(
    template: RequestTemplate,
    include_path: bool = True,
) -> List[InjectionPoint]:
    """Return every testable parameter for a given request template.

    Combines query params, body params, and (optionally) path-like values.
    """
    points: List[InjectionPoint] = []

    for name, value in template.query_params.items():
        points.append(
            InjectionPoint(
                template=template,
                param_name=name,
                location="query",
                original_value=value,
            )
        )

    for name, value in template.body_params.items():
        points.append(
            InjectionPoint(
                template=template,
                param_name=name,
                location="body",
                original_value=value,
            )
        )

    if include_path:
        points.extend(discover_path_injection_points(template))

    return points


# ---------------------------------------------------------------------------
# Request materialization helpers (used by scanner)
# ---------------------------------------------------------------------------
def materialize(
    point: InjectionPoint,
    injected_value: str,
) -> "tuple[str, str, Optional[Dict[str, str]], Optional[str], str]":
    """Build a concrete request for an injection point with one value replaced.

    Returns a tuple:
        (method, url, form_data_or_None, json_body_or_None, body_type)

    Exactly one of form_data / json_body is populated for POST requests; for GET
    requests both are None and parameters are encoded in the URL.
    """
    template = point.template
    method = template.method

    # Start from copies so we never mutate the template.
    query = dict(template.query_params)
    body = dict(template.body_params)
    url = template.url

    if point.location == "query":
        query[point.param_name] = injected_value
    elif point.location == "body":
        body[point.param_name] = injected_value
    elif point.location == "path" and point.path_index is not None:
        parsed = urlparse(template.url)
        segments = parsed.path.split("/")
        if 0 <= point.path_index < len(segments):
            # URL-encode minimally; keep payload readable for the target parser.
            from urllib.parse import quote
            segments[point.path_index] = quote(injected_value, safe="")
            new_path = "/".join(segments)
            url = urlunparse(parsed._replace(path=new_path))

    # Compose final URL with query string.
    if query:
        parsed = urlparse(url)
        url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

    if method == "POST":
        if template.body_type == "json":
            return method, url, None, json.dumps(body), "json"
        return method, url, body, None, "urlencoded"

    return method, url, None, None, "none"
