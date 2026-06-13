"""
reporter.py
===========

Reporting layer. Produces:
    * A human-readable console summary.
    * A machine-readable JSON report.
    * A styled, self-contained HTML report.

All reporters consume the same ``Finding`` list plus scan metadata, so output
stays consistent across formats.
"""

from __future__ import annotations

import html
import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .scanner import Finding, ScanStats
from . import severity as sev_mod

logger = logging.getLogger("sqli_scanner.reporter")

# ANSI colors for the console (degrade gracefully if redirected).
_COLORS = {
    "High": "\033[91m",      # red
    "Critical": "\033[91m",
    "Medium": "\033[93m",    # yellow
    "Low": "\033[96m",       # cyan
    "Info": "\033[90m",      # grey
    "reset": "\033[0m",
    "bold": "\033[1m",
    "green": "\033[92m",
}


def _c(text: str, key: str, use_color: bool) -> str:
    """Wrap text in an ANSI color if color output is enabled."""
    if not use_color:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['reset']}"


def effective_severity(finding: Finding) -> str:
    """Return the finding's severity, deriving it if not explicitly set."""
    return finding.severity or sev_mod.derive(
        finding.risk, finding.confidence, finding.confirmed
    )


def _sorted_findings(findings: List[Finding]) -> List[Finding]:
    """Sort findings most-severe first (then confirmed before possible)."""
    return sorted(
        findings,
        key=lambda f: (sev_mod.rank(effective_severity(f)), not f.confirmed),
    )


_SEV_ICON = {
    "Critical": "[!!]", "High": "[!]", "Medium": "[*]", "Low": "[-]", "Info": "[i]",
}


def live_finding_line(finding: Finding, use_color: bool = True) -> None:
    """Print a single finding immediately as it is discovered (streaming UI)."""
    sev = effective_severity(finding)
    icon = _SEV_ICON.get(sev, "[*]")
    status = "CONFIRMED" if finding.confirmed else "possible"
    sev_tag = _c(f"{icon} {sev:<8}", sev, use_color)
    cat = _c(f"{finding.category:<18}", "bold", use_color)
    where = finding.param if finding.param else finding.url
    line = f"  {sev_tag} {cat} {finding.vuln_type}  ->  {where}  ({status})"
    print(line, flush=True)


def print_phase(message: str, use_color: bool = True) -> None:
    """Print a scan-phase header line during the scan."""
    print(_c(f"\n[>] {message}", "bold", use_color), flush=True)


def build_report_dict(
    target: str,
    findings: List[Finding],
    stats: ScanStats,
    crawl_info: Dict[str, object],
) -> Dict[str, object]:
    """Assemble the canonical report structure shared by all output formats."""
    findings = _sorted_findings(findings)
    confirmed = [f for f in findings if f.confirmed]
    possible = [f for f in findings if not f.confirmed]
    # Per-category and per-severity breakdowns.
    by_category: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
        sv = effective_severity(f)
        by_severity[sv] = by_severity.get(sv, 0) + 1
    # Order severity breakdown most-severe first.
    by_severity_ordered = {
        s: by_severity[s] for s in sev_mod.SEVERITY_ORDER if s in by_severity
    }
    return {
        "tool": "Defensive Web Vulnerability Detection Scanner",
        "version": "3.0.0",
        "disclaimer": (
            "Authorized security testing only. Detection-only tool: it confirms "
            "the presence of vulnerabilities but performs no data extraction, "
            "no exploitation, no auth/WAF bypass, and no destructive actions."
        ),
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "urls_crawled": crawl_info.get("urls_crawled", 0),
            "unsafe_skipped": crawl_info.get("unsafe_skipped", 0),
            "parameters_tested": stats.params_tested,
            "requests_sent": stats.requests_sent,
            "confirmed_findings": len(confirmed),
            "possible_findings": len(possible),
            "findings_by_severity": by_severity_ordered,
            "findings_by_category": by_category,
            "false_positive_filtered": stats.false_positive_filtered + stats.unstable_skipped,
            "unstable_endpoints_skipped": stats.unstable_skipped,
            "request_budget_exhausted": stats.budget_exhausted,
        },
        "findings": [_finding_to_dict(f) for f in findings],
    }


def _finding_to_dict(finding: Finding) -> Dict[str, object]:
    """Serialize a Finding (including computed severity / status fields)."""
    data = asdict(finding)
    sv = effective_severity(finding)
    data["confirmed"] = finding.confirmed
    data["status"] = "Confirmed" if finding.confirmed else "Possible"
    data["severity"] = sv
    data["cvss_band"] = sev_mod.cvss_band(sv)
    return data


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------
def print_console_summary(
    target: str,
    findings: List[Finding],
    stats: ScanStats,
    crawl_info: Dict[str, object],
    report_paths: Optional[Dict[str, str]] = None,
    use_color: bool = True,
) -> None:
    """Print the end-of-scan console summary and per-finding details."""
    report_paths = report_paths or {}
    findings = _sorted_findings(findings)
    confirmed = [f for f in findings if f.confirmed]
    possible = [f for f in findings if not f.confirmed]

    line = "=" * 70
    print(line)
    print(_c("  WEB VULNERABILITY DETECTION - SCAN SUMMARY", "bold", use_color))
    print(line)
    print(f"  Target                  : {target}")
    print(f"  Total URLs crawled      : {crawl_info.get('urls_crawled', 0)}")
    print(f"  Unsafe actions skipped  : {crawl_info.get('unsafe_skipped', 0)}")
    print(f"  Total parameters tested : {stats.params_tested}")
    print(f"  Total requests sent     : {stats.requests_sent}")
    print(f"  {_c('Confirmed findings', 'High', use_color)}      : "
          f"{_c(str(len(confirmed)), 'High', use_color)}")
    print(f"  {_c('Possible findings', 'Medium', use_color)}       : "
          f"{_c(str(len(possible)), 'Medium', use_color)}")
    # Per-severity breakdown (most severe first).
    by_severity: Dict[str, int] = {}
    for f in findings:
        sv = effective_severity(f)
        by_severity[sv] = by_severity.get(sv, 0) + 1
    if by_severity:
        parts = [f"{_c(s, s, use_color)}={by_severity[s]}"
                 for s in sev_mod.SEVERITY_ORDER if s in by_severity]
        print(f"  By severity             : {', '.join(parts)}")
    # Per-category breakdown.
    by_category: Dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
    if by_category:
        breakdown = ", ".join(f"{cat}={n}" for cat, n in sorted(by_category.items()))
        print(f"  By category             : {breakdown}")
    print(f"  False-positive filtered : "
          f"{stats.false_positive_filtered + stats.unstable_skipped} "
          f"(unstable endpoints: {stats.unstable_skipped})")
    if stats.budget_exhausted:
        print(_c("  NOTE: request budget exhausted; scan may be incomplete.",
                 "Medium", use_color))
    print(line)

    if not findings:
        print(_c("  No vulnerability indicators detected.", "green", use_color))
    else:
        for idx, f in enumerate(findings, start=1):
            status = "Confirmed" if f.confirmed else "Possible"
            sev = effective_severity(f)
            print()
            print(f"  [{idx}] {_c(sev, sev, use_color)} | {status} [{f.category}] - {f.vuln_type}")
            print(f"      URL        : {f.url}")
            print(f"      Parameter  : {f.param}  ({f.location})")
            print(f"      Method     : {f.method}")
            print(f"      Severity   : {_c(sev, sev, use_color)} (CVSS {sev_mod.cvss_band(sev)})")
            print(f"      Confidence : {_c(f.confidence, f.confidence, use_color)}")
            if f.dbms:
                print(f"      DBMS       : {f.dbms}")
            print(f"      Signals    : {', '.join(f.matched_techniques)}")
            if f.evidence:
                print(f"      Evidence   : {f.evidence[0]}")
            print(f"      CWE/OWASP  : {f.cwe.split(':')[0]} / {f.owasp}")

    if report_paths:
        print()
        for fmt, path in report_paths.items():
            print(f"  {fmt.upper()} report written to: {path}")
    print(line)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def write_json_report(path: str, report: Dict[str, object]) -> str:
    """Write the report dict to ``path`` as pretty-printed JSON."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        logger.info("JSON report written to %s", path)
    except OSError as exc:
        logger.error("Failed to write JSON report to %s: %s", path, exc)
        raise
    return path


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def write_html_report(path: str, report: Dict[str, object]) -> str:
    """Write a self-contained, styled HTML report."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_render_html(report))
        logger.info("HTML report written to %s", path)
    except OSError as exc:
        logger.error("Failed to write HTML report to %s: %s", path, exc)
        raise
    return path


def _badge(value: str) -> str:
    """Return an HTML class name for a severity/confidence/risk badge."""
    mapping = {
        "High": "badge-high", "Critical": "badge-critical",
        "Medium": "badge-medium", "Low": "badge-low", "Info": "badge-info",
        "Confirmed": "badge-high", "Possible": "badge-medium",
        "Informational": "badge-info",
    }
    return mapping.get(value, "badge-low")


def _render_html(report: Dict[str, object]) -> str:
    """Render the full HTML document for a report dict."""
    e = html.escape
    summary = report.get("summary", {})  # type: ignore
    findings = report.get("findings", [])  # type: ignore

    rows = []
    for idx, f in enumerate(findings, start=1):  # type: ignore
        status = f.get("status", "Possible")
        category = f.get("category", "SQLi")
        sev = f.get("severity", "Info")
        evidence_items = "".join(
            f"<li>{e(str(item))}</li>" for item in f.get("evidence", [])
        ) or "<li>(no additional evidence captured)</li>"
        repro_items = "".join(
            f"<li>{e(str(step))}</li>" for step in f.get("reproduction", [])
        )
        dbms_row = (
            f"<tr><th>Detected DBMS</th><td>{e(str(f.get('dbms')))}</td></tr>"
            if f.get("dbms") else ""
        )
        rows.append(f"""
        <div class="finding">
          <div class="finding-head">
            <span class="idx">#{idx}</span>
            <span class="badge {_badge(str(sev))}">{e(str(sev))}</span>
            <span class="badge {_badge(status)}">{e(status)}</span>
            <span class="badge badge-cat">{e(str(category))}</span>
            <span class="vtype">{e(str(f.get('vuln_type', 'Vulnerability')))}</span>
          </div>
          <table class="kv">
            <tr><th>Severity</th><td><span class="badge {_badge(str(sev))}">{e(str(sev))}</span> (CVSS {e(str(f.get('cvss_band','')))})</td></tr>
            <tr><th>Affected URL</th><td>{e(str(f.get('url', '')))}</td></tr>
            <tr><th>Parameter</th><td>{e(str(f.get('param', '')))} ({e(str(f.get('location', '')))})</td></tr>
            <tr><th>HTTP Method</th><td>{e(str(f.get('method', '')))}</td></tr>
            <tr><th>Confidence</th><td><span class="badge {_badge(str(f.get('confidence','')))}">{e(str(f.get('confidence', '')))}</span></td></tr>
            <tr><th>Risk Level</th><td><span class="badge {_badge(str(f.get('risk','')))}">{e(str(f.get('risk', '')))}</span></td></tr>
            {dbms_row}
            <tr><th>Signals Matched</th><td>{e(', '.join(f.get('matched_techniques', [])))}</td></tr>
            <tr><th>CWE</th><td>{e(str(f.get('cwe', '')))}</td></tr>
            <tr><th>OWASP</th><td>{e(str(f.get('owasp', '')))}</td></tr>
          </table>
          <div class="section-title">Evidence Summary</div>
          <ul>{evidence_items}</ul>
          <div class="section-title">Reproduction Steps (safe)</div>
          <ol>{repro_items}</ol>
          <div class="section-title">Remediation</div>
          <p>{e(str(f.get('remediation', '')))}</p>
        </div>
        """)

    findings_html = "\n".join(rows) if rows else (
        "<p class='ok'>No vulnerability indicators detected.</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Vulnerability Detection Report</title>
<style>
  :root {{ --bg:#0f1720; --card:#1b2733; --muted:#8aa0b2; --fg:#e6edf3; --accent:#4da3ff; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin:0; background:var(--bg); color:var(--fg); }}
  header {{ padding:24px 32px; background:linear-gradient(90deg,#16202b,#1b2733);
            border-bottom:1px solid #2a3a49; }}
  header h1 {{ margin:0 0 4px; font-size:22px; }}
  header .sub {{ color:var(--muted); font-size:13px; }}
  .disclaimer {{ margin:16px 32px; padding:12px 16px; border-left:4px solid #d29922;
                 background:#2a2410; color:#f0e3b8; border-radius:4px; font-size:13px; }}
  .wrap {{ padding:8px 32px 48px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
           gap:12px; margin:16px 0 28px; }}
  .stat {{ background:var(--card); padding:14px 16px; border-radius:8px;
           border:1px solid #2a3a49; }}
  .stat .num {{ font-size:24px; font-weight:700; }}
  .stat .lbl {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
  .finding {{ background:var(--card); border:1px solid #2a3a49; border-radius:10px;
              padding:18px 20px; margin-bottom:18px; }}
  .finding-head {{ display:flex; align-items:center; gap:10px; margin-bottom:12px; }}
  .idx {{ color:var(--muted); font-weight:700; }}
  .vtype {{ font-weight:600; font-size:15px; }}
  .badge {{ display:inline-block; padding:2px 10px; border-radius:999px;
            font-size:12px; font-weight:700; }}
  .badge-high {{ background:#3d1418; color:#ff8b94; border:1px solid #7a2630; }}
  .badge-critical {{ background:#4a0d12; color:#ff6b78; border:1px solid #b3303d; }}
  .badge-medium {{ background:#3a2f10; color:#f6cd5b; border:1px solid #7a6420; }}
  .badge-low {{ background:#0f2a33; color:#69d2e7; border:1px solid #1d5564; }}
  .badge-info {{ background:#23272e; color:#aab4c0; border:1px solid #3a414b; }}
  .badge-cat {{ background:#1a2a3d; color:#8fb8ff; border:1px solid #2f4a6b; }}
  table.kv {{ width:100%; border-collapse:collapse; margin:6px 0 4px; }}
  table.kv th {{ text-align:left; width:160px; color:var(--muted); font-weight:500;
                 padding:4px 8px; vertical-align:top; font-size:13px; }}
  table.kv td {{ padding:4px 8px; font-size:13px; word-break:break-all; }}
  .section-title {{ margin:14px 0 4px; font-size:12px; text-transform:uppercase;
                    letter-spacing:.05em; color:var(--accent); }}
  ul, ol {{ margin:4px 0 4px 18px; font-size:13px; }}
  .ok {{ color:#5fd38a; font-size:15px; }}
  footer {{ color:var(--muted); font-size:12px; padding:24px 32px; }}
</style>
</head>
<body>
<header>
  <h1>Web Vulnerability Detection Report</h1>
  <div class="sub">Target: {e(str(report.get('target','')))} &middot; Generated: {e(str(report.get('generated_at','')))}</div>
</header>
<div class="disclaimer"><strong>Authorized testing only.</strong> {e(str(report.get('disclaimer','')))}</div>
<div class="wrap">
  <div class="grid">
    <div class="stat"><div class="num">{summary.get('urls_crawled',0)}</div><div class="lbl">URLs Crawled</div></div>
    <div class="stat"><div class="num">{summary.get('parameters_tested',0)}</div><div class="lbl">Params Tested</div></div>
    <div class="stat"><div class="num">{summary.get('requests_sent',0)}</div><div class="lbl">Requests Sent</div></div>
    <div class="stat"><div class="num">{summary.get('confirmed_findings',0)}</div><div class="lbl">Confirmed</div></div>
    <div class="stat"><div class="num">{summary.get('possible_findings',0)}</div><div class="lbl">Possible</div></div>
    <div class="stat"><div class="num">{summary.get('false_positive_filtered',0)}</div><div class="lbl">FP Filtered</div></div>
  </div>
  <h2>Findings</h2>
  {findings_html}
</div>
<footer>Generated by Defensive Web Vulnerability Detection Scanner v{e(str(report.get('version','2.0.0')))}.
Detection-only &middot; no data extraction or exploitation performed.</footer>
</body>
</html>"""
