# Defensive Web Vulnerability Detection Scanner

A lightweight, **detection-only** web vulnerability scanner for **authorized
Vulnerability Assessment and Penetration Testing (VAPT)**. Give it a single URL
and it will safely crawl the same host, discover parameters (query string, forms,
hidden fields, JSON bodies, path-like values), and test them for multiple
vulnerability classes with low false positives.

**Detects:** SQL Injection (SQLi) · Reflected Cross-Site Scripting (XSS) ·
XML External Entity (XXE) · Cross-Site Request Forgery (CSRF) ·
Server-Side Request Forgery (SSRF).

---

## ⚠️ Authorized Use Only

> This tool is intended **exclusively** for security testing of systems you own
> or are **explicitly authorized in writing** to test. Unauthorized scanning of
> third-party systems may be **illegal** and unethical. You are solely
> responsible for ensuring you have permission. The authors assume no liability
> for misuse.

By using this tool you confirm you have authorization for the target.

---

## What it does NOT do (by design)

This is a **defensive detection** tool. It deliberately **does not** implement:

- Database dumping, table/column enumeration, or data extraction
- Password / credential extraction
- **XXE file reads or external-entity / SSRF-via-XML** (only safe *internal*
  entity-expansion is tested)
- Forcing the server to reach internal/loopback/cloud-metadata addresses
- WAF bypass, tamper scripts, or evasion modules
- Authentication bypass exploitation
- Shell upload / RCE / file read-write
- Submitting real state-changing requests (CSRF is analyzed passively)
- Any destructive HTTP methods unless you *explicitly* opt in

It only confirms whether a vulnerability *appears* present, then reports it so a
developer can fix it.

---

## Detection techniques (safe, non-destructive)

| Class | Technique | Confirmation |
|-------|-----------|--------------|
| **SQLi** | Error-based (MySQL/PostgreSQL/MSSQL/Oracle/SQLite fingerprints), boolean-based (TRUE vs FALSE), bounded time-based (delay clamped 2–10s) | ≥ 2 independent signals → Confirmed |
| **XSS** (reflected) | Unique benign marker reflection + unencoded `< > " '` detection with HTML/attribute/script/comment context classification (no browser, no script execution) | Unencoded tag/quote breakout → Confirmed |
| **XXE** | Safe **internal** entity-expansion probe + XML parser error fingerprinting (never uses `SYSTEM`/external entities) | Entity expanded & literal reference gone → Confirmed |
| **CSRF** | Passive analysis of state-changing POST forms for a server-validated anti-CSRF token; optional cookie `SameSite` inspection | Reported as *Possible* (manual verification advised) |
| **SSRF** | Passive identification of URL-accepting parameters; optional **user-supplied public canary** for out-of-band confirmation | Passive = *Possible*; confirm via your own listener |

A finding is marked **Confirmed** only when its detector's confirmation policy
is satisfied; everything else is reported as **Possible** to keep false
positives low. Each finding carries a confidence (Low/Medium/High), risk level,
and CWE / OWASP mapping.

---

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Default: run SQLi + XSS + CSRF + SSRF on a single URL (crawls same host)
python3 -m sqli_scanner.main "https://target.example.com/page?id=1"

# Choose specific checks
python3 -m sqli_scanner.main "https://target.example.com/?id=1" --checks sqli,xss

# Authenticated testing with cookies and headers
python3 -m sqli_scanner.main "https://target.example.com/app?id=1" \
    --cookie "session=abc123" \
    --header "Authorization: Bearer <token>"

# SSRF: confirm safely with YOUR OWN public canary/OAST domain
python3 -m sqli_scanner.main "https://target.example.com/fetch?url=http://x" \
    --ssrf-canary "https://abc123.your-collaborator.example.com"

# XXE: opt-in (only meaningful for XML-accepting endpoints)
python3 -m sqli_scanner.main "https://target.example.com/xmlapi" --test-xml

# Reports + safety tuning
python3 -m sqli_scanner.main "https://target.example.com/?id=1" \
    --max-depth 2 --max-requests 300 --delay 0.5 --timeout 10 \
    --json-report report.json --html-report report.html
```

Run `python3 -m sqli_scanner.main --help` for all options.

> **Note:** Run the command from the directory that *contains* the
> `sqli_scanner/` folder so the package import (`-m sqli_scanner.main`) resolves.

### Key options

| Option | Purpose |
|--------|---------|
| `--checks sqli,xss,csrf,ssrf,xxe` | Subset of checks to run (default: `sqli,xss,csrf,ssrf`; `xxe` is opt-in) |
| `--ssrf-canary URL` | Your public OAST/canary URL for safe SSRF confirmation (internal targets refused) |
| `--test-xml` / `--xml-body` | Enable the XXE check / supply a raw XML body |
| `--csrf-cookie-check` | Also inspect `Set-Cookie` `SameSite` for CSRF |
| `--delay` / `--timeout` / `--max-requests` | Safety controls |
| `--cookie` / `--header` | Authenticated testing |
| `--json-report` / `--html-report` | Output reports |

## Output

The scan prints a console summary with a per-category breakdown and can emit
JSON and HTML reports. Each finding includes: vulnerability type & category,
affected URL, parameter, HTTP method, evidence summary, confidence
(Low/Medium/High), risk level, safe reproduction steps, remediation, and
CWE / OWASP mapping.

## Offline self-test

No live target handy? Run the built-in self-test, which exercises every detector
against in-memory mock apps (and verifies safe apps are **not** flagged):

```bash
python3 -m sqli_scanner.selftest
```

## Project structure

```
sqli_scanner/
├── __init__.py
├── crawler.py        # safe same-host crawling
├── parser.py         # parameter / form / JSON extraction
├── scanner.py        # orchestration, baselining, SQLi engine, shared HTTP probe
├── detector.py       # SQL DB error fingerprints + SQLi signal logic
├── xss_detector.py   # reflected XSS detection
├── xxe_detector.py   # safe XXE (internal entity expansion) detection
├── csrf_detector.py  # passive CSRF analysis
├── ssrf_detector.py  # SSRF surface ID + optional safe canary
├── reporter.py       # console / JSON / HTML reporting
├── main.py           # CLI entry point
├── selftest.py       # offline pipeline test (no network/deps)
├── requirements.txt
└── README.md
```
