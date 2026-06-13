# Defensive SQL Injection Detection Scanner

A lightweight, **detection-only** SQL injection (SQLi) scanner for **authorized
Vulnerability Assessment and Penetration Testing (VAPT)**. Give it a single URL
and it will safely crawl the same host, discover parameters (query string, forms,
hidden fields, JSON bodies, path-like values), and test them for SQL injection
using non-destructive signals with low false positives.

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
- Out-of-band or stacked-query exploitation
- WAF bypass, tamper scripts, or evasion modules
- Authentication bypass exploitation
- Shell upload / RCE / file read-write
- Any destructive HTTP methods unless you *explicitly* opt in

It only confirms whether a parameter *appears* injectable, then reports it so a
developer can fix it.

---

## Detection techniques (safe, non-destructive)

- **Error-based**: fingerprints DB error messages (MySQL, PostgreSQL, MSSQL,
  Oracle, SQLite).
- **Boolean-based**: compares responses for logically TRUE vs. FALSE payloads.
- **Time-based**: bounded `SLEEP`/delay payloads with strict timeouts and
  baseline timing comparison (the only "active" probe, kept minimal and capped).
- **Numeric vs. string** context handling per parameter.

A finding is only marked **confirmed** when **at least two independent signals**
agree and the endpoint is stable across repeated requests.

---

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Basic: scan a single URL (crawls same host within depth limit)
python3 -m sqli_scanner.main "https://target.example.com/page?id=1"

# Authenticated testing with cookies and headers
python3 -m sqli_scanner.main "https://target.example.com/app?id=1" \
    --cookie "session=abc123" \
    --header "Authorization: Bearer <token>"

# Tuning safety controls
python3 -m sqli_scanner.main "https://target.example.com/?id=1" \
    --max-depth 2 --max-requests 300 --delay 0.5 --timeout 10

# Output reports
python3 -m sqli_scanner.main "https://target.example.com/?id=1" \
    --json-report report.json --html-report report.html
```

Run `python3 -m sqli_scanner.main --help` for all options.

> **Note:** Run the command from the directory that *contains* the
> `sqli_scanner/` folder so the package import (`-m sqli_scanner.main`) resolves.

## Output

The scan prints a console summary and can emit JSON and HTML reports. Each
finding includes: vulnerability type, affected URL, parameter, HTTP method,
evidence summary, confidence (Low/Medium/High), risk level, safe reproduction
steps, remediation, and CWE / OWASP mapping.

## Project structure

```
sqli_scanner/
├── __init__.py
├── crawler.py     # safe same-host crawling
├── parser.py      # parameter / form / JSON extraction
├── scanner.py     # orchestration, baselining, multi-signal confirmation
├── detector.py    # DB error fingerprints + detection logic
├── reporter.py    # console / JSON / HTML reporting
├── main.py        # CLI entry point
├── requirements.txt
└── README.md
```
