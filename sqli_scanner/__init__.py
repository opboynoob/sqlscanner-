"""
Defensive SQL Injection Detection Scanner (authorized VAPT use only).

This package implements a NON-DESTRUCTIVE SQL injection *detection* tool.
It does NOT dump databases, enumerate tables, extract data, upload shells,
bypass WAFs, or perform any exploitation. Its sole purpose is to flag
likely-injectable parameters so they can be remediated.

Modules:
    detector  - DB error fingerprints and signal-based detection logic
    parser    - parameter / form / JSON extraction
    crawler   - safe same-host crawling
    scanner   - orchestration, baselining, multi-signal confirmation
    reporter  - console / JSON / HTML reporting
    main      - CLI entry point
"""

__version__ = "1.0.0"
__all__ = ["detector", "parser", "crawler", "scanner", "reporter"]
