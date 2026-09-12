# WebGuard — Vulnerability Testing & Remediation

A small, self-hosted REST API with three deliberately built-in vulnerabilities, used to practice functional and security testing, documented findings, remediation, and retesting.

## Quick start

```
pip install -r requirements.txt

# Terminal 1 - the vulnerable version
python vulnerable_api.py

# Terminal 2 - attack it for real
python exploit_tests.py
```

Then, to see the remediated version:

```
# Terminal 1 - stop vulnerable_api.py, run the fixed one instead
python fixed_api.py

# Terminal 2 - prove the same attacks now fail
python retest.py
```

## What's inside

| File | Purpose |
|---|---|
| `vulnerable_api.py` | The target: SQL Injection, IDOR, and an exposed debug endpoint |
| `exploit_tests.py` | Real Python `requests`-based tests proving each vulnerability |
| `fixed_api.py` | The same API with all three findings remediated |
| `retest.py` | Retest cycle proving each fix actually closes the vulnerability, without breaking legitimate access |
| `SECURITY_ASSESSMENT_REPORT.md` | The findings write-up: severity, evidence, impact, remediation, retest result |

## Findings summary

| Finding | Severity | Status |
|---|---|---|
| SQL Injection / Auth Bypass on `/api/login` | Critical | Resolved, verified |
| Broken Access Control (IDOR) on `/api/orders/<id>` | High | Resolved, verified |
| Security Misconfiguration — exposed debug endpoint | Medium | Resolved, verified |

Built with Python, Flask, sqlite3, and the `requests` library — testing followed OWASP Top 10 categories (Injection, Broken Access Control, Security Misconfiguration).
