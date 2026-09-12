# WebGuard — Security Assessment Report

**Target:** a small, self-hosted REST API (`vulnerable_api.py`) built specifically for this exercise — not a real production system.
**Method:** functional and security testing via Python scripts using the `requests` library, exercising each endpoint under different input and access-control conditions.
**Scope:** `/api/login`, `/api/orders/<id>`, `/api/debug/config`.

## Finding 1 — SQL Injection / Authentication Bypass
**Severity:** Critical
**Endpoint:** `POST /api/login`
**Description:** the login query concatenated user input directly into a raw SQL string instead of using parameterized queries. Submitting `' OR '1'='1` as the password field made the WHERE clause always true, authenticating as any user with no valid password.
**Evidence:** baseline request with a wrong password correctly returned `401`; the injection payload returned `200` with `authenticated: true` and the target user's real ID.
**Impact:** complete authentication bypass — any account could be accessed without credentials.
**Remediation:** replaced the string-concatenated query with a parameterized query (`?` placeholders), so user input is always treated as data, never as SQL code.
**Retest result:** PASS — the same payload now correctly returns `401`.

## Finding 2 — Broken Access Control (IDOR)
**Severity:** High
**Endpoint:** `GET /api/orders/<id>`
**Description:** the endpoint returned any order by ID with no check that the requester actually owned it.
**Evidence:** requesting another user's order ID returned their full order, including partial card data (`card_last4`).
**Impact:** any user could enumerate order IDs and read every customer's order data.
**Remediation:** added an explicit ownership check — the endpoint now compares the requester's identity against the order's `owner_user_id` and rejects mismatches with `403`.
**Retest result:** PASS — cross-user access now returns `403`; the legitimate owner can still access their own order (`200`), confirming the fix didn't break normal use.

## Finding 3 — Security Misconfiguration (exposed debug endpoint)
**Severity:** Medium
**Endpoint:** `GET /api/debug/config`
**Description:** an internal diagnostics endpoint was reachable with no authentication, exposing the database file path and framework details.
**Evidence:** unauthenticated `GET` request returned internal configuration data with `200`.
**Impact:** free reconnaissance information for an attacker planning further attacks.
**Remediation:** removed the endpoint entirely from the production code path.
**Retest result:** PASS — the endpoint now returns `404`.

## Summary
| Finding | Severity | Status |
|---|---|---|
| SQL Injection / Auth Bypass | Critical | Resolved, verified |
| Broken Access Control (IDOR) | High | Resolved, verified |
| Security Misconfiguration | Medium | Resolved, verified |

**Tools used:** Python (`requests`, `Flask`, `sqlite3`), manual test design following OWASP Top 10 categories (Injection, Broken Access Control, Security Misconfiguration).
