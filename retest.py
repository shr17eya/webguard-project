"""
WebGuard - retest cycle: prove each finding is actually closed.

Run this against fixed_api.py (port 5001), NOT vulnerable_api.py. Every
check here asserts the ATTACK now fails for the right reason - same
philosophy as TestForge's negative tests: don't just check "no crash",
check the SPECIFIC rejection.

Run:  python retest.py
"""

import requests

BASE = "http://127.0.0.1:5001"


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    return condition


def retest_sql_injection():
    print("\n--- Retest: SQL Injection on /api/login ---")
    resp = requests.post(BASE + "/api/login", json={"username": "alice", "password": "' OR '1'='1"})
    print("Response:", resp.status_code, resp.json())
    return check(
        "Injection payload is correctly rejected (401, not authenticated)",
        resp.status_code == 401 and resp.json().get("authenticated") is False,
    )


def retest_idor():
    print("\n--- Retest: IDOR on /api/orders/<id> ---")
    # Ask for alice's order (101) while claiming to be bob (user 2).
    resp = requests.get(BASE + "/api/orders/101", headers={"X-User-Id": "2"})
    print("Response:", resp.status_code, resp.json())
    ok = check(
        "Bob requesting Alice's order is correctly forbidden (403)",
        resp.status_code == 403,
    )

    # Control case: bob CAN still read his own order (102).
    own = requests.get(BASE + "/api/orders/102", headers={"X-User-Id": "2"})
    print("Own order response:", own.status_code, own.json())
    ok2 = check("Bob can still read his OWN order (fix didn't break legitimate access)", own.status_code == 200)
    return ok and ok2


def retest_debug_endpoint():
    print("\n--- Retest: debug endpoint ---")
    resp = requests.get(BASE + "/api/debug/config")
    print("Response:", resp.status_code)
    return check("Debug endpoint no longer exists (404)", resp.status_code == 404)


if __name__ == "__main__":
    print("WebGuard - retest cycle against", BASE)
    results = [retest_sql_injection(), retest_idor(), retest_debug_endpoint()]
    print(f"\n{sum(results)}/{len(results)} findings verified as resolved.")
