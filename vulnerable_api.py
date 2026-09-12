"""
WebGuard - a small, deliberately vulnerable REST API used as the target
for hands-on security testing.

This is NOT how you should ever write a real API. Every vulnerability here
is intentional, so it can be found, documented, and fixed - exactly the
workflow described on the resume: functional + security testing,
authentication/authorization/input-validation/configuration issues,
documented findings with severity, remediation, and retesting.

Run:  python vulnerable_api.py
Then: python exploit_tests.py   (in another terminal)
"""

import sqlite3
from pathlib import Path

from flask import Flask, g, jsonify, request

app = Flask(__name__)
DB_PATH = Path(__file__).parent / "webguard.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def seed_database():
    """(Re)create the database with two users and two orders, every run."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("DROP TABLE IF EXISTS orders")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.execute(
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, card_last4 TEXT)"
    )
    conn.executemany(
        "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
        [(1, "alice", "alice123"), (2, "bob", "bobpassword")],
    )
    conn.executemany(
        "INSERT INTO orders (id, user_id, item, card_last4) VALUES (?, ?, ?, ?)",
        [
            (101, 1, "Laptop stand", "4242"),
            (102, 2, "Mechanical keyboard", "9911"),
        ],
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# VULNERABILITY 1: SQL Injection on login (Broken Authentication / Injection)
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")

    # VULNERABLE: user input is pasted directly into the SQL string instead
    # of using a parameterized query. An attacker can inject SQL logic here.
    query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
    cur = get_db().execute(query)
    row = cur.fetchone()

    if row:
        return jsonify({"authenticated": True, "user_id": row[0], "username": row[1]})
    return jsonify({"authenticated": False}), 401


# ---------------------------------------------------------------------------
# VULNERABILITY 2: Broken Access Control / IDOR on orders
# ---------------------------------------------------------------------------
@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    # VULNERABLE: no check that the requester actually owns this order.
    # A logged-in user (identified only by the header below, no real auth)
    # can view ANY order by simply changing the ID in the URL.
    cur = get_db().execute(
        "SELECT id, user_id, item, card_last4 FROM orders WHERE id = ?", (order_id,)
    )
    row = cur.fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(
        {"order_id": row[0], "owner_user_id": row[1], "item": row[2], "card_last4": row[3]}
    )


# ---------------------------------------------------------------------------
# VULNERABILITY 3: Security Misconfiguration - a debug endpoint left exposed
# ---------------------------------------------------------------------------
@app.route("/api/debug/config", methods=["GET"])
def debug_config():
    # VULNERABLE: an internal diagnostics endpoint with no authentication
    # at all, leaking internal details an attacker could use for further
    # attacks (paths, DB location, framework version).
    return jsonify(
        {
            "db_path": str(DB_PATH.resolve()),
            "flask_debug_mode": app.debug,
            "framework": "Flask 3.x",
            "note": "This endpoint should never exist in production.",
        }
    )


if __name__ == "__main__":
    seed_database()
    print("WebGuard vulnerable API seeded and starting on http://127.0.0.1:5000")
    app.run(port=5000, debug=False)
