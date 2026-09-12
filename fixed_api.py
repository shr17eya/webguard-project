"""
WebGuard - the SAME api, with all three findings remediated.

Compare this file to vulnerable_api.py line by line - that diff IS the
remediation report. Run this instead of vulnerable_api.py, then run
retest.py against it.

Run:  python fixed_api.py
Then: python retest.py
"""

import sqlite3
from pathlib import Path

from flask import Flask, g, jsonify, request

app = Flask(__name__)
DB_PATH = Path(__file__).parent / "webguard_fixed.db"


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
# FIX 1: parameterized query - user input can never become SQL code.
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")

    # FIXED: "?" placeholders mean the driver sends username/password as
    # pure data, never as part of the SQL text itself - the classic
    # `' OR '1'='1` payload is now just a literal string with no username.
    cur = get_db().execute(
        "SELECT id, username FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    row = cur.fetchone()

    if row:
        return jsonify({"authenticated": True, "user_id": row[0], "username": row[1]})
    return jsonify({"authenticated": False}), 401


# ---------------------------------------------------------------------------
# FIX 2: ownership check via a (simple, demo-level) auth header.
# ---------------------------------------------------------------------------
@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    # A real system would use a signed session/JWT; for this demo, the
    # caller states who they are via a header, and we ENFORCE it matches
    # the order's actual owner - that enforcement is the fix, not the
    # header mechanism itself.
    requesting_user_id = request.headers.get("X-User-Id", type=int)

    cur = get_db().execute(
        "SELECT id, user_id, item, card_last4 FROM orders WHERE id = ?", (order_id,)
    )
    row = cur.fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404

    owner_user_id = row[1]
    # FIXED: reject if the requester isn't the order's owner.
    if requesting_user_id != owner_user_id:
        return jsonify({"error": "forbidden - not your order"}), 403

    return jsonify(
        {"order_id": row[0], "owner_user_id": row[1], "item": row[2], "card_last4": row[3]}
    )


# ---------------------------------------------------------------------------
# FIX 3: debug endpoint removed entirely - not "hidden", GONE.
# ---------------------------------------------------------------------------
# (intentionally no /api/debug/config route in this file)


if __name__ == "__main__":
    seed_database()
    print("WebGuard FIXED API seeded and starting on http://127.0.0.1:5001")
    app.run(port=5001, debug=False)
