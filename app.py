import re
import sqlite3

from flask import Flask, jsonify, request

import db

app = Flask(__name__)

db.init_db()

# TEMPORARY: stands in for real login until Phase 4.
DEV_USER_ID = 1


def ensure_dev_user():
    conn = db.get_connection()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users (id, email, password_hash) VALUES (?, ?, ?)",
            (DEV_USER_ID, "dev@sumworth.local", "not-a-real-hash"),
        )
        conn.commit()
    finally:
        conn.close()


ensure_dev_user()


def current_user_id():
    # Phase 4 replaces this with the user from a verified login token.
    return DEV_USER_ID


def account_to_dict(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "account_number": row["account_number"],
        "balance_kobo": row["balance_kobo"],
    }


def clean_name(text):
    return re.sub(r"\s+", " ", text.strip())


def validate_account(data):
    """Return (clean_values, error_message). Exactly one of them is None."""
    name = data.get("name")
    number = data.get("account_number")
    balance = data.get("balance_kobo")

    if not isinstance(name, str) or not clean_name(name):
        return None, "Please enter an account name."
    if not isinstance(number, str) or not re.fullmatch(r"\d{4}", number.strip()):
        return None, "Account number must be exactly 4 digits."
    if isinstance(balance, bool) or not isinstance(balance, int) or balance < 0:
        return None, "Balance must be a whole number of kobo, zero or more."

    return {
        "name": clean_name(name),
        "account_number": number.strip(),
        "balance_kobo": balance,
    }, None


@app.get("/health")
def health():
    return jsonify(status="ok", app="SumWorth API")


@app.get("/accounts")
def list_accounts():
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT id, name, account_number, balance_kobo FROM accounts "
            "WHERE user_id = ? ORDER BY name COLLATE NOCASE, account_number",
            (current_user_id(),),
        ).fetchall()
    finally:
        conn.close()
    return jsonify([account_to_dict(r) for r in rows])


@app.post("/accounts")
def create_account():
    data = request.get_json(silent=True) or {}
    values, error = validate_account(data)
    if error:
        return jsonify(error=error), 400

    conn = db.get_connection()
    try:
        try:
            cur = conn.execute(
                "INSERT INTO accounts (user_id, name, account_number, balance_kobo) "
                "VALUES (?, ?, ?, ?)",
                (current_user_id(), values["name"], values["account_number"], values["balance_kobo"]),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify(error="You already have an account with this name and number."), 409
        row = conn.execute(
            "SELECT id, name, account_number, balance_kobo FROM accounts WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
    finally:
        conn.close()
    return jsonify(account_to_dict(row)), 201

@app.delete("/accounts/<int:account_id>")
def delete_account(account_id):
    conn = db.get_connection()
    try:
        cur = conn.execute(
            "DELETE FROM accounts WHERE id = ? AND user_id = ?",
            (account_id, current_user_id()),
        )
        conn.commit()
    finally:
        conn.close()
    if cur.rowcount == 0:
        return jsonify(error="Account not found."), 404
    return "", 204

if __name__ == "__main__":
    app.run(debug=True)
