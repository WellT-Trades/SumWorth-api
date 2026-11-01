import re
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from flask import Flask, g, jsonify, request
import os
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
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
def load_secret_key():
    path = Path(__file__).parent / "secret.key"
    if not path.exists():
        path.write_text(secrets.token_hex(32))
    return path.read_text().strip()


serializer = URLSafeTimedSerializer(load_secret_key(), salt="sumworth-auth")
TOKEN_MAX_AGE = 60 * 60 * 24 * 7  # 7 days, in seconds


def make_token(user_id):
    return serializer.dumps({"uid": user_id})


def require_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Please log in."), 401

        token = header[7:]
        try:
            payload = serializer.loads(token, max_age=TOKEN_MAX_AGE)
        except SignatureExpired:
            return jsonify(error="Session expired. Please log in again."), 401
        except BadSignature:
            return jsonify(error="Invalid token."), 401

        g.user_id = payload["uid"]
        return view(*args, **kwargs)

    return wrapper


def current_user_id():
    return g.user_id

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
@require_auth
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
@require_auth
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

@app.put("/accounts/<int:account_id>")
@require_auth
def update_account(account_id):
    data = request.get_json(silent=True) or {}
    values, error = validate_account(data)
    if error:
        return jsonify(error=error), 400

    conn = db.get_connection()
    try:
        try:
            cur = conn.execute(
                "UPDATE accounts "
                "SET name = ?, account_number = ?, balance_kobo = ?, updated_at = datetime('now') "
                "WHERE id = ? AND user_id = ?",
                (
                    values["name"],
                    values["account_number"],
                    values["balance_kobo"],
                    account_id,
                    current_user_id(),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify(error="You already have an account with this name and number."), 409
        if cur.rowcount == 0:
            return jsonify(error="Account not found."), 404
        row = conn.execute(
            "SELECT id, name, account_number, balance_kobo FROM accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
    finally:
        conn.close()
    return jsonify(account_to_dict(row))



@app.delete("/accounts/<int:account_id>")
@require_auth
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

@app.post("/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()
    ):
        return jsonify(error="Please enter a valid email address."), 400
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        return jsonify(error="Password must be 8 to 128 characters."), 400

    email = email.strip().lower()
    password_hash = generate_password_hash(password)

    conn = db.get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="That email is already registered."), 409
    finally:
        conn.close()

    return jsonify(id=cur.lastrowid, email=email), 201

@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify(error="Please enter your email and password."), 400

    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?",
            (email.strip().lower(),),
        ).fetchone()
    finally:
        conn.close()

    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify(error="Wrong email or password."), 401

    return jsonify(
        token=make_token(row["id"]),
        user={"id": row["id"], "email": row["email"]},
    )
if __name__ == "__main__":
    app.run(debug=True)
