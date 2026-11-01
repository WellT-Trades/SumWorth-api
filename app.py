import math
import time
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

MAX_ATTEMPTS = 4
LOCK_SECONDS = 15 * 60

# Used so a login for an unknown email takes as long as a real one.
DUMMY_HASH = generate_password_hash("not-a-real-password")


def lock_seconds_left(conn, email):
    row = conn.execute(
        "SELECT locked_until FROM login_attempts WHERE email = ?", (email,)
    ).fetchone()
    if row is None:
        return 0
    return max(0, row["locked_until"] - int(time.time()))


def record_failure(conn, email):
    """Count a failed login. Returns the attempts left (0 means now locked)."""
    now = int(time.time())
    row = conn.execute(
        "SELECT failed_count, last_failed FROM login_attempts WHERE email = ?",
        (email,),
    ).fetchone()

    if row is None or now - row["last_failed"] >= LOCK_SECONDS:
        count = 1
    else:
        count = row["failed_count"] + 1

    locked_until = now + LOCK_SECONDS if count >= MAX_ATTEMPTS else 0
    conn.execute(
        "INSERT OR REPLACE INTO login_attempts "
        "(email, failed_count, last_failed, locked_until) VALUES (?, ?, ?, ?)",
        (email, count, now, locked_until),
    )
    conn.commit()
    return max(0, MAX_ATTEMPTS - count)


def clear_failures(conn, email):
    conn.execute("DELETE FROM login_attempts WHERE email = ?", (email,))
    conn.commit()


def too_many(seconds):
    minutes = max(1, math.ceil(seconds / 60))
    return jsonify(error=f"Too many attempts. Try again in {minutes} minute(s)."), 429

@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify(error="Please enter your email and password."), 400

    email = email.strip().lower()

    conn = db.get_connection()
    try:
        wait = lock_seconds_left(conn, email)
        if wait:
            return too_many(wait)

        row = conn.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        stored_hash = row["password_hash"] if row else DUMMY_HASH
        password_ok = check_password_hash(stored_hash, password)

        if row is None or not password_ok:
            left = record_failure(conn, email)
            if left == 0:
                return too_many(LOCK_SECONDS)
            return jsonify(error=f"Wrong email or password. {left} attempt(s) left."), 401

        clear_failures(conn, email)
    finally:
        conn.close()

    return jsonify(
        token=make_token(row["id"]),
        user={"id": row["id"], "email": row["email"]},
    )

RESET_MINUTES = 15
RESET_MAX_TRIES = 5


def send_reset_code(email, code):
    # DEV ONLY: prints the code. Replace with a real email sender before launch.
    print(f"[DEV ONLY] Password reset code for {email}: {code}", flush=True)


def invalid_code():
    return jsonify(error="Invalid or expired code."), 400


@app.post("/auth/forgot-password")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    if not isinstance(email, str) or not email.strip():
        return jsonify(error="Please enter your email."), 400
    email = email.strip().lower()

    # Always do the same work, so an unknown email isn't faster to answer.
    code = f"{secrets.randbelow(10**6):06d}"
    code_hash = generate_password_hash(code)

    conn = db.get_connection()
    try:
        user = conn.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()
        if user:
            conn.execute(
                "INSERT OR REPLACE INTO password_resets "
                "(user_id, code_hash, expires_at, tries) VALUES (?, ?, ?, 0)",
                (user["id"], code_hash, int(time.time()) + RESET_MINUTES * 60),
            )
            conn.commit()
            send_reset_code(email, code)
    finally:
        conn.close()

    return jsonify(message="If that email is registered, a reset code has been sent.")


@app.post("/auth/reset-password")
def reset_password():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    code = data.get("code")
    new_password = data.get("new_password")

    if not all(isinstance(v, str) for v in (email, code, new_password)):
        return jsonify(error="Please fill in every field."), 400
    if not 8 <= len(new_password) <= 128:
        return jsonify(error="Password must be 8 to 128 characters."), 400
    email = email.strip().lower()

    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT u.id AS uid, r.code_hash, r.expires_at, r.tries "
            "FROM users u JOIN password_resets r ON r.user_id = u.id "
            "WHERE u.email = ?",
            (email,),
        ).fetchone()

        # Check against a dummy hash when there's no row, so timing stays the same.
        stored = row["code_hash"] if row else DUMMY_HASH
        code_ok = check_password_hash(stored, code.strip())

        if (
            row is None
            or row["expires_at"] < int(time.time())
            or row["tries"] >= RESET_MAX_TRIES
        ):
            return invalid_code()

        if not code_ok:
            conn.execute(
                "UPDATE password_resets SET tries = tries + 1 WHERE user_id = ?",
                (row["uid"],),
            )
            conn.commit()
            return invalid_code()

        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), row["uid"]),
        )
        conn.execute("DELETE FROM password_resets WHERE user_id = ?", (row["uid"],))
        conn.commit()
        clear_failures(conn, email)
    finally:
        conn.close()

    return jsonify(message="Password updated. Please log in.")
if __name__ == "__main__":
    app.run(debug=True)
