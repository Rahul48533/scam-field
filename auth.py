"""Accounts for Scam Shield: sign up, sign in, sign out, change password.

Passwords are never stored. Only a salted hash is kept (Werkzeug scrypt/pbkdf2).
Everything lives in a small SQLite file next to this script (scamshield.db).
"""
import os
import re
import sqlite3
import time
from contextlib import contextmanager

from flask import Blueprint, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SCAMSHIELD_DB", os.path.join(BASE_DIR, "scamshield.db"))

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789", "1234567890",
    "qwerty123", "qwertyuiop", "iloveyou", "abc12345", "11111111", "00000000",
    "admin123", "welcome1", "letmein1", "scamshield",
}

# After 5 wrong passwords the account/action is locked for 5 minutes.
MAX_FAILS = 5
LOCK_SECONDS = 300
_fails = {}   # key -> [number of failures, time of first failure]

# Used so a login for an unknown email takes as long as a real one.
DUMMY_HASH = generate_password_hash("not-a-real-password")


# ---------------------------------------------------------------- database
@contextmanager
def connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with connection() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   email TEXT NOT NULL UNIQUE,
                   password_hash TEXT NOT NULL,
                   pw_version INTEGER NOT NULL DEFAULT 1,
                   created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
               )"""
        )


init_db()


# ---------------------------------------------------------------- helpers
def _locked(key):
    entry = _fails.get(key)
    if not entry:
        return False
    if time.time() - entry[1] > LOCK_SECONDS:
        _fails.pop(key, None)
        return False
    return entry[0] >= MAX_FAILS


def _record_fail(key):
    entry = _fails.get(key)
    if not entry or time.time() - entry[1] > LOCK_SECONDS:
        _fails[key] = [1, time.time()]
    else:
        entry[0] += 1


def _error(code, status):
    return jsonify({"error": code}), status


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def clean_email(value):
    value = (value or "").strip().lower() if isinstance(value, str) else ""
    return value if len(value) <= 254 and EMAIL_RE.match(value) else None


def password_problem(password, email=""):
    if not isinstance(password, str) or not 8 <= len(password) <= 128:
        return "weak_length"
    if password.lower() in COMMON_PASSWORDS or password.lower() == email:
        return "common_password"
    return None


def profile(email, created_at):
    """What the page is allowed to know about the signed-in user."""
    return {"email": email, "member_since": (created_at or "")[:10] or None}


def start_session(user_id, pw_version):
    session.clear()
    session["uid"] = user_id
    session["pwv"] = pw_version
    session.permanent = True


def current_user():
    """The signed-in user, or None. A password change signs out every other device."""
    user_id = session.get("uid")
    if not user_id:
        return None
    with connection() as conn:
        row = conn.execute(
            "SELECT id, email, pw_version, created_at FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if row is None or row["pw_version"] != session.get("pwv"):
        session.clear()
        return None
    return row


# ---------------------------------------------------------------- protection
@auth_bp.before_request
def guard():
    if request.method == "POST":
        origin = request.headers.get("Origin")
        if origin and origin.split("://", 1)[-1] != request.host:
            return _error("forbidden", 403)          # blocks other websites
        if not request.is_json:
            return _error("bad_request", 400)


@auth_bp.after_request
def no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------- routes
@auth_bp.post("/register")
def register():
    data = _body()
    email = clean_email(data.get("email"))
    password = data.get("password")
    if not email:
        return _error("invalid_email", 400)
    problem = password_problem(password, email)
    if problem:
        return _error(problem, 400)
    try:
        with connection() as conn:
            cursor = conn.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, generate_password_hash(password)),
            )
            user_id = cursor.lastrowid
            created = conn.execute(
                "SELECT created_at FROM users WHERE id = ?", (user_id,)
            ).fetchone()["created_at"]
    except sqlite3.IntegrityError:
        return _error("email_taken", 409)
    start_session(user_id, 1)
    return jsonify(profile(email, created)), 201


@auth_bp.post("/login")
def login():
    data = _body()
    email = clean_email(data.get("email"))
    password = data.get("password")
    if not email or not isinstance(password, str):
        return _error("invalid_credentials", 401)
    key = "login:" + email
    if _locked(key):
        return _error("too_many_attempts", 429)
    with connection() as conn:
        user = conn.execute(
            "SELECT id, email, password_hash, pw_version, created_at FROM users WHERE email = ?", (email,)
        ).fetchone()
    if user is None:
        check_password_hash(DUMMY_HASH, password)
        good = False
    else:
        good = check_password_hash(user["password_hash"], password)
    if not good:
        _record_fail(key)
        return _error("invalid_credentials", 401)
    _fails.pop(key, None)
    start_session(user["id"], user["pw_version"])
    return jsonify(profile(user["email"], user["created_at"]))


@auth_bp.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@auth_bp.get("/me")
def me():
    user = current_user()
    if user is None:
        return jsonify({"email": None, "member_since": None})
    return jsonify(profile(user["email"], user["created_at"]))


@auth_bp.post("/change-password")
def change_password():
    user = current_user()
    if user is None:
        return _error("not_signed_in", 401)
    data = _body()
    current = data.get("current_password")
    new = data.get("new_password")
    key = "change:%d" % user["id"]
    if _locked(key):
        return _error("too_many_attempts", 429)

    with connection() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
        ).fetchone()
    if not isinstance(current, str) or not check_password_hash(row["password_hash"], current):
        _record_fail(key)
        return _error("wrong_current", 403)

    problem = password_problem(new, user["email"])
    if problem:
        return _error(problem, 400)
    if new == current:
        return _error("same_password", 400)

    new_version = user["pw_version"] + 1
    with connection() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, pw_version = ? WHERE id = ?",
            (generate_password_hash(new), new_version, user["id"]),
        )
    _fails.pop(key, None)
    session["pwv"] = new_version        # keep THIS device signed in; other devices are signed out
    return jsonify({"ok": True})