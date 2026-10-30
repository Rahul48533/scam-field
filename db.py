import json
import os
import sqlite3
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

DB = "scamshield.db"
MIN_REPORTS = 3   # an entry counts as a scam only after this many reports

# Demo data so the database isn't empty. Replace with real reports later.
SEED = [
    ("upi", "fraud@ybl", "fake refund", 14),
    ("upi", "lucky.prize@paytm", "lottery", 9),
    ("upi", "refund.support@okaxis", "fake refund", 6),
    ("domain", "paytm-kyc.xyz", "kyc phishing", 21),
    ("domain", "sbi-reward.top", "reward phishing", 11),
    ("phone", "9999999999", "fake bank call", 5),
]


def _conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def supabase_settings():
    url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    service_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    anon_key = os.environ.get("SUPABASE_ANON_KEY", "").strip()
    return {"url": url, "service_key": service_key, "anon_key": anon_key}


def supabase_server_enabled():
    settings = supabase_settings()
    return bool(settings["url"] and settings["service_key"])


def supabase_realtime_config():
    settings = supabase_settings()
    if not settings["url"] or not settings["anon_key"] or not settings["service_key"]:
        return None
    return {"url": settings["url"], "anonKey": settings["anon_key"]}


def _supabase_request(path, method="GET", payload=None, prefer=None):
    settings = supabase_settings()
    if not settings["url"] or not settings["service_key"]:
        raise RuntimeError("Supabase server credentials are not configured")
    headers = {
        "apikey": settings["service_key"],
        "Authorization": "Bearer " + settings["service_key"],
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = Request(settings["url"] + path, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=4) as response:
            raw = response.read()
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("Supabase request failed") from exc
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Supabase returned an invalid response") from exc


def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            category TEXT DEFAULT 'other',
            reports INTEGER DEFAULT 1,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(kind, value))""")
        c.execute("""CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
            comment TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        if c.execute("SELECT COUNT(*) FROM scams").fetchone()[0] == 0:
            c.executemany(
                "INSERT INTO scams(kind, value, category, reports) VALUES (?,?,?,?)", SEED)


def lookup(kind, value):
    """Returns the database row if this value is a known scam, else None."""
    normalized = value.strip().lower()
    if supabase_server_enabled():
        query = urlencode({
            "select": "kind,value,category,reports,last_seen",
            "kind": "eq." + kind,
            "value": "eq." + normalized,
            "reports": "gte." + str(MIN_REPORTS),
            "limit": "1",
        })
        try:
            rows = _supabase_request("/rest/v1/scams?" + query)
            if rows:
                return rows[0]
        except (RuntimeError, ValueError, TypeError):
            pass
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM scams WHERE kind=? AND value=? AND reports>=?",
            (kind, normalized, MIN_REPORTS)).fetchone()
    return dict(row) if row else None


def add_report(kind, value, category="other"):
    value = value.strip().lower()
    with _conn() as c:
        c.execute("""INSERT INTO scams(kind, value, category) VALUES (?,?,?)
                     ON CONFLICT(kind, value)
                     DO UPDATE SET reports = reports + 1, last_seen = CURRENT_TIMESTAMP""",
                  (kind, value, category[:40]))
        return c.execute("SELECT reports FROM scams WHERE kind=? AND value=?",
                         (kind, value)).fetchone()[0]


def scam_entries(limit=5000):
    limit = max(1, min(int(limit), 5000))
    with _conn() as c:
        rows = c.execute(
            "SELECT kind, value, category, reports, last_seen FROM scams ORDER BY id LIMIT ?",
            (limit,)).fetchall()
    return [dict(row) for row in rows]


def add_supabase_report(kind, value, category="other"):
    result = _supabase_request(
        "/rest/v1/rpc/report_scam",
        method="POST",
        payload={"p_kind": kind, "p_value": value.strip().lower(), "p_category": category[:40]},
    )
    if not isinstance(result, int):
        raise RuntimeError("Supabase returned an invalid report count")
    return result


def stats():
    with _conn() as c:
        n, r = c.execute("SELECT COUNT(*), COALESCE(SUM(reports),0) FROM scams").fetchone()
    return {"entries": n, "reports": r}


def add_review(rating, comment=""):
    with _conn() as c:
        cursor = c.execute(
            "INSERT INTO reviews(rating, comment) VALUES (?,?)", (rating, comment.strip()))
        row = c.execute(
            "SELECT rating, comment, created_at FROM reviews WHERE id=?",
            (cursor.lastrowid,)).fetchone()
    return dict(row)


def recent_reviews(limit=8):
    limit = max(1, min(int(limit), 20))
    with _conn() as c:
        count, average = c.execute(
            "SELECT COUNT(*), COALESCE(AVG(rating), 0) FROM reviews").fetchone()
        rows = c.execute(
            "SELECT rating, comment, created_at FROM reviews ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
    return {"count": count, "average": round(average, 1), "reviews": [dict(row) for row in rows]}