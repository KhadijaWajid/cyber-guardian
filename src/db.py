import os
import json
import sqlite3
import hashlib
import secrets
import datetime
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cyber_guardian.db")


def get_db_path(db_path: Optional[str] = None) -> str:
    """Returns the effective database path."""
    if db_path:
        return db_path
    return os.getenv("CYBER_GUARDIAN_DB_PATH", DEFAULT_DB_PATH)


@contextmanager
def get_connection(db_path: Optional[str] = None):
    """Creates a sqlite3 connection with Row factory enabled, committing and closing on exit."""
    path = get_db_path(db_path)
    if os.path.dirname(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def hash_password(password: str) -> str:
    """Hashes a password with a cryptographically secure random salt using SHA-256."""
    salt = secrets.token_hex(16)
    salted = f"{salt}:{password}".encode("utf-8")
    digest = hashlib.sha256(salted).hexdigest()
    return f"{salt}:{digest}"


def verify_password_hash(password: str, stored_hash: str) -> bool:
    """Verifies a plaintext password against a salt:hash string."""
    try:
        salt, digest = stored_hash.split(":", 1)
        salted = f"{salt}:{password}".encode("utf-8")
        return hashlib.sha256(salted).hexdigest() == digest
    except Exception:
        return False


def init_db(db_path: Optional[str] = None):
    """Initializes the database schema including users and threat_records if not present."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # Users table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )

        # Threat records table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                sender_handle TEXT,
                threat_type TEXT,
                risk_score INTEGER,
                impersonated_target TEXT,
                extracted_links TEXT,
                notes TEXT,
                username TEXT
            );
            """
        )

        # Add username column if missing in existing legacy database
        cursor.execute("PRAGMA table_info(threat_records);")
        existing_cols = [row["name"] for row in cursor.fetchall()]
        if "username" not in existing_cols:
            try:
                cursor.execute("ALTER TABLE threat_records ADD COLUMN username TEXT;")
            except sqlite3.OperationalError:
                pass

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_sender_handle ON threat_records(sender_handle);"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_threat_username ON threat_records(username);"
        )
        conn.commit()


def create_user(username: str, password: str, db_path: Optional[str] = None) -> bool:
    """
    Creates a new user account with SHA-256 + salt password hashing.
    Returns True if successfully created, False if username already exists or invalid.
    """
    clean_user = (username or "").strip().lower()
    clean_pass = (password or "").strip()
    if not clean_user or not clean_pass:
        return False

    init_db(db_path)
    now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pwd_hash = hash_password(clean_pass)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (clean_user, pwd_hash, now_iso),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Username already taken
            return False
        except Exception:
            return False


def verify_user(username: str, password: str, db_path: Optional[str] = None) -> bool:
    """
    Verifies a user's credentials against the stored hash.
    Returns True on success, False on incorrect credentials or user not found.
    """
    clean_user = (username or "").strip().lower()
    clean_pass = (password or "").strip()
    if not clean_user or not clean_pass:
        return False

    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (clean_user,))
        row = cursor.fetchone()
        if not row:
            return False
        return verify_password_hash(clean_pass, row["password_hash"])


def log_threat(
    sender_handle: str,
    threat_type: str,
    risk_score: int,
    impersonated_target: str,
    extracted_links: Optional[List[str]] = None,
    notes: str = "",
    db_path: Optional[str] = None,
    username: Optional[str] = None,
    is_guest: bool = False,
) -> int:
    """
    Logs a detected threat into the SQLite database.
    If is_guest is True, bypasses database insertion completely and returns 0.
    Returns the newly inserted row ID (or 0 if bypassed).
    """
    if is_guest:
        return 0

    init_db(db_path)
    links_json = json.dumps(extracted_links or [])
    now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_username = username.strip().lower() if username else None

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO threat_records (
                timestamp,
                sender_handle,
                threat_type,
                risk_score,
                impersonated_target,
                extracted_links,
                notes,
                username
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_iso,
                sender_handle.strip().lower() if sender_handle else "unknown",
                threat_type or "phishing",
                risk_score,
                impersonated_target or "None",
                links_json,
                notes,
                clean_username,
            ),
        )
        conn.commit()
        return cursor.lastrowid or 0


def check_repeat_offender(
    sender_handle: str = "",
    links: Optional[List[str]] = None,
    db_path: Optional[str] = None,
    username: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Checks if a sender handle (email/phone/domain) or any of the URLs have been logged before.
    If username is provided, filters recidivism to this user's logged history.
    Returns repeat count, previous dates, previous risk scores, matched identifiers, and a warning badge.
    """
    init_db(db_path)
    clean_handle = (sender_handle or "").strip().lower()
    clean_links = [l.strip() for l in (links or []) if l.strip()]
    clean_user = username.strip().lower() if username else None

    matched_records: Dict[int, Dict[str, Any]] = {}
    matched_identifiers: List[str] = []

    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # Check sender handle match if not unknown/empty
        if clean_handle and clean_handle != "unknown":
            if clean_user:
                cursor.execute(
                    "SELECT * FROM threat_records WHERE LOWER(sender_handle) = ? AND (username = ? OR username IS NULL) ORDER BY id DESC",
                    (clean_handle, clean_user),
                )
            else:
                cursor.execute(
                    "SELECT * FROM threat_records WHERE LOWER(sender_handle) = ? ORDER BY id DESC",
                    (clean_handle,),
                )
            rows = cursor.fetchall()
            for r in rows:
                matched_records[r["id"]] = dict(r)
            if rows:
                matched_identifiers.append(clean_handle)

        # Check links match in extracted_links JSON column
        for link in clean_links:
            search_pattern = f"%{link}%"
            if clean_user:
                cursor.execute(
                    "SELECT * FROM threat_records WHERE extracted_links LIKE ? AND (username = ? OR username IS NULL) ORDER BY id DESC",
                    (search_pattern, clean_user),
                )
            else:
                cursor.execute(
                    "SELECT * FROM threat_records WHERE extracted_links LIKE ? ORDER BY id DESC",
                    (search_pattern,),
                )
            rows = cursor.fetchall()
            for r in rows:
                matched_records[r["id"]] = dict(r)
            if rows and link not in matched_identifiers:
                matched_identifiers.append(link)

    records_list = sorted(matched_records.values(), key=lambda x: x["id"], reverse=True)
    repeat_count = len(records_list)
    is_repeat = repeat_count > 0

    previous_dates = [r["timestamp"] for r in records_list]
    previous_risk_scores = [r["risk_score"] for r in records_list]
    previous_threat_types = list(dict.fromkeys([r["threat_type"] for r in records_list]))

    warning_badge = None
    if is_repeat:
        plural = "s" if repeat_count > 1 else ""
        warning_badge = f"⚠️ REPEAT OFFENDER: Observed {repeat_count} time{plural} previously"

    return {
        "is_repeat_offender": is_repeat,
        "repeat_count": repeat_count,
        "warning_badge": warning_badge,
        "matched_identifiers": matched_identifiers,
        "previous_dates": previous_dates,
        "previous_risk_scores": previous_risk_scores,
        "previous_threat_types": previous_threat_types,
        "previous_records": records_list,
    }


def get_all_records(
    limit: Any = 50,
    db_path: Optional[str] = None,
    username: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetches recent threat records for dashboard display.
    If username is specified, only returns threat records associated with that user.
    """
    if isinstance(limit, str):
        db_path = limit
        limit = 50
    init_db(db_path)
    clean_user = username.strip().lower() if username else None

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        if clean_user:
            cursor.execute(
                "SELECT * FROM threat_records WHERE username = ? ORDER BY id DESC LIMIT ?",
                (clean_user, int(limit)),
            )
        else:
            cursor.execute("SELECT * FROM threat_records ORDER BY id DESC LIMIT ?", (int(limit),))
        return [dict(r) for r in cursor.fetchall()]


def clear_db(db_path: Optional[str] = None):
    """Deletes all records from threat_records and users tables (for test isolation)."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM threat_records")
        cursor.execute("DELETE FROM users")
        conn.commit()
