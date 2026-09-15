"""
Session-based authentication service.

Sessions are persisted to backend/data/sessions.json so login survives
process restarts. This module intentionally has no FastAPI imports so it
can be used from CLI or test code.
"""
import calendar
import json
import os
import pathlib
import secrets
import tempfile
import threading
import time
from typing import Dict, Optional

from backend.app.identity.manager import (
    DEMO_PASSPHRASE,
    load_recipient,
    lock_user,
    register_user,
    unlock_user,
)

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "backend" / "data"
SESSIONS_FILE = DATA_DIR / "sessions.json"

SESSION_TTL_SECONDS = 12 * 60 * 60
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_lock = threading.RLock()

__all__ = [
    "DEMO_PASSPHRASE",
    "SESSION_TTL_SECONDS",
    "SESSIONS_FILE",
    "register",
    "login",
    "logout",
    "get_session",
]


def _iso(ts: float) -> str:
    return time.strftime(_TIME_FORMAT, time.gmtime(ts))


def _epoch(iso_str: str) -> Optional[int]:
    try:
        return calendar.timegm(time.strptime(iso_str, _TIME_FORMAT))
    except (TypeError, ValueError):
        return None


def _load_sessions() -> Dict[str, dict]:
    if not SESSIONS_FILE.exists():
        return {}
    try:
        data = json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _prune(sessions: Dict[str, dict]) -> Dict[str, dict]:
    now = time.time()
    pruned = {}
    for token, entry in sessions.items():
        if not isinstance(entry, dict):
            continue
        expires = _epoch(entry.get("expires_at"))
        if expires is not None and expires > now:
            pruned[token] = entry
    return pruned


def _save_sessions(sessions: Dict[str, dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=SESSIONS_FILE.name + ".", suffix=".tmp", dir=str(DATA_DIR)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(sessions, indent=2))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, str(SESSIONS_FILE))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _user_dict(rid: str) -> Dict:
    rec = load_recipient(rid) or {}
    return {
        "recipient_id": rid,
        "username": rid,
        "display_name": rec.get("display_name") or rid.capitalize(),
    }


def register(username: str, display_name: str, passphrase: str) -> Dict:
    """Register a new passphrase-protected account and return its user dict."""
    record = register_user(username, display_name, passphrase)
    rid = record["recipient_id"]
    return {
        "recipient_id": rid,
        "username": rid,
        "display_name": record.get("display_name") or rid.capitalize(),
    }


def login(username: str, passphrase: str) -> Dict:
    """
    Verify credentials by unlocking the account, then issue a session token.
    Raises PermissionError for unknown users and bad passphrases alike.
    """
    rid = (username or "").strip().upper()
    error = PermissionError("unknown user or invalid passphrase")
    if not rid or load_recipient(rid) is None:
        raise error
    if not isinstance(passphrase, str) or not passphrase:
        raise error
    try:
        unlock_user(rid, passphrase)
    except (PermissionError, FileNotFoundError) as exc:
        raise error from exc

    now = time.time()
    expires_at = _iso(now + SESSION_TTL_SECONDS)
    token = secrets.token_urlsafe(32)
    user = _user_dict(rid)
    entry = {"user": user, "created_at": _iso(now), "expires_at": expires_at}
    with _lock:
        sessions = _prune(_load_sessions())
        sessions[token] = entry
        _save_sessions(sessions)
    return {"token": token, "user": user, "expires_at": expires_at}


def logout(token: str) -> None:
    """Invalidate a session token. Unknown tokens are ignored."""
    if not token:
        return None
    with _lock:
        sessions = _load_sessions()
        sessions.pop(token, None)
        _save_sessions(_prune(sessions))
    return None


def get_session(token: str) -> Optional[Dict]:
    """Return the user dict for a valid session token, else None."""
    if not token:
        return None
    with _lock:
        sessions = _load_sessions()
        pruned = _prune(sessions)
        if len(pruned) != len(sessions):
            _save_sessions(pruned)
        entry = pruned.get(token)
    if not entry:
        return None
    user = entry.get("user")
    if isinstance(user, dict):
        return dict(user)
    if isinstance(user, str):
        return _user_dict(user.upper())
    return None


def lock(recipient_id: str) -> None:
    """Drop the in-memory unlock for a recipient (keys are no longer cached)."""
    lock_user(recipient_id)
