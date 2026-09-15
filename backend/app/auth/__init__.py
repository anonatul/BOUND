"""
Auth package.

Only the FastAPI-free service API is re-exported here; import
backend.app.auth.deps explicitly from web code so non-FastAPI callers
never pull in FastAPI.
"""
from backend.app.auth.service import (
    DEMO_PASSPHRASE,
    SESSION_TTL_SECONDS,
    SESSIONS_FILE,
    get_session,
    login,
    logout,
    register,
)

__all__ = [
    "DEMO_PASSPHRASE",
    "SESSION_TTL_SECONDS",
    "SESSIONS_FILE",
    "get_session",
    "login",
    "logout",
    "register",
]
