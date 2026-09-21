"""FastAPI dependencies for bearer-token session authentication."""
from typing import Optional

from fastapi import Header, HTTPException

from backend.app.auth.service import get_session

_BEARER_PREFIX = "Bearer "
_UNAUTHORIZED_HEADERS = {"WWW-Authenticate": "Bearer"}


def _extract_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization or not authorization.startswith(_BEARER_PREFIX):
        return None
    token = authorization[len(_BEARER_PREFIX):].strip()
    return token or None


def get_current_user(authorization: str | None = Header(None)) -> dict:
    """Require a valid Bearer token; raise HTTP 401 otherwise."""
    token = _extract_token(authorization)
    user = get_session(token) if token else None
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers=_UNAUTHORIZED_HEADERS,
        )
    return user


def get_current_user_optional(authorization: str | None = Header(None)) -> dict | None:
    """Return the session user if a valid Bearer token was supplied, else None."""
    token = _extract_token(authorization)
    if not token:
        return None
    return get_session(token)
