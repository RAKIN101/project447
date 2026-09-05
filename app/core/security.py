from datetime import datetime, timezone
import hmac
import secrets
from secrets import token_urlsafe

from fastapi import HTTPException, Request, status

from app.crypto.password import hash_password, verify_password


def new_session_id() -> str:
    return token_urlsafe(32)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def validate_csrf(request: Request, submitted_token: str) -> None:
    expected_token = request.session.get("csrf_token")
    if not expected_token or not hmac.compare_digest(expected_token, submitted_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")
