from datetime import datetime, timezone
from secrets import token_urlsafe

from app.crypto.password import hash_password, verify_password


def new_session_id() -> str:
    return token_urlsafe(32)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
