from datetime import datetime, timezone

from app.core.security import new_session_id
from app.models import AuthSessionRecord


_active_sessions: dict[str, tuple[int, datetime]] = {}
_revoked_sessions: set[str] = set()


def create_auth_session(user_id: int, expires_at: datetime) -> str:
    session_id = new_session_id()
    _active_sessions[session_id] = (user_id, expires_at)
    return session_id


def revoke_auth_session(session_id: str | None) -> None:
    if session_id:
        _active_sessions.pop(session_id, None)
        _revoked_sessions.add(session_id)


def is_auth_session_valid(session_id: str | None, user_id: int) -> bool:
    if not session_id or session_id in _revoked_sessions:
        return False
    record = _active_sessions.get(session_id)
    if not record or record[0] != user_id:
        return False
    if record[1] <= datetime.now(timezone.utc):
        _active_sessions.pop(session_id, None)
        return False
    return True


def create_persistent_auth_session(db, user_id: int, expires_at: datetime) -> str:
    session_id = new_session_id()
    db.add(AuthSessionRecord(session_id=session_id, user_id=user_id, expires_at=expires_at.replace(tzinfo=None)))
    db.commit()
    return session_id


def revoke_persistent_auth_session(db, session_id: str | None) -> None:
    if session_id:
        record = db.get(AuthSessionRecord, session_id)
        if record:
            record.revoked = True
            db.commit()


def is_persistent_auth_session_valid(db, session_id: str | None, user_id: int) -> bool:
    if not session_id:
        return False
    record = db.get(AuthSessionRecord, session_id)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if not record or record.user_id != user_id or record.revoked or record.expires_at <= now:
        if record and record.expires_at <= now:
            record.revoked = True
            db.commit()
        return False
    return True