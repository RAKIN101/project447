from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.core.security import new_session_id
from app.crypto.mac import mac_bytes, verify_mac
from app.models import OTPChallenge


OTP_TTL = timedelta(minutes=5)
OTP_RATE_WINDOW = timedelta(minutes=5)
MAX_OTP_ATTEMPTS = 5
MAX_OTP_ISSUES = 5


@dataclass
class OTPRecord:
    code: str
    expires_at: datetime
    attempts: int = 0


_records: dict[str, OTPRecord] = {}
_issue_history: dict[int, list[datetime]] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def can_issue(user_id: int) -> bool:
    now = _now()
    history = [item for item in _issue_history.get(user_id, []) if item + OTP_RATE_WINDOW > now]
    _issue_history[user_id] = history
    return len(history) < MAX_OTP_ISSUES


def remember_issue(user_id: int, session_id: str, code: str) -> OTPRecord:
    now = _now()
    _issue_history.setdefault(user_id, []).append(now)
    record = OTPRecord(code=code, expires_at=now + OTP_TTL)
    _records[session_id] = record
    return record


def get(session_id: str | None) -> OTPRecord | None:
    if not session_id:
        return None
    record = _records.get(session_id)
    if not record:
        return None
    if record.expires_at <= _now():
        _records.pop(session_id, None)
        return None
    return record


def register_failure(session_id: str) -> bool:
    record = get(session_id)
    if not record:
        return False
    record.attempts += 1
    if record.attempts >= MAX_OTP_ATTEMPTS:
        _records.pop(session_id, None)
        return False
    return True


def consume(session_id: str) -> None:
    _records.pop(session_id, None)


def clear() -> None:
    _records.clear()
    _issue_history.clear()


def can_issue_persistent(db, user_id: int) -> bool:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - OTP_RATE_WINDOW
    return db.query(OTPChallenge).filter(OTPChallenge.user_id == user_id, OTPChallenge.created_at >= cutoff).count() < MAX_OTP_ISSUES


def remember_issue_persistent(db, user_id: int, code: str) -> str:
    session_id = new_session_id()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    db.add(OTPChallenge(session_id=session_id, user_id=user_id, code_mac=mac_bytes(settings.crypto_mac_secret.encode("utf-8"), code.encode("utf-8")), expires_at=now + OTP_TTL))
    db.commit()
    return session_id


def verify_persistent(db, session_id: str | None, user_id: int, code: str) -> bool:
    if not session_id:
        return False
    record = db.get(OTPChallenge, session_id)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if not record or record.user_id != user_id or record.expires_at <= now:
        return False
    if verify_mac(settings.crypto_mac_secret.encode("utf-8"), code.encode("utf-8"), record.code_mac):
        db.delete(record)
        db.commit()
        return True
    record.attempts += 1
    if record.attempts >= MAX_OTP_ATTEMPTS:
        db.delete(record)
    db.commit()
    return False


def consume_persistent(db, session_id: str | None) -> None:
    if session_id:
        record = db.get(OTPChallenge, session_id)
        if record:
            db.delete(record)
            db.commit()
