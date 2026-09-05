from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core.security import csrf_token, hash_password, validate_csrf, verify_password
from app.core.sessions import create_auth_session, create_persistent_auth_session, is_auth_session_valid, is_persistent_auth_session_valid, revoke_auth_session, revoke_persistent_auth_session
from app.core.config import Settings
from app.core.otp_store import MAX_OTP_ATTEMPTS, can_issue, can_issue_persistent, clear, get, register_failure, remember_issue, remember_issue_persistent, verify_persistent


def test_passwords_are_hashed_and_verifiable():
    password_hash = hash_password("correct horse battery staple")
    assert password_hash != "correct horse battery staple"
    assert verify_password("correct horse battery staple", password_hash)
    assert not verify_password("wrong password", password_hash)


def test_csrf_token_rejects_missing_or_invalid_values():
    request = Request({"type": "http", "headers": [], "session": {}})
    token = csrf_token(request)
    validate_csrf(request, token)
    with pytest.raises(HTTPException):
        validate_csrf(request, "wrong-token")


def test_auth_session_expires_and_revokes():
    session_id = create_auth_session(7, datetime.now(timezone.utc) + timedelta(minutes=1))
    assert is_auth_session_valid(session_id, 7)
    revoke_auth_session(session_id)
    assert not is_auth_session_valid(session_id, 7)

    expired_id = create_auth_session(7, datetime.now(timezone.utc) - timedelta(seconds=1))
    assert not is_auth_session_valid(expired_id, 7)


def test_otp_records_are_rate_limited_attempt_limited_and_single_use():
    clear()
    assert all(can_issue(8) and remember_issue(8, f"issue-{index}", "123456") for index in range(5))
    assert not can_issue(8)
    remember_issue(9, "otp-session", "123456")
    assert get("otp-session") is not None
    for _ in range(MAX_OTP_ATTEMPTS):
        register_failure("otp-session")
    assert get("otp-session") is None
    clear()


def test_production_settings_reject_missing_secrets_and_insecure_cookies():
    with pytest.raises(ValueError):
        Settings(environment="production", secure_cookies=False)


def test_persistent_otp_and_sessions_survive_helper_boundaries(db):
    session_id = create_persistent_auth_session(db, 7, datetime.now(timezone.utc) + timedelta(minutes=1))
    assert is_persistent_auth_session_valid(db, session_id, 7)
    revoke_persistent_auth_session(db, session_id)
    assert not is_persistent_auth_session_valid(db, session_id, 7)

    assert can_issue_persistent(db, 7)
    otp_session = remember_issue_persistent(db, 7, "123456")
    assert verify_persistent(db, otp_session, 7, "123456")
    assert not verify_persistent(db, otp_session, 7, "123456")
