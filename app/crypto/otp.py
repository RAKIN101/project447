"""One-time passwords for the second authentication factor."""

from datetime import datetime, timezone
import hmac
import secrets


def generate_otp() -> str:
    """Return a random six-digit OTP. The caller owns expiry storage."""
    return f"{secrets.randbelow(1_000_000):06d}"


def verify_two_step(primary_valid: bool, submitted_otp: str, expected_otp: str, expires_at: datetime) -> bool:
    """Require valid primary credentials, an unexpired OTP, and an exact match."""
    now = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return primary_valid and now <= expires_at and hmac.compare_digest(submitted_otp, expected_otp)
