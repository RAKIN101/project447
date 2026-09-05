"""HMAC-SHA256 message authentication code.

HMAC is used only for integrity and authenticity. It never encrypts data.
"""

import base64
import hashlib
import hmac


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def mac_bytes(key: bytes, message: bytes) -> str:
    """Create an HMAC tag for a message."""
    return _encode(hmac.new(key, message, hashlib.sha256).digest())


def verify_mac(key: bytes, message: bytes, tag: str) -> bool:
    """Verify a tag in constant time."""
    expected = mac_bytes(key, message)
    return hmac.compare_digest(expected, tag)
