"""Application storage boundary for encrypted user/profile and post payloads."""

from decimal import Decimal
from typing import Any

from app.core.config import settings
from app.crypto.envelope import GovPayCrypto
from app.crypto.kms import KeyManagementModule
from app.crypto.mac import mac_bytes


_kms = KeyManagementModule(settings.kms_path)


def _ensure_key(algorithm: str, key_id: str) -> str:
    try:
        _kms.get_active(key_id)
    except (KeyError, ValueError):
        _kms.generate(algorithm, key_id)
    return key_id


def _crypto() -> GovPayCrypto:
    _ensure_key("RSA", "govpay-user-data")
    _ensure_key("ECC", "govpay-post-data")
    return GovPayCrypto(_kms, settings.crypto_mac_secret.encode("utf-8"))


def _json_safe(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    return value


def user_lookup(username: str) -> str:
    return mac_bytes(settings.crypto_mac_secret.encode("utf-8"), username.strip().lower().encode("utf-8"))


def email_lookup(email: str) -> str:
    return mac_bytes(settings.crypto_mac_secret.encode("utf-8"), email.strip().lower().encode("utf-8"))


def encrypt_user_profile(*, username: str, email: str, full_name: str, phone: str, address: str) -> str:
    payload = {"username": username, "email": email, "full_name": full_name, "phone": phone, "address": address}
    return _crypto().encrypt_user_record(payload, "govpay-user-data")


def decrypt_user_profile(payload: str) -> dict[str, str]:
    return _crypto().decrypt_user_record(payload)


def encrypt_post(*, title: str, content: str) -> str:
    return _crypto().encrypt_post_record({"title": title, "content": content}, "govpay-post-data")


def decrypt_post(payload: str) -> dict[str, str]:
    return _crypto().decrypt_post_record(payload)
