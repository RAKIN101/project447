"""Application storage boundary for encrypted user/profile and post payloads."""

from decimal import Decimal
from datetime import date, datetime
from typing import Any

from app.core.config import settings
from app.crypto.envelope import GovPayCrypto
from app.crypto.kms import KeyManagementModule
from app.crypto.rsa import RSAPrivateKey, RSAPublicKey
from app.crypto.mac import mac_bytes


def _load_rsa_key(value: str | None, private: bool):
    if not value:
        return None
    parsed = __import__("json").loads(value)
    return RSAPrivateKey(**parsed) if private else RSAPublicKey(**parsed)


_kms = KeyManagementModule(settings.kms_path, _load_rsa_key(settings.kms_wrap_public_key, False), _load_rsa_key(settings.kms_wrap_private_key, True))


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
    if isinstance(value, (date, datetime)):
        return value.isoformat()
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


def encrypt_rsa_data(payload: dict[str, Any]) -> str:
    return _crypto().encrypt_rsa_record(payload, "govpay-user-data")


def decrypt_rsa_data(payload: str) -> dict[str, Any]:
    return _crypto().decrypt_rsa_record(payload)


def encrypt_ecc_data(payload: dict[str, Any]) -> str:
    return _crypto().encrypt_ecc_record(payload, "govpay-post-data")


def decrypt_ecc_data(payload: str) -> dict[str, Any]:
    return _crypto().decrypt_ecc_record(payload)


def encrypt_rsa_bytes(value: bytes) -> str:
    return _crypto().encrypt_rsa_bytes(value, "govpay-user-data")


def decrypt_rsa_bytes(payload: str) -> bytes:
    return _crypto().decrypt_rsa_bytes(payload)


def encrypt_ecc_bytes(value: bytes) -> str:
    return _crypto().encrypt_ecc_bytes(value, "govpay-post-data")


def decrypt_ecc_bytes(payload: str) -> bytes:
    return _crypto().decrypt_ecc_bytes(payload)


def encrypt_bill_data(*, bill_type: str, title: str, description: str, amount: Decimal, due_date: date, paid_date: datetime | None = None) -> str:
    return encrypt_rsa_data({"bill_type": bill_type, "title": title, "description": description, "amount": str(amount), "due_date": due_date.isoformat()})


def decrypt_bill_data(payload: str) -> dict[str, str]:
    return decrypt_rsa_data(payload)


def encrypt_payment_data(*, amount: Decimal, payment_method: str, transaction_reference: str, payment_date: datetime) -> str:
    return encrypt_rsa_data({"amount": str(amount), "payment_method": payment_method, "transaction_reference": transaction_reference, "payment_date": payment_date.isoformat()})


def decrypt_payment_data(payload: str) -> dict[str, str]:
    return decrypt_rsa_data(payload)


def encrypt_proof_data(*, proof_text: str, proof_image_name: str, reviewer_note: str) -> str:
    return encrypt_rsa_data({"proof_text": proof_text, "proof_image_name": proof_image_name, "reviewer_note": reviewer_note})


def decrypt_proof_data(payload: str) -> dict[str, str]:
    return decrypt_rsa_data(payload)


def encrypt_notification_data(*, title: str, message: str, link: str) -> str:
    return encrypt_rsa_data({"title": title, "message": message, "link": link})


def decrypt_notification_data(payload: str) -> dict[str, str]:
    return decrypt_rsa_data(payload)


def encrypt_support_subject(subject: str) -> str:
    return encrypt_ecc_data({"subject": subject})


def decrypt_support_subject(payload: str) -> str:
    return str(decrypt_ecc_data(payload)["subject"])


def encrypt_support_message(message: str) -> str:
    return encrypt_ecc_data({"message": message})


def decrypt_support_message(payload: str) -> str:
    return str(decrypt_ecc_data(payload)["message"])
