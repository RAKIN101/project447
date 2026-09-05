"""Authenticated storage envelopes for the application service layer.

User/profile records use RSA. Post records use ECC. HMAC authenticates the
algorithm, key id, and ciphertext so database tampering is detected.
"""

import base64
import hashlib
import json
import secrets
from dataclasses import asdict
from typing import Any

from app.crypto.ecc import ECCPrivateKey, ECCPublicKey, ecc_decrypt, ecc_encrypt
from app.crypto.kms import KeyManagementModule, KeyRecord
from app.crypto.mac import mac_bytes, verify_mac
from app.crypto.rsa import RSAPrivateKey, RSAPublicKey, rsa_decrypt, rsa_encrypt


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class GovPayCrypto:
    """The explicit service boundary between business logic and crypto."""

    def __init__(self, kms: KeyManagementModule, mac_key: bytes | None = None):
        self.kms = kms
        self.mac_key = mac_key or secrets.token_bytes(32)

    def _wrap(self, algorithm: str, key_id: str, ciphertext: str) -> str:
        body = {"algorithm": algorithm, "key_id": key_id, "ciphertext": ciphertext}
        body["mac"] = mac_bytes(self.mac_key, _canonical(body))
        return json.dumps(body, separators=(",", ":"))

    def _unwrap(self, envelope: str) -> tuple[dict[str, Any], KeyRecord]:
        try:
            body = json.loads(envelope)
            tag = body.pop("mac")
        except (TypeError, ValueError, KeyError) as exc:
            raise ValueError("integrity check failed: malformed envelope") from exc
        if not verify_mac(self.mac_key, _canonical(body), tag):
            raise ValueError("integrity check failed: ciphertext or metadata was modified")
        return body, self.kms.get_active(body["key_id"])

    def encrypt_user_record(self, record: dict[str, Any], key_id: str) -> str:
        key = self.kms.get_active(key_id)
        if key.algorithm != "RSA":
            raise ValueError("user records require an RSA key")
        return self._wrap("RSA", key_id, rsa_encrypt(RSAPublicKey(**key.public), _canonical(record)))

    def decrypt_user_record(self, envelope: str) -> dict[str, Any]:
        body, key = self._unwrap(envelope)
        if body["algorithm"] != "RSA":
            raise ValueError("user records require RSA")
        return json.loads(rsa_decrypt(RSAPrivateKey(**key.private), body["ciphertext"]))

    def encrypt_post_record(self, record: dict[str, Any], key_id: str) -> str:
        key = self.kms.get_active(key_id)
        if key.algorithm != "ECC":
            raise ValueError("post records require an ECC key")
        return self._wrap("ECC", key_id, ecc_encrypt(ECCPublicKey(**key.public), _canonical(record)))

    def decrypt_post_record(self, envelope: str) -> dict[str, Any]:
        body, key = self._unwrap(envelope)
        if body["algorithm"] != "ECC":
            raise ValueError("post records require ECC")
        return json.loads(ecc_decrypt(ECCPrivateKey(**key.private), body["ciphertext"]))
