"""Executable CSE447 cryptoanalysis demonstrations.

Each demonstration attempts a concrete attack against a GovPay boundary and
returns whether the implemented control rejected it. These are educational
checks, not substitutes for a production cryptographic library or penetration
assessment.
"""

import json
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.otp_store import MAX_OTP_ATTEMPTS, clear, get, register_failure, remember_issue
from app.core.sessions import create_auth_session, is_auth_session_valid, revoke_auth_session
from app.crypto.ecc import ECCPublicKey, ecc_decrypt, ecc_encrypt, generate_ecc_keypair
from app.crypto.envelope import GovPayCrypto
from app.crypto.kms import KeyManagementModule
from app.crypto.mac import mac_bytes, verify_mac
from app.crypto.rsa import generate_rsa_keypair, rsa_decrypt, rsa_encrypt


@dataclass(frozen=True)
class AttackResult:
    name: str
    attack_blocked: bool
    evidence: str


def _result(name: str, blocked: bool, evidence: str) -> AttackResult:
    return AttackResult(name, blocked, evidence)


def demonstrate_hmac_forgery() -> AttackResult:
    key = b"demo-integrity-key"
    tag = mac_bytes(key, b"approved payment")
    blocked = not verify_mac(key, b"approved payment forged", tag)
    return _result("hmac-forgery", blocked, "A modified message does not verify with the original tag.")


def demonstrate_envelope_metadata_tampering() -> AttackResult:
    with tempfile.TemporaryDirectory() as directory:
        kms = KeyManagementModule(Path(directory) / "kms.json")
        record = kms.generate("RSA", "demo-user")
        crypto = GovPayCrypto(kms, b"demo-envelope-mac" * 2)
        envelope = json.loads(crypto.encrypt_user_record({"value": "protected"}, record.key_id))
        envelope["key_id"] = "attacker-key"
        try:
            crypto.decrypt_user_record(json.dumps(envelope, separators=(",", ":")))
        except ValueError as exc:
            blocked = "integrity" in str(exc)
        else:
            blocked = False
    return _result("envelope-metadata-tampering", blocked, "Changing authenticated key metadata is rejected before key lookup.")


def demonstrate_rsa_oaep_malleability() -> AttackResult:
    keys = generate_rsa_keypair()
    ciphertext = json.loads(rsa_encrypt(keys.public, b"protected"))
    raw = bytearray(__import__("base64").urlsafe_b64decode(ciphertext[0]))
    raw[-1] ^= 1
    ciphertext[0] = __import__("base64").urlsafe_b64encode(raw).decode("ascii")
    try:
        rsa_decrypt(keys.private, json.dumps(ciphertext))
    except ValueError:
        blocked = True
    else:
        blocked = False
    return _result("rsa-oaep-tampering", blocked, "OAEP decoding rejects a modified RSA block.")


def demonstrate_rsa_wrong_key() -> AttackResult:
    keys = generate_rsa_keypair()
    wrong_key = generate_rsa_keypair()
    ciphertext = rsa_encrypt(keys.public, b"protected")
    try:
        rsa_decrypt(wrong_key.private, ciphertext)
    except (ValueError, OverflowError):
        blocked = True
    else:
        blocked = False
    return _result("rsa-wrong-key", blocked, "A ciphertext cannot be decrypted with another private key.")


def demonstrate_ecc_invalid_point() -> AttackResult:
    keys = generate_ecc_keypair()
    try:
        ecc_encrypt(ECCPublicKey("00" * 32 + ":" + "00" * 32), b"attack")
    except ValueError:
        blocked = True
    else:
        blocked = False
    return _result("ecc-invalid-point", blocked, "Off-curve public points are rejected before encryption.")


def demonstrate_ecc_ciphertext_structure_attack() -> AttackResult:
    keys = generate_ecc_keypair()
    try:
        ecc_decrypt(keys.private, json.dumps([{"c1": "", "c2": ""}]))
    except ValueError:
        blocked = True
    else:
        blocked = False
    return _result("ecc-malformed-ciphertext", blocked, "Infinity and malformed point encodings are rejected.")


def demonstrate_otp_bruteforce() -> AttackResult:
    clear()
    session_id = "attack-demo-otp"
    remember_issue(41, session_id, "123456")
    for _ in range(MAX_OTP_ATTEMPTS):
        register_failure(session_id)
    blocked = get(session_id) is None
    clear()
    return _result("otp-brute-force", blocked, "The OTP record is destroyed after the bounded attempt budget.")


def demonstrate_session_replay() -> AttackResult:
    session_id = create_auth_session(41, datetime.now(timezone.utc) + timedelta(minutes=1))
    revoke_auth_session(session_id)
    return _result("session-replay-after-logout", not is_auth_session_valid(session_id, 41), "A revoked session identifier cannot authenticate again.")


def run_all_attack_demonstrations() -> list[AttackResult]:
    return [
        demonstrate_hmac_forgery(),
        demonstrate_envelope_metadata_tampering(),
        demonstrate_rsa_oaep_malleability(),
        demonstrate_rsa_wrong_key(),
        demonstrate_ecc_invalid_point(),
        demonstrate_ecc_ciphertext_structure_attack(),
        demonstrate_otp_bruteforce(),
        demonstrate_session_replay(),
    ]
