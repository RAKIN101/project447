from datetime import datetime, timedelta, timezone

import pytest

from app.crypto.ecc import ecc_decrypt, ecc_encrypt, generate_ecc_keypair
from app.crypto.envelope import GovPayCrypto
from app.crypto.kms import KeyManagementModule
from app.crypto.mac import mac_bytes, verify_mac
from app.crypto.otp import generate_otp, verify_two_step
from app.crypto.password import hash_password, verify_password
from app.crypto.rsa import generate_rsa_keypair, rsa_decrypt, rsa_encrypt


def test_rsa_round_trip_and_wrong_private_key_fails():
    first = generate_rsa_keypair()
    second = generate_rsa_keypair()
    message = b"user profile data that is longer than one OAEP block " * 3
    ciphertext = rsa_encrypt(first.public, message)
    assert rsa_decrypt(first.private, ciphertext) == message
    with pytest.raises(ValueError):
        rsa_decrypt(second.private, ciphertext)


def test_ecc_round_trip_uses_different_asymmetric_algorithm():
    keys = generate_ecc_keypair()
    message = b"post content" * 8
    ciphertext = ecc_encrypt(keys.public, message)
    assert ecc_decrypt(keys.private, ciphertext) == message


def test_authenticated_envelopes_map_categories_to_distinct_algorithms(tmp_path):
    kms = KeyManagementModule(tmp_path / "kms.json")
    rsa = kms.generate("RSA", "user-data")
    ecc = kms.generate("ECC", "post-data")
    crypto = GovPayCrypto(kms, b"test-mac-key" * 3)
    user = {"username": "citizen", "email": "citizen@example.com"}
    post = {"title": "Notice", "content": "A public service update"}

    user_envelope = crypto.encrypt_user_record(user, rsa.key_id)
    post_envelope = crypto.encrypt_post_record(post, ecc.key_id)
    assert crypto.decrypt_user_record(user_envelope) == user
    assert crypto.decrypt_post_record(post_envelope) == post
    assert '"algorithm":"RSA"' in user_envelope
    assert '"algorithm":"ECC"' in post_envelope
    with pytest.raises(ValueError, match="integrity"):
        crypto.decrypt_post_record(post_envelope[:-3] + "abc")


def test_mac_detects_modified_data():
    key, message = b"integrity-key", b"important record"
    tag = mac_bytes(key, message)
    assert verify_mac(key, message, tag)
    assert not verify_mac(key, b"modified record", tag)


def test_passwords_are_salted_hashes_not_encryption():
    first = hash_password("GovPay secret")
    second = hash_password("GovPay secret")
    assert first != second
    assert verify_password("GovPay secret", first)
    assert not verify_password("wrong", first)


def test_otp_requires_primary_factor_and_expiration():
    otp = generate_otp()
    future = datetime.now(timezone.utc) + timedelta(minutes=1)
    assert len(otp) == 6 and otp.isdigit()
    assert verify_two_step(True, otp, otp, future)
    assert not verify_two_step(False, otp, otp, future)
    assert not verify_two_step(True, "000000", otp, future)
    assert not verify_two_step(True, otp, otp, datetime.now(timezone.utc) - timedelta(seconds=1))


def test_kms_persists_rotates_and_revokes(tmp_path):
    path = tmp_path / "kms.json"
    kms = KeyManagementModule(path)
    first = kms.generate("RSA", "user-data")
    rotated = kms.rotate("user-data")
    assert rotated.version == 2
    assert len(kms.records) == 2
    reloaded = KeyManagementModule(path)
    assert reloaded.get_active("user-data").version == 2
    reloaded.revoke("user-data")
    with pytest.raises(ValueError, match="active"):
        reloaded.get_active("user-data")
    assert first.status == "retired"
