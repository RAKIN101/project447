"""Compatibility facade for older imports.

The concrete code is intentionally split by responsibility:
`rsa.py`, `ecc.py`, `mac.py`, `password.py`, `otp.py`, `kms.py`, and
`envelope.py`. New code should import from those focused modules directly.
"""

from app.crypto.ecc import ECCKeyPair, ECCPrivateKey, ECCPublicKey, ecc_decrypt, ecc_encrypt, generate_ecc_keypair
from app.crypto.envelope import GovPayCrypto
from app.crypto.kms import KeyManagementModule, KeyRecord
from app.crypto.mac import mac_bytes, verify_mac
from app.crypto.otp import generate_otp, verify_two_step
from app.crypto.password import hash_password, verify_password
from app.crypto.rsa import RSAKeyPair, RSAPrivateKey, RSAPublicKey, generate_rsa_keypair, rsa_decrypt, rsa_encrypt

__all__ = [
    "GovPayCrypto", "KeyManagementModule", "KeyRecord",
    "RSAKeyPair", "RSAPublicKey", "RSAPrivateKey", "generate_rsa_keypair", "rsa_encrypt", "rsa_decrypt",
    "ECCKeyPair", "ECCPublicKey", "ECCPrivateKey", "generate_ecc_keypair", "ecc_encrypt", "ecc_decrypt",
    "mac_bytes", "verify_mac", "hash_password", "verify_password", "generate_otp", "verify_two_step",
]
