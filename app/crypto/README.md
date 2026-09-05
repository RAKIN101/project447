# GovPay Crypto Module

This directory is the CSE447 educational cryptography boundary.

| File | Responsibility | Assignment mapping |
| --- | --- | --- |
| `rsa.py` | From-scratch RSA-OAEP and key generation | User/profile records |
| `ecc.py` | From-scratch secp256k1 point arithmetic and ECC-ElGamal | Post records |
| `mac.py` | HMAC-SHA256 integrity verification | Tamper detection only |
| `password.py` | Argon2id salted password hashes | Passwords are never encrypted |
| `otp.py` | Temporary second-factor generation/verification | Two-step authentication |
| `kms.py` | Key IDs, versions, persistence, rotation, revocation | Key management |
| `envelope.py` | Authenticated storage envelope | Service-layer integration point |
| `govpay_crypto.py` | Single implementation source and compatibility facade | Existing imports remain stable |

## Data flow

```text
User/profile -> envelope.py -> RSA (rsa.py) -> HMAC (mac.py) -> database
Post         -> envelope.py -> ECC (ecc.py) -> HMAC (mac.py) -> database
Password     -> password.py -> Argon2id hash -> database
Login        -> password.py + otp.py + session/RBAC -> dashboard
```

No AES, DES, 3DES, Fernet, ChaCha20, or RSA/ECC library encryption is used.
HMAC is permitted here solely as a MAC for integrity; it is not an encryption
algorithm. The KMS JSON file is an educational local store and should be
replaced with an HSM or OS key vault for a real deployment. When configured,
the JSON backend RSA-wraps private records using deployment-provided RSA
wrapping keys; production startup requires those wrapping keys.

## Cryptoanalysis demonstrations

`app.crypto.attack_demos.run_all_attack_demonstrations()` executes eight
named demonstrations: HMAC forgery, envelope metadata tampering, RSA OAEP
tampering, RSA wrong-key decryption, ECC invalid-point injection, malformed
ECC ciphertext, OTP brute force, and post-logout session replay.
