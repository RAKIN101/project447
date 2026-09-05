# CSE447 Crypto Audit

## Implemented

- RSA key generation, modular arithmetic, OAEP-style encoding, chunked encryption, and decryption are implemented in Python in `govpay_crypto.py`.
- ECC secp256k1 point arithmetic and ECC-ElGamal message encryption/decryption are implemented in Python in `govpay_crypto.py`.
- RSA is reserved for user/profile envelopes; ECC is reserved for post envelopes.
- HMAC-SHA256 authenticates envelope metadata and ciphertext. It detects modification but does not encrypt.
- Argon2id generates salted password hashes. Passwords are never encrypted.
- OTP generation and expiry-aware two-step verification are implemented and wired into the existing login flow.
- The KMS persists RSA/ECC key IDs, versions, active/retired/revoked status, and rotation history in a restrictive local file.
- The existing `app/core/security.py` password API now delegates to the dedicated crypto package without changing callers.
- Existing server-side role checks and signed session cookies remain in place.

## Integration status

- `User.encrypted_profile` stores the RSA encrypted profile envelope, while HMAC lookup columns support username/email authentication without plaintext lookup values.
- `Post.encrypted_content` stores the ECC encrypted title/content envelope.
- Legacy plaintext columns remain nullable for migration compatibility and are cleared by `scripts/migrate_encrypted_storage.py`.
- Run `python -m scripts.migrate_encrypted_storage` once against an existing PostgreSQL database to add the columns, create lookup indexes, and encrypt existing user/profile and post rows.
- A production KMS must protect private key material with an HSM, OS key vault, or equivalent. The local JSON KMS is intentionally an educational CSE447 implementation.
- The MAC secret must be loaded from a deployment secret manager; the `.env` value is development-only.
- Bill, payment-proof, support, and notification content are outside the current encrypted-storage migration and retain their existing schema.

## Tests

`tests/test_crypto.py` covers RSA, ECC, algorithm separation, envelope tampering, HMAC, Argon2 passwords, OTP expiry/primary-factor checks, KMS persistence, rotation, and revocation.