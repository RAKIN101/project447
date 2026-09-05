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

## Important remaining integration work

- The current SQLAlchemy `User` and `Post` schemas still contain legacy plaintext columns. The new envelope API is tested and ready at the service boundary, but those columns are not yet replaced with ciphertext columns.
- A production KMS must protect private key material with an HSM, OS key vault, or equivalent. The local JSON KMS is intentionally an educational CSE447 implementation.
- The MAC secret must be loaded from a deployment secret manager; the `.env` value is development-only.
- Existing database rows created before ciphertext-column migration are not automatically transformed.

These are deliberately called out rather than hidden: the cryptographic primitives and service boundary are implemented, but claiming that the current live database is already ciphertext-only would be inaccurate until the schema migration and service wiring are completed.

## Tests

`tests/test_crypto.py` covers RSA, ECC, algorithm separation, envelope tampering, HMAC, Argon2 passwords, OTP expiry/primary-factor checks, KMS persistence, rotation, and revocation.