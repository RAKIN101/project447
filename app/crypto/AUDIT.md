# CSE447 Crypto Audit

## Implemented

- RSA key generation, modular arithmetic, OAEP-style encoding, chunked encryption, and decryption are implemented in Python in `rsa.py`.
- ECC secp256k1 point arithmetic and ECC-ElGamal message encryption/decryption are implemented in Python in `ecc.py`.
- RSA covers user/profile, bill, payment, proof, and notification envelopes; ECC covers post, support, and proof-file envelopes.
- HMAC-SHA256 authenticates envelope metadata and ciphertext. It detects modification but does not encrypt.
- Argon2id generates salted password hashes. Passwords are never encrypted.
- OTP generation, SMTP delivery, expiry, issuance throttling, attempt limits, and single-use verification are wired into login.
- The KMS persists RSA/ECC key IDs, versions, active/retired/revoked status, and rotation history in a restrictive local file; configured production deployments RSA-wrap private records with deployment-held wrapping keys.
- The existing `app/core/security.py` password API now delegates to the dedicated crypto package without changing callers.
- Existing server-side role checks and signed session cookies remain in place.

## Integration status

- `User.encrypted_profile` stores the RSA encrypted profile envelope, while HMAC lookup columns support username/email authentication without plaintext lookup values.
- `Post.encrypted_content` stores the ECC encrypted title/content envelope.
- Bills, payments, payment proofs, notifications, and support subjects/messages use authenticated RSA/ECC encrypted payload columns.
- Payment proof files are encrypted with ECC and stored outside public static serving; downloads require the owning citizen or an admin.
- Legacy plaintext columns remain nullable for migration compatibility and are cleared by `scripts/migrate_encrypted_storage.py`.
- Run `python -m scripts.migrate_encrypted_storage` once against an existing PostgreSQL database to add the columns, create lookup indexes, and encrypt existing user/profile and post rows.
- A production KMS must protect private key material with an HSM, OS key vault, or equivalent. The local JSON KMS is intentionally an educational CSE447 implementation.
- The MAC secret must be loaded from a deployment secret manager; the `.env` value is development-only.
- Legacy plaintext columns are retained only as nullable migration compatibility fields; current writes clear them and the migration clears existing values.

## Attack demonstrations

Eight executable attack demonstrations are covered by `tests/test_crypto.py`:
HMAC forgery, envelope metadata tampering, RSA OAEP tampering, wrong-key RSA
decryption, ECC invalid-point injection, malformed ECC ciphertext, OTP brute
force, and post-logout session replay.

## Tests

`tests/test_crypto.py` covers RSA, ECC, algorithm separation, envelope tampering, HMAC, Argon2 passwords, OTP expiry/primary-factor checks, KMS persistence, rotation, and revocation.