# GovPay Cryptography Guide

This document maps every cryptographic control in GovPay to the exact file it
lives in and explains how it works for the feature that uses it. It is meant
as a reading guide for the CSE447 crypto module (`app/crypto/`) and the
service layer that calls into it (`app/services/`, `app/core/`, `app/main.py`).

No AES/DES/Fernet/ChaCha20 or a crypto library's own RSA/ECC is used anywhere.
RSA and ECC are implemented from scratch in this repo. HMAC is used only for
integrity/authenticity, never for encryption.

---

## 1. The building blocks (`app/crypto/`)

| File | Algorithm | Purpose |
| --- | --- | --- |
| [app/crypto/rsa.py](app/crypto/rsa.py) | RSA-OAEP (from scratch, 1024-bit default) | Asymmetric encryption for "structured record" data |
| [app/crypto/ecc.py](app/crypto/ecc.py) | secp256k1 ECC-ElGamal (from scratch) | Asymmetric encryption for "social/messaging" data |
| [app/crypto/mac.py](app/crypto/mac.py) | HMAC-SHA256 | Tamper detection / authenticity only, never confidentiality |
| [app/crypto/password.py](app/crypto/password.py) | Argon2id (via `argon2-cffi`) | One-way password hashing |
| [app/crypto/otp.py](app/crypto/otp.py) | CSPRNG (`secrets`) + constant-time compare | One-time password generation/verification |
| [app/crypto/kms.py](app/crypto/kms.py) | Key Management Module | Generates, versions, persists, rotates, revokes RSA/ECC keys |
| [app/crypto/envelope.py](app/crypto/envelope.py) | `GovPayCrypto` | The single boundary that combines algorithm + key + HMAC into one storable "envelope" string |
| [app/crypto/govpay_crypto.py](app/crypto/govpay_crypto.py) / [app/crypto/__init__.py](app/crypto/__init__.py) | — | Re-export facades so other modules can `from app.crypto import ...` |
| [app/crypto/attack_demos.py](app/crypto/attack_demos.py) | — | Runnable proof-of-concept attacks showing each control actually rejects tampering |

### 1.1 RSA-OAEP — [app/crypto/rsa.py](app/crypto/rsa.py)

- `generate_rsa_keypair(bits=1024)` ([rsa.py:103](app/crypto/rsa.py#L103)) builds two random probable primes with a Miller–Rabin test (`_probably_prime`, [rsa.py:51](app/crypto/rsa.py#L51)), forms `n = p*q`, fixes the public exponent `e = 65537`, and derives the private exponent `d` with the extended Euclidean algorithm (`_inverse`, [rsa.py:44](app/crypto/rsa.py#L44)).
- `rsa_encrypt` ([rsa.py:148](app/crypto/rsa.py#L148)) OAEP-pads each chunk of plaintext (SHA-256 based MGF1 masking, [rsa.py:120](app/crypto/rsa.py#L120)), does modular exponentiation `c = m^e mod n`, and returns a JSON array of base64url blocks (long records are split into multiple RSA blocks).
- `rsa_decrypt` ([rsa.py:160](app/crypto/rsa.py#L160)) reverses this with the private exponent `d` and strictly validates the OAEP padding structure — a single flipped bit makes decoding raise `ValueError` (this is what `demonstrate_rsa_oaep_malleability` in `attack_demos.py` proves).
- Also doubles as the **KMS wrapping key** — see §1.6.

### 1.2 ECC-ElGamal — [app/crypto/ecc.py](app/crypto/ecc.py)

- Uses the secp256k1 curve (`_P`, `_G`, `_N`, [ecc.py:13](app/crypto/ecc.py#L13)) with hand-written point addition/doubling (`_add`, [ecc.py:23](app/crypto/ecc.py#L23)) and scalar multiplication (`_multiply`, [ecc.py:42](app/crypto/ecc.py#L42)).
- `generate_ecc_keypair` picks a random scalar `d` as the private key and `Q = d·G` as the public key ([ecc.py:95](app/crypto/ecc.py#L95)).
- Plaintext bytes are encoded as a curve point `M` in ≤28-byte chunks (`_encode_message`, [ecc.py:100](app/crypto/ecc.py#L100), using the standard "try increasing x until `x³+7` is a quadratic residue" trick).
- `ecc_encrypt` ([ecc.py:124](app/crypto/ecc.py#L124)) picks an ephemeral scalar `k` and returns the ElGamal pair `(C1, C2) = (k·G, M + k·Q)`.
- `ecc_decrypt` ([ecc.py:138](app/crypto/ecc.py#L138)) recovers `M = C2 - d·C1` using the recipient's private scalar `d`, and validates every point is actually on the curve before using it (rejecting the classic "invalid curve point" attack).

### 1.3 HMAC-SHA256 — [app/crypto/mac.py](app/crypto/mac.py)

`mac_bytes` / `verify_mac` wrap Python's `hmac` module with SHA-256 and a constant-time comparison (`hmac.compare_digest`). This one primitive is reused for four unrelated purposes across the app (envelope integrity, OTP-code storage, and the two blind-index lookups) — see §2 for each.

### 1.4 Argon2id passwords — [app/crypto/password.py](app/crypto/password.py)

`hash_password` / `verify_password` are a thin wrapper around `argon2.PasswordHasher`. Passwords are **hashed, never encrypted** — there is no reverse operation. Argon2id automatically manages a random salt and its own tunable memory/time cost per hash string.

### 1.5 OTP (second factor) — [app/crypto/otp.py](app/crypto/otp.py)

- `generate_otp()` returns a random 6-digit string from `secrets.randbelow` (CSPRNG, not `random`).
- `verify_two_step` is a helper that combines "primary credential was valid" AND "not expired" AND "constant-time equal to expected code" — used by the in-memory OTP path (see §2.2).

### 1.6 Key Management Module (KMS) — [app/crypto/kms.py](app/crypto/kms.py)

This is a small versioned key store, not a real HSM:

- `KeyRecord` ([kms.py:17](app/crypto/kms.py#L17)) holds `key_id`, `algorithm`, `version`, `status` (`active`/`retired`/`revoked`), the public key, the private key, and a timestamp.
- `generate(algorithm, key_id)` ([kms.py:84](app/crypto/kms.py#L84)) creates a brand-new RSA or ECC keypair and stores it as version `N+1` for that `key_id`, marked `active`.
- `rotate(key_id)` ([kms.py:113](app/crypto/kms.py#L113)) retires the current active key and generates a new active version — old ciphertexts stay decryptable because `get_for_decryption(key_id, version)` ([kms.py:107](app/crypto/kms.py#L107)) can still fetch any non-revoked version.
- `revoke(key_id)` ([kms.py:120](app/crypto/kms.py#L120)) marks **every** version of that key id `revoked` — after this, nothing encrypted under that key can ever be decrypted again by this KMS instance.
- **Key wrapping at rest**: the whole key store is persisted to `.govpay-kms.json` (path from `KMS_PATH`). If `KMS_WRAP_PUBLIC_KEY` / `KMS_WRAP_PRIVATE_KEY` are configured (a *separate* RSA keypair, env-provided), every private key written to disk is itself RSA-OAEP-encrypted with the wrapping public key before it touches the filesystem (`_save`, [kms.py:49](app/crypto/kms.py#L49)), and decrypted with the wrapping private key on load (`_load`, [kms.py:38](app/crypto/kms.py#L38)). This is the classic **KEK-wraps-DEK** pattern: the wrapping keypair is the Key-Encrypting-Key, and the per-purpose RSA/ECC keys it protects are the Data-Encrypting-Keys.
- The file is written atomically (temp file + `os.replace`) and chmod'd to owner-read/write only; it also refuses to load through a symlink ([kms.py:74](app/crypto/kms.py#L74)).
- **Where this file lives in your local setup**: `.govpay-kms.json` in the project root (see `.env`'s `KMS_PATH`). It currently holds two application data keys — `govpay-user-data` (RSA) and `govpay-post-data` (ECC) — auto-created the first time the app runs (`_ensure_key` in `crypto_service.py`, see §2).

### 1.7 The envelope format — [app/crypto/envelope.py](app/crypto/envelope.py)

`GovPayCrypto` is the **only** place that turns "a Python dict" into "a string that goes in a `TEXT` database column", and back. Every encrypted column in the database holds a JSON string shaped like:

```json
{"algorithm":"RSA","key_id":"govpay-user-data","version":1,"ciphertext":"...","mac":"..."}
```

- `_wrap` ([envelope.py:31](app/crypto/envelope.py#L31)) builds this JSON, canonicalizes it (`sort_keys=True`) so the byte representation is deterministic, and appends an HMAC tag (`mac`) computed over everything except the tag itself, keyed by `CRYPTO_MAC_SECRET`.
- `_unwrap` ([envelope.py:36](app/crypto/envelope.py#L36)) does the reverse **in a specific, important order**: it verifies the HMAC tag *before* it ever looks up the key or attempts to decrypt. This means an attacker who edits `key_id`, `version`, or the ciphertext in the database gets rejected immediately with "integrity check failed", instead of the app potentially decrypting with the wrong key or leaking a padding-oracle-style error. (`demonstrate_envelope_metadata_tampering` in `attack_demos.py` is a runnable proof of this.)
- `encrypt_rsa_record` / `decrypt_rsa_record` and `encrypt_ecc_record` / `decrypt_ecc_record` are the generic dict-based envelope operations; `encrypt_rsa_bytes` / `encrypt_ecc_bytes` are byte-based variants used for the payment-proof image file (see §2.6).

---

## 2. Where each feature actually calls this (the parts you'll interact with)

The service-layer boundary is [app/services/crypto_service.py](app/services/crypto_service.py). It is the **only** file that constructs a `GovPayCrypto` instance; every other service (`auth_service`, `bill_service`, `payment_service`, `post_service`, `support_service`, `notification_service`) calls one of its `encrypt_*` / `decrypt_*` helpers and never touches `app/crypto/` directly. If you want to find "how is X encrypted", start in `crypto_service.py`, then follow the call into `app/crypto/`.

Two application data keys are lazily created the first time they're needed (`_ensure_key`, [crypto_service.py:24](app/services/crypto_service.py#L24)):
- **`govpay-user-data`** — an RSA key, used for every "RSA record" below.
- **`govpay-post-data`** — an ECC key, used for every "ECC record" below.

### 2.1 Registration & login credentials

**Files:** [app/services/auth_service.py](app/services/auth_service.py), [app/main.py](app/main.py) (`/register`, `/login` routes)

- `register_user` ([auth_service.py:11](app/services/auth_service.py#L11)) hashes the password with Argon2id (`hash_password`) and stores only the hash in `users.password_hash`. The plaintext password is never persisted anywhere.
- `authenticate` ([auth_service.py:39](app/services/auth_service.py#L39)) looks the user up by a **blind index** (see §2.7), then calls `verify_password` to check the submitted password against the stored Argon2id hash.
- This is one-factor-then-two-factor: a correct password only gets you to the OTP step (`/otp`), not straight into a session — see §2.2.

### 2.2 OTP two-factor login

**Files:** [app/core/otp_store.py](app/core/otp_store.py), [app/main.py:123-162](app/main.py#L123), [app/services/otp_delivery.py](app/services/otp_delivery.py)

There are actually **two** OTP implementations in the codebase — know which one is live:

- **Persistent / production path** (what `/login` and `/otp` in `main.py` actually use): `remember_issue_persistent` ([otp_store.py:83](app/core/otp_store.py#L83)) writes an `OTPChallenge` row to PostgreSQL containing `code_mac = HMAC(CRYPTO_MAC_SECRET, code)` — **the raw 6-digit code is never written to the database**, only its HMAC digest. `verify_persistent` ([otp_store.py:91](app/core/otp_store.py#L91)) recomputes the HMAC of the submitted code and compares it in constant time (`verify_mac`) against `code_mac`. A 5-minute expiry (`OTP_TTL`) and a 5-attempt lockout (`MAX_OTP_ATTEMPTS`) are both enforced before the row is deleted.
- **In-memory path** ([otp_store.py:16-76](app/core/otp_store.py#L16)): a simpler dict-based version of the same idea (`remember_issue` / `get` / `register_failure`), kept around for `attack_demos.py`'s brute-force demonstration and `tests/`. Not used by the live routes.
- **Delivery**: `deliver_otp` in [otp_delivery.py](app/services/otp_delivery.py) emails the code over SMTP in production. For local development I added a `OTP_DELIVERY_MODE=console` branch ([otp_delivery.py:8-10](app/services/otp_delivery.py#L8)) that only activates when `DEBUG=true`, and prints the code to the server's terminal instead — this is how you've been reading OTPs during local testing. It has no effect in production because `config.py`'s `model_post_init` hard-requires `otp_delivery_mode == "smtp"` whenever `ENVIRONMENT=production`.
- `generate_otp()` ([otp.py:8](app/crypto/otp.py#L8)) is what actually produces the 6-digit string, using `secrets.randbelow` — a CSPRNG, not the general-purpose `random` module.

### 2.3 User profile (username, email, full name, phone, address)

**Files:** [app/services/crypto_service.py:46-60](app/services/crypto_service.py#L46), [app/services/auth_service.py](app/services/auth_service.py), `users` table

- `encrypt_user_profile` bundles all five fields into one dict and calls `encrypt_rsa_record(..., "govpay-user-data")` — one RSA-OAEP envelope holds the whole profile, stored in `users.encrypted_profile`.
- The plaintext columns `users.username`, `.email`, `.full_name`, `.phone`, `.address` are always written as **empty strings** ([auth_service.py:18](app/services/auth_service.py#L18)) — they exist only for schema/legacy compatibility and never hold real data at rest.
- `hydrate_user` ([auth_service.py:48](app/services/auth_service.py#L48)) is called after every load: it decrypts `encrypted_profile` and populates those fields **only on the in-memory SQLAlchemy object** (`set_committed_value`, which does not mark them dirty / does not get written back to the DB). This is why every route that touches `user.email` etc. calls `hydrate_user` first — the ORM columns are a mirage that only exists in memory for the current request.

### 2.4 Blind-index lookups (finding a user by username/email without storing them in plaintext)

**Files:** [app/services/crypto_service.py:46-51](app/services/crypto_service.py#L46)

`user_lookup(username)` / `email_lookup(email)` are `HMAC(CRYPTO_MAC_SECRET, lowercased_trimmed_value)`, stored in the indexed, unique columns `users.username_lookup` / `users.email_lookup`. Because HMAC is deterministic for a fixed key, `WHERE username_lookup = HMAC(secret, "admin")` can find the row by exact match **without** the database ever storing or indexing the plaintext username — this is what lets `authenticate` and `register_user` do exact-match SQL lookups against encrypted data (something a real ciphertext, which is randomized per-encryption via OAEP/ElGamal, could never support).

### 2.5 Bills, Payments, Notifications (RSA records)

**Files:** [app/services/bill_service.py](app/services/bill_service.py), [app/services/payment_service.py](app/services/payment_service.py), [app/services/notification_service.py](app/services/notification_service.py), [crypto_service.py:103-132](app/services/crypto_service.py#L103)

All three follow the identical pattern, each with its own thin wrapper in `crypto_service.py`:

- `encrypt_bill_data` → RSA envelope of `{bill_type, title, description, amount, due_date}` → `bills.encrypted_data`.
- `encrypt_payment_data` → RSA envelope of `{amount, payment_method, transaction_reference, payment_date}` → `payments.encrypted_data`.
- `encrypt_notification_data` → RSA envelope of `{title, message, link}` → `notifications.encrypted_content`.

Just like profiles, the corresponding plaintext columns (`bills.title`, `payments.amount`, `notifications.message`, etc.) are written empty/`None` at creation time, and a `hydrate_bill` / `hydrate_payment` / `hydrate_notification` function decrypts back into the in-memory object on every read (e.g. [bill_service.py:31](app/services/bill_service.py#L31), [payment_service.py:38](app/services/payment_service.py#L38), [notification_service.py:29](app/services/notification_service.py#L29)).

### 2.6 Payment proof — the one feature that uses **both** algorithms

**Files:** [app/services/payment_service.py](app/services/payment_service.py), [app/main.py:217-282](app/main.py#L217), [crypto_service.py:119-124](app/services/crypto_service.py#L119)

This is worth calling out separately because it's the only feature that mixes RSA and ECC for one logical object:

- The **metadata** — copied bill text, the stored image's filename, and the admin's review note — goes through `encrypt_proof_data` → `encrypt_rsa_data` (RSA envelope) → `payment_verifications.encrypted_proof`.
- The **image file itself**, if the citizen uploads a screenshot, is encrypted differently: `main.py`'s `make_payment` route reads the uploaded bytes and calls `encrypt_ecc_bytes` ([main.py:237](app/main.py#L237)) — an **ECC-ElGamal envelope over raw bytes** (`GovPayCrypto.encrypt_ecc_bytes`, [envelope.py:97](app/crypto/envelope.py#L97)) — and writes the resulting JSON envelope as a `.enc` text file under `app/private_uploads/payment_proofs/`, **outside** the `app/static/` tree that FastAPI serves publicly. A route matching `/static/uploads/{path}` is explicitly blocked ([main.py:43](app/main.py#L43)) as defense in depth in case a legacy public path is ever guessed.
- Downloading a proof image (`GET /payment-proofs/{payment_id}`, [main.py:261](app/main.py#L261)) checks the requester owns the payment or is an Admin, reads the `.enc` file, decrypts it with `decrypt_ecc_bytes`, and streams the raw bytes back with the correct `media_type` — the decrypted image is never written back to disk.

### 2.7 Posts and Support conversations (ECC records)

**Files:** [app/services/post_service.py](app/services/post_service.py), [app/services/support_service.py](app/services/support_service.py), [crypto_service.py:63-68](app/services/crypto_service.py#L63) and [crypto_service.py:135-148](app/services/crypto_service.py#L135)

- `encrypt_post` → ECC envelope of `{title, content}` → `posts.encrypted_content` (`govpay-post-data` key). `hydrate_post` decrypts it back on read.
- `encrypt_support_subject` / `encrypt_support_message` are each their own single-field ECC envelope → `support_conversations.encrypted_subject` and `support_messages.encrypted_content` respectively.
- Same "plaintext columns stay empty, hydrate-on-read" pattern as everything above.

### 2.8 Session cookies, CSRF, and server-side session revocation

These aren't in `app/crypto/`, but they're the other half of "how a login stays a login" — worth knowing about alongside the OTP flow:

- **Signed session cookie**: `SessionMiddleware` ([main.py:40](app/main.py#L40)) is Starlette's `itsdangerous`-based cookie signer, keyed by `SESSION_SECRET_KEY`. It's tamper-evident (a modified cookie fails signature verification and is discarded), not encrypted — don't put secrets you don't want the browser to see into `request.session`.
- **CSRF tokens**: `csrf_token` / `validate_csrf` ([app/core/security.py:19-30](app/core/security.py#L19)) generate a random per-session token (`secrets.token_urlsafe(32)`) and compare submissions with `hmac.compare_digest` (constant-time, to avoid timing attacks on the comparison itself). Every state-changing form in the templates carries this as a hidden field.
- **Server-side session revocation**: the signed cookie only proves "this session id was issued by us" — it says nothing about whether it's still valid. `AuthSessionRecord` rows ([app/models/entities.py:183](app/models/entities.py#L183)) are the actual source of truth: `create_persistent_auth_session` / `is_persistent_auth_session_valid` / `revoke_persistent_auth_session` ([app/core/sessions.py:35-60](app/core/sessions.py#L35)) let `/logout` immediately invalidate a session server-side even though the browser still holds a validly-signed cookie for it.

---

## 3. Proving the controls work — `app/crypto/attack_demos.py`

Each function in this file is a small, runnable "attack" against one control, returning whether it was blocked:

| Demo | What it does | What should happen |
| --- | --- | --- |
| `demonstrate_hmac_forgery` | Modifies a signed message | HMAC verification fails |
| `demonstrate_envelope_metadata_tampering` | Edits `key_id` inside an envelope | Rejected before key lookup even happens |
| `demonstrate_rsa_oaep_malleability` | Flips one bit of an RSA ciphertext | OAEP padding check fails |
| `demonstrate_rsa_wrong_key` | Decrypts with an unrelated private key | Fails/garbage rejected |
| `demonstrate_ecc_invalid_point` | Encrypts to an off-curve "public key" | Rejected before encryption |
| `demonstrate_ecc_ciphertext_structure_attack` | Feeds a malformed/infinity point | Rejected during decode |
| `demonstrate_otp_bruteforce` | Hammers one OTP past `MAX_OTP_ATTEMPTS` | Record destroyed, no further guesses possible |
| `demonstrate_session_replay` | Reuses a session id after logout | Rejected — revocation persists |

Run them all from a Python shell in the project venv:

```powershell
.venv\Scripts\python.exe -c "from app.crypto.attack_demos import run_all_attack_demonstrations; [print(r) for r in run_all_attack_demonstrations()]"
```

`tests/test_crypto.py` also exercises these paths as part of the automated `pytest` suite.

---

## 4. Quick lookup — "I want to see how X is protected"

| Feature | Algorithm | Encrypt/decrypt call | Storage column |
| --- | --- | --- | --- |
| Password | Argon2id (hash, not encryption) | `hash_password` / `verify_password` | `users.password_hash` |
| Username/email exact-match search | HMAC-SHA256 (blind index) | `user_lookup` / `email_lookup` | `users.username_lookup`, `users.email_lookup` |
| User profile (name/email/phone/address) | RSA-OAEP | `encrypt_user_profile` / `decrypt_user_profile` | `users.encrypted_profile` |
| Login OTP code | HMAC-SHA256 (never stored raw) | `remember_issue_persistent` / `verify_persistent` | `otp_challenges.code_mac` |
| Bill details | RSA-OAEP | `encrypt_bill_data` / `decrypt_bill_data` | `bills.encrypted_data` |
| Payment details | RSA-OAEP | `encrypt_payment_data` / `decrypt_payment_data` | `payments.encrypted_data` |
| Payment proof text/filename/note | RSA-OAEP | `encrypt_proof_data` / `decrypt_proof_data` | `payment_verifications.encrypted_proof` |
| Payment proof **image file** | ECC-ElGamal (byte envelope) | `encrypt_ecc_bytes` / `decrypt_ecc_bytes` | file on disk under `app/private_uploads/payment_proofs/*.enc` |
| Notifications | RSA-OAEP | `encrypt_notification_data` / `decrypt_notification_data` | `notifications.encrypted_content` |
| Posts | ECC-ElGamal | `encrypt_post` / `decrypt_post` | `posts.encrypted_content` |
| Support subject | ECC-ElGamal | `encrypt_support_subject` / `decrypt_support_subject` | `support_conversations.encrypted_subject` |
| Support message | ECC-ElGamal | `encrypt_support_message` / `decrypt_support_message` | `support_messages.encrypted_content` |
| Envelope integrity (all of the above) | HMAC-SHA256 | `GovPayCrypto._wrap` / `_unwrap` | the `"mac"` field inside every envelope JSON |
| KMS private keys at rest | RSA-OAEP (key-wrapping) | `KeyManagementModule._save` / `_load` | `.govpay-kms.json` |
| Session cookie | Signed (itsdangerous), not encrypted | `SessionMiddleware` | the `session` cookie |
| CSRF token | Random token + constant-time compare | `csrf_token` / `validate_csrf` | `request.session["csrf_token"]` |
