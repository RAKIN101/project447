# GovPay Feature Guide

An overview of every feature in GovPay: what it is, how it's implemented, and
how to actually use it while the app is running. For a deep dive into the
cryptography specifically (algorithms, math, envelope format, key
management), see **[CRYPTO_GUIDE.md](CRYPTO_GUIDE.md)** — this document
covers *every* feature and only summarizes the crypto side, linking out to
that file for detail.

**Stack:** FastAPI + Jinja2 server-rendered templates, SQLAlchemy over
PostgreSQL, Argon2id passwords, from-scratch RSA/ECC encryption. No
JavaScript framework — every feature is a normal HTML form POST.

**Roles:** `Citizen` (default signup role), `Government` (elevated but not
admin), `Admin` (full control). Enforced by
[app/core/dependencies.py](app/core/dependencies.py) and the `require_role`
helper in [app/main.py:84](app/main.py#L84).

**Demo accounts** (password `GovPayDemo!447` for all): `admin`, `government`,
`citizen1`, `citizen2`, `citizen3` — created by
[scripts/seed_database.py](scripts/seed_database.py).

---

## 1. Registration

**What it is:** Public self-signup, always creates a `Citizen` account.

**How it works:** `POST /register` ([main.py:105](app/main.py#L105)) validates
input with `RegistrationInput` ([app/schemas/user.py](app/schemas/user.py) —
full name 2-120 chars, username 3-50 chars, a real email address, password
8-128 chars), then `register_user`
([app/services/auth_service.py:11](app/services/auth_service.py#L11)):
hashes the password with **Argon2id**, computes **HMAC blind-index** values
for username/email (so they can be looked up later without ever storing them
in plaintext), and **RSA-encrypts** the whole profile (name/email/phone/
address) into one envelope stored in `users.encrypted_profile`. Duplicate
username or email (matched via the blind index) is rejected before any of
that happens.

**How to use it:**
1. Go to `/register`.
2. Fill in full name, username, email, phone (optional), address (optional),
   password, confirm password.
3. Submit → redirected to `/login?registered=1`.
4. New accounts are always `Citizen` role — only an Admin can create
   Government or Admin accounts (see §14).

---

## 2. Login + OTP two-factor authentication

**What it is:** Username+password, followed by a mandatory 6-digit one-time
code, before a session is ever created.

**How it works:**
- `POST /login` ([main.py:123](app/main.py#L123)) calls `authenticate`
  (looks the user up by the HMAC blind index, verifies the Argon2id hash).
- On success, a random 6-digit OTP is generated (`generate_otp`, CSPRNG-based)
  and **only its HMAC digest** is stored server-side (`OTPChallenge.code_mac`
  in PostgreSQL) — the raw code is never persisted. It's rate-limited (max 5
  issuances per 5 minutes) and expires after 5 minutes.
- Delivery: in production this emails the code over SMTP
  ([app/services/otp_delivery.py](app/services/otp_delivery.py)). **For this
  local setup**, `OTP_DELIVERY_MODE=console` in `.env` prints the code to the
  terminal running `uvicorn` instead (dev-only, gated by `DEBUG=true`).
- `POST /otp` ([main.py:147](app/main.py#L147)) verifies the code
  (constant-time HMAC compare, 5-attempt lockout), then creates a real
  session: a DB-backed `AuthSessionRecord` plus a signed session cookie.
- See [CRYPTO_GUIDE.md §2.1–2.2](CRYPTO_GUIDE.md#21-registration--login-credentials) for the full crypto trace.

**How to use it:**
1. Go to `/login`, enter username + password.
2. You're redirected to `/otp`.
3. **Read the OTP from the server's terminal** — it prints as
   `[GovPay dev OTP] <email>: <code>`.
4. Enter the 6-digit code → redirected to `/dashboard` (or `/admin` if the
   account is an Admin).

---

## 3. Session, logout, and CSRF protection

**What it is:** How you stay logged in, how logout actually revokes access,
and how forms are protected from cross-site forgery.

**How it works:**
- The browser holds a **signed** (not encrypted) session cookie
  (`itsdangerous`, via Starlette's `SessionMiddleware`,
  [main.py:40](app/main.py#L40)), keyed by `SESSION_SECRET_KEY`. It just
  proves the cookie wasn't tampered with — it does **not** by itself prove
  the session is still valid.
- The actual source of truth is the `auth_sessions` table
  ([app/core/sessions.py](app/core/sessions.py)). Every authenticated request
  re-checks `is_persistent_auth_session_valid`, so `POST /logout`
  ([main.py:165](app/main.py#L165)) can immediately invalidate a session
  server-side even if the browser still presents a validly-signed cookie.
- Every state-changing form (login, register, post, payment, admin actions,
  …) carries a hidden `csrf_token` field, generated per-session
  (`app/core/security.py`) and checked with a constant-time comparison.
  Submitting a form without a valid token gets a `403`.

**How to use it:** Nothing to do manually — this runs on every page. Click
"Logout" in the nav to end your session immediately (both server-side and
client-side).

---

## 4. Dashboard

**What it is:** The citizen/government landing page after login, showing
bill stats and recent payments.

**How it works:** `GET /dashboard` ([main.py:173](app/main.py#L173)) redirects
Admins to `/admin` automatically. For everyone else it lists the user's
bills (auto-flagging overdue ones — see §5), takes the 5 most recent
payments, and computes simple counts (total/pending/paid/overdue).

**How to use it:** Land here automatically after OTP verification, or click
"Dashboard" in the nav.

---

## 5. Bills

**What it is:** The utility bills (Electricity, Water, Gas, Waste, Property
Tax) issued to a citizen.

**How it works:** [app/services/bill_service.py](app/services/bill_service.py)
stores bill type/title/description/amount/due-date as one **RSA-encrypted**
envelope in `bills.encrypted_data`; every read decrypts it back
(`hydrate_bill`). `refresh_overdue` flips a `Pending` bill to `Overdue` on
read once its due date has passed. Bills are only ever created by an Admin
(§15) — citizens can't create their own bills.

**How to use it:**
1. `/bills` — list your bills, optionally filtered by status
   (`?status_filter=Pending|Paid|Overdue`).
2. `/bills/{id}` — bill detail, with a "Pay now" link if unpaid.

---

## 6. Payments (submit for review)

**What it is:** A citizen pays a bill by submitting proof of payment (copied
bill text and/or a screenshot); an admin later approves or rejects it. There
is **no instant/automatic payment success path** in the live app — every
payment starts `Pending` and needs admin review (an instant-success helper,
`create_payment`, exists in the service layer but is only exercised by the
test suite, not by any route).

**How it works:** `POST /payments/{bill_id}`
([main.py:217](app/main.py#L217)) validates the payment method against a
fixed set (`Mobile Banking` / `Card` / `Bank Transfer`), requires at least
proof text or a proof image, and calls `submit_payment_for_review`
([app/services/payment_service.py:61](app/services/payment_service.py#L61)):
- Creates a `Payment` row (status `Pending`) with amount/method/reference
  **RSA-encrypted** into `payments.encrypted_data`.
- Creates a `PaymentVerification` row with the proof text/filename/reviewer
  note **RSA-encrypted** into `encrypted_proof`.
- Notifies every Admin (see §10).

**How to use it:**
1. From a bill detail page (or `/payments/{bill_id}` directly), choose a
   payment method.
2. Paste the bill text you were asked to copy, and/or upload a screenshot
   (PNG/JPG/JPEG/WEBP, ≤5 MB).
3. Submit → redirected to `/payments?submitted=1`, status shows `Pending`
   until an admin reviews it (§17).

---

## 7. Payment proof image storage & download

**What it is:** The uploaded screenshot itself, handled completely
differently from the proof metadata — it's the one feature that mixes both
encryption algorithms for one logical record.

**How it works:** The uploaded bytes are **ECC-encrypted**
(`encrypt_ecc_bytes`, [main.py:237](app/main.py#L237)) and written as a
`.enc` file under `app/private_uploads/payment_proofs/` — **outside** the
publicly-served `app/static/` tree. `GET /payment-proofs/{payment_id}`
([main.py:261](app/main.py#L261)) checks you own the payment (or are an
Admin), decrypts the file in memory, and streams the image back — the
decrypted image is never written to disk. See
[CRYPTO_GUIDE.md §2.6](CRYPTO_GUIDE.md#26-payment-proof--the-one-feature-that-uses-both-algorithms).

**How to use it:** The image (if you uploaded one) appears automatically
wherever a payment's proof is shown (your `/payments` list, the admin
verification queue). There's no separate "download" button to look for — the
`<img>` tag's `src` points straight at the authenticated route.

---

## 8. Receipts

**What it is:** A confirmation page for an approved/completed payment.

**How it works:** `GET /payments/receipt/{payment_id}`
([main.py:251](app/main.py#L251)) loads the payment (owned by you), decrypts
it, and renders `receipt.html`.

**How to use it:** Click through from `/payments`, or follow the link in the
"Payment verified" notification you get when an admin approves your proof.

---

## 9. Profile

**What it is:** View/edit your own name, phone, and address (username and
email are fixed at registration).

**How it works:** `POST /profile` ([main.py:290](app/main.py#L290))
re-encrypts the whole profile record (full name, phone, address — plus the
unchanged username/email) into a fresh RSA envelope and overwrites
`encrypted_profile`.

**How to use it:** `/profile` → edit the editable fields → Save → redirected
to `/profile?saved=1`.

---

## 10. Notifications

**What it is:** In-app messages about bills issued, payments approved/
rejected, and support replies.

**How it works:** [app/services/notification_service.py](app/services/notification_service.py)
creates a `Notification` row with title/message/link **RSA-encrypted** into
`encrypted_content`. `notify_admins` fans one out to every active Admin (used
when a citizen submits a payment for review). The nav bar's unread badge
count is computed in `context()` ([main.py:57](app/main.py#L57)) on every
page load.

**How to use it:** `/notifications` lists them newest-first; the nav badge
shows how many are unread.

---

## 11. Posts (community board)

**What it is:** A shared feed — anyone logged in can read every post, but
can only edit/delete their own (Admins can moderate/delete any post).

**How it works:** [app/services/post_service.py](app/services/post_service.py)
**ECC-encrypts** title+content into `posts.encrypted_content`
(`govpay-post-data` key — a different key than the RSA one protecting
profiles/bills). Ownership is enforced in `main.py`'s edit/delete routes
(`post.user_id != user.id and user.role != UserRole.ADMIN` → `403`).

**How to use it:**
1. `/posts` — read the feed.
2. `/posts/create` — title (3-160 chars) + content (1-5000 chars) → posted
   immediately, no moderation queue.
3. Edit/delete your own posts from the feed (Admins can moderate any post).

---

## 12. Support / helpdesk conversations

**What it is:** A citizen-to-admin ticket/chat thread.

**How it works:** [app/services/support_service.py](app/services/support_service.py)
**ECC-encrypts** the subject and each message independently (so an admin
replying doesn't need to re-encrypt the whole thread). A conversation is
`Open` or `Closed`; only an Admin can change that status
(`require_role(..., UserRole.ADMIN)` on `POST /support/{id}/status`,
[main.py:411](app/main.py#L411)).

**How to use it:**
1. `/support` — start a new conversation (subject 3-160 chars, message
   1-5000 chars) or see your existing ones.
2. `/support/{id}` — the thread view; post more messages with the same box.
3. Only you (the opener) or an Admin can view/reply to a given thread.

---

## 13. Admin dashboard

**What it is:** Landing page for Admins, with portal-wide counters.

**How it works:** `GET /admin` ([main.py:424](app/main.py#L424)) — total
users, bills, payments, successful payments, and open support tickets, via
plain SQL `COUNT`s (these counters don't need decryption since they're just
counts, not content).

**How to use it:** Admins are redirected here automatically from
`/dashboard`; everyone else gets `403`.

---

## 14. Admin: manage users

**What it is:** Create new accounts of any role (including Government/Admin,
unlike public `/register` which is Citizen-only), and deactivate/delete
users.

**How it works:** `POST /admin/users` ([main.py:468](app/main.py#L468)) reuses
`RegistrationInput`/`register_user` but accepts `role` from the form.
`POST /admin/users/{id}/delete` ([main.py:480](app/main.py#L480)) cascades
through `delete_user` ([auth_service.py:25](app/services/auth_service.py#L25)),
removing the user's support conversations, payments, bills, and posts in one
transaction. An admin cannot delete their own account.

**How to use it:** `/admin/users` — the "create user" form lets you pick a
role; the user list has a delete action per row.

---

## 15. Admin: issue bills

**What it is:** Admins create bills either for one citizen or broadcast to
every active citizen at once.

**How it works:** `POST /admin/bills` ([main.py:444](app/main.py#L444)) →
`create_bill` ([bill_service.py:48](app/services/bill_service.py#L48))
validates the bill type is one of the five fixed categories, builds one
**RSA-encrypted** bill row per targeted citizen, and fires a "New bill
available" notification to each of them.

**How to use it:** `/admin/bills` — pick bill type, title, description,
amount (BDT), due date, and scope (`individual` + pick a citizen, or
`global` for everyone).

---

## 16. Admin: view all payments

**What it is:** A read-only ledger of every payment across all citizens.

**How it works:** `GET /admin/payments` ([main.py:493](app/main.py#L493))
lists and decrypts every `Payment` (`list_payments` with no `user_id`
filter) plus the paying user's identity.

**How to use it:** `/admin/payments`.

---

## 17. Admin: payment proof verification

**What it is:** The approve/reject step that actually marks a bill Paid.

**How it works:** `GET /admin/verifications` ([main.py:508](app/main.py#L508))
lists every `Pending` payment; `POST /admin/verifications/{payment_id}`
([main.py:525](app/main.py#L525)) → `review_payment`
([payment_service.py:76](app/services/payment_service.py#L76)):
- **Approve** → payment `Successful`, bill `Paid`, citizen gets a "Payment
  verified" notification linking to their receipt.
- **Reject** → payment `Failed`, citizen gets a notification with the
  reviewer's note and a link back to retry payment.
- Either way, the reviewer's note is folded back into the same
  **RSA-encrypted** proof envelope (`encrypted_proof`) alongside the
  original proof text/filename.
- A payment can only be reviewed once (`VerificationStatus.PENDING` check).

**How to use it:** `/admin/verifications` → open a pending item → view the
citizen's proof text/image (decrypted for display, see §7) → Approve or
Reject with an optional note.

---

## 18. Admin: support moderation

**What it is:** See every citizen's support thread and close resolved ones.

**How it works:** `GET /admin/support` ([main.py:502](app/main.py#L502)) lists
every conversation (no `user_id` filter, unlike the citizen-facing
`/support`). Status changes go through the same `POST /support/{id}/status`
endpoint used elsewhere, gated to Admin only.

**How to use it:** `/admin/support` → click into a thread (reuses
`/support/{id}`) → reply or mark it Closed.

---

## 19. Role-based access control (RBAC)

**What it is:** The rule layer deciding who can see/do what.

**How it works:** [app/core/dependencies.py](app/core/dependencies.py) defines
`require_admin`, `require_citizen`, `require_government` (Government routes
also accept Admin) as FastAPI dependencies for potential router-based use;
`app/main.py` currently implements the same checks inline via its own
`current_user` / `require_role` helpers ([main.py:72](app/main.py#L72)).
Ownership checks (bills, posts, support threads, payment proofs) are
additionally enforced per-record — role alone doesn't imply you can see
someone else's data unless you're an Admin.

**How to use it:** Nothing to configure — just note that every role
(`Citizen`, `Government`, `Admin`) sees a different nav/feature set
automatically based on the logged-in account.

---

## 20. Key Management (KMS) & key rotation

**What it is:** The mechanism behind every encryption feature above — not a
page you visit, but worth knowing where it lives.

**How it works:** [app/crypto/kms.py](app/crypto/kms.py) auto-generates two
long-lived keys the first time the app runs: `govpay-user-data` (RSA — backs
every feature in §1, §5, §6, §7's metadata, §9, §10, §17) and
`govpay-post-data` (ECC — backs §7's image file, §11, §12). They're persisted
to `.govpay-kms.json` (path from `KMS_PATH` in `.env`), optionally wrapped at
rest by a separate RSA "key-encrypting key" pair
(`KMS_WRAP_PUBLIC_KEY`/`KMS_WRAP_PRIVATE_KEY`). Full detail, including
rotation/revocation semantics, is in
[CRYPTO_GUIDE.md §1.6](CRYPTO_GUIDE.md#16-key-management-module-kms--appcryptokmspy).

**How to use it:** No UI for this — it's operational, not a citizen/admin
feature. If you ever need to rotate a key, that's a Python call
(`KeyManagementModule.rotate("govpay-user-data")`), not a route.

---

## 21. Data migration scripts

**What it is:** One-off scripts for moving data, not features you interact
with while the app runs.

**How it works:**
- [scripts/seed_database.py](scripts/seed_database.py) — creates the demo
  accounts/bills/posts/support ticket described at the top of this doc. Safe
  to re-run (it no-ops if `admin` already exists).
- [scripts/migrate_encrypted_storage.py](scripts/migrate_encrypted_storage.py) —
  a one-time upgrade path for a PostgreSQL database that predates the
  encrypted-column model: adds the new encrypted columns/tables, encrypts any
  existing plaintext rows in place, moves any legacy public proof-image files
  into the private encrypted store, and blanks the old plaintext columns.
- [scripts/migrate_legacy_sqlite.py](scripts/migrate_legacy_sqlite.py) —
  imports data from an older SQLite-based version of the app into the current
  PostgreSQL schema.

**How to use it:** `python -m scripts.<name>` from the project root (needs
the venv active and `.env` configured, same as running the app).

---

## 22. Automated tests

**What it is:** `pytest` coverage for password hashing, registration
validation, encrypted persistence, bill ownership, overdue handling, payment
state transitions, envelope tampering, KMS rotation/revocation, and the
attack demonstrations (§ below).

**How it works:** Tests run against an isolated in-memory SQLite database, so
`pytest` does **not** need PostgreSQL running.

**How to use it:**
```powershell
.venv\Scripts\Activate.ps1
pytest
```

---

## 23. Cryptoanalysis attack demonstrations

**What it is:** Runnable proof that each crypto control actually rejects the
attack it's meant to reject (HMAC forgery, envelope tampering, RSA/ECC
ciphertext manipulation, OTP brute force, session replay after logout).

**How it works / how to use it:** See
[CRYPTO_GUIDE.md §3](CRYPTO_GUIDE.md#3-proving-the-controls-work--appcryptoattack_demospy)
for the full list and the one-line command to run them all.

---

## 24. Health check

**What it is:** A trivial unauthenticated endpoint for uptime checks.

**How to use it:** `GET /api/health` → `{"status": "ok", "service": "GovPay"}`.
