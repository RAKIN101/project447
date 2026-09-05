# GovPay

GovPay is a Python-only FastAPI/Jinja2 prototype for government utility bill payments. It includes citizen accounts, OTP sign-in, bill management, prototype payments, receipts, posts, helpdesk conversations, and admin views.

Bills are displayed in Bangladeshi Taka (BDT). Admins can issue Electricity, Water, Gas, Waste, or Property Tax bills either to one citizen or globally to every active citizen. Citizens submit copied bill text or an image/screenshot as payment proof; admins approve or reject the proof and citizens receive in-app notifications.

The CSE447 crypto module provides educational from-scratch RSA and ECC encryption, HMAC integrity, Argon2id password hashing, OTP verification, RBAC, signed sessions, and a versioned KMS. User/profile data and posts are encrypted before PostgreSQL persistence and decrypted on retrieval. Passwords remain one-way hashes rather than encrypted values.

## Technology

- Python 3.11+
- FastAPI and Uvicorn
- SQLAlchemy with PostgreSQL through Psycopg
- Jinja2 server-rendered templates
- Argon2id password hashing through `argon2-cffi`
- pytest

## Setup

1. Create a PostgreSQL database and account:

```sql
CREATE USER govpay_user WITH PASSWORD 'change-this';
CREATE DATABASE govpay OWNER govpay_user;
GRANT ALL PRIVILEGES ON DATABASE govpay TO govpay_user;
```

2. Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

3. Copy `.env.example` to `.env` and set the PostgreSQL connection string:

```text
DATABASE_URL=postgresql+psycopg://govpay_user:your-password@127.0.0.1:5432/govpay
APP_SECRET_KEY=use-a-long-random-value
SESSION_SECRET_KEY=use-a-different-long-random-value
CRYPTO_MAC_SECRET=use-a-third-long-random-value
KMS_WRAP_PUBLIC_KEY_JSON={"n":...,"e":65537}
KMS_WRAP_PRIVATE_KEY_JSON={"n":...,"d":...,"e":65537}
OTP_DELIVERY_MODE=smtp
SMTP_HOST=smtp.example.gov
SMTP_PORT=587
SMTP_USERNAME=your-smtp-user
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=govpay@example.gov
```

4. Seed demo data:

```powershell
python scripts/seed_database.py
```

For an existing PostgreSQL database, apply the encrypted-storage migration once:

```powershell
python -m scripts.migrate_encrypted_storage
```

## Run

```powershell
python run.py
```

Open http://127.0.0.1:8000. FastAPI documentation is at http://127.0.0.1:8000/docs.

## Demo accounts

All seeded demo accounts use the password printed by the seed command: `GovPayDemo!447`.

- `admin` - Admin role
- `government` - Government role
- `citizen1`, `citizen2`, `citizen3` - Citizen roles

The OTP is generated per login, delivered through configured SMTP, expires after five minutes, is single-use, and is protected by issuance and attempt limits. OTP values are never written to logs.

## Features and routes

Public: `/`, `/register`, `/login`, `/otp`.

Citizens: `/dashboard`, `/bills`, `/bills/{id}`, `/payments`, `/payments/{bill_id}`, `/payments/receipt/{id}`, `/profile`, `/posts`, `/support`, `/support/{id}`.

Admins: `/admin`, `/admin/users`, `/admin/payments`, `/admin/support`, plus post moderation through `/posts`.

Admin billing: `/admin/bills` creates individual or global bills. Payment review: `/admin/verifications` approves or rejects citizen proof. Notifications: `/notifications`.

Authentication uses a signed, expiring session cookie backed by a server-side session registry with logout revocation. Pending OTP values are held server-side in memory. Role checks happen in route handlers and ownership checks restrict bills, posts, support conversations, and proof downloads to their owners. State-changing browser forms use CSRF tokens.

User/profile, bill, payment, payment-proof, and notification records use RSA encrypted envelopes; post and support records use ECC encrypted envelopes. HMAC authenticates all envelopes and lookup indexes. Proof files are encrypted outside the public static tree and served only through authorized downloads. Envelope key versions support KMS rotation and decryption of prior versions; revoked keys cannot decrypt data. Run the migration command once for existing PostgreSQL data.
Production KMS records require RSA wrapping keys from a deployment secret manager; the local JSON backend is for the assignment and development only.

## Architecture

Routers are represented by the FastAPI route layer in `app/main.py`; business operations live in `app/services/`; SQLAlchemy entities are in `app/models/`; validation schemas are in `app/schemas/`; cryptographic persistence operations are centralized in `app/services/crypto_service.py`.

## Testing

The included tests cover password hashing, registration validation, encrypted user/profile and post persistence, bill ownership, overdue handling, payment state changes, envelope tampering, KMS rotation, and revocation. They use an isolated in-memory SQLite database for test execution, so running the test suite does not require a PostgreSQL server:

```powershell
pytest
```

The application itself remains configured for PostgreSQL and does not silently use SQLite in production.
