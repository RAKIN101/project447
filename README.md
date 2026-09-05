# GovPay

GovPay is a Python-only FastAPI/Jinja2 prototype for government utility bill payments. It includes citizen accounts, OTP sign-in, bill management, prototype payments, receipts, posts, helpdesk conversations, and admin views.

Bills are displayed in Bangladeshi Taka (BDT). Admins can issue Electricity, Water, Gas, Waste, or Property Tax bills either to one citizen or globally to every active citizen. Citizens submit copied bill text or an image/screenshot as payment proof; admins approve or reject the proof and citizens receive in-app notifications.

> Cryptographic functionality will be implemented in a later development phase. This phase intentionally does not implement RSA, ECC, HMAC, AES/Fernet, encryption, KMS, key rotation, or cryptoanalysis.

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
```

4. Seed demo data:

```powershell
python scripts/seed_database.py
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

The OTP is generated per login, expires after five minutes, and is printed to the development server log. It is not a permanent hard-coded OTP.

## Features and routes

Public: `/`, `/register`, `/login`, `/otp`.

Citizens: `/dashboard`, `/bills`, `/bills/{id}`, `/payments`, `/payments/{bill_id}`, `/payments/receipt/{id}`, `/profile`, `/posts`, `/support`, `/support/{id}`.

Admins: `/admin`, `/admin/users`, `/admin/payments`, `/admin/support`, plus post moderation through `/posts`.

Admin billing: `/admin/bills` creates individual or global bills. Payment review: `/admin/verifications` approves or rejects citizen proof. Notifications: `/notifications`.

Authentication is a signed session cookie containing only an authenticated user id. Pending OTP values are held server-side in memory. Role checks happen in route handlers and ownership checks restrict bills, posts, and support conversations to their owners.

## Architecture

Routers are represented by the FastAPI route layer in `app/main.py`; business operations live in `app/services/`; SQLAlchemy entities are in `app/models/`; validation schemas are in `app/schemas/`. Future cryptographic services can be introduced between services and persistence without changing the browser routes.

## Testing

The included tests cover password hashing, registration validation, bill ownership, overdue handling, and payment state changes. They use an isolated in-memory SQLite database for test execution, so running the test suite does not require a PostgreSQL server:

```powershell
pytest
```

The application itself remains configured for PostgreSQL and does not silently use SQLite in production.
