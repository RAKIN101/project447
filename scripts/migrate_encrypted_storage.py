"""Encrypt existing PostgreSQL user/profile and post rows in place.

Run once after deploying the encrypted model columns:
    python -m scripts.migrate_encrypted_storage
"""

from sqlalchemy import text
from pathlib import Path

from app.core.database import SessionLocal, engine
from app.models import Bill, Notification, Payment, PaymentVerification, Post, SupportConversation, SupportMessage, User
from app.services.auth_service import hydrate_user
from app.services.crypto_service import email_lookup, encrypt_user_profile, user_lookup
from app.services.crypto_service import encrypt_bill_data, encrypt_ecc_bytes, encrypt_notification_data, encrypt_payment_data, encrypt_proof_data, encrypt_support_message, encrypt_support_subject
from app.services.post_service import encrypt_post


DDL = (
    "CREATE TABLE IF NOT EXISTS auth_sessions (session_id VARCHAR(128) PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at TIMESTAMP NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    "CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_id ON auth_sessions (user_id)",
    "CREATE TABLE IF NOT EXISTS otp_challenges (session_id VARCHAR(128) PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), code_mac VARCHAR(128) NOT NULL, expires_at TIMESTAMP NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    "CREATE INDEX IF NOT EXISTS ix_otp_challenges_user_id ON otp_challenges (user_id)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS username_lookup VARCHAR(100)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_lookup VARCHAR(100)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_profile TEXT",
    "ALTER TABLE posts ADD COLUMN IF NOT EXISTS encrypted_content TEXT",
    "ALTER TABLE bills ADD COLUMN IF NOT EXISTS encrypted_data TEXT",
    "ALTER TABLE payments ADD COLUMN IF NOT EXISTS encrypted_data TEXT",
    "ALTER TABLE payment_verifications ADD COLUMN IF NOT EXISTS encrypted_proof TEXT",
    "ALTER TABLE notifications ADD COLUMN IF NOT EXISTS encrypted_content TEXT",
    "ALTER TABLE support_conversations ADD COLUMN IF NOT EXISTS encrypted_subject TEXT",
    "ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS encrypted_content TEXT",
    "ALTER TABLE users ALTER COLUMN username DROP NOT NULL",
    "ALTER TABLE users ALTER COLUMN email DROP NOT NULL",
    "ALTER TABLE users ALTER COLUMN full_name DROP NOT NULL",
    "ALTER TABLE users ALTER COLUMN phone DROP NOT NULL",
    "ALTER TABLE users ALTER COLUMN address DROP NOT NULL",
    "ALTER TABLE posts ALTER COLUMN title DROP NOT NULL",
    "ALTER TABLE posts ALTER COLUMN content DROP NOT NULL",
    "ALTER TABLE bills ALTER COLUMN title DROP NOT NULL",
    "ALTER TABLE bills ALTER COLUMN description DROP NOT NULL",
    "ALTER TABLE bills ALTER COLUMN amount DROP NOT NULL",
    "ALTER TABLE bills ALTER COLUMN bill_type DROP NOT NULL",
    "ALTER TABLE bills ALTER COLUMN due_date DROP NOT NULL",
    "ALTER TABLE payments ALTER COLUMN amount DROP NOT NULL",
    "ALTER TABLE payments ALTER COLUMN payment_method DROP NOT NULL",
    "ALTER TABLE payments ALTER COLUMN transaction_reference DROP NOT NULL",
    "ALTER TABLE payments ALTER COLUMN payment_date DROP NOT NULL",
    "ALTER TABLE payment_verifications ALTER COLUMN proof_text DROP NOT NULL",
    "ALTER TABLE payment_verifications ALTER COLUMN proof_image_path DROP NOT NULL",
    "ALTER TABLE payment_verifications ALTER COLUMN reviewer_note DROP NOT NULL",
    "ALTER TABLE notifications ALTER COLUMN title DROP NOT NULL",
    "ALTER TABLE notifications ALTER COLUMN message DROP NOT NULL",
    "ALTER TABLE notifications ALTER COLUMN link DROP NOT NULL",
    "ALTER TABLE support_conversations ALTER COLUMN subject DROP NOT NULL",
    "ALTER TABLE support_messages ALTER COLUMN message DROP NOT NULL",
    "ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_key",
    "ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key",
    "DROP INDEX IF EXISTS ix_users_username",
    "DROP INDEX IF EXISTS ix_users_email",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username_lookup ON users (username_lookup) WHERE username_lookup IS NOT NULL",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_lookup ON users (email_lookup) WHERE email_lookup IS NOT NULL",
)


def migrate_proof_file(path_value: str) -> str:
    if not path_value:
        return ""
    source = Path(__file__).resolve().parents[1] / path_value.lstrip("/")
    if not source.is_file():
        return path_value
    private_dir = source.parents[3] / "private_uploads" / "payment_proofs"
    private_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"migrated-{source.name}.enc"
    (private_dir / stored_name).write_text(encrypt_ecc_bytes(source.read_bytes()), encoding="utf-8")
    source.unlink()
    return stored_name


def migrate() -> None:
    with engine.begin() as connection:
        for statement in DDL:
            connection.execute(text(statement))
    db = SessionLocal()
    try:
        for user in db.query(User).all():
            if not user.encrypted_profile and user.username:
                username, email = user.username, user.email
                user.encrypted_profile = encrypt_user_profile(username=username, email=email, full_name=user.full_name or "", phone=user.phone or "", address=user.address or "")
                user.username_lookup = user_lookup(username)
                user.email_lookup = email_lookup(email)
            user.username = user.email = user.full_name = user.phone = user.address = ""
        for post in db.query(Post).all():
            if not post.encrypted_content and post.title is not None:
                post.encrypted_content = encrypt_post(title=post.title, content=post.content or "")
            post.title = post.content = ""
        for bill in db.query(Bill).all():
            if not bill.encrypted_data and bill.title is not None and bill.amount is not None:
                bill.encrypted_data = encrypt_bill_data(bill_type=bill.bill_type, title=bill.title, description=bill.description or "", amount=bill.amount, due_date=bill.due_date)
            bill.bill_type = bill.title = bill.description = ""
            bill.amount = bill.due_date = None
        for payment in db.query(Payment).all():
            if not payment.encrypted_data and payment.amount is not None:
                payment.encrypted_data = encrypt_payment_data(amount=payment.amount, payment_method=payment.payment_method or "", transaction_reference=payment.transaction_reference or "", payment_date=payment.payment_date)
            payment.amount = None
            payment.payment_date = None
            payment.payment_method = ""
            payment.transaction_reference = None
        for verification in db.query(PaymentVerification).all():
            if not verification.encrypted_proof:
                image_name = migrate_proof_file(verification.proof_image_path or "")
                verification.encrypted_proof = encrypt_proof_data(proof_text=verification.proof_text or "", proof_image_name=image_name, reviewer_note=verification.reviewer_note or "")
            verification.proof_text = verification.proof_image_path = verification.reviewer_note = ""
        for notification in db.query(Notification).all():
            if not notification.encrypted_content and notification.title is not None:
                notification.encrypted_content = encrypt_notification_data(title=notification.title, message=notification.message or "", link=notification.link or "")
            notification.title = notification.message = notification.link = ""
        for conversation in db.query(SupportConversation).all():
            if not conversation.encrypted_subject and conversation.subject is not None:
                conversation.encrypted_subject = encrypt_support_subject(conversation.subject)
            conversation.subject = ""
        for message in db.query(SupportMessage).all():
            if not message.encrypted_content and message.message is not None:
                message.encrypted_content = encrypt_support_message(message.message)
            message.message = ""
        public_proof_dir = Path(__file__).resolve().parents[1] / "app" / "static" / "uploads" / "payment_proofs"
        if public_proof_dir.is_dir():
            for public_file in public_proof_dir.iterdir():
                if public_file.is_file():
                    public_file.unlink()
        db.commit()
        print("Existing PostgreSQL user/profile and post data encrypted.")
        print("Encrypted users:", db.query(User).filter(User.encrypted_profile.is_not(None)).count())
        print("Encrypted posts:", db.query(Post).filter(Post.encrypted_content.is_not(None)).count())
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
