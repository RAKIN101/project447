"""Encrypt existing PostgreSQL user/profile and post rows in place.

Run once after deploying the encrypted model columns:
    python -m scripts.migrate_encrypted_storage
"""

from sqlalchemy import text

from app.core.database import SessionLocal, engine
from app.models import Post, User
from app.services.auth_service import hydrate_user
from app.services.crypto_service import email_lookup, encrypt_user_profile, user_lookup
from app.services.post_service import encrypt_post, hydrate_post


DDL = (
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS username_lookup VARCHAR(100)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_lookup VARCHAR(100)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_profile TEXT",
    "ALTER TABLE posts ADD COLUMN IF NOT EXISTS encrypted_content TEXT",
    "ALTER TABLE users ALTER COLUMN username DROP NOT NULL",
    "ALTER TABLE users ALTER COLUMN email DROP NOT NULL",
    "ALTER TABLE users ALTER COLUMN full_name DROP NOT NULL",
    "ALTER TABLE users ALTER COLUMN phone DROP NOT NULL",
    "ALTER TABLE users ALTER COLUMN address DROP NOT NULL",
    "ALTER TABLE posts ALTER COLUMN title DROP NOT NULL",
    "ALTER TABLE posts ALTER COLUMN content DROP NOT NULL",
    "ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_key",
    "ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key",
    "DROP INDEX IF EXISTS ix_users_username",
    "DROP INDEX IF EXISTS ix_users_email",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username_lookup ON users (username_lookup) WHERE username_lookup IS NOT NULL",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_lookup ON users (email_lookup) WHERE email_lookup IS NOT NULL",
)


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
