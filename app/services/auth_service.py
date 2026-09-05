from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.models import User
from app.models.entities import UserRole


def register_user(db: Session, *, full_name: str, username: str, email: str, phone: str, address: str, password: str) -> User:
    existing = db.scalar(select(User).where(or_(User.username == username, User.email == email)))
    if existing:
        raise ValueError("Username or email is already registered")
    user = User(full_name=full_name, username=username, email=email.lower(), phone=phone, address=address, password_hash=hash_password(password), role=UserRole.CITIZEN)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = db.scalar(select(User).where(User.username == username))
    if user and user.is_active and verify_password(password, user.password_hash):
        return user
    return None
