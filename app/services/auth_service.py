from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.models import User
from app.models.entities import UserRole
from app.services.crypto_service import decrypt_user_profile, email_lookup, encrypt_user_profile, user_lookup


def register_user(db: Session, *, full_name: str, username: str, email: str, phone: str, address: str, password: str, role: str = "Citizen") -> User:
    lookup = user_lookup(username)
    existing = db.scalar(select(User).where(or_(User.username_lookup == lookup, User.email_lookup == email_lookup(email))))
    if existing:
        raise ValueError("Username or email is already registered")
    if role not in {UserRole.CITIZEN.value, UserRole.ADMIN.value}:
        raise ValueError("Only Citizen or Admin roles can be selected")
    user = User(username="", email="", full_name="", phone="", address="", username_lookup=lookup, email_lookup=email_lookup(email), encrypted_profile=encrypt_user_profile(username=username, email=email.lower(), full_name=full_name, phone=phone, address=address), password_hash=hash_password(password), role=UserRole(role))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def delete_user(db: Session, user: User) -> None:
    """Delete a user and owned records as one transaction."""
    for conversation in list(user.support_conversations):
        db.delete(conversation)
    for payment in list(user.payments):
        db.delete(payment)
    for bill in list(user.bills):
        db.delete(bill)
    for post in list(user.posts):
        db.delete(post)
    db.delete(user)
    db.commit()


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = db.scalar(select(User).where(User.username_lookup == user_lookup(username)))
    if user and user.encrypted_profile:
        hydrate_user(user)
    if user and user.is_active and verify_password(password, user.password_hash):
        return user
    return None


def hydrate_user(user: User) -> User:
    if user.encrypted_profile:
        profile = decrypt_user_profile(user.encrypted_profile)
        user.username = profile["username"]
        user.email = profile["email"]
        user.full_name = profile["full_name"]
        user.phone = profile["phone"]
        user.address = profile["address"]
    return user
