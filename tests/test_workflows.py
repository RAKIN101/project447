from datetime import date, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models import Bill, User
from app.models.entities import BillStatus, UserRole
from app.services.auth_service import register_user
from app.services.bill_service import get_bill
from app.services.payment_service import create_payment, list_payments


def create_user(db: Session, username: str) -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        full_name=username.title(),
        password_hash=hash_password("GovPayTest!447"),
        role=UserRole.CITIZEN,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_registration_rejects_duplicate_username_or_email(db: Session):
    register_user(
        db,
        full_name="First Citizen",
        username="citizen",
        email="citizen@example.com",
        phone="",
        address="",
        password="GovPayTest!447",
    )
    with pytest.raises(ValueError):
        register_user(
            db,
            full_name="Another Citizen",
            username="citizen",
            email="another@example.com",
            phone="",
            address="",
            password="GovPayTest!447",
        )
    with pytest.raises(ValueError):
        register_user(
            db,
            full_name="Another Citizen",
            username="another",
            email="citizen@example.com",
            phone="",
            address="",
            password="GovPayTest!447",
        )


def test_bill_ownership_and_successful_payment(db: Session):
    owner = create_user(db, "owner")
    other_user = create_user(db, "other")
    bill = Bill(
        user_id=owner.id,
        bill_type="Water",
        title="Water service",
        description="Test bill",
        amount=Decimal("42.50"),
        due_date=date.today() + timedelta(days=7),
        status=BillStatus.PENDING,
    )
    db.add(bill)
    db.commit()
    db.refresh(bill)

    assert get_bill(db, bill.id, owner.id) is not None
    assert get_bill(db, bill.id, other_user.id) is None

    payment = create_payment(db, bill, owner.id, "Card")
    db.refresh(bill)
    assert payment.transaction_reference.startswith("GP-")
    assert bill.status == BillStatus.PAID
    assert len(list_payments(db, owner.id)) == 1
    assert db.scalar(select(Bill).where(Bill.id == bill.id)).paid_date is not None
