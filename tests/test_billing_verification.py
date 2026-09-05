from datetime import date, timedelta
from decimal import Decimal

from app.core.security import hash_password
from app.models import Notification, User
from app.models.entities import BillStatus, PaymentStatus, UserRole, VerificationStatus
from app.services.bill_service import create_bill
from app.services.payment_service import review_payment, submit_payment_for_review


def citizen(db, username: str) -> User:
    user = User(username=username, email=f"{username}@example.com", full_name=username.title(), password_hash=hash_password("CitizenTest!447"), role=UserRole.CITIZEN)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_admin_can_create_individual_and_global_bills(db):
    admin = User(username="admin", email="admin@example.com", full_name="Admin", password_hash=hash_password("AdminTest!447"), role=UserRole.ADMIN)
    first, second = citizen(db, "first"), citizen(db, "second")
    db.add(admin)
    db.commit()

    individual = create_bill(db, admin_id=admin.id, bill_type="Electricity", title="First electricity", description="Metered", amount=Decimal("120.00"), due_date=date.today() + timedelta(days=7), scope="individual", citizen_id=first.id)
    global_bills = create_bill(db, admin_id=admin.id, bill_type="Water", title="Water service", description="Global tariff", amount=Decimal("30.00"), due_date=date.today() + timedelta(days=7), scope="global")

    assert [bill.user_id for bill in individual] == [first.id]
    assert {bill.user_id for bill in global_bills} == {first.id, second.id}
    assert db.query(Notification).count() == 3


def test_citizen_proof_requires_admin_review(db):
    admin = User(username="admin", email="admin@example.com", full_name="Admin", password_hash=hash_password("AdminTest!447"), role=UserRole.ADMIN)
    user = citizen(db, "payer")
    db.add(admin)
    db.commit()
    bill = create_bill(db, admin_id=admin.id, bill_type="Gas", title="Gas service", description="Monthly", amount=Decimal("45.00"), due_date=date.today() + timedelta(days=7), scope="individual", citizen_id=user.id)[0]

    payment = submit_payment_for_review(db, bill, user.id, "Mobile Banking", "Copied bill text")
    assert payment.status == PaymentStatus.PENDING
    assert bill.status == BillStatus.PENDING
    assert payment.verification.status == VerificationStatus.PENDING

    review_payment(db, payment, admin.id, True, "Proof matches bill")
    assert payment.status == PaymentStatus.SUCCESSFUL
    assert bill.status == BillStatus.PAID
    assert payment.verification.status == VerificationStatus.APPROVED
