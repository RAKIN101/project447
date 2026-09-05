from datetime import datetime
from secrets import token_hex

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.models import Bill, Notification, Payment, PaymentVerification
from app.models.entities import BillStatus, PaymentStatus, UserRole, VerificationStatus
from app.services.notification_service import create_notification, notify_admins


def create_payment(db: Session, bill: Bill, user_id: int, method: str) -> Payment:
    if bill.status == BillStatus.PAID:
        raise ValueError("This bill has already been paid")
    reference = f"GP-{datetime.now():%Y%m%d}-{token_hex(3).upper()}"
    payment = Payment(user_id=user_id, bill_id=bill.id, amount=bill.amount, payment_method=method, transaction_reference=reference, status=PaymentStatus.SUCCESSFUL, payment_date=utcnow())
    bill.status = BillStatus.PAID
    bill.paid_date = payment.payment_date
    db.add(payment)
    db.commit()
    db.refresh(payment)
    return payment


def list_payments(db: Session, user_id: int | None = None):
    query = select(Payment).order_by(Payment.payment_date.desc())
    if user_id is not None:
        query = query.where(Payment.user_id == user_id)
    return list(db.scalars(query))


def submit_payment_for_review(db: Session, bill: Bill, user_id: int, method: str, proof_text: str = "", proof_image_path: str = "") -> Payment:
    if bill.status == BillStatus.PAID:
        raise ValueError("This bill has already been paid")
    payment = Payment(user_id=user_id, bill_id=bill.id, amount=bill.amount, payment_method=method, transaction_reference=f"GP-{datetime.now():%Y%m%d}-{token_hex(3).upper()}", status=PaymentStatus.PENDING, payment_date=utcnow())
    db.add(payment)
    db.flush()
    db.add(PaymentVerification(payment_id=payment.id, submitted_by_id=user_id, proof_text=proof_text.strip(), proof_image_path=proof_image_path))
    notify_admins(db, "Payment verification required", f"A citizen submitted proof for {bill.title}.", f"/admin/verifications/{payment.id}")
    db.commit()
    db.refresh(payment)
    return payment


def review_payment(db: Session, payment: Payment, reviewer_id: int, approved: bool, note: str = "") -> PaymentVerification:
    verification = payment.verification
    if not verification or verification.status != VerificationStatus.PENDING:
        raise ValueError("This payment has already been reviewed")
    verification.status = VerificationStatus.APPROVED if approved else VerificationStatus.REJECTED
    verification.reviewer_id = reviewer_id
    verification.reviewer_note = note.strip()
    verification.reviewed_at = utcnow()
    if approved:
        payment.status = PaymentStatus.SUCCESSFUL
        payment.bill.status = BillStatus.PAID
        payment.bill.paid_date = verification.reviewed_at
        create_notification(db, payment.user_id, "Payment verified", f"Your payment for {payment.bill.title} was approved.", f"/payments/receipt/{payment.id}")
    else:
        payment.status = PaymentStatus.FAILED
        create_notification(db, payment.user_id, "Payment proof rejected", f"Your proof for {payment.bill.title} was rejected. {note}", f"/payments/{payment.bill_id}")
    db.commit()
    db.refresh(verification)
    return verification
