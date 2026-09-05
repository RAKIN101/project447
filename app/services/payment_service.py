from datetime import datetime
from decimal import Decimal
from secrets import token_hex

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from app.core.security import utcnow
from app.models import Bill, Notification, Payment, PaymentVerification
from app.models.entities import BillStatus, PaymentStatus, UserRole, VerificationStatus
from app.services.notification_service import create_notification, notify_admins
from app.services.bill_service import hydrate_bill
from app.services.crypto_service import decrypt_payment_data, decrypt_proof_data, encrypt_bill_data, encrypt_payment_data, encrypt_proof_data


def create_payment(db: Session, bill: Bill, user_id: int, method: str) -> Payment:
    if bill.status == BillStatus.PAID:
        raise ValueError("This bill has already been paid")
    reference = f"GP-{datetime.now():%Y%m%d}-{token_hex(3).upper()}"
    payment_date = utcnow()
    payment = Payment(user_id=user_id, bill_id=bill.id, amount=None, payment_method="", transaction_reference=None, encrypted_data=encrypt_payment_data(amount=bill.amount, payment_method=method, transaction_reference=reference, payment_date=payment_date), status=PaymentStatus.SUCCESSFUL, payment_date=None)
    bill.status = BillStatus.PAID
    bill.paid_date = payment_date
    db.add(payment)
    db.commit()
    db.refresh(payment)
    return hydrate_payment(payment)


def list_payments(db: Session, user_id: int | None = None):
    query = select(Payment).order_by(Payment.payment_date.desc())
    if user_id is not None:
        query = query.where(Payment.user_id == user_id)
    return [hydrate_payment(payment) for payment in db.scalars(query)]


def hydrate_payment(payment: Payment | None) -> Payment | None:
    if not payment:
        return None
    if payment.encrypted_data:
        data = decrypt_payment_data(payment.encrypted_data)
        set_committed_value(payment, "amount", Decimal(data["amount"]))
        set_committed_value(payment, "payment_method", data["payment_method"])
        set_committed_value(payment, "transaction_reference", data["transaction_reference"])
        set_committed_value(payment, "payment_date", datetime.fromisoformat(data["payment_date"]))
    hydrate_bill(payment.bill)
    hydrate_verification(payment.verification)
    return payment


def hydrate_verification(verification: PaymentVerification | None) -> PaymentVerification | None:
    if verification and verification.encrypted_proof:
        data = decrypt_proof_data(verification.encrypted_proof)
        set_committed_value(verification, "proof_text", data["proof_text"])
        set_committed_value(verification, "proof_image_path", data["proof_image_name"])
        set_committed_value(verification, "reviewer_note", data["reviewer_note"])
    return verification


def submit_payment_for_review(db: Session, bill: Bill, user_id: int, method: str, proof_text: str = "", proof_image_path: str = "") -> Payment:
    if bill.status == BillStatus.PAID:
        raise ValueError("This bill has already been paid")
    payment_date = utcnow()
    reference = f"GP-{datetime.now():%Y%m%d}-{token_hex(3).upper()}"
    payment = Payment(user_id=user_id, bill_id=bill.id, amount=None, payment_method="", transaction_reference=None, encrypted_data=encrypt_payment_data(amount=bill.amount, payment_method=method, transaction_reference=reference, payment_date=payment_date), status=PaymentStatus.PENDING, payment_date=None)
    db.add(payment)
    db.flush()
    db.add(PaymentVerification(payment_id=payment.id, submitted_by_id=user_id, proof_text="", proof_image_path="", reviewer_note="", encrypted_proof=encrypt_proof_data(proof_text=proof_text.strip(), proof_image_name=proof_image_path, reviewer_note="")))
    notify_admins(db, "Payment verification required", f"A citizen submitted proof for {bill.title}.", f"/admin/verifications/{payment.id}")
    db.commit()
    db.refresh(payment)
    return hydrate_payment(payment)


def review_payment(db: Session, payment: Payment, reviewer_id: int, approved: bool, note: str = "") -> PaymentVerification:
    hydrate_payment(payment)
    verification = payment.verification
    if not verification or verification.status != VerificationStatus.PENDING:
        raise ValueError("This payment has already been reviewed")
    verification.status = VerificationStatus.APPROVED if approved else VerificationStatus.REJECTED
    verification.reviewer_id = reviewer_id
    current = decrypt_proof_data(verification.encrypted_proof) if verification.encrypted_proof else {"proof_text": verification.proof_text or "", "proof_image_name": verification.proof_image_path or "", "reviewer_note": ""}
    verification.reviewer_note = ""
    verification.encrypted_proof = encrypt_proof_data(proof_text=current["proof_text"], proof_image_name=current["proof_image_name"], reviewer_note=note.strip())
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
