from datetime import datetime
from secrets import token_hex

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.models import Bill, Payment
from app.models.entities import BillStatus, PaymentStatus


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
