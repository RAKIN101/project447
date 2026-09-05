from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Bill
from app.models.entities import BillStatus


def list_bills(db: Session, user_id: int, status: str | None = None):
    query = select(Bill).where(Bill.user_id == user_id).order_by(Bill.due_date)
    if status in {item.value for item in BillStatus}:
        query = query.where(Bill.status == status)
    return list(db.scalars(query))


def get_bill(db: Session, bill_id: int, user_id: int | None = None) -> Bill | None:
    query = select(Bill).where(Bill.id == bill_id)
    if user_id is not None:
        query = query.where(Bill.user_id == user_id)
    return db.scalar(query)


def refresh_overdue(bill: Bill) -> Bill:
    if bill.status == BillStatus.PENDING and bill.due_date < date.today():
        bill.status = BillStatus.OVERDUE
    return bill
