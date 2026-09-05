from datetime import date
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Bill, User
from app.models.entities import BillStatus, UserRole
from app.services.notification_service import create_notification

BILL_TYPES = ("Electricity", "Water", "Gas", "Waste", "Property Tax")


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


def create_bill(db: Session, *, admin_id: int, bill_type: str, title: str, description: str, amount: Decimal, due_date: date, scope: str, citizen_id: int | None = None) -> list[Bill]:
    if bill_type not in BILL_TYPES:
        raise ValueError("Invalid bill category")
    if scope not in {"individual", "global"}:
        raise ValueError("Invalid bill scope")
    if scope == "individual" and citizen_id is None:
        raise ValueError("Choose a citizen for an individual bill")
    if scope == "global":
        users = list(db.scalars(select(User).where(User.role == UserRole.CITIZEN, User.is_active.is_(True))))
    else:
        user = db.get(User, citizen_id)
        if not user or user.role != UserRole.CITIZEN or not user.is_active:
            raise ValueError("Citizen not found")
        users = [user]
    bills = [Bill(user_id=user.id, bill_type=bill_type, title=title, description=description, amount=amount, due_date=due_date, status=BillStatus.PENDING) for user in users]
    db.add_all(bills)
    db.flush()
    for bill, user in zip(bills, users):
        create_notification(db, user.id, "New bill available", f"{title} bill: BDT {amount:.2f}", f"/bills/{bill.id}")
    db.commit()
    for bill in bills:
        db.refresh(bill)
    return bills
