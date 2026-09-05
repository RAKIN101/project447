from datetime import date, timedelta
from decimal import Decimal

from app.models.entities import Bill, BillStatus
from app.services.bill_service import refresh_overdue


def test_pending_past_due_bill_becomes_overdue():
    bill = Bill(amount=Decimal("10.00"), due_date=date.today() - timedelta(days=1), status=BillStatus.PENDING)
    refresh_overdue(bill)
    assert bill.status == BillStatus.OVERDUE
