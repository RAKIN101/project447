"""Merge legacy govpay_local.db history into the configured PostgreSQL database.

The migration matches users by username, preserves existing PostgreSQL users,
and skips duplicate bills/payments/posts/conversations/messages where possible.
Run once from the project root with: python -m scripts.migrate_legacy_sqlite
"""

import sqlite3
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

from sqlalchemy import select

from app.core.database import SessionLocal
from app.models import Bill, Payment, Post, SupportConversation, SupportMessage, User
from app.models.entities import BillStatus, ConversationStatus, PaymentStatus, UserRole


SOURCE = Path("govpay_local.db")


def parse_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def migrate() -> None:
    if not SOURCE.exists():
        raise FileNotFoundError(f"Legacy database not found: {SOURCE}")
    source = sqlite3.connect(SOURCE)
    source.row_factory = sqlite3.Row
    db = SessionLocal()
    user_map: dict[int, User] = {}
    bill_map: dict[int, Bill] = {}
    conversation_map: dict[int, SupportConversation] = {}
    try:
        for row in source.execute("SELECT * FROM users"):
            user = db.scalar(select(User).where(User.username == row["username"]))
            if not user:
                user = User(username=row["username"], email=row["email"], password_hash=row["password_hash"], role=UserRole[row["role"]], full_name=row["full_name"], phone=row["phone"], address=row["address"], created_at=parse_datetime(row["created_at"]), is_active=bool(row["is_active"]))
                db.add(user)
                db.flush()
            user_map[row["id"]] = user

        for row in source.execute("SELECT * FROM bills"):
            user = user_map[row["user_id"]]
            bill = db.scalar(select(Bill).where(Bill.user_id == user.id, Bill.title == row["title"], Bill.amount == Decimal(str(row["amount"])), Bill.due_date == date.fromisoformat(row["due_date"])))
            if not bill:
                bill = Bill(user_id=user.id, bill_type=row["bill_type"], title=row["title"], description=row["description"], amount=Decimal(str(row["amount"])), due_date=date.fromisoformat(row["due_date"]), status=BillStatus[row["status"]], paid_date=parse_datetime(row["paid_date"]), created_at=parse_datetime(row["created_at"]))
                db.add(bill)
                db.flush()
            bill_map[row["id"]] = bill

        for row in source.execute("SELECT * FROM payments"):
            user = user_map[row["user_id"]]
            bill = bill_map[row["bill_id"]]
            payment = db.scalar(select(Payment).where(Payment.transaction_reference == row["transaction_reference"]))
            if not payment:
                payment = Payment(user_id=user.id, bill_id=bill.id, amount=Decimal(str(row["amount"])), payment_method=row["payment_method"], transaction_reference=row["transaction_reference"], status=PaymentStatus[row["status"]], payment_date=parse_datetime(row["payment_date"]), created_at=parse_datetime(row["created_at"]))
                db.add(payment)

        for row in source.execute("SELECT * FROM posts"):
            user = user_map[row["user_id"]]
            exists = db.scalar(select(Post).where(Post.user_id == user.id, Post.title == row["title"], Post.content == row["content"]))
            if not exists:
                db.add(Post(user_id=user.id, title=row["title"], content=row["content"], created_at=parse_datetime(row["created_at"]), updated_at=parse_datetime(row["updated_at"])))

        for row in source.execute("SELECT * FROM support_conversations"):
            user = user_map[row["user_id"]]
            conversation = db.scalar(select(SupportConversation).where(SupportConversation.user_id == user.id, SupportConversation.subject == row["subject"]))
            if not conversation:
                conversation = SupportConversation(user_id=user.id, subject=row["subject"], status=ConversationStatus[row["status"]], created_at=parse_datetime(row["created_at"]), updated_at=parse_datetime(row["updated_at"]))
                db.add(conversation)
                db.flush()
            conversation_map[row["id"]] = conversation

        for row in source.execute("SELECT * FROM support_messages"):
            conversation = conversation_map[row["conversation_id"]]
            sender = user_map[row["sender_id"]]
            exists = db.scalar(select(SupportMessage).where(SupportMessage.conversation_id == conversation.id, SupportMessage.sender_id == sender.id, SupportMessage.message == row["message"]))
            if not exists:
                db.add(SupportMessage(conversation_id=conversation.id, sender_id=sender.id, message=row["message"], created_at=parse_datetime(row["created_at"])))
        db.commit()
        print("Legacy SQLite history merged into PostgreSQL.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
        source.close()


if __name__ == "__main__":
    migrate()
