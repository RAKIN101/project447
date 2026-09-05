from datetime import date, timedelta
from decimal import Decimal

from sqlalchemy import select

from app.core.database import Base, SessionLocal, engine
from app.core.security import hash_password
from app.models import Bill, Post, SupportConversation, SupportMessage, User
from app.models.entities import BillStatus, ConversationStatus, UserRole

DEMO_PASSWORD = "GovPayDemo!447"


def seed() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == "admin")):
            print("Seed data already exists.")
            return
        admin = User(username="admin", email="admin@govpay.local", full_name="GovPay Administrator", password_hash=hash_password(DEMO_PASSWORD), role=UserRole.ADMIN, phone="0100000000", address="Central Government Office")
        government = User(username="government", email="government@govpay.local", full_name="Government Services", password_hash=hash_password(DEMO_PASSWORD), role=UserRole.GOVERNMENT, phone="0100000001", address="Public Services Department")
        citizens = [User(username=f"citizen{i}", email=f"citizen{i}@govpay.local", full_name=f"Citizen {i}", password_hash=hash_password(DEMO_PASSWORD), role=UserRole.CITIZEN, phone=f"01000000{i:02d}", address=f"{i} Civic Street") for i in range(1, 4)]
        db.add_all([admin, government, *citizens])
        db.flush()
        today = date.today()
        bill_sets = [[("Electricity", "Monthly electricity service", Decimal("84.50"), BillStatus.PENDING), ("Water", "Residential water service", Decimal("32.00"), BillStatus.PAID), ("Gas", "Monthly gas service", Decimal("45.75"), BillStatus.OVERDUE)], [("Electricity", "Monthly electricity service", Decimal("116.20"), BillStatus.PENDING), ("Property Tax", "Annual property tax installment", Decimal("250.00"), BillStatus.PAID)], [("Water", "Residential water service", Decimal("28.50"), BillStatus.PENDING), ("Waste", "Municipal waste collection", Decimal("18.00"), BillStatus.OVERDUE)]]
        for citizen, items in zip(citizens, bill_sets):
            for bill_type, title, amount, bill_status in items:
                db.add(Bill(user_id=citizen.id, bill_type=bill_type, title=title, description=f"Sample {bill_type.lower()} bill for {citizen.full_name}.", amount=amount, due_date=today + timedelta(days=10) if bill_status != BillStatus.OVERDUE else today - timedelta(days=4), status=bill_status))
        db.add_all([Post(user_id=government.id, title="Welcome to GovPay", content="Use this portal to manage utility payments and contact the government helpdesk."), Post(user_id=citizens[0].id, title="Water service question", content="Has anyone received the latest service schedule?"), SupportConversation(user_id=citizens[1].id, subject="Payment assistance", status=ConversationStatus.OPEN)])
        db.flush()
        conversation = db.scalar(select(SupportConversation).where(SupportConversation.user_id == citizens[1].id))
        db.add(SupportMessage(conversation_id=conversation.id, sender_id=citizens[1].id, message="I need help understanding my latest payment statement."))
        db.commit()
    print("Seed data created.")
    print(f"Demo password for all accounts: {DEMO_PASSWORD}")


if __name__ == "__main__":
    seed()
