from datetime import date, timedelta
from decimal import Decimal

from sqlalchemy import select

from app.core.database import Base, SessionLocal, engine
from app.core.security import hash_password
from app.models import Bill, Post, SupportConversation, SupportMessage, User
from app.models.entities import BillStatus, ConversationStatus, UserRole
from app.services.crypto_service import email_lookup, encrypt_post, encrypt_user_profile, user_lookup

DEMO_PASSWORD = "GovPayDemo!447"


def seed() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username_lookup == user_lookup("admin"))):
            print("Seed data already exists.")
            return
        def new_user(username: str, email: str, full_name: str, role: UserRole, phone: str, address: str) -> User:
            return User(username="", email="", full_name="", phone="", address="", username_lookup=user_lookup(username), email_lookup=email_lookup(email), encrypted_profile=encrypt_user_profile(username=username, email=email, full_name=full_name, phone=phone, address=address), password_hash=hash_password(DEMO_PASSWORD), role=role)

        admin = new_user("admin", "admin@govpay.local", "GovPay Administrator", UserRole.ADMIN, "0100000000", "Central Government Office")
        government = new_user("government", "government@govpay.local", "Government Services", UserRole.GOVERNMENT, "0100000001", "Public Services Department")
        citizens = [new_user(f"citizen{i}", f"citizen{i}@govpay.local", f"Citizen {i}", UserRole.CITIZEN, f"01000000{i:02d}", f"{i} Civic Street") for i in range(1, 4)]
        db.add_all([admin, government, *citizens])
        db.flush()
        today = date.today()
        bill_sets = [[("Electricity", "Monthly electricity service", Decimal("84.50"), BillStatus.PENDING), ("Water", "Residential water service", Decimal("32.00"), BillStatus.PAID), ("Gas", "Monthly gas service", Decimal("45.75"), BillStatus.OVERDUE)], [("Electricity", "Monthly electricity service", Decimal("116.20"), BillStatus.PENDING), ("Property Tax", "Annual property tax installment", Decimal("250.00"), BillStatus.PAID)], [("Water", "Residential water service", Decimal("28.50"), BillStatus.PENDING), ("Waste", "Municipal waste collection", Decimal("18.00"), BillStatus.OVERDUE)]]
        for citizen, items in zip(citizens, bill_sets):
            for bill_type, title, amount, bill_status in items:
                db.add(Bill(user_id=citizen.id, bill_type=bill_type, title=title, description=f"Sample {bill_type.lower()} bill for {citizen.full_name}.", amount=amount, due_date=today + timedelta(days=10) if bill_status != BillStatus.OVERDUE else today - timedelta(days=4), status=bill_status))
        db.add_all([Post(user_id=government.id, title="", content="", encrypted_content=encrypt_post(title="Welcome to GovPay", content="Use this portal to manage utility payments and contact the government helpdesk.")), Post(user_id=citizens[0].id, title="", content="", encrypted_content=encrypt_post(title="Water service question", content="Has anyone received the latest service schedule?")), SupportConversation(user_id=citizens[1].id, subject="Payment assistance", status=ConversationStatus.OPEN)])
        db.flush()
        conversation = db.scalar(select(SupportConversation).where(SupportConversation.user_id == citizens[1].id))
        db.add(SupportMessage(conversation_id=conversation.id, sender_id=citizens[1].id, message="I need help understanding my latest payment statement."))
        db.commit()
    print("Seed data created.")
    print(f"Demo password for all accounts: {DEMO_PASSWORD}")


if __name__ == "__main__":
    seed()
