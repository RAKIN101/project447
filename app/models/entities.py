from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum

from sqlalchemy import Boolean, Date, DateTime, Enum as SqlEnum, ForeignKey, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class UserRole(str, Enum):
    CITIZEN = "Citizen"
    ADMIN = "Admin"
    GOVERNMENT = "Government"


class BillStatus(str, Enum):
    PENDING = "Pending"
    PAID = "Paid"
    OVERDUE = "Overdue"


class PaymentStatus(str, Enum):
    SUCCESSFUL = "Successful"
    PENDING = "Pending"
    FAILED = "Failed"


class VerificationStatus(str, Enum):
    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"


class ConversationStatus(str, Enum):
    OPEN = "Open"
    CLOSED = "Closed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), nullable=True, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    username_lookup: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=True)
    email_lookup: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=True)
    encrypted_profile: Mapped[str] = mapped_column(Text, nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(SqlEnum(UserRole), default=UserRole.CITIZEN)
    full_name: Mapped[str] = mapped_column(String(120), nullable=True)
    phone: Mapped[str] = mapped_column(String(40), default="", nullable=True)
    address: Mapped[str] = mapped_column(String(255), default="", nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    bills = relationship("Bill", back_populates="user", cascade="all, delete-orphan")
    payments = relationship("Payment", back_populates="user")
    posts = relationship("Post", back_populates="user", cascade="all, delete-orphan")
    support_conversations = relationship("SupportConversation", back_populates="user", cascade="all, delete-orphan")


class Bill(Base):
    __tablename__ = "bills"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    bill_type: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(150))
    description: Mapped[str] = mapped_column(Text, default="")
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    due_date: Mapped[date] = mapped_column(Date)
    status: Mapped[BillStatus] = mapped_column(SqlEnum(BillStatus), default=BillStatus.PENDING)
    paid_date = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user = relationship("User", back_populates="bills")
    payments = relationship("Payment", back_populates="bill")


class Payment(Base):
    __tablename__ = "payments"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    bill_id: Mapped[int] = mapped_column(ForeignKey("bills.id"), index=True)
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    payment_method: Mapped[str] = mapped_column(String(50))
    transaction_reference: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    status: Mapped[PaymentStatus] = mapped_column(SqlEnum(PaymentStatus), default=PaymentStatus.SUCCESSFUL)
    payment_date: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user = relationship("User", back_populates="payments")
    bill = relationship("Bill", back_populates="payments")
    verification = relationship("PaymentVerification", back_populates="payment", uselist=False, cascade="all, delete-orphan")


class PaymentVerification(Base):
    __tablename__ = "payment_verifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    payment_id: Mapped[int] = mapped_column(ForeignKey("payments.id"), unique=True, index=True)
    submitted_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    proof_text: Mapped[str] = mapped_column(Text, default="")
    proof_image_path: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[VerificationStatus] = mapped_column(SqlEnum(VerificationStatus), default=VerificationStatus.PENDING)
    reviewer_id = mapped_column(ForeignKey("users.id"), nullable=True)
    reviewer_note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    reviewed_at = mapped_column(DateTime, nullable=True)

    payment = relationship("Payment", back_populates="verification")
    submitted_by = relationship("User", foreign_keys=[submitted_by_id])
    reviewer = relationship("User", foreign_keys=[reviewer_id])


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(160))
    message: Mapped[str] = mapped_column(Text)
    link: Mapped[str] = mapped_column(String(255), default="")
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user = relationship("User")


class Post(Base):
    __tablename__ = "posts"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(160), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=True)
    encrypted_content: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    user = relationship("User", back_populates="posts")


class SupportConversation(Base):
    __tablename__ = "support_conversations"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    subject: Mapped[str] = mapped_column(String(160))
    status: Mapped[ConversationStatus] = mapped_column(SqlEnum(ConversationStatus), default=ConversationStatus.OPEN)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    user = relationship("User", back_populates="support_conversations")
    messages = relationship("SupportMessage", back_populates="conversation", cascade="all, delete-orphan")


class SupportMessage(Base):
    __tablename__ = "support_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("support_conversations.id"), index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    conversation = relationship("SupportConversation", back_populates="messages")
    sender = relationship("User")
