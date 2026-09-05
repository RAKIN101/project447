from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.security import utcnow
from app.models import SupportConversation, SupportMessage
from app.models.entities import ConversationStatus


def list_conversations(db: Session, user_id: int | None = None):
    query = select(SupportConversation).order_by(SupportConversation.updated_at.desc())
    if user_id is not None:
        query = query.where(SupportConversation.user_id == user_id)
    return list(db.scalars(query))


def get_conversation(db: Session, conversation_id: int) -> SupportConversation | None:
    return db.scalar(select(SupportConversation).options(joinedload(SupportConversation.messages)).where(SupportConversation.id == conversation_id))


def create_conversation(db: Session, user_id: int, subject: str, message: str) -> SupportConversation:
    conversation = SupportConversation(user_id=user_id, subject=subject)
    db.add(conversation)
    db.flush()
    db.add(SupportMessage(conversation_id=conversation.id, sender_id=user_id, message=message))
    db.commit()
    db.refresh(conversation)
    return conversation


def add_message(db: Session, conversation: SupportConversation, sender_id: int, message: str) -> SupportMessage:
    support_message = SupportMessage(conversation_id=conversation.id, sender_id=sender_id, message=message)
    conversation.updated_at = utcnow()
    db.add(support_message)
    db.commit()
    db.refresh(support_message)
    return support_message


def set_status(db: Session, conversation: SupportConversation, status: ConversationStatus) -> None:
    conversation.status = status
    conversation.updated_at = utcnow()
    db.commit()
