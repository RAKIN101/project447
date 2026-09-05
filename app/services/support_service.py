from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.orm.attributes import set_committed_value

from app.core.security import utcnow
from app.models import SupportConversation, SupportMessage
from app.models.entities import ConversationStatus
from app.services.crypto_service import decrypt_support_message, decrypt_support_subject, encrypt_support_message, encrypt_support_subject


def list_conversations(db: Session, user_id: int | None = None):
    query = select(SupportConversation).order_by(SupportConversation.updated_at.desc())
    if user_id is not None:
        query = query.where(SupportConversation.user_id == user_id)
    return [hydrate_conversation(item) for item in db.scalars(query)]


def get_conversation(db: Session, conversation_id: int) -> SupportConversation | None:
    conversation = db.scalar(select(SupportConversation).options(joinedload(SupportConversation.messages)).where(SupportConversation.id == conversation_id))
    return hydrate_conversation(conversation) if conversation else None


def hydrate_conversation(conversation: SupportConversation | None) -> SupportConversation | None:
    if not conversation:
        return None
    if conversation.encrypted_subject:
        set_committed_value(conversation, "subject", decrypt_support_subject(conversation.encrypted_subject))
    for message in conversation.messages:
        if message.encrypted_content:
            set_committed_value(message, "message", decrypt_support_message(message.encrypted_content))
    return conversation


def create_conversation(db: Session, user_id: int, subject: str, message: str) -> SupportConversation:
    conversation = SupportConversation(user_id=user_id, subject="", encrypted_subject=encrypt_support_subject(subject))
    db.add(conversation)
    db.flush()
    db.add(SupportMessage(conversation_id=conversation.id, sender_id=user_id, message="", encrypted_content=encrypt_support_message(message)))
    db.commit()
    db.refresh(conversation)
    return hydrate_conversation(conversation)


def add_message(db: Session, conversation: SupportConversation, sender_id: int, message: str) -> SupportMessage:
    support_message = SupportMessage(conversation_id=conversation.id, sender_id=sender_id, message="", encrypted_content=encrypt_support_message(message))
    conversation.updated_at = utcnow()
    db.add(support_message)
    db.commit()
    db.refresh(support_message)
    return hydrate_conversation(conversation).messages[-1]


def set_status(db: Session, conversation: SupportConversation, status: ConversationStatus) -> None:
    conversation.status = status
    conversation.updated_at = utcnow()
    db.commit()
