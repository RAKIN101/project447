from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from app.models import Notification, User
from app.models.entities import UserRole
from app.services.crypto_service import decrypt_notification_data, encrypt_notification_data


def create_notification(db: Session, user_id: int, title: str, message: str, link: str = "") -> Notification:
    notification = Notification(user_id=user_id, title="", message="", link="", encrypted_content=encrypt_notification_data(title=title, message=message, link=link))
    db.add(notification)
    return notification


def notify_admins(db: Session, title: str, message: str, link: str = "") -> None:
    admin_ids = db.scalars(select(User.id).where(User.role == UserRole.ADMIN, User.is_active.is_(True))).all()
    for admin_id in admin_ids:
        create_notification(db, admin_id, title, message, link)


def list_notifications(db: Session, user_id: int, unread_only: bool = False):
    query = select(Notification).where(Notification.user_id == user_id).order_by(Notification.created_at.desc())
    if unread_only:
        query = query.where(Notification.is_read.is_(False))
    return [hydrate_notification(item) for item in db.scalars(query)]


def hydrate_notification(notification: Notification) -> Notification:
    if notification.encrypted_content:
        data = decrypt_notification_data(notification.encrypted_content)
        set_committed_value(notification, "title", data["title"])
        set_committed_value(notification, "message", data["message"])
        set_committed_value(notification, "link", data["link"])
    return notification
