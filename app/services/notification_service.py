from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Notification, User
from app.models.entities import UserRole


def create_notification(db: Session, user_id: int, title: str, message: str, link: str = "") -> Notification:
    notification = Notification(user_id=user_id, title=title, message=message, link=link)
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
    return list(db.scalars(query))
