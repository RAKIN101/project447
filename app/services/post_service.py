from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import utcnow
from app.models import Post


def list_posts(db: Session):
    return list(db.scalars(select(Post).order_by(Post.created_at.desc())))


def create_post(db: Session, user_id: int, title: str, content: str) -> Post:
    post = Post(user_id=user_id, title=title, content=content)
    db.add(post)
    db.commit()
    db.refresh(post)
    return post


def get_post(db: Session, post_id: int) -> Post | None:
    return db.get(Post, post_id)


def update_post(db: Session, post: Post, title: str, content: str) -> Post:
    post.title, post.content, post.updated_at = title, content, utcnow()
    db.commit()
    db.refresh(post)
    return post
