from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from app.core.security import utcnow
from app.models import Post
from app.services.crypto_service import decrypt_post, encrypt_post
from app.services.auth_service import hydrate_user


def hydrate_post(post: Post) -> Post:
    if post.encrypted_content:
        payload = decrypt_post(post.encrypted_content)
        set_committed_value(post, "title", payload["title"])
        set_committed_value(post, "content", payload["content"])
    if post.user:
        hydrate_user(post.user)
    return post


def list_posts(db: Session):
    posts = list(db.scalars(select(Post).order_by(Post.created_at.desc())))
    return [hydrate_post(post) for post in posts]


def create_post(db: Session, user_id: int, title: str, content: str) -> Post:
    post = Post(user_id=user_id, title="", content="", encrypted_content=encrypt_post(title=title, content=content))
    db.add(post)
    db.commit()
    db.refresh(post)
    return hydrate_post(post)


def get_post(db: Session, post_id: int) -> Post | None:
    post = db.get(Post, post_id)
    return hydrate_post(post) if post else None


def update_post(db: Session, post: Post, title: str, content: str) -> Post:
    post.title, post.content, post.encrypted_content, post.updated_at = "", "", encrypt_post(title=title, content=content), utcnow()
    db.commit()
    db.refresh(post)
    return hydrate_post(post)
