from app.models import Post
from app.services.auth_service import register_user
from app.services.post_service import create_post, list_posts


def test_user_profile_is_ciphertext_at_rest(db):
    user = register_user(
        db,
        full_name="Encrypted Citizen",
        username="encrypted-citizen",
        email="encrypted@example.com",
        phone="0123456789",
        address="Private address",
        password="StorageTest!447",
    )
    db.refresh(user)
    assert user.username == ""
    assert user.email == ""
    assert user.full_name == ""
    assert user.encrypted_profile
    assert "Encrypted Citizen" not in user.encrypted_profile


def test_post_is_ciphertext_at_rest_and_decrypted_on_service_read(db):
    user = register_user(
        db,
        full_name="Post Author",
        username="post-author",
        email="post@example.com",
        phone="",
        address="",
        password="StorageTest!447",
    )
    post = create_post(db, user.id, "Private title", "Private post content")
    db.expire_all()
    stored = db.get(Post, post.id)
    assert stored.title == ""
    assert stored.content == ""
    assert stored.encrypted_content
    assert list_posts(db)[0].title == "Private title"
