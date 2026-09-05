import pytest

from app.models import User
from app.models.entities import UserRole
from app.services.auth_service import delete_user, register_user


def test_registration_can_create_only_citizen_or_admin(db):
    admin = register_user(
        db,
        full_name="Portal Admin",
        username="portaladmin",
        email="portaladmin@example.com",
        phone="",
        address="",
        password="AdminTest!447",
        role="Admin",
    )
    assert admin.role == UserRole.ADMIN
    with pytest.raises(ValueError):
        register_user(
            db,
            full_name="Government User",
            username="government",
            email="government@example.com",
            phone="",
            address="",
            password="AdminTest!447",
            role="Government",
        )


def test_admin_delete_service_removes_account(db):
    user = register_user(
        db,
        full_name="Delete Me",
        username="delete-me",
        email="delete-me@example.com",
        phone="",
        address="",
        password="CitizenTest!447",
    )
    delete_user(db, user)
    assert db.query(User).filter(User.username == "delete-me").first() is None
