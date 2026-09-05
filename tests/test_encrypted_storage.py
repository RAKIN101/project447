from datetime import date, timedelta
from decimal import Decimal

from app.models import Bill, Notification, Payment, PaymentVerification, Post, SupportConversation, SupportMessage
from app.models.entities import BillStatus, UserRole
from app.services.auth_service import register_user
from app.services.bill_service import create_bill
from app.services.crypto_service import decrypt_ecc_bytes, encrypt_ecc_bytes
from app.services.notification_service import create_notification
from app.services.payment_service import submit_payment_for_review
from app.services.post_service import create_post, list_posts
from app.services.support_service import create_conversation, get_conversation


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


def test_critical_service_payloads_are_ciphertext_at_rest(db):
    admin = register_user(db, full_name="Admin User", username="storage-admin", email="storage-admin@example.com", phone="", address="", password="StorageTest!447", role="Admin")
    citizen = register_user(db, full_name="Storage Citizen", username="storage-citizen", email="storage-citizen@example.com", phone="", address="", password="StorageTest!447")
    bill = create_bill(db, admin_id=admin.id, bill_type="Gas", title="Private bill", description="Private description", amount=Decimal("15.25"), due_date=date.today() + timedelta(days=3), scope="individual", citizen_id=citizen.id)[0]
    payment = submit_payment_for_review(db, bill, citizen.id, "Card", "Private proof")
    conversation = create_conversation(db, citizen.id, "Private subject", "Private support message")
    create_notification(db, citizen.id, "Private notice", "Private notification", "/bills/1")
    bill_id, payment_id, conversation_id = bill.id, payment.id, conversation.id
    db.expunge_all()

    stored_bill = db.get(Bill, bill_id)
    stored_payment = db.get(Payment, payment_id)
    stored_proof = db.get(PaymentVerification, payment_id)
    stored_notification = db.query(Notification).filter(Notification.user_id == citizen.id).order_by(Notification.id.desc()).first()
    stored_conversation = db.get(SupportConversation, conversation_id)
    stored_message = db.query(SupportMessage).filter(SupportMessage.conversation_id == conversation_id).first()
    assert stored_bill.encrypted_data and stored_bill.title == "" and stored_bill.description == "" and stored_bill.amount is None
    assert stored_payment.encrypted_data and stored_payment.payment_method == "" and stored_payment.transaction_reference is None and stored_payment.amount is None
    assert stored_proof.encrypted_proof and stored_proof.proof_text == ""
    assert stored_notification.encrypted_content and stored_notification.title == ""
    assert stored_conversation.encrypted_subject and stored_conversation.subject == ""
    assert stored_message.encrypted_content and stored_message.message == ""
    assert get_conversation(db, conversation_id).subject == "Private subject"


def test_encrypted_proof_bytes_round_trip():
    value = b"private proof image bytes"
    assert decrypt_ecc_bytes(encrypt_ecc_bytes(value)) == value
