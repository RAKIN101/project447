from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from secrets import token_hex

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import settings
from app.core.database import Base, SessionLocal, engine, get_db
from app.core.otp_store import can_issue_persistent, consume_persistent, remember_issue_persistent, verify_persistent
from app.core.security import csrf_token, validate_csrf
from app.core.sessions import create_persistent_auth_session, is_persistent_auth_session_valid, revoke_persistent_auth_session
from app.crypto.otp import generate_otp
from app.models import Bill, Notification, Payment, Post, SupportConversation, User
from app.models.entities import BillStatus, ConversationStatus, PaymentStatus, UserRole, VerificationStatus
from app.schemas.bill import PaymentInput
from app.schemas.post import PostInput
from app.schemas.support import SupportInput
from app.schemas.user import RegistrationInput
from app.services.auth_service import authenticate, delete_user, hydrate_user, register_user
from app.services.bill_service import BILL_TYPES, create_bill, get_bill, hydrate_bill, list_bills, refresh_overdue
from app.services.crypto_service import decrypt_ecc_bytes, encrypt_ecc_bytes, encrypt_user_profile
from app.services.notification_service import list_notifications, hydrate_notification
from app.services.otp_delivery import deliver_otp
from app.services.payment_service import create_payment, hydrate_payment, list_payments, review_payment, submit_payment_for_review
from app.services.post_service import create_post, get_post, hydrate_post, list_posts, update_post
from app.services.support_service import add_message, create_conversation, get_conversation, list_conversations, set_status

BASE_DIR = Path(__file__).resolve().parent
PRIVATE_UPLOAD_DIR = BASE_DIR / "private_uploads" / "payment_proofs"
PRIVATE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="GovPay", description="Government utility payment portal")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key, max_age=settings.session_max_age_seconds, https_only=settings.secure_cookies, same_site="lax")


@app.get("/static/uploads/{path:path}")
def block_public_uploads(path: str):
    raise HTTPException(404, "Upload not found")


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.on_event("startup")
def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


def context(request: Request, **values):
    user = None
    unread_notifications = 0
    user_id = request.session.get("user_id")
    if user_id:
        with SessionLocal() as db:
            if not is_persistent_auth_session_valid(db, request.session.get("auth_session_id"), user_id):
                user_id = None
            user = db.get(User, user_id) if user_id else None
            if user:
                hydrate_user(user)
                unread_notifications = db.query(Notification).filter(Notification.user_id == user.id, Notification.is_read.is_(False)).count()
    return {"request": request, "user": user, "unread_notifications": unread_notifications, "csrf_token": csrf_token(request), **values}


def current_user(request: Request, db: Session) -> User:
    user_id = request.session.get("user_id")
    if not is_persistent_auth_session_valid(db, request.session.get("auth_session_id"), user_id or 0):
        request.session.clear()
        raise HTTPException(status_code=401, detail="Authentication required")
    user = db.get(User, user_id) if user_id else None
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Authentication required")
    hydrate_user(user)
    return user


def require_role(request: Request, db: Session, *roles: UserRole) -> User:
    user = current_user(request, db)
    if user.role not in roles:
        raise HTTPException(status_code=403, detail="Access denied")
    return user


def form_error(request: Request, message: str, template: str, **values):
    return templates.TemplateResponse(template, context(request, error=message, **values), status_code=400)


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return templates.TemplateResponse("landing.html", context(request))


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", context(request))


@app.post("/register")
def register(request: Request, full_name: str = Form(...), username: str = Form(...), email: str = Form(...), phone: str = Form(""), address: str = Form(""), password: str = Form(...), confirm_password: str = Form(...), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    if password != confirm_password:
        return form_error(request, "Passwords do not match.", "register.html")
    try:
        data = RegistrationInput(full_name=full_name, username=username, email=email, phone=phone, address=address, password=password, role="Citizen")
        register_user(db, **data.model_dump())
    except (ValidationError, ValueError) as exc:
        return form_error(request, str(exc), "register.html")
    return RedirectResponse("/login?registered=1", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", context(request, registered=request.query_params.get("registered")))


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    user = authenticate(db, username, password)
    if not user:
        return form_error(request, "Invalid username or password.", "login.html")
    if not can_issue_persistent(db, user.id):
        return form_error(request, "Too many verification attempts. Try again later.", "login.html")
    otp = generate_otp()
    if not deliver_otp(user.email, otp):
        return form_error(request, "Verification delivery is temporarily unavailable. Try again later.", "login.html")
    session_id = remember_issue_persistent(db, user.id, otp)
    request.session["pending_session"] = session_id
    request.session["pending_user_id"] = user.id
    return RedirectResponse("/otp", status_code=303)


@app.get("/otp", response_class=HTMLResponse)
def otp_page(request: Request):
    if not request.session.get("pending_session"):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("otp.html", context(request))


@app.post("/otp")
def verify_otp(request: Request, otp: str = Form(...), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    session_id = request.session.get("pending_session")
    user_id = request.session.get("pending_user_id")
    if not verify_persistent(db, session_id, user_id or 0, otp):
        return form_error(request, "The OTP is invalid or expired.", "otp.html")
    user = db.get(User, user_id)
    if not user:
        return RedirectResponse("/login", status_code=303)
    auth_session_id = create_persistent_auth_session(db, user.id, datetime.now(timezone.utc) + timedelta(seconds=settings.session_max_age_seconds))
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["auth_session_id"] = auth_session_id
    consume_persistent(db, session_id)
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    revoke_persistent_auth_session(db, request.session.get("auth_session_id"))
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if user.role == UserRole.ADMIN:
        return RedirectResponse("/admin", status_code=303)
    bills = list_bills(db, user.id)
    for bill in bills:
        refresh_overdue(bill)
    db.commit()
    payments = list_payments(db, user.id)[:5]
    stats = {"total": len(bills), "pending": sum(bill.status == BillStatus.PENDING for bill in bills), "paid": sum(bill.status == BillStatus.PAID for bill in bills), "overdue": sum(bill.status == BillStatus.OVERDUE for bill in bills)}
    return templates.TemplateResponse("dashboard.html", context(request, bills=bills, payments=payments, stats=stats))


@app.get("/bills", response_class=HTMLResponse)
def bills_page(request: Request, status_filter: str | None = None, db: Session = Depends(get_db)):
    user = current_user(request, db)
    bills = list_bills(db, user.id, status_filter)
    for bill in bills:
        refresh_overdue(bill)
    db.commit()
    return templates.TemplateResponse("bills.html", context(request, bills=bills, active_filter=status_filter or "All"))


@app.get("/bills/{bill_id}", response_class=HTMLResponse)
def bill_detail(request: Request, bill_id: int, db: Session = Depends(get_db)):
    user = current_user(request, db)
    bill = get_bill(db, bill_id, user.id)
    if not bill:
        raise HTTPException(404, "Bill not found")
    refresh_overdue(bill)
    db.commit()
    return templates.TemplateResponse("bill_detail.html", context(request, bill=bill))


@app.get("/payments/{bill_id}", response_class=HTMLResponse)
def payment_page(request: Request, bill_id: int, db: Session = Depends(get_db)):
    user = current_user(request, db)
    bill = get_bill(db, bill_id, user.id)
    if not bill:
        raise HTTPException(404, "Bill not found")
    return templates.TemplateResponse("payment_form.html", context(request, bill=bill))


@app.post("/payments/{bill_id}")
async def make_payment(request: Request, bill_id: int, payment_method: str = Form(...), proof_text: str = Form(""), proof_image: UploadFile | None = File(None), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    user = current_user(request, db)
    bill = get_bill(db, bill_id, user.id)
    if not bill:
        raise HTTPException(404, "Bill not found")
    try:
        method = PaymentInput(payment_method=payment_method).payment_method
        if not proof_text.strip() and not proof_image:
            raise ValueError("Provide copied bill text or upload a bill image")
        image_path = ""
        if proof_image and proof_image.filename:
            suffix = Path(proof_image.filename).suffix.lower()
            if suffix not in {".png", ".jpg", ".jpeg", ".webp"}:
                raise ValueError("Proof image must be PNG, JPG, JPEG, or WEBP")
            content = await proof_image.read()
            if len(content) > 5 * 1024 * 1024:
                raise ValueError("Proof image must be 5 MB or smaller")
            stored_name = f"{token_hex(16)}{suffix}.enc"
            (PRIVATE_UPLOAD_DIR / stored_name).write_text(encrypt_ecc_bytes(content), encoding="utf-8")
            image_path = stored_name
        submit_payment_for_review(db, bill, user.id, method, proof_text, image_path)
    except (ValidationError, ValueError) as exc:
        return form_error(request, str(exc), "payment_form.html", bill=bill)
    return RedirectResponse("/payments?submitted=1", status_code=303)


@app.get("/payments", response_class=HTMLResponse)
def payments_page(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    return templates.TemplateResponse("payments.html", context(request, payments=list_payments(db, user.id), submitted=request.query_params.get("submitted")))


@app.get("/payments/receipt/{payment_id}", response_class=HTMLResponse)
def receipt(request: Request, payment_id: int, db: Session = Depends(get_db)):
    user = current_user(request, db)
    payment = db.scalar(select(Payment).where(Payment.id == payment_id, Payment.user_id == user.id))
    hydrate_payment(payment)
    if not payment:
        raise HTTPException(404, "Payment not found")
    return templates.TemplateResponse("receipt.html", context(request, payment=payment))


@app.get("/payment-proofs/{payment_id}")
def payment_proof(request: Request, payment_id: int, db: Session = Depends(get_db)):
    user = current_user(request, db)
    payment = db.get(Payment, payment_id)
    if not payment:
        raise HTTPException(404, "Payment not found")
    hydrate_payment(payment)
    if payment.user_id != user.id and user.role != UserRole.ADMIN:
        raise HTTPException(403, "Access denied")
    file_name = payment.verification.proof_image_path if payment.verification else ""
    if not file_name or Path(file_name).name != file_name:
        raise HTTPException(404, "Proof image not found")
    encrypted_path = PRIVATE_UPLOAD_DIR / file_name
    if not encrypted_path.is_file():
        raise HTTPException(404, "Proof image not found")
    try:
        content = decrypt_ecc_bytes(encrypted_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(404, "Proof image unavailable")
    suffix = Path(file_name).stem.lower()
    media_type = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}.get(Path(suffix).suffix, "application/octet-stream")
    return Response(content=content, media_type=media_type)


@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("profile.html", context(request, profile_user=current_user(request, db)))


@app.post("/profile")
def update_profile(request: Request, full_name: str = Form(...), phone: str = Form(""), address: str = Form(""), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    user = current_user(request, db)
    user.full_name, user.phone, user.address = full_name.strip(), phone.strip(), address.strip()
    user.encrypted_profile = encrypt_user_profile(username=user.username, email=user.email, full_name=user.full_name, phone=user.phone, address=user.address)
    db.commit()
    return RedirectResponse("/profile?saved=1", status_code=303)


@app.get("/notifications")
def notifications(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    items = list_notifications(db, user.id)
    return templates.TemplateResponse("notifications.html", context(request, notifications=items))




@app.get("/notifications/{notification_id}/open")
def open_notification(request: Request, notification_id: int, db: Session = Depends(get_db)):
    user = current_user(request, db)

    notification = db.scalar(
        select(Notification).where(
            Notification.id == notification_id,
            Notification.user_id == user.id
        )
    )

    if not notification:
        raise HTTPException(404, "Notification not found")

    hydrate_notification(notification)
    notification.is_read = True
    db.commit()

    return RedirectResponse(notification.link or "/notifications", status_code=303)

@app.get("/posts", response_class=HTMLResponse)
def posts_page(request: Request, db: Session = Depends(get_db)):
    current_user(request, db)
    return templates.TemplateResponse("posts.html", context(request, posts=list_posts(db)))


@app.get("/posts/create", response_class=HTMLResponse)
def create_post_page(request: Request, db: Session = Depends(get_db)):
    current_user(request, db)
    return templates.TemplateResponse("post_form.html", context(request, post=None))


@app.post("/posts/create")
def create_post_route(request: Request, title: str = Form(...), content: str = Form(...), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    user = current_user(request, db)
    try:
        data = PostInput(title=title, content=content)
        create_post(db, user.id, data.title, data.content)
    except ValidationError as exc:
        return form_error(request, str(exc), "post_form.html", post=None)
    return RedirectResponse("/posts", status_code=303)


@app.get("/posts/{post_id}/edit", response_class=HTMLResponse)
def edit_post_page(request: Request, post_id: int, db: Session = Depends(get_db)):
    user = current_user(request, db)
    post = get_post(db, post_id)
    if not post:
        raise HTTPException(404, "Post not found")
    if post.user_id != user.id and user.role != UserRole.ADMIN:
        raise HTTPException(403, "Access denied")
    return templates.TemplateResponse("post_form.html", context(request, post=post))


@app.post("/posts/{post_id}/edit")
def edit_post_route(request: Request, post_id: int, title: str = Form(...), content: str = Form(...), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    user = current_user(request, db)
    post = get_post(db, post_id)
    if not post:
        raise HTTPException(404, "Post not found")
    if post.user_id != user.id and user.role != UserRole.ADMIN:
        raise HTTPException(403, "Access denied")
    try:
        data = PostInput(title=title, content=content)
        update_post(db, post, data.title, data.content)
    except ValidationError as exc:
        return form_error(request, str(exc), "post_form.html", post=post)
    return RedirectResponse("/posts", status_code=303)


@app.post("/posts/{post_id}/delete")
def delete_post(request: Request, post_id: int, csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    user = current_user(request, db)
    post = get_post(db, post_id)
    if not post:
        raise HTTPException(404, "Post not found")
    if post.user_id != user.id and user.role != UserRole.ADMIN:
        raise HTTPException(403, "Access denied")
    db.delete(post)
    db.commit()
    return RedirectResponse("/posts", status_code=303)


@app.get("/support", response_class=HTMLResponse)
def support_page(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    return templates.TemplateResponse("support.html", context(request, conversations=list_conversations(db, user.id)))


@app.post("/support")
def create_support(request: Request, subject: str = Form(...), message: str = Form(...), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    user = current_user(request, db)
    try:
        data = SupportInput(subject=subject, message=message)
        conversation = create_conversation(db, user.id, data.subject, data.message)
    except ValidationError as exc:
        return form_error(request, str(exc), "support.html", conversations=list_conversations(db, user.id))
    return RedirectResponse(f"/support/{conversation.id}", status_code=303)


@app.get("/support/{conversation_id}", response_class=HTMLResponse)
def support_chat(request: Request, conversation_id: int, db: Session = Depends(get_db)):
    user = current_user(request, db)
    conversation = get_conversation(db, conversation_id)
    if not conversation or (conversation.user_id != user.id and user.role != UserRole.ADMIN):
        raise HTTPException(404, "Conversation not found")
    return templates.TemplateResponse("support_chat.html", context(request, conversation=conversation))


@app.post("/support/{conversation_id}/message")
def support_message(request: Request, conversation_id: int, message: str = Form(...), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    user = current_user(request, db)
    conversation = get_conversation(db, conversation_id)
    if not conversation or (conversation.user_id != user.id and user.role != UserRole.ADMIN):
        raise HTTPException(404, "Conversation not found")
    add_message(db, conversation, user.id, message.strip())
    return RedirectResponse(f"/support/{conversation_id}", status_code=303)


@app.post("/support/{conversation_id}/status")
def support_status(request: Request, conversation_id: int, conversation_status: str = Form(...), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    user = require_role(request, db, UserRole.ADMIN)
    conversation = get_conversation(db, conversation_id)
    if not conversation:
        raise HTTPException(404, "Conversation not found")
    if conversation_status not in {item.value for item in ConversationStatus}:
        raise HTTPException(400, "Invalid conversation status")
    set_status(db, conversation, ConversationStatus(conversation_status))
    return RedirectResponse(f"/support/{conversation_id}", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    require_role(request, db, UserRole.ADMIN)
    stats = {"users": db.scalar(select(func.count(User.id))), "bills": db.scalar(select(func.count(Bill.id))), "payments": db.scalar(select(func.count(Payment.id))), "successful": db.scalar(select(func.count(Payment.id)).where(Payment.status == "SUCCESSFUL")), "open_support": db.scalar(select(func.count(SupportConversation.id)).where(SupportConversation.status == "OPEN"))}
    return templates.TemplateResponse("admin/dashboard.html", context(request, stats=stats))


@app.get("/admin/bills", response_class=HTMLResponse)
def admin_bills(request: Request, db: Session = Depends(get_db)):
    require_role(request, db, UserRole.ADMIN)
    citizens = list(db.scalars(select(User).where(User.role == UserRole.CITIZEN, User.is_active.is_(True)).order_by(User.username)))
    for citizen in citizens:
        hydrate_user(citizen)
    bills = list(db.scalars(select(Bill).order_by(Bill.created_at.desc()).limit(100)))
    for bill in bills:
        hydrate_bill(bill)
        hydrate_user(bill.user)
    return templates.TemplateResponse("admin/bills.html", context(request, citizens=citizens, bills=bills, bill_types=BILL_TYPES))


@app.post("/admin/bills")
def admin_create_bill(request: Request, bill_type: str = Form(...), title: str = Form(...), description: str = Form(""), amount: str = Form(...), due_date: date = Form(...), scope: str = Form(...), citizen_id: str = Form(""), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    admin = require_role(request, db, UserRole.ADMIN)
    try:
        selected_citizen_id = int(citizen_id) if citizen_id.strip() else None
        created = create_bill(db, admin_id=admin.id, bill_type=bill_type, title=title.strip(), description=description.strip(), amount=Decimal(amount), due_date=due_date, scope=scope, citizen_id=selected_citizen_id)
    except (ValueError, InvalidOperation) as exc:
        citizens = list(db.scalars(select(User).where(User.role == UserRole.CITIZEN, User.is_active.is_(True)).order_by(User.username)))
        for citizen in citizens:
            hydrate_user(citizen)
        return form_error(request, str(exc), "admin/bills.html", citizens=citizens, bills=list(db.scalars(select(Bill).order_by(Bill.created_at.desc()).limit(100))), bill_types=BILL_TYPES)
    return RedirectResponse(f"/admin/bills?created={len(created)}", status_code=303)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, db: Session = Depends(get_db)):
    require_role(request, db, UserRole.ADMIN)
    users = list(db.scalars(select(User).order_by(User.created_at.desc())))
    for item in users:
        hydrate_user(item)
    return templates.TemplateResponse("admin/users.html", context(request, users=users))


@app.post("/admin/users")
def admin_create_user(request: Request, full_name: str = Form(...), username: str = Form(...), email: str = Form(...), password: str = Form(...), role: str = Form("Citizen"), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    require_role(request, db, UserRole.ADMIN)
    try:
        data = RegistrationInput(full_name=full_name, username=username, email=email, phone="", address="", password=password, role=role)
        register_user(db, **data.model_dump())
    except (ValidationError, ValueError) as exc:
        return form_error(request, str(exc), "admin/users.html", users=list(db.scalars(select(User).order_by(User.created_at.desc()))))
    return RedirectResponse("/admin/users?created=1", status_code=303)


@app.post("/admin/users/{user_id}/delete")
def admin_delete_user(request: Request, user_id: int, csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    admin = require_role(request, db, UserRole.ADMIN)
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        return form_error(request, "You cannot delete your own admin account.", "admin/users.html", users=list(db.scalars(select(User).order_by(User.created_at.desc()))))
    delete_user(db, user)
    return RedirectResponse("/admin/users?deleted=1", status_code=303)


@app.get("/admin/payments", response_class=HTMLResponse)
def admin_payments(request: Request, db: Session = Depends(get_db)):
    require_role(request, db, UserRole.ADMIN)
    payments = list_payments(db)
    for payment in payments:
        hydrate_user(payment.user)
    return templates.TemplateResponse("admin/payments.html", context(request, payments=payments))


@app.get("/admin/support", response_class=HTMLResponse)
def admin_support(request: Request, db: Session = Depends(get_db)):
    require_role(request, db, UserRole.ADMIN)
    return templates.TemplateResponse("admin/support.html", context(request, conversations=list_conversations(db)))


@app.get("/admin/verifications", response_class=HTMLResponse)
def admin_verifications(request: Request, db: Session = Depends(get_db)):
    require_role(request, db, UserRole.ADMIN)
    verifications = list(db.scalars(select(Payment).where(Payment.status == PaymentStatus.PENDING).order_by(Payment.created_at.desc())))
    for payment in verifications:
        hydrate_payment(payment)
    return templates.TemplateResponse("admin/verifications.html", context(request, payments=verifications))


@app.get("/admin/verifications/{payment_id}")
def admin_verification_link(request: Request, payment_id: int, db: Session = Depends(get_db)):
    require_role(request, db, UserRole.ADMIN)
    if not db.get(Payment, payment_id):
        raise HTTPException(404, "Payment not found")
    return RedirectResponse("/admin/verifications", status_code=303)


@app.post("/admin/verifications/{payment_id}")
def admin_review_verification(request: Request, payment_id: int, decision: str = Form(...), reviewer_note: str = Form(""), csrf_token_value: str = Form(..., alias="csrf_token"), db: Session = Depends(get_db)):
    validate_csrf(request, csrf_token_value)
    admin = require_role(request, db, UserRole.ADMIN)
    payment = db.get(Payment, payment_id)
    if not payment:
        raise HTTPException(404, "Payment not found")
    review_payment(db, payment, admin.id, decision == "approve", reviewer_note)
    return RedirectResponse("/admin/verifications", status_code=303)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "GovPay"}


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException):
    page = {401: "401.html", 403: "403.html", 404: "404.html"}.get(exc.status_code)
    if page:
        return templates.TemplateResponse(f"errors/{page}", context(request, message=exc.detail), status_code=exc.status_code)
    return HTMLResponse(str(exc.detail), status_code=exc.status_code)


@app.exception_handler(Exception)
async def server_error_handler(request: Request, exc: Exception):
    return templates.TemplateResponse("errors/500.html", context(request), status_code=500)
