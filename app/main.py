from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import settings
from app.core.database import Base, SessionLocal, engine, get_db
from app.core.security import new_session_id
from app.crypto.otp import generate_otp, verify_two_step
from app.models import Bill, Payment, Post, SupportConversation, User
from app.models.entities import BillStatus, ConversationStatus, UserRole
from app.schemas.bill import PaymentInput
from app.schemas.post import PostInput
from app.schemas.support import SupportInput
from app.schemas.user import RegistrationInput
from app.services.auth_service import authenticate, register_user
from app.services.bill_service import get_bill, list_bills, refresh_overdue
from app.services.payment_service import create_payment, list_payments
from app.services.post_service import create_post, get_post, list_posts, update_post
from app.services.support_service import add_message, create_conversation, get_conversation, list_conversations, set_status

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="GovPay", description="Government utility payment portal")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key, https_only=False, same_site="lax")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
otp_store: dict[str, tuple[str, datetime]] = {}


@app.on_event("startup")
def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


def context(request: Request, **values):
    user = None
    user_id = request.session.get("user_id")
    if user_id:
        with SessionLocal() as db:
            user = db.get(User, user_id)
    return {"request": request, "user": user, **values}


def current_user(request: Request, db: Session) -> User:
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if user_id else None
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Authentication required")
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
def register(request: Request, full_name: str = Form(...), username: str = Form(...), email: str = Form(...), phone: str = Form(""), address: str = Form(""), password: str = Form(...), confirm_password: str = Form(...), db: Session = Depends(get_db)):
    if password != confirm_password:
        return form_error(request, "Passwords do not match.", "register.html")
    try:
        data = RegistrationInput(full_name=full_name, username=username, email=email, phone=phone, address=address, password=password)
        register_user(db, **data.model_dump())
    except (ValidationError, ValueError) as exc:
        return form_error(request, str(exc), "register.html")
    return RedirectResponse("/login?registered=1", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", context(request, registered=request.query_params.get("registered")))


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = authenticate(db, username, password)
    if not user:
        return form_error(request, "Invalid username or password.", "login.html")
    session_id = new_session_id()
    otp = generate_otp()
    otp_store[session_id] = (otp, datetime.now(timezone.utc) + timedelta(minutes=5))
    request.session["pending_session"] = session_id
    request.session["pending_user_id"] = user.id
    print(f"[GovPay development OTP] {user.username}: {otp}")
    return RedirectResponse("/otp", status_code=303)


@app.get("/otp", response_class=HTMLResponse)
def otp_page(request: Request):
    if not request.session.get("pending_session"):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("otp.html", context(request))


@app.post("/otp")
def verify_otp(request: Request, otp: str = Form(...), db: Session = Depends(get_db)):
    session_id = request.session.get("pending_session")
    record = otp_store.get(session_id)
    if not record or not verify_two_step(True, otp, record[0], record[1]):
        return form_error(request, "The OTP is invalid or expired.", "otp.html")
    user = db.get(User, request.session.get("pending_user_id"))
    if not user:
        return RedirectResponse("/login", status_code=303)
    request.session.clear()
    request.session["user_id"] = user.id
    otp_store.pop(session_id, None)
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request):
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
def make_payment(request: Request, bill_id: int, payment_method: str = Form(...), db: Session = Depends(get_db)):
    user = current_user(request, db)
    bill = get_bill(db, bill_id, user.id)
    if not bill:
        raise HTTPException(404, "Bill not found")
    try:
        method = PaymentInput(payment_method=payment_method).payment_method
        payment = create_payment(db, bill, user.id, method)
    except (ValidationError, ValueError) as exc:
        return form_error(request, str(exc), "payment_form.html", bill=bill)
    return RedirectResponse(f"/payments/receipt/{payment.id}", status_code=303)


@app.get("/payments", response_class=HTMLResponse)
def payments_page(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    return templates.TemplateResponse("payments.html", context(request, payments=list_payments(db, user.id)))


@app.get("/payments/receipt/{payment_id}", response_class=HTMLResponse)
def receipt(request: Request, payment_id: int, db: Session = Depends(get_db)):
    user = current_user(request, db)
    payment = db.scalar(select(Payment).where(Payment.id == payment_id, Payment.user_id == user.id))
    if not payment:
        raise HTTPException(404, "Payment not found")
    return templates.TemplateResponse("receipt.html", context(request, payment=payment))


@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("profile.html", context(request, profile_user=current_user(request, db)))


@app.post("/profile")
def update_profile(request: Request, full_name: str = Form(...), phone: str = Form(""), address: str = Form(""), db: Session = Depends(get_db)):
    user = current_user(request, db)
    user.full_name, user.phone, user.address = full_name.strip(), phone.strip(), address.strip()
    db.commit()
    return RedirectResponse("/profile?saved=1", status_code=303)


@app.get("/posts", response_class=HTMLResponse)
def posts_page(request: Request, db: Session = Depends(get_db)):
    current_user(request, db)
    return templates.TemplateResponse("posts.html", context(request, posts=list_posts(db)))


@app.get("/posts/create", response_class=HTMLResponse)
def create_post_page(request: Request, db: Session = Depends(get_db)):
    current_user(request, db)
    return templates.TemplateResponse("post_form.html", context(request, post=None))


@app.post("/posts/create")
def create_post_route(request: Request, title: str = Form(...), content: str = Form(...), db: Session = Depends(get_db)):
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
def edit_post_route(request: Request, post_id: int, title: str = Form(...), content: str = Form(...), db: Session = Depends(get_db)):
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
def delete_post(request: Request, post_id: int, db: Session = Depends(get_db)):
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
def create_support(request: Request, subject: str = Form(...), message: str = Form(...), db: Session = Depends(get_db)):
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
def support_message(request: Request, conversation_id: int, message: str = Form(...), db: Session = Depends(get_db)):
    user = current_user(request, db)
    conversation = get_conversation(db, conversation_id)
    if not conversation or (conversation.user_id != user.id and user.role != UserRole.ADMIN):
        raise HTTPException(404, "Conversation not found")
    add_message(db, conversation, user.id, message.strip())
    return RedirectResponse(f"/support/{conversation_id}", status_code=303)


@app.post("/support/{conversation_id}/status")
def support_status(request: Request, conversation_id: int, conversation_status: str = Form(...), db: Session = Depends(get_db)):
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


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, db: Session = Depends(get_db)):
    require_role(request, db, UserRole.ADMIN)
    return templates.TemplateResponse("admin/users.html", context(request, users=list(db.scalars(select(User).order_by(User.created_at.desc())))))


@app.get("/admin/payments", response_class=HTMLResponse)
def admin_payments(request: Request, db: Session = Depends(get_db)):
    require_role(request, db, UserRole.ADMIN)
    return templates.TemplateResponse("admin/payments.html", context(request, payments=list_payments(db)))


@app.get("/admin/support", response_class=HTMLResponse)
def admin_support(request: Request, db: Session = Depends(get_db)):
    require_role(request, db, UserRole.ADMIN)
    return templates.TemplateResponse("admin/support.html", context(request, conversations=list_conversations(db)))


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
