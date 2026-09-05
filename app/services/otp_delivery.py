import smtplib
from email.message import EmailMessage

from app.core.config import settings


def deliver_otp(recipient: str, code: str) -> bool:
    if settings.otp_delivery_mode.lower() == "console" and settings.debug:
        print(f"[GovPay dev OTP] {recipient}: {code}")
        return True
    if settings.otp_delivery_mode.lower() != "smtp" or not settings.smtp_host or not settings.smtp_from:
        return False
    message = EmailMessage()
    message["Subject"] = "GovPay sign-in verification code"
    message["From"] = settings.smtp_from
    message["To"] = recipient
    message.set_content(f"Your GovPay verification code is {code}. It expires in five minutes.")
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as connection:
            connection.starttls()
            if settings.smtp_username and settings.smtp_password:
                connection.login(settings.smtp_username, settings.smtp_password)
            connection.send_message(message)
    except (OSError, smtplib.SMTPException):
        return False
    return True