from functools import lru_cache
import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "GovPay"
    app_secret_key: str | None = None
    session_secret_key: str | None = None
    database_url: str = "postgresql+psycopg://govpay_user:change-this@127.0.0.1:5432/govpay"
    crypto_mac_secret: str | None = None
    kms_path: str | None = None
    kms_wrap_public_key: str | None = None
    kms_wrap_private_key: str | None = None
    debug: bool = True
    secure_cookies: bool = False
    session_max_age_seconds: int = 1800
    environment: str = "development"
    otp_delivery_mode: str = "smtp"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def model_post_init(self, __context: object) -> None:
        if self.environment.lower() in {"production", "prod"}:
            missing = [name for name in ("app_secret_key", "session_secret_key", "crypto_mac_secret") if not getattr(self, name)]
            weak = [name for name in ("app_secret_key", "session_secret_key", "crypto_mac_secret") if getattr(self, name) and len(getattr(self, name) or "") < 32]
            if missing or weak or not self.secure_cookies or not self.kms_path or not self.kms_wrap_public_key or not self.kms_wrap_private_key or self.otp_delivery_mode.lower() != "smtp" or not self.smtp_host or not self.smtp_from:
                raise ValueError("Production requires strong secrets, secure cookies, RSA-wrapped KMS keys, and SMTP OTP delivery")
        self.app_secret_key = self.app_secret_key or secrets.token_urlsafe(48)
        self.session_secret_key = self.session_secret_key or secrets.token_urlsafe(48)
        self.crypto_mac_secret = self.crypto_mac_secret or secrets.token_urlsafe(48)
        self.kms_path = self.kms_path or ".govpay-kms.json"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
