from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "GovPay"
    app_secret_key: str = "development-secret-change-me"
    session_secret_key: str = "development-session-secret-change-me"
    database_url: str = "postgresql+psycopg://govpay_user:change-this@127.0.0.1:5432/govpay"
    crypto_mac_secret: str = "set-a-long-random-crypto-mac-secret"
    kms_path: str = ".govpay-kms.json"
    debug: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
