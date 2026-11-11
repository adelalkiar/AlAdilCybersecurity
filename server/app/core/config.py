"""إعدادات الخادم المركزي، قابلة للتجاوز عبر متغيرات البيئة."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ALADIL_", env_file=".env")

    app_name: str = "AlAdil Cybersecurity"
    database_url: str = "sqlite:///./data/aladil.db"
    jwt_secret: str = "CHANGE_ME_IN_PRODUCTION"  # يجب تجاوزه عبر ALADIL_JWT_SECRET
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 8

    # مفتاح NVD API (اختياري) لرفع حد طلبات مطابقة الثغرات
    nvd_api_key: str | None = None

    # مفتاح التوقيع الخاص بتراخيص العملاء (Ed25519 PEM) - يُولَّد عبر
    # server/app/services/license_service.py::generate_signing_key
    license_private_key_path: str = "./data/license_signing_key.pem"
    license_public_key_path: str = "./data/license_signing_key.pub"

    cors_allow_origins: list[str] = ["http://localhost:5173", "http://localhost:8000"]


settings = Settings()
