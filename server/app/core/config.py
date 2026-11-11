"""إعدادات الخادم المركزي، قابلة للتجاوز عبر متغيرات البيئة."""
from __future__ import annotations

import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# ملف سر JWT المولَّد تلقائيًا عند عدم ضبط ALADIL_JWT_SECRET صراحةً - خارج
# data/ عمدًا (مجلد منفصل يُستبعد من النسخ الاحتياطي/المشاركة الاعتيادية
# لقاعدة البيانات)، حتى لا يُشارك سر الجلسات بالخطأ مع نسخة بيانات العملاء.
_AUTO_JWT_SECRET_PATH = Path("./secrets/jwt_secret.key")


def _load_or_create_jwt_secret() -> str:
    _AUTO_JWT_SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _AUTO_JWT_SECRET_PATH.exists():
        return _AUTO_JWT_SECRET_PATH.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(64)
    _AUTO_JWT_SECRET_PATH.write_text(secret, encoding="utf-8")
    return secret


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ALADIL_", env_file=".env")

    app_name: str = "AlAdil Cybersecurity"
    database_url: str = "sqlite:///./data/aladil.db"
    # لا قيمة افتراضية ثابتة هنا عمدًا (كانت "CHANGE_ME_IN_PRODUCTION" سابقًا
    # وهي ثغرة: أي نشر بلا ضبط ALADIL_JWT_SECRET كان يجعل سر توقيع الجلسات
    # معروفًا للجميع عبر قراءة الكود المصدري نفسه). الآن: إن لم يُضبط عبر
    # متغير البيئة، يُولَّد سر عشوائي محليًا مرة واحدة ويُحفظ للاستخدام
    # القادم - بلا أي قيمة قابلة للتخمين على الإطلاق.
    jwt_secret: str = ""
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
if not settings.jwt_secret:
    settings.jwt_secret = _load_or_create_jwt_secret()
