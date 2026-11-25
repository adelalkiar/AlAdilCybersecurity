"""
نظام التراخيص ورموز التفعيل.

يستخدم توقيعًا رقميًا Ed25519 بدلًا من سلسلة عشوائية بسيطة، بحيث يمكن
لعميل (Agent) غير متصل بالإنترنت أن يتحقق محليًا من صحة مفتاح الترخيص دون
الحاجة لطلب شبكي للخادم (التحقق بالمفتاح العام المضمَّن في حزمة التثبيت)،
بينما يبقى التفعيل الفعلي (ربط الترخيص بعدد الأجهزة المسموح بها) من
مسؤولية الخادم المركزي.

صيغة مفتاح الترخيص: base64(payload_json) + "." + base64(signature)
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from server.app.core.config import settings


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def ensure_signing_key() -> Ed25519PrivateKey:
    """يولّد زوج مفاتيح توقيع جديد إن لم يكن موجودًا مسبقًا، ويحفظه محليًا."""
    priv_path = Path(settings.license_private_key_path)
    pub_path = Path(settings.license_public_key_path)
    priv_path.parent.mkdir(parents=True, exist_ok=True)

    if priv_path.exists():
        priv_bytes = priv_path.read_bytes()
        return serialization.load_pem_private_key(priv_bytes, password=None)

    private_key = Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    return private_key


def load_public_key() -> Ed25519PublicKey:
    pub_bytes = Path(settings.license_public_key_path).read_bytes()
    return serialization.load_pem_public_key(pub_bytes)


def sign_payload(data: bytes) -> str:
    """يوقّع بايتات بمفتاح الخادم الخاص (Ed25519) ويرجع التوقيع كـ base64url.
    يُستخدم لتوقيع تقارير الفحص (عدم الإنكار - الفصل 1): يثبت أن الخادم
    شهد بهذا المحتوى في هذا الوقت، فلا يستطيع أحد إنكاره أو تزويره لاحقًا."""
    private_key = ensure_signing_key()
    return _b64e(private_key.sign(data))


def verify_payload(data: bytes, signature_b64: str) -> bool:
    """يتحقق من توقيع بايتات بالمفتاح العام. يرجع True إن كان صالحًا."""
    try:
        load_public_key().verify(_b64d(signature_b64), data)
        return True
    except Exception:  # noqa: BLE001  # أي فشل تحقق = توقيع غير صالح
        return False


# وحدات زمن صلاحية الترخيص المدعومة في واجهة النظام (دقيقة/ساعة/يوم/
# أسبوع/شهر/سنة) مع تحويلها إلى timedelta. الشهر والسنة تقديريان (30 و
# 365 يومًا) لعدم تعقيد الحساب بتقويم فعلي - دقيق بما يكفي لأغراض الترخيص.
DURATION_UNIT_SECONDS: dict[str, int] = {
    "minute": 60,
    "hour": 60 * 60,
    "day": 60 * 60 * 24,
    "week": 60 * 60 * 24 * 7,
    "month": 60 * 60 * 24 * 30,
    "year": 60 * 60 * 24 * 365,
}


def duration_to_timedelta(unit: str, count: int) -> timedelta:
    if unit not in DURATION_UNIT_SECONDS:
        raise ValueError(
            f"وحدة زمن غير معروفة: '{unit}'. الوحدات المدعومة: "
            f"{', '.join(DURATION_UNIT_SECONDS)}"
        )
    if count <= 0:
        raise ValueError("عدد وحدات الزمن يجب أن يكون أكبر من صفر")
    return timedelta(seconds=DURATION_UNIT_SECONDS[unit] * count)


def generate_license_key(
    customer_name: str,
    customer_email: str,
    max_agents: int = 1,
    duration_unit: str | None = "day",
    duration_count: int | None = 365,
) -> str:
    """
    duration_unit/duration_count: مدة صلاحية الترخيص بوحدة زمنية حرّة
    يختارها المستخدم من واجهة النظام (minute/hour/day/week/month/year +
    عدد، مثل "3 أشهر" أو "15 دقيقة" لترخيص تجريبي قصير جدًا). مرّر
    duration_unit=None لإصدار ترخيص بلا تاريخ انتهاء (دائم).
    """
    private_key = ensure_signing_key()
    expires_at = None
    if duration_unit:
        expires_at = (
            datetime.utcnow() + duration_to_timedelta(duration_unit, duration_count or 1)
        ).isoformat() + "Z"

    payload = {
        "customer_name": customer_name,
        "customer_email": customer_email,
        "max_agents": max_agents,
        "issued_at": datetime.utcnow().isoformat() + "Z",
        "expires_at": expires_at,
        "duration_unit": duration_unit,
        "duration_count": duration_count,
    }
    payload_bytes = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    signature = private_key.sign(payload_bytes)
    return f"ALADIL-{_b64e(payload_bytes)}.{_b64e(signature)}"


def verify_license_key(license_key: str) -> dict | None:
    """يتحقق من التوقيع ومن تاريخ الانتهاء، ويرجع بيانات الترخيص إن كان صالحًا."""
    try:
        body = license_key.removeprefix("ALADIL-")
        payload_b64, signature_b64 = body.split(".")
        payload_bytes = _b64d(payload_b64)
        signature = _b64d(signature_b64)

        public_key = load_public_key()
        public_key.verify(signature, payload_bytes)  # يرفع استثناء إن كان التوقيع غير صالح

        payload = json.loads(payload_bytes)
        expires_at = payload.get("expires_at")
        if expires_at and datetime.fromisoformat(expires_at.rstrip("Z")) < datetime.utcnow():
            return None
        return payload
    except Exception:  # noqa: BLE001  # أي خطأ تنسيق/تحقق = مفتاح غير صالح
        return None
