"""
سجل أحداث الخادم كسلسلة تجزئة (عدم الإنكار والمساءلة - الفصل 1): كل حدث
مهم على الخادم (تسجيل دخول، إصدار ترخيص، استقبال تقرير فحص) يُضاف كسطر
مربوط بتجزئة السطر السابق، فأي حذف أو تعديل يُكتشَف عبر verify.

يستخدم نفس وحدة shared.integrity المشتركة مع سجل تفويض العميل.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from server.app.core.config import settings
from shared.integrity import append_entry, verify_chain

# نضع السجل بجانب قاعدة البيانات (داخل data/ المستبعد من git)
if settings.database_url.startswith("sqlite"):
    _DATA_DIR = Path(settings.database_url.split("///")[-1]).parent
else:
    _DATA_DIR = Path("./data")

SERVER_EVENTS_PATH = _DATA_DIR / "server_events.log"


def record_event(event_type: str, detail: dict | None = None, actor: str = "") -> dict:
    """يضيف حدثًا موقَّتًا للسلسلة. أمثلة event_type: login, license_issued,
    scan_received. detail: حقول إضافية غير حسّاسة فقط."""
    return append_entry(
        SERVER_EVENTS_PATH,
        {"event": event_type, "actor": actor, "detail": detail or {}},
        timestamp=datetime.utcnow().isoformat() + "Z",
    )


def verify_server_events() -> dict:
    return verify_chain(SERVER_EVENTS_PATH)
