"""
تشفير عند السكون لحقول قاعدة بيانات الخادم الحسّاسة (مفاتيح التراخيص
بشكل أساسي). يستخدم Fernet (AES) بمفتاح يُولَّد محليًا ويُخزَّن في ملف
منفصل داخل data/ — هذا يحمي من قراءة ملف قاعدة البيانات مباشرة (SQLite
file) أو نسخة احتياطية منها دون صلاحية الوصول لمفتاح التشفير، وليس بديلًا
عن تأمين الوصول للخادم نفسه.
"""
from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import String
from sqlalchemy.types import TypeDecorator

from server.app.core.config import settings

_KEY_PATH = Path(settings.database_url.split("///")[-1]).parent / "db_encryption.key" \
    if settings.database_url.startswith("sqlite") else Path("./data/db_encryption.key")


def _load_or_create_key() -> bytes:
    _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _KEY_PATH.exists():
        return _KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    _KEY_PATH.write_bytes(key)
    return key


_fernet = Fernet(_load_or_create_key())


class EncryptedString(TypeDecorator):
    """عمود نصّي يُشفَّر تلقائيًا قبل الكتابة ويُفكّ تلقائيًا عند القراءة -
    شفّاف تمامًا لبقية الكود، يُستخدم تمامًا مثل String العادي."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        return _fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def process_result_value(self, value: str | None, dialect) -> str | None:
        if value is None:
            return None
        try:
            return _fernet.decrypt(value.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            # بيانات قديمة غير مشفَّرة (قبل تفعيل هذا التشفير) أو تالفة -
            # نُرجعها كما هي بدل تعطّل الاستعلام بالكامل
            return value
