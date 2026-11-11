"""تراخيص العملاء الصادرة لكل عميل/جهاز (License + Activation)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from server.app.core.crypto import EncryptedString
from server.app.db.database import Base


class License(Base):
    __tablename__ = "licenses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # الحقول التالية تخص العميل مباشرة (اسم/بريد/رمز ترخيص) فتُشفَّر عند
    # السكون؛ لا يوجد فهرس unique عليها بعد التشفير لأن كل تشفير يُنتج
    # نصًا مختلفًا حتى لنفس القيمة (IV عشوائي) - البحث يتم بفك التشفير
    # في طبقة التطبيق عند الحاجة، وليس عبر استعلام SQL مباشر على القيمة.
    license_key: Mapped[str] = mapped_column(EncryptedString(2048))
    customer_name: Mapped[str] = mapped_column(EncryptedString(512))
    customer_email: Mapped[str] = mapped_column(EncryptedString(512))
    max_agents: Mapped[int] = mapped_column(Integer, default=1)
    activated_agents_count: Mapped[int] = mapped_column(Integer, default=0)
    issued_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
