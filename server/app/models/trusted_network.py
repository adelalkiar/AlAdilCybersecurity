"""
"الأجهزة/الشبكات الموثوقة" - قائمة توثيقية يُدخلها المستخدم يدويًا من
لوحة التحكم عن الشبكات الفرعية أو الأجهزة التي يثق بها (مثل شبكة
المنزل أو مكتب الشركة)، لتسهيل مراجعتها لاحقًا عند إنشاء قواعد جدار
حماية يدويًا هو بنفسه.

هذا النظام **لا ينشئ ولا يعدّل أي قاعدة جدار حماية فعلية على أي جهاز** -
هذه قاعدة بيانات توثيقية بحتة؛ إنشاء القاعدة الفعلية في ويندوز (أو أي
نظام تشغيل) يبقى دائمًا فعلًا يدويًا يقوم به المستخدم بنفسه.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from server.app.db.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class TrustedNetworkEntry(Base):
    __tablename__ = "trusted_networks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    label: Mapped[str] = mapped_column(String(255))
    cidr_or_host: Mapped[str] = mapped_column(String(255))
    note: Mapped[str] = mapped_column(Text, default="")
    added_by_username: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
