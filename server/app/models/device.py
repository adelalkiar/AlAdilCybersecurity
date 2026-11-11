"""نماذج قاعدة البيانات الخاصة بالأجهزة، الفحوصات، والثغرات."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from server.app.core.crypto import EncryptedString
from server.app.db.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(64))
    version: Mapped[str] = mapped_column(String(32))
    license_key: Mapped[str] = mapped_column(EncryptedString(2048))  # مشفَّر عند السكون
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    devices: Mapped[list["Device"]] = relationship(back_populates="agent")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"))

    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_guess: Mapped[str | None] = mapped_column(String(255), nullable=True)

    device_type: Mapped[str] = mapped_column(String(32), default="unknown")
    connection_medium: Mapped[str] = mapped_column(String(32), default="ethernet")
    signal_strength_dbm: Mapped[int | None] = mapped_column(Integer, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    access_likelihood_score: Mapped[float] = mapped_column(Float, default=0.0)
    potential_damage_score: Mapped[float] = mapped_column(Float, default=0.0)
    overall_threat_level: Mapped[str] = mapped_column(String(16), default="info")
    intruder_status: Mapped[str] = mapped_column(String(32), default="none")
    failed_connection_attempts: Mapped[int] = mapped_column(Integer, default=0)
    successful_connection_attempts: Mapped[int] = mapped_column(Integer, default=0)

    open_ports_json: Mapped[list] = mapped_column(JSON, default=list)
    exploitability_notes_json: Mapped[list] = mapped_column(JSON, default=list)
    is_unidentified: Mapped[bool] = mapped_column(default=False)

    # كشف انتحال الهوية: جهاز جديد (MAC مختلف) بدأ فجأة يستخدم اسم
    # مضيف كان يُستخدمه جهاز آخر موثوق سابقًا على نفس الشبكة
    identity_spoof_suspected: Mapped[bool] = mapped_column(default=False)
    identity_spoof_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # سلوك الوصول لجهاز النظام نفسه (الجهاز الذي يعمل عليه العميل):
    # هل حاول هذا الجهاز تسجيل الدخول إليه؟ هل نقل بيانات بحجم غير معتاد
    # منه (مؤشر نسخ/تسريب محتمل)؟
    accessed_host_system: Mapped[bool] = mapped_column(default=False)
    unusual_data_transfer_detected: Mapped[bool] = mapped_column(default=False)
    host_activity_notes_json: Mapped[list] = mapped_column(JSON, default=list)

    # ملاحظة يدوية حرة يضيفها المستخدم (تصنيف ثقة، تعليق تحقيق ...)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    agent: Mapped["Agent"] = relationship(back_populates="devices")
    vulnerabilities: Mapped[list["VulnerabilityRecord"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class VulnerabilityRecord(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))

    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    affected_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    affected_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    recommended_fix: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16), default="nvd")
    added_by_user: Mapped[bool] = mapped_column(default=False)
    added_by_username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    device: Mapped["Device"] = relationship(back_populates="vulnerabilities")


class ScanAuditLog(Base):
    """سجل تدقيق لكل عملية فحص هدف خارجي تم تفويضها (متطلب امتثالي)."""
    __tablename__ = "scan_audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(String(36))
    target: Mapped[str] = mapped_column(String(255))
    authorization_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    authorized_by_username: Mapped[str] = mapped_column(String(100))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
