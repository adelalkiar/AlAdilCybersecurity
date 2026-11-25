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
    # بصمة SHA-256 غير قابلة للعكس من مفتاح الترخيص، تُستخدم للمطابقة/العدّ
    # في استعلامات SQL (تشفير Fernet غير حتمي - IV عشوائي في كل مرة - فلا
    # يمكن مطابقة license_key المشفَّر مباشرة ضمن WHERE بشكل موثوق)
    license_key_hash: Mapped[str] = mapped_column(String(64), index=True, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # نتائج آخر فحص "برامج غير موقَّعة/متخفّية" على جهاز الوكيل نفسه (قراءة
    # فقط - بلا احتواء تلقائي) - قائمة UnsignedProgramFinding مُسلسَلة JSON
    unsigned_program_findings_json: Mapped[list] = mapped_column(JSON, default=list)
    # نتائج آخر تدقيق أمني للقراءة فقط على إعدادات حماية جهاز الوكيل
    security_audit_findings_json: Mapped[list] = mapped_column(JSON, default=list)
    # نتيجة آخر تدقيق جدار ناري (الفصل 3) - كائن FirewallAuditReport مُسلسَل
    firewall_audit_json: Mapped[dict] = mapped_column(JSON, default=dict)

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


class ScanReportRecord(Base):
    """
    سجل موقَّع رقميًا لكل تقرير فحص مستلَم - لتحقيق «عدم الإنكار» (الفصل 1):
    يحفظ الخادم بصمة محتوى التقرير + حمولة مشهادة موقَّعة بمفتاحه الخاص
    (Ed25519)، فيمكن لاحقًا التحقق أن الخادم شهد بهذا التقرير في هذا الوقت
    عبر /api/scans/{id}/verify، ولا يستطيع أحد إنكاره أو تزويره.
    """
    __tablename__ = "scan_report_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(String(36), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    content_hash: Mapped[str] = mapped_column(String(64))
    # الحمولة المشهادة الموقَّعة (JSON متعارف) + توقيعها
    signed_payload: Mapped[str] = mapped_column(Text)
    signature: Mapped[str] = mapped_column(Text)


class ScanAuditLog(Base):
    """سجل تدقيق لكل عملية فحص هدف خارجي تم تفويضها (متطلب امتثالي)."""
    __tablename__ = "scan_audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(String(36))
    target: Mapped[str] = mapped_column(String(255))
    authorization_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    authorized_by_username: Mapped[str] = mapped_column(String(100))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
