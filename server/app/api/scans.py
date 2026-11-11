"""
نقطة استقبال تقارير الفحص القادمة من العملاء (Agents). المصادقة هنا تتم
عبر مفتاح الترخيص (License Key) الموقَّع رقميًا، وليس جلسة JWT الخاصة
بلوحة التحكم، لأن العميل يعمل بشكل مستقل على جهاز المستخدم/العميل.
"""
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException
from sqlalchemy.orm import Session

from server.app.db.database import SessionLocal
from server.app.models.device import Agent, Device, ScanAuditLog, VulnerabilityRecord
from server.app.services.license_service import verify_license_key
from shared.models import ScanReport

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _authenticate_agent(x_license_key: str | None) -> dict:
    if not x_license_key:
        raise HTTPException(401, "رأس X-License-Key مطلوب")
    payload = verify_license_key(x_license_key)
    if not payload:
        raise HTTPException(401, "مفتاح الترخيص غير صالح أو منتهي")
    return payload


@router.post("/report")
def submit_scan_report(
    report: ScanReport,
    x_license_key: str | None = Header(default=None),
):
    _authenticate_agent(x_license_key)

    db: Session = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.id == report.agent_id).first()
        if not agent:
            agent = Agent(
                id=report.agent_id,
                hostname="unknown",
                platform="unknown",
                version="unknown",
                license_key=x_license_key or "",
            )
            db.add(agent)
        agent.last_seen = report.finished_at

        for scanned in report.devices:
            device = (
                db.query(Device)
                .filter(
                    Device.agent_id == report.agent_id,
                    Device.mac_address == scanned.fingerprint.mac_address,
                )
                .first()
                if scanned.fingerprint.mac_address
                else None
            )
            is_new_device = device is None
            if not device:
                device = Device(agent_id=report.agent_id)
                db.add(device)

            # كشف انتحال الهوية: جهاز جديد (MAC مختلف) بدأ يستخدم اسم
            # مضيف كان يُستخدمه جهاز آخر موثوق سابقًا على نفس الشبكة -
            # قد يكون المخترق سمّى جهازه باسم صديق/جهاز معروف ليبدو موثوقًا
            if is_new_device and scanned.fingerprint.hostname:
                conflicting = (
                    db.query(Device)
                    .filter(
                        Device.agent_id == report.agent_id,
                        Device.hostname == scanned.fingerprint.hostname,
                        Device.mac_address != scanned.fingerprint.mac_address,
                    )
                    .first()
                )
                if conflicting:
                    device.identity_spoof_suspected = True
                    device.identity_spoof_note = (
                        f"جهاز جديد (MAC: {scanned.fingerprint.mac_address}) يستخدم اسم "
                        f"المضيف '{scanned.fingerprint.hostname}' الذي كان مرتبطًا سابقًا "
                        f"بجهاز مختلف (MAC: {conflicting.mac_address}). تحقّق يدويًا قبل "
                        "الوثوق بهذا الجهاز - راجع قسم التحقّق من الهوية في التوثيق."
                    )

            device.ip_address = scanned.ip_address
            device.mac_address = scanned.fingerprint.mac_address
            device.vendor = scanned.fingerprint.vendor
            device.hostname = scanned.fingerprint.hostname
            device.os_guess = scanned.fingerprint.os_guess
            device.device_type = scanned.device_type.value
            device.connection_medium = scanned.connection_medium.value
            device.signal_strength_dbm = scanned.signal_strength_dbm
            device.last_seen = scanned.last_seen
            device.access_likelihood_score = scanned.access_likelihood_score
            device.potential_damage_score = scanned.potential_damage_score
            device.overall_threat_level = scanned.overall_threat_level.value
            device.intruder_status = scanned.intruder_status.value
            device.failed_connection_attempts = scanned.failed_connection_attempts
            device.successful_connection_attempts = scanned.successful_connection_attempts
            device.open_ports_json = [p.model_dump() for p in scanned.open_ports]
            device.exploitability_notes_json = scanned.exploitability_notes
            device.is_unidentified = scanned.is_unidentified
            device.accessed_host_system = scanned.accessed_host_system
            device.unusual_data_transfer_detected = scanned.unusual_data_transfer_detected
            device.host_activity_notes_json = scanned.host_activity_notes
            # لا نكتب identity_spoof_suspected/note هنا - يُحسبان أعلاه
            # عند أول ظهور الجهاز فقط ويُحافَظ عليهما عبر دورات الفحص
            # اللاحقة (لا نُصفّرهما كل مرة إلا إذا أُعيد اكتشاف تعارض)

            db.flush()  # للحصول على device.id قبل ربط الثغرات

            # نحذف نتائج الفحص الآلي القديمة لهذا الجهاز قبل إدراج نتائج
            # هذه الدورة، وإلا تتراكم ثغرات قديمة/زائفة إلى الأبد عبر كل
            # دورات الفحص المتكررة. نُبقي على الثغرات التي أضافها محلل
            # بشري يدويًا (added_by_user=True) لأنها ليست نتاج فحص آلي.
            db.query(VulnerabilityRecord).filter(
                VulnerabilityRecord.device_id == device.id,
                VulnerabilityRecord.added_by_user.is_(False),
            ).delete(synchronize_session=False)

            for vuln in scanned.vulnerabilities:
                db.add(
                    VulnerabilityRecord(
                        device_id=device.id,
                        cve_id=vuln.cve_id,
                        title=vuln.title,
                        description=vuln.description,
                        cvss_score=vuln.cvss_score,
                        severity=vuln.severity.value,
                        affected_port=vuln.affected_port,
                        affected_product=vuln.affected_product,
                        recommended_fix=vuln.recommended_fix,
                        source=vuln.source,
                        added_by_user=vuln.added_by_user,
                    )
                )

        if report.target.authorized_by_user:
            db.add(
                ScanAuditLog(
                    agent_id=report.agent_id,
                    target=report.target.cidr_or_host,
                    authorization_note=report.target.authorization_note,
                    authorized_by_username="agent-local-confirmation",
                )
            )

        db.commit()
        return {"ok": True, "devices_processed": len(report.devices), "errors": report.errors}
    finally:
        db.close()
