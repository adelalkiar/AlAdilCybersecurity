"""
نقاط نهاية الأجهزة المكتشفة: القائمة مرتّبة حسب الخطورة، التفاصيل،
تصنيف المخترقين غير الفعّالين، وإضافة ملاحظات/حلول يدوية.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session

from server.app.api.deps import get_current_user
from server.app.db.database import get_db
from server.app.models.device import Device, VulnerabilityRecord
from server.app.models.user import User

router = APIRouter(prefix="/api/devices", tags=["devices"], dependencies=[Depends(get_current_user)])


@router.get("")
def list_devices(
    threat_level: str | None = None,
    intruder_status: str | None = None,
    unidentified_only: bool = False,
    identity_spoof_only: bool = False,
    db: Session = Depends(get_db),
):
    """
    يرجع الأجهزة مرتّبة تنازليًا حسب (احتمالية الوصول + الضرر المحتمل)
    بحيث تظهر أخطر الأجهزة أولًا في لوحة التحكم.

    - unidentified_only: الأجهزة بلا اسم/شركة مصنّعة/نوع معروف فقط.
    - identity_spoof_only: الأجهزة المشتبه بانتحالها اسم جهاز موثوق آخر.
    """
    query = db.query(Device)
    if threat_level:
        query = query.filter(Device.overall_threat_level == threat_level)
    if intruder_status:
        query = query.filter(Device.intruder_status == intruder_status)
    if unidentified_only:
        query = query.filter(Device.is_unidentified.is_(True))
    if identity_spoof_only:
        query = query.filter(Device.identity_spoof_suspected.is_(True))

    devices = query.all()
    devices.sort(
        key=lambda d: (d.access_likelihood_score + d.potential_damage_score), reverse=True
    )
    return [_serialize_device(d) for d in devices]


@router.get("/{device_id}")
def get_device(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "الجهاز غير موجود")
    return _serialize_device(device, include_vulns=True)


@router.get("/{device_id}/block-command")
def device_block_command(device_id: str, db: Session = Depends(get_db)):
    """
    يُرجع أمر PowerShell نموذجيًا (كنصّ فقط - لا يُنفَّذ هنا إطلاقًا) لحظر
    عنوان IP هذا الجهاز واردًا وصادرًا في جدار حماية ويندوز، ليُنفّذه
    المستخدم بنفسه كمسؤول إن قرّر عزل جهاز يشتبه أنه تهديد. النظام **لا
    يُنشئ ولا يُعدّل أي قاعدة جدار حماية فعلية** ولا يعزل أي جهاز تلقائيًا.
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "الجهاز غير موجود")
    if not device.ip_address:
        raise HTTPException(
            400, "لا يمكن إنشاء أمر حظر: هذا الجهاز بلا عنوان IP (قد يكون جهاز Bluetooth)"
        )

    ip = device.ip_address
    safe = "".join(c for c in ip if c.isalnum() or c in "._-")
    rule_in = f"AlAdil-Block-{safe}-in"
    rule_out = f"AlAdil-Block-{safe}-out"
    command = (
        f'New-NetFirewallRule -DisplayName "{rule_in}" -Direction Inbound '
        f'-RemoteAddress {ip} -Action Block; '
        f'New-NetFirewallRule -DisplayName "{rule_out}" -Direction Outbound '
        f'-RemoteAddress {ip} -Action Block'
    )
    undo = f'Remove-NetFirewallRule -DisplayName "{rule_in}","{rule_out}"'
    return {
        "ip": ip,
        "command": command,
        "undo_command": undo,
        "note": (
            "انسخ أمر الحظر ونفّذه بنفسك في PowerShell كمسؤول (Run as Administrator) "
            "إن قرّرت عزل هذا الجهاز. هذا النظام لا ينفّذه نيابةً عنك ولا يعزل أي جهاز "
            "تلقائيًا. تأكد أولًا أن هذا ليس جهازًا تحتاجه (مثل راوتر أو خادم قاعدة بيانات)، "
            "واستخدم أمر التراجع لإلغاء الحظر لاحقًا."
        ),
    }


@router.patch("/{device_id}/notes")
def update_notes(device_id: str, notes: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "الجهاز غير موجود")
    device.analyst_notes = notes
    db.commit()
    return {"ok": True}


@router.post("/{device_id}/vulnerabilities/manual")
def add_manual_vulnerability(
    device_id: str,
    title: str,
    description: str,
    recommended_fix: str,
    severity: str = "medium",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """يسمح للمستخدم بإضافة ثغرة/حل بحث عنه بنفسه وتوثيقه في قاعدة بيانات النظام."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "الجهاز غير موجود")

    record = VulnerabilityRecord(
        device_id=device_id,
        title=title,
        description=description,
        recommended_fix=recommended_fix,
        severity=severity,
        source="community",
        added_by_user=True,
        added_by_username=current_user.username,
    )
    db.add(record)
    db.commit()
    return {"ok": True, "id": record.id}


def _serialize_device(device: Device, include_vulns: bool = False) -> dict:
    data = {
        "id": device.id,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "vendor": device.vendor,
        "hostname": device.hostname,
        "os_guess": device.os_guess,
        "device_type": device.device_type,
        "connection_medium": device.connection_medium,
        "overall_threat_level": device.overall_threat_level,
        "intruder_status": device.intruder_status,
        "access_likelihood_score": device.access_likelihood_score,
        "potential_damage_score": device.potential_damage_score,
        "failed_connection_attempts": device.failed_connection_attempts,
        "successful_connection_attempts": device.successful_connection_attempts,
        "open_ports": device.open_ports_json,
        "last_seen": device.last_seen.isoformat(),
        "analyst_notes": device.analyst_notes,
        "vulnerability_count": len(device.vulnerabilities),
        "exploitability_notes": device.exploitability_notes_json,
        "is_unidentified": device.is_unidentified,
        "identity_spoof_suspected": device.identity_spoof_suspected,
        "identity_spoof_note": device.identity_spoof_note,
        "accessed_host_system": device.accessed_host_system,
        "unusual_data_transfer_detected": device.unusual_data_transfer_detected,
        "host_activity_notes": device.host_activity_notes_json,
        "attack_phase": device.attack_phase,
        "attacker_timeline": device.attacker_timeline_json,
    }
    if include_vulns:
        data["vulnerabilities"] = [
            {
                "id": v.id,
                "cve_id": v.cve_id,
                "title": v.title,
                "description": v.description,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "affected_port": v.affected_port,
                "recommended_fix": v.recommended_fix,
                "source": v.source,
                "added_by_user": v.added_by_user,
            }
            for v in device.vulnerabilities
        ]
    return data
