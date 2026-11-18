"""
إدارة قائمة "الأجهزة/الشبكات الموثوقة" التوثيقية - للمشرفين فقط.

تنويه مهم: هذا API **لا يُنشئ ولا يُعدّل أي قاعدة جدار حماية فعلية** على
أي جهاز. إنشاء القاعدة الحقيقية (في جدار حماية ويندوز مثلًا) يبقى دائمًا
فعلًا يدويًا يقوم به المستخدم بنفسه - انظر الأمر النموذجي الذي تُرجعه
نقطة /example-firewall-command أدناه.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from server.app.api.deps import get_current_user
from server.app.db.database import get_db
from server.app.models.trusted_network import TrustedNetworkEntry
from server.app.models.user import User

router = APIRouter(
    prefix="/api/trusted-networks", tags=["trusted-networks"],
    dependencies=[Depends(get_current_user)],
)


class TrustedNetworkCreate(BaseModel):
    label: str
    cidr_or_host: str
    note: str = ""


def _serialize(entry: TrustedNetworkEntry) -> dict:
    return {
        "id": entry.id,
        "label": entry.label,
        "cidr_or_host": entry.cidr_or_host,
        "note": entry.note,
        "added_by_username": entry.added_by_username,
        "created_at": entry.created_at.isoformat(),
    }


@router.get("")
def list_trusted_networks(db: Session = Depends(get_db)):
    entries = db.query(TrustedNetworkEntry).order_by(TrustedNetworkEntry.created_at.desc()).all()
    return [_serialize(e) for e in entries]


@router.post("")
def add_trusted_network(
    body: TrustedNetworkCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    entry = TrustedNetworkEntry(
        label=body.label.strip(),
        cidr_or_host=body.cidr_or_host.strip(),
        note=body.note.strip(),
        added_by_username=current_user.username,
        created_at=datetime.utcnow(),
    )
    db.add(entry)
    db.commit()
    return _serialize(entry)


@router.delete("/{entry_id}")
def delete_trusted_network(entry_id: str, db: Session = Depends(get_db)):
    entry = db.query(TrustedNetworkEntry).filter(TrustedNetworkEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(404, "العنصر غير موجود")
    db.delete(entry)
    db.commit()
    return {"ok": True}


@router.get("/example-firewall-command")
def example_firewall_command(cidr_or_host: str, port: int = 1433):
    """
    يُرجع أمر PowerShell نموذجيًا (كنص فقط - لا يُنفَّذ هنا إطلاقًا) لإنشاء
    قاعدة سماح لعنوان/نطاق موثوق على منفذ محدد في ملف Windows Firewall،
    مقيَّدة بملف الشبكة الخاصة فقط، ليُنفّذه المستخدم بنفسه في PowerShell
    كمسؤول إن أراد ذلك.
    """
    safe_label = "".join(c for c in cidr_or_host if c.isalnum() or c in "._-") or "Trusted"
    command = (
        f'New-NetFirewallRule -DisplayName "AlAdil-Allow-{safe_label}-{port}" '
        f'-Direction Inbound -Action Allow -Protocol TCP -LocalPort {port} '
        f'-RemoteAddress {cidr_or_host} -Profile Private,Domain'
    )
    return {
        "command": command,
        "note": (
            "انسخ هذا الأمر ونفّذه بنفسك في PowerShell كمسؤول (Run as Administrator). "
            "هذا النظام لا ينفّذه نيابةً عنك ولا يُعدّل جدار الحماية إطلاقًا."
        ),
    }
