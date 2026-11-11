"""إصدار رموز التفعيل (License Keys) للعملاء الجدد — للمشرفين فقط."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from server.app.api.deps import get_current_user
from server.app.db.database import get_db
from server.app.models.license import License
from server.app.models.user import User
from server.app.services.license_service import (
    DURATION_UNIT_SECONDS,
    duration_to_timedelta,
    generate_license_key,
    verify_license_key,
)

router = APIRouter(prefix="/api/licenses", tags=["licenses"])


@router.get("/duration-units")
def list_duration_units():
    """الوحدات الزمنية المتاحة لواجهة النظام عند إصدار ترخيص جديد."""
    return {"units": list(DURATION_UNIT_SECONDS.keys())}


@router.post("")
def issue_license(
    customer_name: str,
    customer_email: str,
    max_agents: int = 1,
    duration_unit: str = "day",
    duration_count: int = 365,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user.is_admin:
        raise HTTPException(403, "صلاحية مشرف مطلوبة لإصدار تراخيص")

    try:
        expires_delta = duration_to_timedelta(duration_unit, duration_count)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    key = generate_license_key(
        customer_name, customer_email, max_agents, duration_unit, duration_count
    )
    record = License(
        license_key=key,
        customer_name=customer_name,
        customer_email=customer_email,
        max_agents=max_agents,
        expires_at=datetime.utcnow() + expires_delta,
    )
    db.add(record)
    db.commit()
    return {
        "license_key": key,
        "expires_at": record.expires_at.isoformat(),
        "duration": f"{duration_count} {duration_unit}",
    }


@router.get("")
def list_licenses(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    if not current_user.is_admin:
        raise HTTPException(403, "صلاحية مشرف مطلوبة لعرض التراخيص")
    licenses = db.query(License).order_by(License.issued_at.desc()).all()
    return [
        {
            "id": lic.id,
            "customer_name": lic.customer_name,
            "customer_email": lic.customer_email,
            "max_agents": lic.max_agents,
            "activated_agents_count": lic.activated_agents_count,
            "issued_at": lic.issued_at.isoformat(),
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
            "revoked": lic.revoked,
            "license_key": lic.license_key,
        }
        for lic in licenses
    ]


@router.get("/verify")
def check_license(key: str):
    payload = verify_license_key(key)
    if not payload:
        raise HTTPException(400, "مفتاح غير صالح")
    return payload
