"""عرض العملاء (Agents) ونتائج فحص "البرامج غير الموقَّعة/المتخفّية" على
أجهزتهم المحلية - للمشرفين فقط عبر لوحة التحكم."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from server.app.api.deps import get_current_user
from server.app.db.database import get_db
from server.app.models.device import Agent

router = APIRouter(
    prefix="/api/agents", tags=["agents"], dependencies=[Depends(get_current_user)]
)


@router.get("")
def list_agents(db: Session = Depends(get_db)):
    agents = db.query(Agent).order_by(Agent.last_seen.desc()).all()
    return [
        {
            "id": agent.id,
            "hostname": agent.hostname,
            "platform": agent.platform,
            "version": agent.version,
            "first_seen": agent.first_seen.isoformat(),
            "last_seen": agent.last_seen.isoformat(),
            "unsigned_program_findings": agent.unsigned_program_findings_json or [],
            "security_audit_findings": agent.security_audit_findings_json or [],
        }
        for agent in agents
    ]
