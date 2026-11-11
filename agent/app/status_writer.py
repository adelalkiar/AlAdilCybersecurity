"""
يكتب ملف حالة محلي خفيف (status.json) بعد كل دورة فحص، تقرؤه واجهة
أيقونة النظام (tray_app.py) لعرض حالة مفهومة للمستخدم دون أي بيانات
حسّاسة (لا رمز ترخيص، لا تفاصيل أجهزة الشبكة) - فقط ملخّص عام.
"""
from __future__ import annotations

import json
from datetime import datetime

from agent.app.config import CONFIG_DIR
from shared.models import ScanReport, ThreatLevel

STATUS_PATH = CONFIG_DIR / "status.json"


def write_status(report: ScanReport, is_error: bool = False, error_message: str | None = None) -> None:
    high_risk_count = sum(
        1
        for d in report.devices
        if d.overall_threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH)
    )
    status = {
        "last_scan_at": datetime.utcnow().isoformat() + "Z",
        "devices_found": len(report.devices),
        "high_risk_count": high_risk_count,
        "errors": report.errors,
        "ok": not is_error,
        "error_message": error_message,
    }
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        STATUS_PATH.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass  # عدم القدرة على كتابة حالة العرض لا يجب أن يوقف الفحص نفسه


def write_error_status(message: str) -> None:
    status = {
        "last_scan_at": datetime.utcnow().isoformat() + "Z",
        "devices_found": 0,
        "high_risk_count": 0,
        "errors": [message],
        "ok": False,
        "error_message": message,
    }
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        STATUS_PATH.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def read_status() -> dict | None:
    if not STATUS_PATH.exists():
        return None
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
