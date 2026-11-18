"""
سجل الثغرات المحلي: يتراكم عبر الزمن على جهاز النظام نفسه بنتائج كل دورة
تدقيق أمني وفحص برامج غير موقَّعة. لكل بند: متى شوهد أول مرة، آخر مرة، كم
مرة، وهل ما زال مفتوحًا أم اختفى (قد يدل اختفاؤه على أن المستخدم أصلحه).

**محلي بالكامل - خصوصية أولًا.** هذا السجل لا يُرفع لأي خادم مركزي ولا
يُشارك عبر أجهزة أخرى. رفضنا عمدًا فكرة "سجل ثغرات عالمي يجمع من كل حاسوب"
لأن قاعدة بيانات مركزية بثغرات كل المستخدمين هي بحد ذاتها كنز للمهاجمين
وخطر خصوصية جسيم. يبقى السجل على جهاز صاحبه وحده.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from agent.app.config import CONFIG_DIR

logger = logging.getLogger("aladil.discovery.vuln_registry")

_REGISTRY_PATH = CONFIG_DIR / "vuln_registry.json"


def _load() -> dict:
    if not _REGISTRY_PATH.exists():
        return {"entries": {}}
    try:
        return json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"entries": {}}


def _save(data: dict) -> None:
    _REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    _REGISTRY_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def update_local_registry(audit_findings: list, unsigned_findings: list) -> dict:
    """يحدّث السجل المحلي ببنود هذه الدورة. يرجع ملخّصًا {open, resolved,
    total_ever}. البنود تُفتَرض كائنات Pydantic لها الحقول المذكورة."""
    data = _load()
    entries: dict = data.get("entries", {})
    now = datetime.utcnow().isoformat() + "Z"

    seen_keys: set[str] = set()

    def _touch(key: str, kind: str, title: str, severity: str) -> None:
        seen_keys.add(key)
        if key in entries:
            entry = entries[key]
            entry["last_seen"] = now
            entry["times_seen"] = entry.get("times_seen", 1) + 1
            entry["status"] = "open"
            entry["severity"] = severity
            entry["title"] = title
        else:
            entries[key] = {
                "kind": kind, "title": title, "severity": severity,
                "first_seen": now, "last_seen": now, "times_seen": 1, "status": "open",
            }

    for f in audit_findings:
        if getattr(f, "status", "vulnerable") == "vulnerable":
            _touch(f"audit:{f.id}", "audit", f.title, f.severity)

    for f in unsigned_findings:
        if getattr(f, "level", "review") in ("danger", "suspect"):
            _touch(f"unsigned:{f.path}", "unsigned", f.display_name, f.level)

    # أي بند كان مفتوحًا ولم يَعُد يظهر هذه الدورة = يُعلَّم "اختفى" (ربما
    # أصلحه المستخدم)، لكن لا نحذفه حتى يبقى تاريخه في السجل
    for key, entry in entries.items():
        if entry.get("status") == "open" and key not in seen_keys:
            entry["status"] = "resolved"
            entry["resolved_at"] = now

    data["entries"] = entries
    data["updated_at"] = now
    _save(data)

    open_count = sum(1 for e in entries.values() if e.get("status") == "open")
    resolved_count = sum(1 for e in entries.values() if e.get("status") == "resolved")
    return {"open": open_count, "resolved": resolved_count, "total_ever": len(entries)}


def read_local_registry() -> dict:
    """يقرأ السجل المحلي كاملًا (للعرض أو التقارير)."""
    return _load()
