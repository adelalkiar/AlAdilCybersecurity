"""
بوّابة التفويض: أي نطاق/عنوان خارج الشبكات المحلية المباشرة للجهاز
(أي ليس subnet البطاقة الشبكية نفسها) يجب أن يُؤكَّد تفويضه صراحة من
المستخدم قبل فحصه، ويُسجَّل هذا التأكيد في سجل تدقيق (audit log) دائم.

هذا يمنع استخدام النظام لفحص بنى تحتية لا يملكها/لا يُصرَّح له بفحصها
المستخدم، ويحافظ على سجل قابل للمراجعة لاحقًا (متطلب قانوني/امتثالي
في أغلب برامج اختبار الاختراق واتفاقيات الفحص).
"""
from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime
from pathlib import Path

from shared.models import ConnectionMedium, ScanTarget

logger = logging.getLogger("aladil.authorization")

AUDIT_LOG_PATH = Path(__file__).resolve().parent.parent / "data" / "authorization_audit.log"


def _is_local_subnet(cidr_or_host: str, local_subnets: list[str]) -> bool:
    try:
        network = ipaddress.ip_network(cidr_or_host, strict=False)
    except ValueError:
        return False  # اسم مستضاف (hostname) وليس IP/CIDR -> يُعامل كخارجي
    for subnet in local_subnets:
        try:
            if network.subnet_of(ipaddress.ip_network(subnet, strict=False)):
                return True
        except (ValueError, TypeError):
            continue
    return False


class AuthorizationRequiredError(PermissionError):
    """يُرفع عند محاولة فحص نطاق خارجي لم يؤكّد المستخدم تفويضه."""


def ensure_authorized(target: ScanTarget, local_subnets: list[str]) -> ScanTarget:
    """
    يتحقق من أن الهدف إما:
      1) داخل الشبكة المحلية المباشرة للجهاز (لا يحتاج تأكيدًا إضافيًا)، أو
      2) نطاق خارجي أكّد المستخدم صراحةً (authorized_by_user=True) أنه
         يملكه أو مُصرَّح له قانونيًا بفحصه (مثل اتفاقية pentest).

    عند التأكيد، يُسجَّل الحدث في سجل تدقيق لا يمكن حذفه من داخل الواجهة.
    """
    if target.medium != ConnectionMedium.EXTERNAL or _is_local_subnet(
        target.cidr_or_host, local_subnets
    ):
        return target

    if not target.authorized_by_user:
        raise AuthorizationRequiredError(
            f"الهدف '{target.cidr_or_host}' خارج الشبكة المحلية ولم يتم تأكيد "
            "تفويض فحصه. يجب أن يؤكد المستخدم أنه يملك هذا النطاق أو لديه "
            "تصريح قانوني صريح بفحصه (مثل اتفاقية اختبار اختراق موثّقة) قبل "
            "المتابعة."
        )

    _write_audit_entry(target)
    return target


def _write_audit_entry(target: ScanTarget) -> None:
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "target": target.cidr_or_host,
        "authorization_note": target.authorization_note or "",
    }
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    logger.warning("تم تأكيد تفويض فحص هدف خارجي: %s", entry)
