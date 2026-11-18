"""
محرّك تقييم المخاطر: يحوّل نتائج الفحص (منافذ مفتوحة + ثغرات + نوع
الجهاز + محاولات الاتصال) إلى تصنيف يفهمه الإنسان بسهولة في الواجهة:
  - access_likelihood_score: ما مدى سهولة وصول طرف غير مخوّل لهذا الجهاز؟
  - potential_damage_score:  ما حجم الضرر إن تم اختراقه؟
  - overall_threat_level:    تصنيف نهائي (حرج/مرتفع/متوسط/منخفض)
  - intruder_status:         هل هناك مخترق نشط فعليًا أم محاولات فاشلة
                              متكررة غير فعّالة (dormant/ineffective)؟
"""
from __future__ import annotations

from shared.models import (
    DeviceType,
    IntruderStatus,
    ScannedDevice,
    ThreatLevel,
)

_HIGH_RISK_PORTS = {23, 21, 445, 3389, 5900, 135, 139, 1433, 3306, 5432, 6379, 27017, 5555}
_CRITICAL_DEVICE_TYPES = {DeviceType.ROUTER, DeviceType.CAMERA, DeviceType.COMPUTER}

# ملاحظات وصفية جاهزة عن قابلية الاستغلال - تصف المخاطر المعروفة لمنفذ
# معيّن بصياغة مفهومة للمستخدم (ليست أداة استغلال، فقط شرح المخاطر
# الشائعة الموثّقة لهذه الخدمة عند تركها مفتوحة دون تحكّم كافٍ بالوصول)
_PORT_EXPLOITABILITY_NOTES = {
    23: "Telnet: بروتوكول غير مشفَّر، كلمات المرور تُرسَل كنص صريح - استبدله بـ SSH.",
    21: "FTP: قد يسمح بنقل ملفات دون تشفير - راجع صلاحيات الدخول المجهول (anonymous).",
    445: "SMB: هدف شائع لبرمجيات الفدية والانتشار الجانبي (مثل EternalBlue) - قيّد الوصول له من الشبكة الخارجية.",
    3389: "RDP: هدف شائع لهجمات تخمين كلمات المرور (brute-force) - فعّل MFA أو قيّده عبر VPN.",
    5900: "VNC: يفتقر أحيانًا لتشفير قوي افتراضيًا - تأكد من وجود كلمة مرور قوية.",
    1433: "MSSQL مكشوف على الشبكة - يجب ألا يكون متاحًا مباشرة من خارج الشبكة المحلية.",
    3306: "MySQL مكشوف على الشبكة - يجب ألا يكون متاحًا مباشرة من خارج الشبكة المحلية.",
    5432: "PostgreSQL مكشوف على الشبكة - يجب ألا يكون متاحًا مباشرة من خارج الشبكة المحلية.",
    6379: "Redis غالبًا بلا مصادقة افتراضيًا - هدف شائع للاختراق الآلي إن تُرك مكشوفًا.",
    27017: "MongoDB غالبًا بلا مصادقة افتراضيًا في الإعداد الافتراضي - تحقّق من تفعيل المصادقة.",
    5555: "منفذ ADB مكشوف عبر الشبكة على جهاز Android: إن كان «تصحيح الأخطاء عبر الشبكة» مفعّلًا فقد يتيح لأي جهاز على نفس الشبكة تثبيت تطبيقات أو التحكم بالجهاز دون مصادقة - أطفئ تصحيح USB/الشبكة من إعدادات المطوّر فورًا.",
}

_SEVERITY_WEIGHT = {
    ThreatLevel.CRITICAL: 40,
    ThreatLevel.HIGH: 25,
    ThreatLevel.MEDIUM: 12,
    ThreatLevel.LOW: 5,
    ThreatLevel.INFO: 0,
}


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def score_device(device: ScannedDevice) -> ScannedDevice:
    """يحدّث حقول التقييم داخل ScannedDevice ويُرجعه (in-place + return)."""

    # 1) احتمالية الوصول: منافذ عالية الخطورة مفتوحة + عدد الثغرات + محاولات فاشلة
    access_score = 0.0
    access_score += sum(8 for p in device.open_ports if p.port in _HIGH_RISK_PORTS)
    access_score += sum(3 for p in device.open_ports if p.port not in _HIGH_RISK_PORTS)
    access_score += len(device.vulnerabilities) * 4
    access_score += min(device.failed_connection_attempts * 1.5, 20)
    device.access_likelihood_score = _clamp(access_score)

    # 2) الضرر المحتمل: نوع الجهاز (راوتر/كمبيوتر/كاميرا أخطر من جهاز IoT بسيط)
    #    بالإضافة إلى شدة الثغرات المكتشفة فعليًا على هذا الجهاز.
    damage_score = 0.0
    if device.device_type in _CRITICAL_DEVICE_TYPES:
        damage_score += 25
    damage_score += sum(_SEVERITY_WEIGHT.get(v.severity, 0) for v in device.vulnerabilities)
    device.potential_damage_score = _clamp(damage_score)

    # 3) التصنيف الكلي = أعلى قيمة بين احتمالية الوصول والضرر المحتمل (موزونة)
    combined = _clamp(0.5 * device.access_likelihood_score + 0.5 * device.potential_damage_score)
    if combined >= 75:
        device.overall_threat_level = ThreatLevel.CRITICAL
    elif combined >= 50:
        device.overall_threat_level = ThreatLevel.HIGH
    elif combined >= 25:
        device.overall_threat_level = ThreatLevel.MEDIUM
    elif combined > 0:
        device.overall_threat_level = ThreatLevel.LOW
    else:
        device.overall_threat_level = ThreatLevel.INFO

    # 4) كشف المخترقين غير الفعّالين: محاولات فاشلة كثيرة بدون أي نجاح
    #    تُصنَّف كتهديد "خامل/غير فعّال" بدل "نشط"، لتخفيف أولوية الاستجابة.
    if device.successful_connection_attempts > 0 and device.failed_connection_attempts > 0:
        device.intruder_status = IntruderStatus.ACTIVE_THREAT
    elif device.failed_connection_attempts >= 5 and device.successful_connection_attempts == 0:
        device.intruder_status = IntruderStatus.DORMANT_INEFFECTIVE
    else:
        device.intruder_status = IntruderStatus.NONE

    # 5) جهاز "مجهول": لا اسم مضيف، لا شركة مصنّعة معروفة من MAC، ولا نوع
    #    جهاز محدَّد - يحتاج تحقيقًا يدويًا من المستخدم لتحديد هويته
    device.is_unidentified = (
        not device.fingerprint.hostname
        and not device.fingerprint.vendor
        and device.device_type == DeviceType.UNKNOWN
    )

    # 6) ملاحظات قابلية الاستغلال: شرح وصفي لكل منفذ معروف المخاطر مفتوح
    #    فعليًا على هذا الجهاز - تقييم مخاطر وليس أداة استغلال
    device.exploitability_notes = [
        _PORT_EXPLOITABILITY_NOTES[p.port]
        for p in device.open_ports
        if p.port in _PORT_EXPLOITABILITY_NOTES
    ]

    return device


def score_all(devices: list[ScannedDevice]) -> list[ScannedDevice]:
    return [score_device(d) for d in devices]


def rank_by_priority(devices: list[ScannedDevice]) -> list[ScannedDevice]:
    """يرتّب الأجهزة تنازليًا حسب الخطورة الكلية لعرضها في لوحة التحكم أولًا."""
    return sorted(
        devices,
        key=lambda d: (d.access_likelihood_score + d.potential_damage_score),
        reverse=True,
    )
