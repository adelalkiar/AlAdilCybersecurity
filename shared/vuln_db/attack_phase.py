"""
وسم كل جهاز مشبوه بمرحلة الهجوم التي يوافقها سلوكه المرصود (الفصل 2:
مراحل الاختراق)، وبناء «خط زمني للمهاجم» يوضّح الأدلة في كل مرحلة.

مراحل المنهج الثلاث:
  1. اختيار الهدف (target_selection): كل جهاز يظهر على الشبكة مرشّح.
  2. جمع المعلومات / الاستطلاع (reconnaissance): منافذ مفتوحة تخدم
     الاستطلاع، أو دخول/اتصال بجهاز النظام (فحص منافذ أو ARP من جهاز آخر).
  3. الهجوم (attack): محاولات دخول (فاشلة/ناجحة) أو نقل بيانات غير معتاد
     أو ثغرات قابلة للاستغلال.

دالة نقيّة (بلا I/O) تُعدّل حقول ScannedDevice مباشرة، فيسهل اختبارها.
"""
from __future__ import annotations

from shared.models import IntruderStatus, ScannedDevice

PHASE_LABELS = {
    "target_selection": "اختيار الهدف",
    "reconnaissance": "جمع المعلومات (استطلاع)",
    "attack": "الهجوم",
}
_ORDER = ["target_selection", "reconnaissance", "attack"]


def classify_attack_phase(device: ScannedDevice) -> ScannedDevice:
    """يضبط device.attack_phase (أبعد مرحلة بلغها سلوك الجهاز) و
    device.attacker_timeline (قائمة مراحل بالأدلة). دالة نقيّة."""
    timeline: list[dict] = []
    reached = "target_selection"

    # المرحلة 1: اختيار الهدف - مجرد وجود الجهاز على الشبكة يجعله مرشّحًا
    ident = device.fingerprint.hostname or device.fingerprint.mac_address or device.ip_address or "جهاز"
    timeline.append({
        "phase": "target_selection", "label": PHASE_LABELS["target_selection"],
        "evidence": f"ظهر الجهاز «{ident}» على الشبكة (مرشّح ضمن أهداف محتملة).",
    })

    # المرحلة 2: جمع المعلومات - منافذ مفتوحة، أو دخول/وصول لجهاز النظام
    recon_signals = []
    if device.open_ports:
        recon_signals.append(f"{len(device.open_ports)} منفذ مفتوح يكشف خدمات الجهاز")
    if device.accessed_host_system:
        recon_signals.append("رُصد اتصال/دخول من هذا الجهاز إلى جهاز النظام")
    if recon_signals:
        reached = "reconnaissance"
        timeline.append({
            "phase": "reconnaissance", "label": PHASE_LABELS["reconnaissance"],
            "evidence": "، ".join(recon_signals) + ".",
        })

    # المرحلة 3: الهجوم - محاولات دخول أو نقل بيانات غير معتاد أو ثغرات
    attack_signals = []
    if device.failed_connection_attempts > 0:
        attack_signals.append(f"{device.failed_connection_attempts} محاولة دخول فاشلة")
    if device.successful_connection_attempts > 0:
        attack_signals.append(f"{device.successful_connection_attempts} اتصال ناجح")
    if device.unusual_data_transfer_detected:
        attack_signals.append("نقل بيانات غير معتاد (مؤشر تسريب)")
    if device.vulnerabilities:
        attack_signals.append(f"{len(device.vulnerabilities)} ثغرة قابلة للاستغلال")
    if attack_signals or device.intruder_status == IntruderStatus.ACTIVE_THREAT:
        reached = "attack"
        timeline.append({
            "phase": "attack", "label": PHASE_LABELS["attack"],
            "evidence": ("، ".join(attack_signals) or "سلوك هجومي نشط") + ".",
        })

    device.attack_phase = reached
    device.attacker_timeline = timeline
    return device


def classify_all_phases(devices: list[ScannedDevice]) -> list[ScannedDevice]:
    return [classify_attack_phase(d) for d in devices]
