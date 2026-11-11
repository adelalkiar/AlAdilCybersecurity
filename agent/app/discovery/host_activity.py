"""
مراقبة سلوك الأجهزة الأخرى تجاه جهاز النظام نفسه (الجهاز الذي يعمل عليه
العميل): هل جهاز معيّن متصل فعليًا بجهاز النظام الآن (دخول/وصول)؟ وهل
يوجد نشاط نقل بيانات غير معتاد من جهاز النظام قد يشير لعملية نسخ/تسريب؟

**حدود هذه الوحدة (بصراحة)**: هذه مؤشرات تقريبية وليست مراقبة دقيقة على
مستوى كل اتصال:
  - اكتشاف "الدخول" يعتمد على اتصالات TCP الفعلية الظاهرة في جدول
    النظام (psutil) وقت الفحص فقط - اتصال انتهى بين دورتي فحص لن يُرصد.
  - اكتشاف "نقل بيانات غير معتاد" يقيس إجمالي بايتات الشبكة لكل الجهاز
    (وليس لكل اتصال على حدة) ويقارنها بخط أساس بسيط - لرصد دقيق لكل
    اتصال (مثل "هذا الجهاز نسخ 2GB عبر SMB تحديدًا") يلزم تكامل أعمق مع
    واجهات نظام منخفضة المستوى (ETW على ويندوز، eBPF على لينكس) خارج
    نطاق هذا الإصدار.
"""
from __future__ import annotations

import json
import logging
import time

import psutil

from agent.app.config import CONFIG_DIR
from shared.models import ConnectionMedium

logger = logging.getLogger("aladil.discovery.host_activity")

_STATE_PATH = CONFIG_DIR / "host_activity_state.json"

# حد تقريبي (بايت) لاعتبار نقل البيانات "غير معتاد" خلال فترة بين دورتي
# فحص متتاليتين - قابل للتعديل حسب طبيعة استخدام الجهاز الطبيعي
UNUSUAL_TRANSFER_THRESHOLD_BYTES = 500 * 1024 * 1024  # 500 MB

_SERVICE_BY_PORT = {
    21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 139: "netbios", 443: "https",
    445: "smb (مشاركة ملفات)", 3389: "rdp", 5900: "vnc",
}


def get_established_connections_to_host() -> list[dict]:
    """يرجع قائمة الاتصالات الفعلية الواردة إلى جهاز النظام الآن، كل
    عنصر: {remote_ip, local_port, service}."""
    results: list[dict] = []
    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, PermissionError):
        logger.warning(
            "لا توجد صلاحية كافية لقراءة جدول اتصالات النظام (قد يتطلب "
            "تشغيل العميل بصلاحيات مرتفعة لرؤية كل الاتصالات)."
        )
        return results

    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not conn.laddr:
            continue
        remote_ip = conn.raddr.ip
        if remote_ip.startswith("127.") or remote_ip == "::1":
            continue  # اتصال محلي للجهاز بنفسه، وليس جهازًا آخر فعليًا
        results.append(
            {
                "remote_ip": remote_ip,
                "local_port": conn.laddr.port,
                "service": _SERVICE_BY_PORT.get(conn.laddr.port, f"منفذ {conn.laddr.port}"),
            }
        )
    return results


def detect_unusual_transfer() -> tuple[bool, int]:
    """يقارن إجمالي بايتات الشبكة الحالية بآخر قراءة محفوظة؛ يرجع
    (هل الفارق يتجاوز العتبة, الفارق بالبايت)."""
    try:
        counters = psutil.net_io_counters()
        current_total = counters.bytes_sent + counters.bytes_recv
    except Exception:  # noqa: BLE001
        return False, 0

    now = time.time()
    previous_total = current_total
    try:
        if _STATE_PATH.exists():
            state = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
            previous_total = state.get("total_bytes", current_total)
    except (json.JSONDecodeError, OSError):
        pass

    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STATE_PATH.write_text(
        json.dumps({"total_bytes": current_total, "timestamp": now}), encoding="utf-8"
    )

    delta = max(0, current_total - previous_total)
    return delta > UNUSUAL_TRANSFER_THRESHOLD_BYTES, delta


def annotate_host_activity(devices: list) -> None:
    """يُحدّث حقول accessed_host_system/unusual_data_transfer_detected/
    host_activity_notes على كائنات ScannedDevice المُمرَّرة مباشرة
    (in-place)، بمطابقة عناوين IP للاتصالات الفعلية الواردة."""
    connections = get_established_connections_to_host()
    by_ip: dict[str, list[dict]] = {}
    for conn in connections:
        by_ip.setdefault(conn["remote_ip"], []).append(conn)

    transfer_flagged, delta_bytes = detect_unusual_transfer()
    delta_mb = delta_bytes / (1024 * 1024)

    for device in devices:
        if device.connection_medium == ConnectionMedium.BLUETOOTH:
            continue  # لا عنوان IP ذا معنى هنا
        conns = by_ip.get(device.ip_address, []) if device.ip_address else []
        if conns:
            device.accessed_host_system = True
            for c in conns:
                device.host_activity_notes.append(
                    f"متصل حاليًا بجهاز النظام عبر {c['service']} (منفذ محلي {c['local_port']})."
                )
            if transfer_flagged:
                # إسناد تقريبي: أي جهاز له اتصال فعلي وقت رصد نقل غير
                # معتاد يُعلَّم، دون تأكيد أنه المصدر الحصري للنقل
                device.unusual_data_transfer_detected = True
                device.host_activity_notes.append(
                    f"⚠ رُصد نقل بيانات غير معتاد من جهاز النظام (~{delta_mb:.0f} "
                    "ميجابايت منذ آخر فحص) أثناء وجود اتصال نشط من هذا الجهاز - "
                    "هذا مؤشر تقريبي على مستوى الجهاز بالكامل وليس إثباتًا قاطعًا "
                    "أن هذا الاتصال تحديدًا هو السبب."
                )
