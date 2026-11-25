"""
تدقيق الجدار الناري للقراءة فقط (الفصل 3 - أمنية البيانات: الجدران
النارية). يقرأ حالة جدار حماية ويندوز لكل ملف تعريف، وقواعده، ويصنّف كل
قاعدة حسب أنواع الجدران النارية المذكورة في المنهج، ويُطلق تنبيهات على
الإعدادات الخطرة، ويربط حدود الجدار الناري الأربعة بالوحدة التي تغطّيها.

**قراءة فقط.** يقرأ عبر PowerShell مخفي (Get-NetFirewallProfile /
Get-NetFirewallRule) ولا يُنشئ ولا يُعدّل ولا يحذف أي قاعدة. أمر الإصلاح
يُعرض كنصّ مع أمر التراجع ولا يُنفَّذ.

تصنيف القواعد (أنواع الجدران النارية في المنهج):
  - «تصفية الحزم» (Packet filtering): قاعدة تُصفّي حسب المنفذ/العنوان/
    البروتوكول - أبسط نوع، بلا وعي بحالة الاتصال.
  - «مستوى التطبيق» (Application-level/proxy): قاعدة مقيَّدة ببرنامج
    محدَّد (ApplicationFilter) - تتحكم على مستوى التطبيق لا المنفذ فقط.
  - «فحص الحالة» (Stateful inspection): جدار ويندوز نفسه stateful - يتتبّع
    حالة كل اتصال ويسمح تلقائيًا بردود الاتصالات الصادرة، فكل قاعدة تستفيد
    من فحص الحالة.
  - «مستوى الدائرة» (Circuit-level gateway) و«النموذج المرجعي» (ربط
    الطبقات): غير منطبقَين على جهاز مفرد - مذكوران في general_notes مع
    السبب.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys

from shared.models import (
    FirewallAuditReport,
    FirewallBoundary,
    FirewallProfileInfo,
    FirewallRuleClass,
    SecurityAuditFinding,
)
from shared.vuln_db.risk_scoring import _HIGH_RISK_PORTS

logger = logging.getLogger("aladil.discovery.firewall_audit")

# مجلدات يُكتب فيها من مستوى المستخدم - برنامج يعمل منها وله قاعدة سماح
# في الجدار الناري علامة مريبة
_USER_WRITABLE = ("appdata", "\\temp\\", "users\\public", "programdata\\", "\\downloads")

_GATHER_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
$r=@{}
$r.profiles=@(Get-NetFirewallProfile | ForEach-Object { @{name=$_.Name; enabled=[bool]$_.Enabled; inbound=[string]$_.DefaultInboundAction; outbound=[string]$_.DefaultOutboundAction} })
# قواعد السماح الواردة المفعّلة فقط (الأخطر) - نحدّها بعدد معقول
$r.rules=@(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Select-Object -First 400 | ForEach-Object {
  $pf=$_ | Get-NetFirewallPortFilter; $af=$_ | Get-NetFirewallAddressFilter; $app=$_ | Get-NetFirewallApplicationFilter
  @{name=$_.DisplayName; direction=[string]$_.Direction; profile=[string]$_.Profile;
    local_port=[string]$pf.LocalPort; protocol=[string]$pf.Protocol;
    remote_address=[string]$af.RemoteAddress; program=[string]$app.Program;
    owner=[string]$_.Owner; package=[string]$app.Package}
})
$r | ConvertTo-Json -Depth 6 -Compress
"""


async def _run_gather(timeout: float = 120.0) -> dict | None:
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        proc = await asyncio.create_subprocess_exec(
            "powershell", "-NoProfile", "-NonInteractive", "-Command", _GATHER_SCRIPT,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            creationflags=creationflags,
        )
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (OSError, asyncio.TimeoutError) as exc:
        logger.warning("تعذّر تشغيل سكربت تدقيق الجدار الناري: %s", exc)
        return None
    text = stdout.decode("utf-8", errors="ignore").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _port_in_high_risk(local_port: str | None) -> list[int]:
    """يرجع المنافذ عالية الخطورة الموجودة في وصف منفذ القاعدة."""
    if not local_port:
        return []
    found = []
    for chunk in str(local_port).replace(" ", "").split(","):
        if chunk.isdigit() and int(chunk) in _HIGH_RISK_PORTS:
            found.append(int(chunk))
    return found


def classify_rule(rule: dict) -> FirewallRuleClass:
    """يصنّف قاعدة واحدة حسب أنواع الجدران النارية في المنهج (دالة نقيّة)."""
    local_port = rule.get("local_port") or None
    remote = rule.get("remote_address") or None
    protocol = rule.get("protocol") or None
    program = rule.get("program") or None

    classes: list[str] = []
    # فحص الحالة: جدار ويندوز stateful دائمًا، فكل قاعدة تستفيد منه
    classes.append("فحص الحالة")
    # تصفية الحزم: حين تُصفّي القاعدة حسب منفذ/عنوان/بروتوكول محدَّد
    filters_packet = bool(
        (local_port and str(local_port).lower() != "any")
        or (remote and str(remote).lower() != "any")
        or (protocol and str(protocol).lower() not in ("any", "0"))
    )
    if filters_packet:
        classes.append("تصفية الحزم")
    # مستوى التطبيق: حين تكون القاعدة مقيَّدة ببرنامج محدَّد
    if program and program.lower() not in ("any", ""):
        classes.append("مستوى التطبيق")

    return FirewallRuleClass(
        display_name=rule.get("name") or "(بلا اسم)",
        direction=rule.get("direction") or "Inbound",
        profile=rule.get("profile") or "",
        local_port=local_port, remote_address=remote, protocol=protocol, program=program,
        classes=classes,
    )


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def evaluate_firewall(data: dict, unsigned_paths: set[str] | None = None) -> FirewallAuditReport:
    """
    دالة نقيّة بالكامل (بلا I/O): تبني تقرير تدقيق الجدار الناري من ناتج
    سكربت الجمع. unsigned_paths: مجموعة مسارات برامج غير موقَّعة (من وحدة
    unsigned_programs) لربط قواعد الجدار التي تشير إليها.
    """
    unsigned_paths = {p.lower() for p in (unsigned_paths or set())}
    profiles = [
        FirewallProfileInfo(
            name=p.get("name", "?"), enabled=bool(p.get("enabled")),
            default_inbound=p.get("inbound") or "NotConfigured",
            default_outbound=p.get("outbound") or "NotConfigured",
        )
        for p in _as_list(data.get("profiles"))
    ]
    rules_raw = _as_list(data.get("rules"))
    classified = [classify_rule(r) for r in rules_raw]

    alerts: list[SecurityAuditFinding] = []

    # تنبيه: ملف تعريف مطفأ
    for prof in profiles:
        if not prof.enabled:
            alerts.append(SecurityAuditFinding(
                id=f"fw_profile_off_{prof.name}", title=f"ملف تعريف جدار الحماية «{prof.name}» مطفأ",
                severity="critical", status="vulnerable",
                evidence=f"{prof.name}: Enabled=False",
                impact="بلا جدار ناري على هذا الملف، يصل أي جهاز على الشبكة مباشرة لكل الخدمات المفتوحة.",
                fix_command=f"Set-NetFirewallProfile -Profile {prof.name} -Enabled True",
                undo_command=f"Set-NetFirewallProfile -Profile {prof.name} -Enabled False",
                fix_risk="متوسط - أضف قواعد سماح لأجهزتك الموثوقة قبل/بعد التفعيل",
            ))

    # تنبيه: قاعدة سماح وارد من Any إلى Any (بلا تقييد منفذ ولا عنوان ولا برنامج)
    for r, c in zip(rules_raw, classified):
        remote = (r.get("remote_address") or "Any").lower()
        local_port = (r.get("local_port") or "Any").lower()
        program = (r.get("program") or "Any").lower()
        # نتجاهل قواعد تطبيقات متجر ويندوز (معزولة في AppContainer): لها
        # Owner (معرّف حزمة) أو Package، فهي ليست ثغرة مفتوحة فعليًا رغم أن
        # منفذها/عنوانها يظهران Any - هذا يمنع عشرات التنبيهات الزائفة.
        is_store_app = bool((r.get("owner") or "").strip()) or bool((r.get("package") or "").strip())
        if is_store_app:
            continue
        if remote in ("any", "*") and local_port == "any" and program in ("any", ""):
            alerts.append(SecurityAuditFinding(
                id=f"fw_any_any_{c.display_name[:40]}", title=f"قاعدة سماح وارد مفتوحة بالكامل: {c.display_name}",
                severity="high", status="vulnerable",
                evidence=f"القاعدة «{c.display_name}» تسمح بأي عنوان بعيد وأي منفذ وأي برنامج (Any→Any).",
                impact="قاعدة بهذا الاتساع تُلغي فائدة الجدار عمليًا؛ راجع لماذا أُنشئت وقيّدها بمنفذ/برنامج/عنوان.",
                fix_command=f"Disable-NetFirewallRule -DisplayName {_ps_quote(c.display_name)}",
                undo_command=f"Enable-NetFirewallRule -DisplayName {_ps_quote(c.display_name)}",
                fix_risk="متوسط - قد تكون القاعدة لازمة لخدمة؛ راجعها قبل التعطيل",
            ))

    # تنبيه: منفذ عالي الخطورة مسموح به على ملف Public
    for r, c in zip(rules_raw, classified):
        if "public" not in (r.get("profile") or "").lower() and (r.get("profile") or "").lower() != "any":
            continue
        risky = _port_in_high_risk(r.get("local_port"))
        if risky:
            alerts.append(SecurityAuditFinding(
                id=f"fw_public_highrisk_{c.display_name[:30]}",
                title=f"منفذ عالي الخطورة مسموح من الشبكة العامة: {c.display_name}",
                severity="critical", status="vulnerable",
                evidence=f"القاعدة «{c.display_name}» تسمح بالمنفذ/المنافذ {risky} على ملف Public.",
                impact="منافذ مثل SMB/RDP/قواعد البيانات يجب ألا تكون مفتوحة على شبكة عامة - هدف مباشر للاختراق الآلي.",
                fix_command=f"Set-NetFirewallRule -DisplayName {_ps_quote(c.display_name)} -Profile Domain,Private",
                undo_command=f"Set-NetFirewallRule -DisplayName {_ps_quote(c.display_name)} -Profile {r.get('profile') or 'Any'}",
                fix_risk="منخفض - يقصر القاعدة على الشبكات الخاصة/الموثوقة فقط",
            ))

    # تنبيه: قاعدة سماح لبرنامج غير موقَّع أو من مسار مستخدم
    for r, c in zip(rules_raw, classified):
        program = (r.get("program") or "").strip()
        if not program or program.lower() == "any":
            continue
        prog_lower = program.lower()
        is_unsigned = prog_lower in unsigned_paths
        in_user_path = any(k in prog_lower for k in _USER_WRITABLE)
        if is_unsigned or in_user_path:
            why = "برنامج غير موقَّع (من وحدة فحص البرامج)" if is_unsigned else "برنامج يعمل من مجلد مستخدم"
            alerts.append(SecurityAuditFinding(
                id=f"fw_unsigned_prog_{c.display_name[:30]}",
                title=f"قاعدة سماح لبرنامج مريب: {c.display_name}",
                severity="high" if is_unsigned else "medium", status="vulnerable",
                evidence=f"القاعدة «{c.display_name}» تسمح بالبرنامج: {program} ({why}).",
                impact="برنامج غير موثوق له قاعدة سماح في الجدار يستطيع استقبال اتصالات من الشبكة - راجع شرعيته.",
                fix_command=f"Disable-NetFirewallRule -DisplayName {_ps_quote(c.display_name)}",
                undo_command=f"Enable-NetFirewallRule -DisplayName {_ps_quote(c.display_name)}",
                fix_risk="منخفض - عطّلها إن لم تتعرّف على البرنامج",
            ))

    # حدود الجدار الناري الأربعة (ما لا يحميه الجدار وحده) ← الوحدة المغطّية
    boundaries = [
        FirewallBoundary(
            boundary="المستخدم الداخلي (تهديد من داخل الشبكة/الجهاز)",
            covered_by="host_activity (مراقبة سلوك الوصول لجهاز النظام)",
            note="الجدار الناري يحمي من الخارج؛ المستخدم/الجهاز الداخلي يتجاوزه.",
        ),
        FirewallBoundary(
            boundary="الاتصالات الالتفافية (Wi-Fi/Bluetooth/نقطة اتصال تتجاوز الجدار)",
            covered_by="wifi + bluetooth (اكتشاف الشبكات والأجهزة اللاسلكية المجاورة)",
            note="اتصال لاسلكي مباشر لا يمرّ عبر بوابة الجدار الناري السلكية.",
        ),
        FirewallBoundary(
            boundary="الملفات المصابة (ملف ضار يدخل عبر منفذ مسموح)",
            covered_by="unsigned_programs + vuln_audit (كشف البرامج غير الموقَّعة ونقاط الضعف)",
            note="الجدار يمرّر البيانات على المنافذ المسموحة دون فحص محتواها.",
        ),
        FirewallBoundary(
            boundary="التهديدات الجديدة (هجوم غير معروف مسبقًا)",
            covered_by="تقييم السلوك والمخاطر (risk_scoring + كشف المتسللين)",
            note="قواعد الجدار ثابتة؛ التهديد الجديد يحتاج تحليل سلوك لا قاعدة جاهزة.",
        ),
    ]

    general_notes = [
        "«مستوى الدائرة» (Circuit-level gateway): غير منطبق على جهاز مفرد - فهو بوابة وسيطة "
        "تُدير جلسات TCP نيابة عن شبكة داخلية كاملة، ولا يوجد هنا سوى مضيف واحد.",
        "«النموذج المرجعي» (ربط أنواع الجدران بطبقات OSI): مرجعي تعليمي؛ جدار ويندوز يجمع "
        "تصفية الحزم (طبقة الشبكة/النقل) مع فحص الحالة ومستوى التطبيق في منتج واحد.",
    ]

    return FirewallAuditReport(
        profiles=profiles, classified_rules=classified, alerts=alerts,
        boundaries=boundaries, general_notes=general_notes,
    )


async def run_firewall_audit(unsigned_paths: set[str] | None = None) -> FirewallAuditReport | None:
    """الفحص الكامل للقراءة فقط: يجمع حالة الجدار وقواعده ثم يقيّمها.
    لا يُعدّل أي قاعدة. يُرجع None إن تعذّر الجمع (نظام غير ويندوز مثلًا)."""
    data = await _run_gather()
    if not data:
        return None
    return evaluate_firewall(data, unsigned_paths)
