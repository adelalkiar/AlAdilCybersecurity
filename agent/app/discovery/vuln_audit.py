"""
تدقيق أمني للقراءة فقط على جهاز النظام نفسه: يفحص إعدادات حماية ويندوز
(Defender، جدار الحماية، UAC، الحسابات، LSA، SmartScreen، LLMNR، التشغيل
التلقائي، شبكات Wi-Fi المفتوحة، الثبات الخفي، أدوات التحكم عن بُعد...)
ويحوّلها إلى قائمة نقاط ضعف، لكل واحدة: الدليل على هذا الجهاز، ما يستطيعه
المهاجم من خلالها، وأمر الإصلاح الموصى به مع أمر التراجع.

**هذه وحدة كشف فقط.** بخلاف المرجع الأصلي
(.claude/skills/unsigned-program-detection/reference/hardening.py) الذي
يحوي دالة apply() تُطبّق الإصلاحات فعليًا على النظام، هذه الوحدة لا تُنفّذ
أي تعديل إطلاقًا: أمر الإصلاح يُعرض كنصّ فقط ليُنفّذه المستخدم بنفسه في
PowerShell كمسؤول إن قرّر ذلك. لا تعديل إعدادات، لا رفع صلاحية لتطبيق
إصلاح، لا تعطيل/تفعيل أي حماية من داخل النظام.

يُشغَّل سكربت الجمع بلا نافذة طرفية. بعض الفحوص (استثناءات Defender تحديدًا)
تتطلب صلاحية مسؤول لتظهر كاملة؛ إن عمل الوكيل بلا صلاحية مرتفعة تظهر
النتائج المتاحة فقط، وهذا سلوك صحيح لا خطأ.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
from typing import Any

from shared.models import SecurityAuditFinding

logger = logging.getLogger("aladil.discovery.vuln_audit")

# أسماء ملفات تنفيذية حسّاسة لو استُثنيت من Defender كعملية فهي علامة خطر
_SYSTEM_BINARIES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "svchost.exe", "explorer.exe", "conhost.exe",
}
# مجلدات/مسارات لو استُثنيت من Defender فهي علامة خطر (يختبئ فيها الضار)
_SUSPICIOUS_EXCL = (
    "\\appdata\\local\\updates", "\\windows\\system32\\cmd.exe",
    "\\temp", "\\users\\public", "\\downloads",
)

# سكربت جمع البيانات - للقراءة فقط بالكامل (لا يغيّر أي شيء على الجهاز)
_AUDIT_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
function RegV($path,$name){ try { (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { $null } }
$r=[ordered]@{}
$r.elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$s=Get-MpComputerStatus; $p=Get-MpPreference
$r.defender=@{ tamper=$s.IsTamperProtected; full_scan_age=$s.FullScanAge; cloud=$p.MAPSReporting; sample=$p.SubmitSamplesConsent;
  pua=$p.PUAProtection; network_protection=$p.EnableNetworkProtection;
  excl_path=@($p.ExclusionPath); excl_process=@($p.ExclusionProcess) }

$r.firewall=@(Get-NetFirewallProfile | ForEach-Object { @{name=$_.Name; enabled=[string]$_.Enabled; inbound=[string]$_.DefaultInboundAction; outbound=[string]$_.DefaultOutboundAction} })
$r.listening=@(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1)' } | ForEach-Object {
  $pr=Get-Process -Id $_.OwningProcess; @{port=$_.LocalPort; addr=[string]$_.LocalAddress; name=$pr.ProcessName} } | Sort-Object {$_.port} -Unique)

$r.uac=@{ lua=RegV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA';
  admin_prompt=RegV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin';
  secure_desktop=RegV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' }
$r.accounts=@(Get-LocalUser | ForEach-Object { @{name=$_.Name; enabled=[bool]$_.Enabled; password_required=[bool]$_.PasswordRequired; source=[string]$_.PrincipalSource} })

$r.driver_blocklist=RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'
$r.lsa_ppl=RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
$r.smartscreen=RegV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
$r.smartscreen_policy=RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
$r.remote_assistance=RegV 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'
$r.llmnr=RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
$r.autorun=RegV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
$r.secure_boot=try { [bool](Confirm-SecureBootUEFI) } catch { $null }
$r.hvci_enabled=RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled'
$r.smb1=try { [bool](Get-SmbServerConfiguration).EnableSMB1Protocol } catch { $null }
$r.rdp_denied=RegV 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'

$r.wifi_open=@(netsh wlan show profiles | Select-String 'All User Profile\s+:\s+(.+)$' | ForEach-Object {
  $n=$_.Matches[0].Groups[1].Value.Trim(); $d=netsh wlan show profile name="$n";
  if ($d -match 'Authentication\s+:\s+Open|Authentication\s+:\s+WEP') { $n } })

$r.services_userpath=@(Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'AppData|\\Temp\\|Users\\Public|ProgramData\\[^\\]+\.exe' } | ForEach-Object { @{name=$_.Name; path=$_.PathName; state=$_.State} })
$r.remote_tools=@(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  Where-Object { $_.DisplayName -match 'AnyDesk|TeamViewer|RustDesk|UltraViewer|Radmin|VNC|Splashtop|ScreenConnect|Ammyy|Supremo|AeroAdmin|LogMeIn|Chrome Remote' } | ForEach-Object { @{name=$_.DisplayName; version=[string]$_.DisplayVersion} })

$r | ConvertTo-Json -Depth 6 -Compress
"""


async def _run_audit_script(timeout: float = 120.0) -> dict | None:
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        proc = await asyncio.create_subprocess_exec(
            "powershell", "-NoProfile", "-NonInteractive", "-Command", _AUDIT_SCRIPT,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            creationflags=creationflags,
        )
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (OSError, asyncio.TimeoutError) as exc:
        logger.warning("تعذّر تشغيل سكربت التدقيق الأمني: %s", exc)
        return None
    text = stdout.decode("utf-8", errors="ignore").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning("ناتج سكربت التدقيق الأمني غير صالح كـ JSON.")
        return None


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def evaluate_audit(audit: dict) -> list[SecurityAuditFinding]:
    """
    دالة نقيّة بالكامل (بلا I/O): تحوّل ناتج سكربت التدقيق إلى قائمة نقاط
    ضعف. منقولة بأمانة من evaluate() في hardening.py المرجعية، لكن أوامر
    الإصلاح/التراجع تُخزَّن كنصّ فقط (لا تُنفَّذ). قابلة للاختبار بمعزل.
    """
    findings: list[SecurityAuditFinding] = []
    defender = audit.get("defender") or {}

    # ---- استثناءات Defender المشبوهة
    excl_path = _as_list(defender.get("excl_path"))
    excl_process = _as_list(defender.get("excl_process"))
    bad_paths = [x for x in excl_path if any(k in x.lower() for k in _SUSPICIOUS_EXCL)]
    bad_procs = [x for x in excl_process if os.path.basename(x).lower() in _SYSTEM_BINARIES]
    if bad_paths or bad_procs:
        fix = "; ".join(
            [f"Remove-MpPreference -ExclusionPath {_ps_quote(x)}" for x in bad_paths]
            + [f"Remove-MpPreference -ExclusionProcess {_ps_quote(x)}" for x in bad_procs]
        )
        undo = "; ".join(
            [f"Add-MpPreference -ExclusionPath {_ps_quote(x)}" for x in bad_paths]
            + [f"Add-MpPreference -ExclusionProcess {_ps_quote(x)}" for x in bad_procs]
        )
        findings.append(SecurityAuditFinding(
            id="def_exclusions", title="استثناءات مشبوهة في Microsoft Defender", severity="critical",
            status="vulnerable",
            evidence="مستثناة من الفحص: " + "، ".join(bad_paths + [f"العملية {x}" for x in bad_procs]),
            impact="كل ما يوضع في هذه المجلدات أو يُشغَّل عبر هذه العملية لا يفحصه Defender أبدًا؛ هكذا تختبئ البرامج الضارة وتعمل.",
            fix_command=fix, undo_command=undo, fix_risk="منخفض",
        ))

    # ---- حمايات Defender المعطّلة
    off = []
    if defender.get("cloud") in (0, None):
        off.append(("Set-MpPreference -MAPSReporting Advanced", f"Set-MpPreference -MAPSReporting {defender.get('cloud') or 0}", "الحماية السحابية"))
    if defender.get("pua") != 1:
        off.append(("Set-MpPreference -PUAProtection Enabled", f"Set-MpPreference -PUAProtection {defender.get('pua') or 0}", "حظر البرامج غير المرغوبة (PUA)"))
    if defender.get("network_protection") != 1:
        off.append(("Set-MpPreference -EnableNetworkProtection Enabled", f"Set-MpPreference -EnableNetworkProtection {defender.get('network_protection') or 0}", "حماية الشبكة"))
    if off:
        findings.append(SecurityAuditFinding(
            id="def_protections", title="حمايات Defender معطّلة", severity="high", status="vulnerable",
            evidence="معطّل: " + "، ".join(x[2] for x in off),
            impact="بلا الحماية السحابية لا يعرف Defender البرامج الجديدة؛ وبلا PUA تمرّ برامج التعدين والإعلانات؛ وبلا حماية الشبكة يتصل الضار بخوادمه بحرية.",
            fix_command="; ".join(x[0] for x in off), undo_command="; ".join(x[1] for x in off), fix_risk="منخفض",
        ))
    if not defender.get("tamper"):
        findings.append(SecurityAuditFinding(
            id="def_tamper", title="حماية Defender من العبث معطّلة", severity="high", status="vulnerable",
            evidence="Tamper Protection: معطّل",
            impact="أي برنامج بصلاحية مسؤول يستطيع إيقاف Defender أو إضافة استثناءات.",
            is_auto_safe=False,
            manual_steps=["افتح أمن Windows ← الحماية من الفيروسات والمخاطر ← إدارة الإعدادات ← شغّل «الحماية من العبث» (Windows لا يسمح بتشغيلها بأمر، عمدًا)"],
        ))
    if (defender.get("full_scan_age") or 0) > 3650:
        findings.append(SecurityAuditFinding(
            id="def_fullscan", title="لم يُجرَ فحص كامل قط", severity="medium", status="vulnerable",
            evidence="عمر آخر فحص كامل: لم يحدث",
            impact="ملفات قديمة مخبّأة في القرص لم تُفحص قط؛ الفحص السريع يرى الأماكن الشائعة فقط.",
            fix_command="Start-MpScan -ScanType FullScan -AsJob", undo_command="",
            fix_risk="لا شيء (بطء أثناء الفحص)",
        ))

    # ---- جدار الحماية
    firewall = _as_list(audit.get("firewall"))
    off_profiles = [p["name"] for p in firewall if str(p.get("enabled")).lower() != "true"]
    if off_profiles:
        listening = sorted({
            f"{x.get('name')}:{x.get('port')}" for x in _as_list(audit.get("listening"))
            if str(x.get("addr")) in ("0.0.0.0", "::")
        })
        undo = "; ".join(
            f"Set-NetFirewallProfile -Profile {p['name']} -Enabled "
            f"{'True' if str(p.get('enabled')).lower() == 'true' else 'False'}"
            for p in firewall
        )
        findings.append(SecurityAuditFinding(
            id="firewall", title="جدار الحماية متوقف", severity="critical", status="vulnerable",
            evidence="متوقف على: " + "، ".join(off_profiles)
                     + (f". خدمات مفتوحة لكل الشبكة: {'، '.join(listening[:12])}" if listening else ""),
            impact="أي جهاز على شبكتك نفسها يصل مباشرة إلى قواعد البيانات والخدمات المفتوحة ويجرّب كلمات مرورها أو ثغراتها.",
            fix_command="Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow",
            undo_command=undo, fix_risk="متوسط - قد يقطع وصول أجهزة أخرى لقواعد بياناتك؛ أضف قاعدة سماح لكل جهاز موثوق من شاشة «الشبكات الموثوقة»",
        ))

    # ---- UAC
    uac = audit.get("uac") or {}
    if uac.get("lua") == 0 or uac.get("admin_prompt") == 0 or uac.get("secure_desktop") == 0:
        findings.append(SecurityAuditFinding(
            id="uac", title="التحكم في حساب المستخدم (UAC) لا يسأل", severity="critical", status="vulnerable",
            evidence=f"EnableLUA={uac.get('lua')}، ConsentPromptBehaviorAdmin={uac.get('admin_prompt')}، PromptOnSecureDesktop={uac.get('secure_desktop')}",
            impact="أي برنامج تشغّله يحصل على صلاحية المسؤول دون أن تُسأل: يثبّت تعريفات ومهام مخفية ويعدّل Defender بصمت.",
            fix_command="$k='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty $k EnableLUA 1; Set-ItemProperty $k ConsentPromptBehaviorAdmin 5; Set-ItemProperty $k PromptOnSecureDesktop 1",
            undo_command=f"$k='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'; Set-ItemProperty $k EnableLUA {uac.get('lua', 1)}; Set-ItemProperty $k ConsentPromptBehaviorAdmin {uac.get('admin_prompt', 5)}; Set-ItemProperty $k PromptOnSecureDesktop {uac.get('secure_desktop', 1)}",
            needs_reboot=True, fix_risk="منخفض",
        ))

    # ---- حساب الضيف
    for acc in _as_list(audit.get("accounts")):
        if acc.get("name") == "Guest" and acc.get("enabled"):
            findings.append(SecurityAuditFinding(
                id="guest", title="حساب الضيف مفعّل", severity="critical", status="vulnerable",
                evidence=f"Guest مفعّل، كلمة المرور مطلوبة: {acc.get('password_required')}",
                impact="قد يدخل شخص إلى الحاسبة أو مجلداتها المشتركة دون كلمة مرور.",
                fix_command="Disable-LocalUser -Name Guest", undo_command="Enable-LocalUser -Name Guest",
                fix_risk="منخفض",
            ))

    # ---- قائمة حظر التعريفات المصابة
    if audit.get("driver_blocklist") != 1:
        findings.append(SecurityAuditFinding(
            id="driver_blocklist", title="قائمة حظر التعريفات المصابة معطّلة", severity="high", status="vulnerable",
            evidence="VulnerableDriverBlocklistEnable=0",
            impact="يستطيع المهاجم تحميل تعريف معروف الثغرات (مثل WinRing0) للوصول إلى نواة Windows.",
            fix_command="New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -Force | Out-Null; Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' VulnerableDriverBlocklistEnable 1",
            undo_command=f"Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' VulnerableDriverBlocklistEnable {audit.get('driver_blocklist') or 0}",
            needs_reboot=True, fix_risk="منخفض",
        ))

    # ---- حماية LSA
    if (audit.get("lsa_ppl") or 0) == 0:
        findings.append(SecurityAuditFinding(
            id="lsa", title="حماية LSA معطّلة", severity="high", status="vulnerable",
            evidence="RunAsPPL=0",
            impact="يستطيع برنامج بصلاحية مسؤول قراءة كلمات المرور وجلسات الدخول من ذاكرة Windows (أسلوب Mimikatz).",
            fix_command="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' RunAsPPL 2 -Type DWord",
            undo_command=f"Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' RunAsPPL {audit.get('lsa_ppl') or 0} -Type DWord",
            needs_reboot=True, fix_risk="منخفض",
        ))

    # ---- SmartScreen
    if str(audit.get("smartscreen") or "").lower() in ("off", "") and audit.get("smartscreen_policy") != 1:
        findings.append(SecurityAuditFinding(
            id="smartscreen", title="SmartScreen للبرامج متوقف", severity="medium", status="vulnerable",
            evidence=f"SmartScreenEnabled={audit.get('smartscreen')}",
            impact="تشغيل برنامج منزّل غير معروف (مثل أدوات التفعيل والبرامج المكسورة) يمرّ بلا تحذير.",
            fix_command="Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' SmartScreenEnabled 'Warn'",
            undo_command=f"Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' SmartScreenEnabled {_ps_quote(audit.get('smartscreen') or 'Off')}",
            fix_risk="منخفض",
        ))

    # ---- المساعدة عن بُعد
    if audit.get("remote_assistance") == 1:
        findings.append(SecurityAuditFinding(
            id="remote_assist", title="المساعدة عن بُعد مسموحة", severity="medium", status="vulnerable",
            evidence="fAllowToGetHelp=1",
            impact="يمكن خداعك لقبول دعوة تحكم عن بُعد (أسلوب محتالي «الدعم الفني»).",
            fix_command="Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Remote Assistance' fAllowToGetHelp 0",
            undo_command="Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Remote Assistance' fAllowToGetHelp 1",
            fix_risk="منخفض",
        ))

    # ---- LLMNR
    if audit.get("llmnr") != 0:
        findings.append(SecurityAuditFinding(
            id="llmnr", title="بروتوكول LLMNR مفعّل", severity="medium", status="vulnerable",
            evidence="EnableMulticast غير مضبوط (مفعّل افتراضيًا)",
            impact="على شبكة مشتركة يردّ المهاجم على أسماء الأجهزة بدلًا منها فيلتقط بصمات كلمات المرور (Responder).",
            fix_command="New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null; Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' EnableMulticast 0 -Type DWord",
            undo_command="Remove-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' EnableMulticast",
            fix_risk="منخفض",
        ))

    # ---- SMBv1
    if audit.get("smb1") is True:
        findings.append(SecurityAuditFinding(
            id="smb1", title="بروتوكول SMBv1 القديم مفعّل", severity="high", status="vulnerable",
            evidence="EnableSMB1Protocol=True",
            impact="بروتوكول قديم مليء بالثغرات (مثل EternalBlue/WannaCry)؛ يُستغل عن بُعد عبر الشبكة.",
            fix_command="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            undo_command="Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force",
            fix_risk="منخفض - أجهزة قديمة جدًا فقط تحتاج SMBv1",
        ))

    # ---- التشغيل التلقائي
    if audit.get("autorun") != 255:
        findings.append(SecurityAuditFinding(
            id="autorun", title="التشغيل التلقائي للأقراص والفلاشات", severity="low", status="vulnerable",
            evidence=f"NoDriveTypeAutoRun={audit.get('autorun')}",
            impact="فلاشة مصابة تشغّل محتواها عند توصيلها.",
            fix_command="New-Item 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Force | Out-Null; Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' NoDriveTypeAutoRun 255 -Type DWord",
            undo_command="Remove-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' NoDriveTypeAutoRun",
            fix_risk="منخفض",
        ))

    # ---- شبكات Wi-Fi المفتوحة المحفوظة
    for wifi in _as_list(audit.get("wifi_open")):
        findings.append(SecurityAuditFinding(
            id=f"wifi_{wifi}", title=f"شبكة Wi-Fi مفتوحة محفوظة: {wifi}", severity="medium", status="vulnerable",
            evidence="بلا تشفير، وتتصل الحاسبة بها تلقائيًا",
            impact="أي شخص على الشبكة نفسها يرى ما لا يشفّره البرنامج، ويمكنه إنشاء شبكة مزيفة بالاسم نفسه.",
            fix_command=f"netsh wlan set profileparameter name={_ps_quote(wifi)} connectionmode=manual",
            undo_command=f"netsh wlan set profileparameter name={_ps_quote(wifi)} connectionmode=auto",
            fix_risk="منخفض - تبقى محفوظة لكن لا تتصل وحدها",
        ))

    # ---- الإقلاع الآمن (يدوي: BIOS)
    if audit.get("secure_boot") is False:
        findings.append(SecurityAuditFinding(
            id="secure_boot", title="الإقلاع الآمن (Secure Boot) متوقف", severity="medium", status="vulnerable",
            evidence="Confirm-SecureBootUEFI = False",
            impact="يمكن لبرنامج خبيث أن يزرع نفسه قبل Windows (bootkit) فلا يراه أي برنامج حماية.",
            is_auto_safe=False,
            manual_steps=[
                "أعد التشغيل وادخل BIOS (غالبًا F2) ← Security ← Secure Boot ← Enabled ثم احفظ (F10)",
                "قبل ذلك تأكد أن وضع الإقلاع UEFI لا Legacy/CSM، وإلا قد لا يقلع Windows",
            ],
        ))

    # ---- سلامة الذاكرة (يدوي)
    if audit.get("hvci_enabled") != 1:
        findings.append(SecurityAuditFinding(
            id="hvci", title="سلامة الذاكرة (Memory integrity) متوقفة", severity="medium", status="vulnerable",
            evidence="HVCI غير مفعّل",
            impact="تمنع تحميل تعريفات غير موقّعة أو ضعيفة إلى النواة؛ بدونها يصل التعريف الضار إلى أعمق مستوى.",
            is_auto_safe=False,
            manual_steps=[
                "أمن Windows ← أمان الجهاز ← عزل الأساس ← سلامة الذاكرة ← تشغيل (ثم إعادة تشغيل)",
                "إن رفض Windows بسبب تعريف غير متوافق فاعرض اسمه قبل حذفه",
            ],
        ))

    # ---- خدمات تعمل من مسارات المستخدم (ثبات مشبوه)
    services = _as_list(audit.get("services_userpath"))
    if services:
        findings.append(SecurityAuditFinding(
            id="services_userpath", title="خدمات تعمل من مسارات المستخدم", severity="high", status="vulnerable",
            evidence="، ".join(f"{s.get('name')} ({s.get('path')})" for s in services[:6]),
            impact="الخدمات الشرعية تعمل من Program Files/System32؛ خدمة تعمل من AppData/Temp علامة ثبات لبرنامج ضار.",
            is_auto_safe=False,
            manual_steps=["راجع كل خدمة: إن لم تعرف مصدرها فابحث عن اسمها قبل تعطيلها عبر services.msc"],
        ))

    # ---- أدوات التحكم عن بُعد المثبَّتة (للعلم)
    remote_tools = _as_list(audit.get("remote_tools"))
    if remote_tools:
        findings.append(SecurityAuditFinding(
            id="remote_tools", title="أدوات تحكم عن بُعد مثبَّتة", severity="low", status="info",
            evidence="، ".join(f"{t.get('name')} {t.get('version') or ''}".strip() for t in remote_tools),
            impact="هذه الأدوات تتيح وصولًا عن بُعد لجهازك. تأكد أنك ثبّتها أنت وأنها محمية بكلمة مرور قوية و2FA.",
            is_auto_safe=False,
            manual_steps=["إن لم تثبّت إحداها بنفسك فأزلها فورًا، وغيّر كلمات مرور الأدوات التي تستخدمها"],
        ))

    return findings


async def run_security_audit() -> list[SecurityAuditFinding]:
    """الفحص الكامل: يشغّل سكربت التدقيق (قراءة فقط) ثم يقيّمه. يُرجع قائمة
    نقاط الضعف مُرتَّبة حسب الخطورة. لا يُعدّل أي إعداد على الجهاز."""
    audit = await _run_audit_script()
    if not audit:
        return []
    findings = evaluate_audit(audit)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f.severity, 9))
    return findings
