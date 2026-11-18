"""
كشف البرامج غير الموقَّعة والمتخفّية على جهاز النظام نفسه (الجهاز الذي
يعمل عليه الوكيل) - وليس أجهزة الشبكة البعيدة. هذه وحدة **قراءة فقط**:
لا توقف عملية، ولا تحذف ملفًا، ولا تعزل أي شيء، ولا ترفع أي بيانات لأي
خدمة خارجية. كل نتيجة تُعرض بدرجتها وكل أسبابها كاملة ليقرر المستخدم
بنفسه - أي إجراء احتواء (إيقاف/عزل) خطوة منفصلة يختارها وينفّذها هو
بنفسه خارج هذا النظام تمامًا.

مبنية على منهجية .claude/skills/unsigned-program-detection/SKILL.md
(القسم الأول فقط: الكشف) مع إعادة هيكلتها بنمط asyncio المتوافق مع بقية
الوكيل بدلًا من استدعاءات PowerShell المتزامنة في المرجع الأصلي، ودون
أي من دوال الاحتواء (إيقاف/عزل/استعادة) الموجودة هناك.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from shared.models import UnsignedProgramFinding

logger = logging.getLogger("aladil.discovery.unsigned_programs")

WRITABLE = re.compile(r"\\(appdata|temp|programdata|users\\public|downloads)\\", re.I)
MIMIC = re.compile(
    r"(windows|system|service|svchost|update|host|runtime|defender|security|driver|nvidia|intel|microsoft)",
    re.I,
)
HOLLOW_HOSTS = {
    "cmd.exe", "conhost.exe", "svchost.exe", "explorer.exe", "notepad.exe", "dllhost.exe",
    "regsvcs.exe", "regasm.exe", "applaunch.exe", "msbuild.exe", "installutil.exe",
    "rundll32.exe", "werfault.exe", "vbc.exe", "aspnet_compiler.exe", "attrib.exe",
    "nslookup.exe", "wuauclt.exe",
}
INDICATORS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(rb"WinRing0|OpenLibSys", re.I),
     "يحمل أداة WinRing0/OpenLibSys للوصول إلى مسجّلات المعالج (تستعملها برامج التعدين)", 30),
    (re.compile(rb"xmrig|randomx|cryptonight|nicehash|ethminer|lolminer|phoenixminer|t-rex|nbminer|gminer", re.I),
     "يحمل اسم برنامج أو خوارزمية تعدين معروفة", 35),
    (re.compile(rb"stratum\+(tcp|ssl)|mining\.subscribe|\"pools\"\s*:", re.I),
     "يحمل بروتوكول تجمّعات التعدين (stratum)", 35),
    (re.compile(rb"\b(donate-level|cpu-max-threads-hint|nicehash\.com|minexmr|supportxmr|2miners|f2pool)\b", re.I),
     "يحمل إعدادات تعدين", 25),
    (re.compile(rb"VirtualAllocEx|WriteProcessMemory|NtUnmapViewOfSection|SetThreadContext|ResumeThread", re.I),
     "يستورد دوال حقن الذاكرة في عملية أخرى", 15),
]
URL_RE = re.compile(rb"https?://[\x21-\x7e]{4,120}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")
BENIGN_URL = re.compile(
    r"crl\.|ocsp\.|digicert|globalsign|verisign|microsoft\.com/pki|symantec|sectigo|usertrust|thawte|w3\.org|schemas\.",
    re.I,
)
STORE_APP = re.compile(r"\\program files\\windowsapps\\", re.I)
STANDARD_PORTS = {80, 443, 53, 8080, 8443, 993, 995, 587, 465, 143, 110, 21, 22, 3389}

_ZONE_NAMES = {"0": "هذا الجهاز", "1": "الشبكة المحلية", "2": "موقع موثوق", "3": "الإنترنت", "4": "موقع محظور"}

_GATHER_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
$r = @{}
$r.procs = @(Get-CimInstance Win32_Process | ForEach-Object { @{pid=$_.ProcessId; ppid=$_.ParentProcessId; name=$_.Name; path=$_.ExecutablePath; cmd=$_.CommandLine; ws=$_.WorkingSetSize} })
$r.net = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } | ForEach-Object { @{pid=$_.OwningProcess; ra=$_.RemoteAddress; rp=$_.RemotePort} })
$r.tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $t=$_; foreach($a in $t.Actions){ if($a.Execute){ @{name=($t.TaskPath+$t.TaskName); exe=$a.Execute; args=$a.Arguments; author=$t.Author; hidden=[bool]$t.Settings.Hidden; level=[string]$t.Principal.RunLevel} } } })
$r.run = @()
foreach($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'){
  $p = Get-ItemProperty $k -ErrorAction SilentlyContinue; if($p){ $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $r.run += @{key=$k; name=$_.Name; value=[string]$_.Value} } } }
$r | ConvertTo-Json -Depth 6 -Compress
"""

_FILES_SCRIPT_TEMPLATE = r"""
$ErrorActionPreference='SilentlyContinue'
$out = @{}
foreach($p in @(__LIST__)){
  if(-not (Test-Path -LiteralPath $p)){ continue }
  $i = Get-Item -LiteralPath $p; $s = Get-AuthenticodeSignature -LiteralPath $p; $v = $i.VersionInfo
  $z = Get-Content -LiteralPath $p -Stream Zone.Identifier -Raw -ErrorAction SilentlyContinue
  $owner = try { (Get-Acl -LiteralPath $p -ErrorAction Stop).Owner } catch { $null }
  $out[$p] = @{sig=[string]$s.Status; signer=[string]$s.SignerCertificate.Subject; owner=$owner;
    created=$i.CreationTime.ToString('yyyy-MM-dd HH:mm'); modified=$i.LastWriteTime.ToString('yyyy-MM-dd HH:mm');
    company=$v.CompanyName; product=$v.ProductName; description=$v.FileDescription; zone=$z}
}
$out | ConvertTo-Json -Depth 6 -Compress
"""


async def _run_powershell_json(script: str, timeout: float = 180.0) -> Any:
    """يُشغّل سكربت PowerShell بلا نافذة طرفية ويرجع ناتجه JSON مفكوكًا.
    قراءة فقط دائمًا - السكربتات هنا لا تغيّر أي شيء على الجهاز."""
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        proc = await asyncio.create_subprocess_exec(
            "powershell", "-NoProfile", "-NonInteractive", "-Command", script,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            creationflags=creationflags,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (OSError, asyncio.TimeoutError) as exc:
        logger.warning("تعذّر تشغيل PowerShell لفحص البرامج غير الموقَّعة: %s", exc)
        return None
    text = stdout.decode("utf-8", errors="ignore").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning("ناتج PowerShell غير صالح كـ JSON أثناء فحص البرامج غير الموقَّعة.")
        return None


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _resolve_exe(text: str | None) -> str | None:
    """يستخرج مسار الملف التنفيذي من سطر أوامر/إجراء مهمة مجدولة/قيمة Run."""
    if not text:
        return None
    expanded = os.path.expandvars(text.strip())
    m = re.match(r'^"([^"]+)"', expanded)
    candidate = m.group(1) if m else None
    if not candidate:
        m = re.match(r"^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|scr|dll))\b", expanded, re.I)
        candidate = m.group(1) if m else expanded.split(" ")[0]
    if candidate and not os.path.isabs(candidate):
        sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", candidate)
        candidate = sysdir if os.path.isfile(sysdir) else candidate
    return candidate


def entropy(data: bytes) -> float:
    """إنتروبيا شانون لبايتات - قيمة عالية (>7.6 من أصل 8) مع حجم كبير
    وبلا توقيع نوع ملف معروف تشير لحمولة مشفَّرة مخفية."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def pe_info(data: bytes) -> dict[str, Any]:
    """يقرأ ترويسة PE دون تنفيذ الملف إطلاقًا: نوع المعالج، وقت الترجمة،
    وهل هو DLL/.NET، وأسماء الدوال المستوردة (كمؤشرات سلوك فقط)."""
    if data[:2] != b"MZ" or len(data) < 64:
        return {"pe": False}
    try:
        pe_offset = struct.unpack_from("<I", data, 60)[0]
        if data[pe_offset:pe_offset + 4] != b"PE\0\0":
            return {"pe": False}
        machine, _nsec, ts = struct.unpack_from("<HHI", data, pe_offset + 4)
        chars = struct.unpack_from("<H", data, pe_offset + 22)[0]
    except struct.error:
        return {"pe": False}
    return {
        "pe": True,
        "machine": {0x8664: "x64", 0x14C: "x86", 0xAA64: "ARM64"}.get(machine, hex(machine)),
        "compiled_utc": time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) if ts else None,
        "dll": bool(chars & 0x2000),
        "dotnet": b"_CorExeMain" in data or b"mscoree.dll" in data,
    }


def analyze_file(path: str, max_bytes: int = 64 << 20) -> dict[str, Any]:
    """يحلّل محتوى الملف (هاش، PE، مؤشرات سلوكية، روابط/عناوين IP مضمَّنة،
    وملفات مجاورة قد تكون حمولة مشفَّرة) دون تنفيذه إطلاقًا."""
    p = Path(path)
    try:
        data = p.read_bytes()[:max_bytes]
    except OSError as exc:
        return {"error": str(exc)}

    sha256 = hashlib.sha256(data).hexdigest().upper()
    found: list[str] = []
    indicator_score = 0
    for pattern, reason, points in INDICATORS:
        if pattern.search(data):
            found.append(reason)
            indicator_score += points

    urls = sorted({u.decode(errors="ignore").rstrip("\x00") for u in URL_RE.findall(data)})
    urls = [u for u in urls if not BENIGN_URL.search(u)][:20]
    ips = sorted({i.decode() for i in IP_RE.findall(data)})[:20]

    siblings_has_encrypted = False
    try:
        for sibling in sorted(p.parent.iterdir()):
            if sibling == p or not sibling.is_file():
                continue
            size = sibling.stat().st_size
            if size <= 100_000:
                continue
            head = sibling.read_bytes()[:65536]
            if entropy(head) > 7.6 and head[:2] not in (b"MZ", b"PK", b"\x1f\x8b"):
                siblings_has_encrypted = True
                break
    except OSError:
        pass

    return {
        "sha256": sha256, "pe": pe_info(data), "indicators": found,
        "indicator_score": indicator_score, "urls": urls, "ips": ips,
        "has_encrypted_sibling": siblings_has_encrypted,
    }


def parse_zone(text: str | None) -> dict[str, str]:
    """يفكّك تيار Zone.Identifier (من أين نزل الملف فعليًا - المنطقة 3 = الإنترنت)."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    if "ZoneId" in out:
        out["ZoneName"] = _ZONE_NAMES.get(out["ZoneId"], out["ZoneId"])
    return out


def score_finding(
    path: str, file_info: dict, launchers: list[dict], processes: list[dict], analysis: dict
) -> tuple[int, str, list[str]]:
    """يحسب الدرجة (0-100) وسبب كل نقطة، كما في منهجية المهارة الأصلية.
    دالة نقيّة بالكامل (بلا أي I/O) لسهولة اختبارها بمعزل عن بقية الوحدة."""
    reasons: list[str] = []
    score = 0
    is_store_app = bool(STORE_APP.search(path))
    signature_status = file_info.get("sig")

    if signature_status and signature_status != "Valid" and not is_store_app:
        score += 20
        reasons.append("غير موقّع رقميًا" if signature_status == "NotSigned" else f"توقيعه غير صالح ({signature_status})")
    elif is_store_app and signature_status != "Valid":
        reasons.append("تطبيق من متجر Microsoft: موقّع على مستوى الحزمة لا الملف")

    if WRITABLE.search(path + "\\"):
        score += 15
        reasons.append("يعمل من مجلد يكتب فيه أي برنامج (AppData/Temp/ProgramData)")

    if signature_status != "Valid" and not is_store_app and MIMIC.search(Path(path).stem):
        score += 15
        reasons.append("اسمه يوهم أنه من Windows أو من صانع معروف")

    if (
        signature_status != "Valid" and not is_store_app
        and not (file_info.get("company") or file_info.get("product") or file_info.get("description"))
    ):
        score += 5
        reasons.append("بلا اسم شركة ولا وصف")

    for launcher in launchers:
        if launcher.get("hidden"):
            score += 10
            reasons.append(f"مهمة مجدولة مخفية: {launcher.get('name')}")
        if (launcher.get("level") or "").lower() == "highest":
            score += 10
            reasons.append("تعمل بأعلى صلاحية")

    score += analysis.get("indicator_score", 0)
    reasons += analysis.get("indicators", [])
    if analysis.get("has_encrypted_sibling"):
        score += 10
        reasons.append("بجانبه ملف مشفّر كبير (حمولة مخفية محتملة)")

    for proc in processes:
        if proc.get("hollow"):
            score += 30
            reasons.append(f"برنامج ويندوز ({proc.get('name')}) بلا سطر أوامر وبحمل عالٍ: قد يكون برنامجًا مختبئًا داخله")
        for conn in proc.get("connections", []):
            if conn.get("rp") not in STANDARD_PORTS:
                score += 10
                reasons.append(f"متصل بخادم خارجي على منفذ غير معتاد {conn.get('ra')}:{conn.get('rp')}")
                break

    score = min(100, score)
    level = "danger" if score >= 60 else "suspect" if score >= 35 else "review"
    return score, level, list(dict.fromkeys(reasons))


async def scan_unsigned_programs() -> list[UnsignedProgramFinding]:
    """الفحص الكامل: يجمع العمليات الجارية، المهام المجدولة، ومفاتيح
    التشغيل التلقائي، ثم يفحص توقيع كل ملف تنفيذي فريد عبر PowerShell
    (قراءة فقط)، ويحلّله محليًا دون تنفيذه، ويُرجع النتائج مُرتَّبة حسب
    الدرجة تنازليًا. لا يوقف ولا يحذف ولا يعزل أي شيء."""
    gathered = await _run_powershell_json(_GATHER_SCRIPT)
    if not gathered:
        return []

    procs = _as_list(gathered.get("procs"))
    net = _as_list(gathered.get("net"))
    tasks = _as_list(gathered.get("tasks"))
    run_entries = _as_list(gathered.get("run"))

    connections_by_pid: dict[int, list[dict]] = {}
    for conn in net:
        pid = int(conn.get("pid") or 0)
        connections_by_pid.setdefault(pid, []).append({"ra": conn.get("ra"), "rp": int(conn.get("rp") or 0)})

    launchers_by_path: dict[str, list[dict]] = {}
    for task in tasks:
        exe = _resolve_exe(task.get("exe"))
        if exe:
            launchers_by_path.setdefault(exe.lower(), []).append({
                "type": "task", "name": task.get("name"), "author": task.get("author"),
                "hidden": bool(task.get("hidden")), "level": task.get("level"),
            })
    for entry in run_entries:
        exe = _resolve_exe(entry.get("value"))
        if exe:
            launchers_by_path.setdefault(exe.lower(), []).append({
                "type": "run", "name": f"{entry.get('key')} → {entry.get('name')}",
            })

    processes_by_path: dict[str, list[dict]] = {}
    hollow_processes: list[dict] = []
    for proc in procs:
        pid = int(proc.get("pid") or 0)
        name = (proc.get("name") or "").lower()
        cmdline = (proc.get("cmd") or "").strip()
        connections = connections_by_pid.get(pid, [])
        heavy = (proc.get("ws") or 0) >= (1 << 30)  # ≥1GB working set (لا توجد نسبة CPU متاحة بلا أخذ عينتين)
        odd_port = any(c["rp"] not in STANDARD_PORTS for c in connections)
        entry = {
            "pid": pid, "name": proc.get("name"), "cmd": cmdline, "connections": connections,
            "hollow": name in HOLLOW_HOSTS and not cmdline and heavy and odd_port and pid > 4,
        }
        if proc.get("path"):
            processes_by_path.setdefault(proc["path"].lower(), []).append(entry)
        if entry["hollow"]:
            hollow_processes.append(entry)

    all_paths = {p for p in [*processes_by_path, *launchers_by_path] if p and os.path.isfile(p)}
    if not all_paths:
        return []

    quoted = ",".join("'" + p.replace("'", "''") + "'" for p in all_paths)
    files_script = _FILES_SCRIPT_TEMPLATE.replace("__LIST__", quoted)
    file_info_by_path = await _run_powershell_json(files_script, timeout=240.0) or {}
    file_info_lc = {k.lower(): v for k, v in file_info_by_path.items()}

    findings: list[UnsignedProgramFinding] = []
    for path_lc in all_paths:
        info = file_info_lc.get(path_lc) or {}
        is_signed_valid = info.get("sig") == "Valid"
        is_store_app = bool(STORE_APP.search(path_lc))
        if is_signed_valid and not is_store_app:
            continue  # موقَّع وصالح وليس تطبيق متجر - لا داعي للإبلاغ عنه

        real_path = next((p for p in all_paths if p.lower() == path_lc), path_lc)
        analysis = analyze_file(real_path) if os.path.isfile(real_path) else {}
        launchers = launchers_by_path.get(path_lc, [])
        processes = processes_by_path.get(path_lc, [])
        score, level, reasons = score_finding(real_path, info, launchers, processes, analysis)

        findings.append(UnsignedProgramFinding(
            path=real_path, display_name=os.path.basename(real_path), score=score, level=level,
            reasons=reasons, signature_status=info.get("sig"), signer=info.get("signer"),
            company=info.get("company"), product=info.get("product"), description=info.get("description"),
            owner=info.get("owner"), created=info.get("created"), modified=info.get("modified"),
            sha256=analysis.get("sha256"),
            zone_name=parse_zone(info.get("zone")).get("ZoneName"),
            zone_host_url=parse_zone(info.get("zone")).get("HostUrl"),
            indicators=analysis.get("indicators", []), urls=analysis.get("urls", []),
            ips=analysis.get("ips", []), has_encrypted_sibling=analysis.get("has_encrypted_sibling", False),
            launchers=launchers, processes=processes,
        ))

    # عمليات "الاختباء داخل برنامج موقَّع" (hollowing) التي لم تُنسَب لأي
    # ملف غير موقَّع أعلاه تُبلَّغ عنها بشكل مستقل
    reported_pids = {p["pid"] for f in findings for p in f.processes}
    for hollow in hollow_processes:
        if hollow["pid"] in reported_pids:
            continue
        score, level, reasons = score_finding(f"(داخل {hollow['name']})", {"sig": "Valid"}, [], [hollow], {})
        findings.append(UnsignedProgramFinding(
            path=f"(داخل {hollow['name']})", display_name=hollow["name"], score=score, level=level,
            reasons=reasons, signature_status="Valid", processes=[hollow],
        ))

    findings.sort(key=lambda f: -f.score)
    return findings
