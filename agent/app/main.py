"""
نقطة دخول العميل (Agent) — يعمل على كل جهاز، يفحص الشبكة المحلية
(Ethernet/Wi-Fi/Bluetooth) بشكل دوري ومتوازٍ، ويرسل النتائج للخادم
المركزي. يمكن أيضًا تمرير نطاقات خارجية إضافية عبر --target (تتطلب
تأكيد تفويض صريح).
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# يضمن أن الطرفية على ويندوز (أو أي ترميز غير utf-8) تستطيع طباعة النصوص
# العربية دون فشل (UnicodeEncodeError)، سواء من argparse أو من logging.
# ملاحظة: عند البناء بوضع --windowed (بلا نافذة طرفية، للنسخة الرسومية
# غير المزعجة) تكون sys.stdout/stderr قيمتها None فعليًا، لذا hasattr
# على None يتجنّب الانهيار هنا بأمان.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

# يسمح بتشغيل الملف مباشرة (python agent/app/main.py) من جذر المشروع
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx

from agent.app.config import CONFIG_DIR, AgentConfig
from agent.app.services.scan_orchestrator import AgentScanConfig, run_full_scan
from agent.app.status_writer import write_error_status, write_status
from shared.models import ConnectionMedium, ScanTarget


def _configure_logging() -> None:
    """
    يسجّل دائمًا في ملف (agent.log) بغضّ النظر عن وضع التشغيل، ويضيف
    إخراجًا لنافذة الطرفية فقط إن وُجدت فعليًا (sys.stderr غير None) -
    بدون هذا الفحص ينهار البرنامج فورًا عند البناء بوضع --windowed حيث
    لا توجد نافذة طرفية أصلًا، لأن StreamHandler الافتراضي يفترض وجود
    stderr صالح للكتابة.
    """
    handlers: list[logging.Handler] = []
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(CONFIG_DIR / "agent.log", encoding="utf-8")
        handlers.append(file_handler)
    except OSError:
        pass
    if sys.stderr is not None:
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers or None,  # None -> يسقط إلى سلوك logging الافتراضي كحل أخير
    )


_configure_logging()
logger = logging.getLogger("aladil.agent")


async def _submit_report(server_url: str, license_key: str, report) -> None:
    url = f"{server_url.rstrip('/')}/api/scans/report"
    headers = {"X-License-Key": license_key, "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.post(
                url, headers=headers, content=report.model_dump_json()
            )
            response.raise_for_status()
            logger.info("تم إرسال تقرير الفحص بنجاح: %s", response.json())
        except httpx.HTTPError as exc:
            logger.error("فشل إرسال تقرير الفحص إلى الخادم: %s", exc)


async def run_once(cfg: AgentConfig, extra_targets: list[ScanTarget]) -> None:
    logger.info("بدء دورة فحص جديدة (agent_id=%s)...", cfg.agent_id)
    try:
        report = await run_full_scan(
            agent_id=cfg.agent_id,
            targets=extra_targets,
            config=AgentScanConfig(enable_cve_lookup=True),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("فشلت دورة الفحص بالكامل")
        write_error_status(str(exc))
        return

    logger.info(
        "اكتمل الفحص: %d جهاز، %d خطأ/تحذير.", len(report.devices), len(report.errors)
    )
    for err in report.errors:
        logger.warning("  - %s", err)

    if cfg.license_key:
        await _submit_report(cfg.server_url, cfg.license_key, report)
    else:
        logger.warning("لا يوجد مفتاح ترخيص مُعد؛ لن يتم إرسال التقرير للخادم.")

    # يُستخدم من أيقونة النظام (tray_app.py) لعرض حالة مبسّطة ومفهومة
    # للمستخدم دون نافذة طرفية سوداء
    write_status(report)


async def run_forever(cfg: AgentConfig, extra_targets: list[ScanTarget]) -> None:
    while True:
        await run_once(cfg, extra_targets)
        logger.info("الانتظار %d ثانية قبل دورة الفحص التالية...", cfg.scan_interval_seconds)
        await asyncio.sleep(cfg.scan_interval_seconds)


def _build_targets(args: argparse.Namespace) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    for raw in args.target or []:
        if not args.authorize:
            print(
                f"تحذير: الهدف '{raw}' يتطلب تأكيد تفويض صريح. أضف --authorize "
                "لتأكيد أنك تملك هذا النطاق أو مُصرَّح لك قانونيًا بفحصه."
            )
            continue
        targets.append(
            ScanTarget(
                cidr_or_host=raw,
                medium=ConnectionMedium.EXTERNAL,
                authorized_by_user=True,
                authorization_note=args.authorize_note or "confirmed via CLI --authorize",
            )
        )
    return targets


def main() -> None:
    parser = argparse.ArgumentParser(description="AlAdil Cybersecurity Agent")
    parser.add_argument("--server", help="عنوان الخادم المركزي", default=None)
    parser.add_argument("--license-key", help="مفتاح الترخيص", default=None)
    parser.add_argument(
        "--target", action="append", help="نطاق/عنوان خارجي إضافي لفحصه (CIDR أو host)"
    )
    parser.add_argument(
        "--authorize",
        action="store_true",
        help="تأكيد صريح بأنك تملك/مُصرَّح لك بفحص النطاقات الخارجية الممرَّرة",
    )
    parser.add_argument("--authorize-note", help="ملاحظة توثّق أساس التفويض", default=None)
    parser.add_argument("--once", action="store_true", help="تنفيذ فحص واحد ثم الخروج")
    parser.add_argument(
        "--configure-only",
        action="store_true",
        help=(
            "يحفظ --server/--license-key في ملف الإعدادات المشفَّر ثم يخرج فورًا "
            "دون تشغيل أي فحص. يُستخدم من مثبّت ويندوز أثناء التثبيت الأول فقط "
            "(التحديثات على تثبيت سابق لا تحتاج إعادة إدخال رمز التفعيل)."
        ),
    )
    args = parser.parse_args()

    cfg = AgentConfig()
    if args.server:
        cfg.set_server_url(args.server)
    if args.license_key:
        cfg.set_license_key(args.license_key)

    if args.configure_only:
        logger.info("تم حفظ الإعدادات بنجاح (وضع configure-only). الخروج دون فحص.")
        return

    extra_targets = _build_targets(args)

    if args.once:
        asyncio.run(run_once(cfg, extra_targets))
    else:
        asyncio.run(run_forever(cfg, extra_targets))


if __name__ == "__main__":
    main()
