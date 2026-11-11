"""
يُزامن بناء مثبّت ويندوز مع آخر تطوير في الكود: يقرأ رقم الإصدار من ملف
VERSION في جذر المشروع، يبني العميل (aladil-agent.exe) + الواجهة
الرسومية (aladil-tray.exe) بأحدث كود، يولّد الأيقونات/صور معالج التثبيت
من الهوية البصرية، ثم يُمرّر رقم الإصدار نفسه إلى Inno Setup (ISCC) بحيث
يحمل المثبّت الناتج دائمًا رقم إصدار الكود الفعلي الذي بُني منه.

يحتفظ أيضًا بسجل إصدارات (releases/release_log.json) لكل بناء، وإن
زوّدته ببيانات عميل يُصدر له رمز تفعيل مرن المدة (دقيقة/ساعة/يوم/أسبوع/
شهر/سنة + عدد) + بطاقة تسليم احترافية (صورة + نص رسالة جاهز).

أمثلة الاستخدام:
    python scripts/build_installer.py
    python scripts/build_installer.py --bump patch

    # بناء + إصدار ترخيص لعميل محدَّد مع بطاقة تسليم جاهزة:
    python scripts/build_installer.py \
        --customer-name "شركة المثال" --customer-email "contact@example.com" \
        --duration-unit month --duration-count 3 --max-agents 5

الناتج:
    dist/AlAdilCybersecurity-Agent-Setup-<version>.exe
    releases/release_log.json           (سجل كل البناءات/التراخيص الصادرة)
    releases/cards/<customer>_<ts>.png  (بطاقة التسليم، إن طُلب ترخيص)
    releases/cards/<customer>_<ts>.txt  (نص الرسالة الجاهز للصق)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

# يضمن أن الطرفية على ويندوز (ترميز cp1252 الافتراضي) تستطيع طباعة
# النصوص العربية والرموز التعبيرية في رسائل هذا السكربت دون فشل الإقلاع
# (UnicodeEncodeError) - نفس الإصلاح المطبَّق في نقاط الدخول الأخرى.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # للسماح باستيراد server.app.services.license_service مباشرة

VERSION_FILE = ROOT / "VERSION"
RELEASE_LOG_FILE = ROOT / "releases" / "release_log.json"
ISCC_CANDIDATES = [
    r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    r"C:\Program Files\Inno Setup 6\ISCC.exe",
    r"C:\Program Files\Inno Setup 7\ISCC.exe",
    r"C:\Program Files (x86)\Inno Setup 7\ISCC.exe",
]

# NSSM (public domain, nssm.cc) يُغلّف aladil-agent.exe كخدمة ويندوز
# حقيقية تتحدّث مع SCM بشكل صحيح بدل sc.exe المباشر. يُنزَّل مرة واحدة
# فقط عند أول بناء على هذا الجهاز ويُخزَّن محليًا للبناءات التالية.
NSSM_URL = "https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip"
NSSM_INNER_PATH = "nssm-2.24-101-g897c7ad/win64/nssm.exe"
NSSM_DEST = ROOT / "installers" / "windows" / "redist" / "nssm.exe"


def ensure_nssm() -> None:
    if NSSM_DEST.exists():
        return
    import urllib.request

    print("تنزيل NSSM (مرة واحدة فقط) لتغليف العميل كخدمة ويندوز حقيقية...")
    NSSM_DEST.parent.mkdir(parents=True, exist_ok=True)
    zip_path = NSSM_DEST.parent / "_nssm_download.zip"
    urllib.request.urlretrieve(NSSM_URL, zip_path)  # noqa: S310  # مصدر ثابت معروف (nssm.cc الرسمي)
    with zipfile.ZipFile(zip_path) as zf:
        with zf.open(NSSM_INNER_PATH) as src, open(NSSM_DEST, "wb") as dst:
            dst.write(src.read())
    zip_path.unlink(missing_ok=True)
    print(f"تم: {NSSM_DEST}")


def read_version() -> str:
    if not VERSION_FILE.exists():
        VERSION_FILE.write_text("0.1.0\n", encoding="utf-8")
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def bump_version(version: str, part: str) -> str:
    major, minor, patch = (int(x) for x in version.split("."))
    if part == "major":
        major, minor, patch = major + 1, 0, 0
    elif part == "minor":
        minor, patch = minor + 1, 0
    elif part == "patch":
        patch += 1
    new_version = f"{major}.{minor}.{patch}"
    VERSION_FILE.write_text(new_version + "\n", encoding="utf-8")
    return new_version


def find_iscc() -> str:
    for candidate in ISCC_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return "ISCC.exe"  # يبحث في PATH كحل أخير


def append_release_log(entry: dict) -> None:
    RELEASE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log = []
    if RELEASE_LOG_FILE.exists():
        try:
            log = json.loads(RELEASE_LOG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            log = []
    log.append(entry)
    RELEASE_LOG_FILE.write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")


def issue_license_for_release(
    version: str,
    customer_name: str,
    customer_email: str,
    duration_unit: str,
    duration_count: int,
    max_agents: int,
    server_url: str,
) -> dict:
    """يولّد رمز تفعيل موقَّعًا محليًا (بدون حاجة لخادم يعمل)، ويبني بطاقة
    التسليم + نص الرسالة، ويسجّل كل ذلك في سجل الإصدارات."""
    from server.app.services.license_service import generate_license_key, verify_license_key
    from scripts.generate_license_card import build_card_image, build_message_text

    is_lifetime = duration_unit == "lifetime"
    license_key = generate_license_key(
        customer_name, customer_email, max_agents,
        duration_unit=None if is_lifetime else duration_unit,
        duration_count=duration_count,
    )
    payload = verify_license_key(license_key)  # لاستخراج expires_at المحسوبة فعليًا
    expires_at = (payload or {}).get("expires_at") or ""

    safe_name = "".join(c if c.isalnum() else "_" for c in customer_name)[:40]
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    cards_dir = ROOT / "releases" / "cards"
    image_path = cards_dir / f"{safe_name}_{timestamp}.png"
    text_path = cards_dir / f"{safe_name}_{timestamp}.txt"

    build_card_image(
        customer_name, license_key, duration_unit, duration_count, expires_at, version, image_path
    )
    text_path.write_text(
        build_message_text(
            customer_name, license_key, duration_unit, duration_count, expires_at, version, server_url
        ),
        encoding="utf-8",
    )

    append_release_log(
        {
            "version": version,
            "built_at": datetime.utcnow().isoformat() + "Z",
            "customer_name": customer_name,
            "customer_email": customer_email,
            "duration_unit": duration_unit,
            "duration_count": duration_count,
            "max_agents": max_agents,
            "expires_at": expires_at,
            # نخزّن بصمة قصيرة فقط من المفتاح في السجل المحلي، وليس
            # المفتاح الكامل، لتقليل أثر تسرّب ملف السجل نفسه
            "license_key_preview": f"{license_key[:14]}...{license_key[-8:]}",
            "card_image": str(image_path.relative_to(ROOT)),
            "card_text": str(text_path.relative_to(ROOT)),
        }
    )

    print(f"\n📇 بطاقة التسليم: {image_path}")
    print(f"📄 نص الرسالة الجاهز: {text_path}")
    return {"license_key": license_key, "expires_at": expires_at}


def main() -> None:
    parser = argparse.ArgumentParser(description="بناء مثبّت ويندوز مُزامَن مع الإصدار")
    parser.add_argument(
        "--bump", choices=["major", "minor", "patch"], default=None,
        help="يرفع رقم الإصدار تلقائيًا قبل البناء (وإلا يُستخدم رقم VERSION الحالي)",
    )
    parser.add_argument("--customer-name", default=None, help="يُصدر ترخيصًا لهذا العميل مع البناء")
    parser.add_argument("--customer-email", default=None)
    parser.add_argument("--duration-unit", default="day",
                         choices=["minute", "hour", "day", "week", "month", "year", "lifetime"])
    parser.add_argument("--duration-count", type=int, default=365)
    parser.add_argument("--max-agents", type=int, default=1)
    parser.add_argument("--server-url", default="http://localhost:8000",
                         help="يُذكر في رسالة التسليم للعميل")
    args = parser.parse_args()

    version = bump_version(read_version(), args.bump) if args.bump else read_version()
    print(f"=== بناء الإصدار {version} ===")

    print("\n[1/5] توليد الأيقونة وصور معالج التثبيت من الهوية البصرية...")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_app_icon.py")], check=True)

    print("\n[2/5] بناء خدمة الفحص الخلفية (aladil-agent.exe) من أحدث كود...")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_agent.py")], check=True)

    print("\n[3/5] بناء الواجهة الرسومية (aladil-tray.exe) بلا نافذة طرفية...")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_tray.py")], check=True)

    print("\n[4/5] التأكد من توفّر NSSM (لتغليف الخدمة)...")
    ensure_nssm()

    print("\n[5/5] بناء مثبّت ويندوز (Inno Setup)...")
    iscc = find_iscc()
    iss_path = ROOT / "installers" / "windows" / "aladil.iss"
    subprocess.run([iscc, f"/DMyAppVersion={version}", str(iss_path)], check=True)

    setup_filename = f"AlAdilCybersecurity-Agent-Setup-{version}.exe"
    print(f"\n✅ تم بناء dist/{setup_filename}")
    print("   هذا الملف نفسه يعمل كتثبيت أول (يطلب رمز التفعيل)، أو تحديث")
    print("   تلقائي بلا تفعيل (إن كان مثبَّتًا مسبقًا بإصدار أقدم)، أو لا يفعل")
    print("   شيئًا (إن كان الإصدار المثبَّت مطابقًا تمامًا) حسب حالة الجهاز.")

    if args.customer_name and args.customer_email:
        issue_license_for_release(
            version, args.customer_name, args.customer_email,
            args.duration_unit, args.duration_count, args.max_agents, args.server_url,
        )
    else:
        append_release_log(
            {
                "version": version,
                "built_at": datetime.utcnow().isoformat() + "Z",
                "customer_name": None,
                "note": "بناء بدون إصدار ترخيص (لم تُمرَّر بيانات عميل)",
            }
        )


if __name__ == "__main__":
    main()
