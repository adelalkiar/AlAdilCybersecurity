"""
يولّد "بطاقة تفعيل" احترافية بالهوية البصرية لإرسالها للعميل الذي
أُصدر له رمز التفعيل، بصيغتين:
  1) صورة PNG قابلة للإرسال كملف (بطاقة مرئية بالشعار واسم العميل).
  2) نص جاهز للصق في رسالة (واتساب/بريد إلكتروني) بصياغة احترافية.

الاستخدام (مستقل، أو يُستدعى تلقائيًا من scripts/build_installer.py):
    python scripts/generate_license_card.py \
        --customer-name "شركة المثال" \
        --customer-email "contact@example.com" \
        --license-key "ALADIL-..." \
        --duration-unit month --duration-count 3 \
        --expires-at "2027-02-04T00:00:00Z" \
        --version 0.2.3
"""
from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
LOGO_SOURCE = ROOT / "logo" / "AdilCompanyWithFill..png"
CARDS_DIR = ROOT / "releases" / "cards"

INK_NAVY = (11, 31, 58)
ROUTE_TEAL = (0, 194, 168)
WHITE = (255, 255, 255)
LIGHT_GRAY = (190, 200, 215)

FONT_BOLD = Path("C:/Windows/Fonts/segoeuib.ttf")
FONT_REGULAR = Path("C:/Windows/Fonts/segoeui.ttf")

DURATION_LABELS_AR = {
    "minute": "دقيقة", "hour": "ساعة", "day": "يوم",
    "week": "أسبوع", "month": "شهر", "year": "سنة",
}


def _font(path: Path, size: int) -> ImageFont.FreeTypeFont:
    try:
        return ImageFont.truetype(str(path), size)
    except OSError:
        return ImageFont.load_default()


def _strip_white_background(img: Image.Image, threshold: int = 245) -> Image.Image:
    data = img.getdata()
    new_data = [
        (r, g, b, 0) if (r >= threshold and g >= threshold and b >= threshold) else (r, g, b, a)
        for r, g, b, a in data
    ]
    result = img.copy()
    result.putdata(new_data)
    return result


def build_card_image(
    customer_name: str,
    license_key: str,
    duration_unit: str,
    duration_count: int,
    expires_at: str,
    version: str,
    output_path: Path,
) -> None:
    width, height = 1200, 675
    card = Image.new("RGB", (width, height), INK_NAVY)
    draw = ImageDraw.Draw(card)

    # شريط تمييز علوي بلون الحماية
    draw.rectangle((0, 0, width, 8), fill=ROUTE_TEAL)

    # الشعار أعلى يسار البطاقة
    if LOGO_SOURCE.exists():
        logo = _strip_white_background(Image.open(LOGO_SOURCE).convert("RGBA"))
        logo_w = 220
        logo_h = int(logo_w * logo.size[1] / logo.size[0])
        logo = logo.resize((logo_w, logo_h), Image.LANCZOS)
        card.paste(logo, (60, 50), logo)

    title_font = _font(FONT_BOLD, 40)
    draw.text((60, 160), "بطاقة تفعيل النظام", font=title_font, fill=WHITE)

    label_font = _font(FONT_REGULAR, 22)
    value_font = _font(FONT_BOLD, 26)

    duration_ar = DURATION_LABELS_AR.get(duration_unit, duration_unit)
    try:
        expires_display = datetime.fromisoformat(expires_at.rstrip("Z")).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        expires_display = expires_at

    rows = [
        ("صادرة إلى", customer_name),
        ("إصدار النظام", f"AlAdil Cybersecurity v{version}"),
        ("مدة الصلاحية", f"{duration_count} {duration_ar}"),
        ("تاريخ الانتهاء", expires_display),
    ]

    y = 240
    for label, value in rows:
        draw.text((60, y), label + ":", font=label_font, fill=LIGHT_GRAY)
        draw.text((320, y - 3), value, font=value_font, fill=WHITE)
        y += 55

    # عرض جزء من رمز التفعيل فقط على البطاقة المرئية (الرمز الكامل يُرسل
    # ضمن النص المرافق، وليس مكشوفًا بالكامل على صورة قد تُشارك بصريًا)
    key_preview = f"{license_key[:18]}...{license_key[-10:]}" if len(license_key) > 32 else license_key
    draw.text((60, y + 15), "رمز التفعيل (كامل في الرسالة المرفقة):", font=label_font, fill=LIGHT_GRAY)
    mono_font = _font(FONT_REGULAR, 20)
    draw.text((60, y + 50), key_preview, font=mono_font, fill=ROUTE_TEAL)

    footer_font = _font(FONT_REGULAR, 16)
    draw.text(
        (60, height - 50),
        "Al-Adil Systems — AlAdil Cybersecurity",
        font=footer_font,
        fill=LIGHT_GRAY,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    card.save(output_path)


def build_message_text(
    customer_name: str,
    license_key: str,
    duration_unit: str,
    duration_count: int,
    expires_at: str,
    version: str,
    server_url: str = "",
) -> str:
    duration_ar = DURATION_LABELS_AR.get(duration_unit, duration_unit)
    try:
        expires_display = datetime.fromisoformat(expires_at.rstrip("Z")).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        expires_display = expires_at

    lines = [
        f"مرحبًا {customer_name}،",
        "",
        f"تم تفعيل اشتراكك في نظام AlAdil Cybersecurity (الإصدار {version}) لمراقبة",
        "الأجهزة المتصلة بشبكتك وكشف التهديدات تلقائيًا.",
        "",
        f"🔑 رمز التفعيل: {license_key}",
        f"⏳ مدة الصلاحية: {duration_count} {duration_ar} (ينتهي في {expires_display})",
        "",
        "لتثبيت النظام: شغّل ملف التثبيت المرفق وأدخل رمز التفعيل أعلاه عند الطلب.",
    ]
    if server_url:
        lines.append(f"عنوان الخادم: {server_url}")
    lines += [
        "",
        "لأي استفسار، يسعدنا تواصلك معنا.",
        "— فريق Al-Adil Systems",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="توليد بطاقة ونص تفعيل احترافيَين للعميل")
    parser.add_argument("--customer-name", required=True)
    parser.add_argument("--customer-email", required=True)
    parser.add_argument("--license-key", required=True)
    parser.add_argument("--duration-unit", default="day")
    parser.add_argument("--duration-count", type=int, default=365)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--version", default="0.0.0")
    parser.add_argument("--server-url", default="")
    args = parser.parse_args()

    safe_name = "".join(c if c.isalnum() else "_" for c in args.customer_name)[:40]
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    image_path = CARDS_DIR / f"{safe_name}_{timestamp}.png"
    text_path = CARDS_DIR / f"{safe_name}_{timestamp}.txt"

    build_card_image(
        args.customer_name, args.license_key, args.duration_unit, args.duration_count,
        args.expires_at, args.version, image_path,
    )
    message = build_message_text(
        args.customer_name, args.license_key, args.duration_unit, args.duration_count,
        args.expires_at, args.version, args.server_url,
    )
    text_path.write_text(message, encoding="utf-8")

    print(f"بطاقة الصورة: {image_path}")
    print(f"نص الرسالة: {text_path}")


if __name__ == "__main__":
    main()
