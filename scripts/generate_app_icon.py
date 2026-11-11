"""
يولّد أيقونة التطبيق الاحترافية النهائية من شعار ADIL الفعلي
(logo/AdilCompanyWithFill..png) حسب المواصفة:
  - خلفية غامقة (الكحلي الأساسي للهوية البصرية #0B1F3A)
  - الرمز/النصوص بلون فاتح (أبيض) على الخلفية الغامقة
  - شريط تمييز بلون يدل على الحماية/الأمان (Route Teal #00C2A8)
  - اسم الشركة المصنّعة مختصرًا + اسم النظام تحته، لا يتجاوزان عرض الشعار

الناتج: installers/windows/aladil.ico (يُستخدم تلقائيًا من aladil.iss
ومن scripts/build_agent.py و scripts/build_tray.py كأيقونة EXE).
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
LOGO_SOURCE = ROOT / "logo" / "AdilCompanyWithFill..png"
OUTPUT_ICO = ROOT / "installers" / "windows" / "aladil.ico"
OUTPUT_TRAY_PNG = ROOT / "agent" / "app" / "assets" / "logo.png"
OUTPUT_WIZARD_BANNER = ROOT / "installers" / "windows" / "wizard_banner.bmp"
OUTPUT_WIZARD_SMALL = ROOT / "installers" / "windows" / "wizard_small.bmp"

INK_NAVY = (11, 31, 58, 255)
WHITE = (255, 255, 255, 255)
ROUTE_TEAL = (0, 194, 168, 255)

CANVAS_SIZE = 512
FONT_BOLD = Path("C:/Windows/Fonts/segoeuib.ttf")
FONT_REGULAR = Path("C:/Windows/Fonts/segoeui.ttf")


def _font(path: Path, size: int) -> ImageFont.FreeTypeFont:
    try:
        return ImageFont.truetype(str(path), size)
    except OSError:
        return ImageFont.load_default()


def _text_width(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont) -> int:
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[2] - bbox[0]


def _strip_white_background(img: Image.Image, threshold: int = 245) -> Image.Image:
    """ملف الشعار المصدر محفوظ بخلفية بيضاء صلبة (RGB بلا شفافية)؛ نحوّل
    كل بكسل أبيض تقريبًا إلى شفاف حتى يندمج الرمز بسلاسة مع خلفية
    الأيقونة الكحلية بدل ظهور مستطيل أبيض حوله."""
    data = img.getdata()
    new_data = []
    for r, g, b, a in data:
        if r >= threshold and g >= threshold and b >= threshold:
            new_data.append((r, g, b, 0))
        else:
            new_data.append((r, g, b, a))
    result = img.copy()
    result.putdata(new_data)
    return result


def build_icon() -> None:
    if not LOGO_SOURCE.exists():
        raise FileNotFoundError(f"شعار المصدر غير موجود: {LOGO_SOURCE}")

    # 1) خلفية مربّعة كحلية بزوايا مدوّرة (متوافقة مع لغة التصميم: 10.5u
    #    نصف قطر على شبكة 48u في دليل الهوية البصرية)
    canvas = Image.new("RGBA", (CANVAS_SIZE, CANVAS_SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    corner_radius = int(CANVAS_SIZE * 0.14)
    draw.rounded_rectangle(
        (0, 0, CANVAS_SIZE - 1, CANVAS_SIZE - 1), radius=corner_radius, fill=INK_NAVY
    )

    # 2) رمز ADIL الفعلي، أبيض بالفعل في النسخة "WithFill"، يُلصق في
    #    الثلثين العلويين تاركًا مساحة للنصوص أسفله
    logo = Image.open(LOGO_SOURCE).convert("RGBA")
    logo = _strip_white_background(logo)
    logo_w, logo_h = logo.size
    target_w = int(CANVAS_SIZE * 0.72)
    target_h = int(target_w * logo_h / logo_w)
    logo = logo.resize((target_w, target_h), Image.LANCZOS)

    logo_x = (CANVAS_SIZE - target_w) // 2
    logo_y = int(CANVAS_SIZE * 0.14)
    canvas.paste(logo, (logo_x, logo_y), logo)

    # 3) شريط تمييز بلون الحماية/الأمان (Route Teal) أسفل الرمز مباشرة -
    #    لا يتجاوز عرض الرمز نفسه
    bar_y = logo_y + target_h + int(CANVAS_SIZE * 0.035)
    bar_h = max(3, int(CANVAS_SIZE * 0.012))
    draw.rounded_rectangle(
        (logo_x, bar_y, logo_x + target_w, bar_y + bar_h),
        radius=bar_h // 2,
        fill=ROUTE_TEAL,
    )

    # 4) اسم الشركة المصنّعة (مختصر) + اسم النظام تحته - أبيض، لا يتجاوزان
    #    عرض الرمز، بحجم خط يُقلَّص تلقائيًا إن لزم
    company_text = "Al-Adil Systems"
    product_text = "AlAdil Cybersecurity"

    company_font_size = int(CANVAS_SIZE * 0.075)
    company_font = _font(FONT_BOLD, company_font_size)
    while _text_width(draw, company_text, company_font) > target_w and company_font_size > 10:
        company_font_size -= 2
        company_font = _font(FONT_BOLD, company_font_size)

    product_font_size = int(CANVAS_SIZE * 0.052)
    product_font = _font(FONT_REGULAR, product_font_size)
    while _text_width(draw, product_text, product_font) > target_w and product_font_size > 8:
        product_font_size -= 2
        product_font = _font(FONT_REGULAR, product_font_size)

    text_y = bar_y + bar_h + int(CANVAS_SIZE * 0.04)
    company_w = _text_width(draw, company_text, company_font)
    draw.text(
        ((CANVAS_SIZE - company_w) // 2, text_y), company_text, font=company_font, fill=WHITE
    )

    product_y = text_y + company_font_size + int(CANVAS_SIZE * 0.015)
    product_w = _text_width(draw, product_text, product_font)
    draw.text(
        ((CANVAS_SIZE - product_w) // 2, product_y),
        product_text,
        font=product_font,
        fill=(200, 210, 225, 255),  # رمادي-أبيض خفيف لتمييزه عن اسم الشركة
    )

    # 5) حفظ كملف .ico متعدد الأحجام لكل استخدامات ويندوز (من 16 حتى 256px)
    OUTPUT_ICO.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(
        OUTPUT_ICO, sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    )
    print(f"تم إنشاء الأيقونة: {OUTPUT_ICO}")

    # 6) نسخة PNG مربّعة لأيقونة شريط النظام (tray) في الواجهة الرسومية
    OUTPUT_TRAY_PNG.parent.mkdir(parents=True, exist_ok=True)
    canvas.resize((256, 256), Image.LANCZOS).save(OUTPUT_TRAY_PNG)
    print(f"تم تحديث أيقونة شريط النظام: {OUTPUT_TRAY_PNG}")


def build_wizard_images() -> None:
    """يولّد صورتَي معالج التثبيت (Inno Setup WizardImageFile/
    WizardSmallImageFile) بنفس الهوية البصرية بدل الصورة الافتراضية
    العامة - أول انطباع يراه العميل عند فتح المثبّت."""
    logo = _strip_white_background(Image.open(LOGO_SOURCE).convert("RGBA"))

    # اللوحة الجانبية الطويلة (يسار معالج التثبيت الكلاسيكي/الحديث)
    banner_w, banner_h = 192, 386
    banner = Image.new("RGB", (banner_w, banner_h), INK_NAVY[:3])
    draw = ImageDraw.Draw(banner)

    logo_target_w = int(banner_w * 0.78)
    logo_target_h = int(logo_target_w * logo.size[1] / logo.size[0])
    logo_resized = logo.resize((logo_target_w, logo_target_h), Image.LANCZOS)
    logo_x = (banner_w - logo_target_w) // 2
    logo_y = int(banner_h * 0.38)
    banner.paste(logo_resized, (logo_x, logo_y), logo_resized)

    bar_y = logo_y + logo_target_h + 14
    draw.rounded_rectangle(
        (logo_x, bar_y, logo_x + logo_target_w, bar_y + 4), radius=2, fill=ROUTE_TEAL[:3]
    )

    tagline_font = _font(FONT_REGULAR, 13)
    tagline = "Cybersecurity"
    tagline_w = _text_width(draw, tagline, tagline_font)
    draw.text(
        ((banner_w - tagline_w) // 2, bar_y + 16), tagline, font=tagline_font, fill=(210, 216, 226)
    )

    OUTPUT_WIZARD_BANNER.parent.mkdir(parents=True, exist_ok=True)
    banner.save(OUTPUT_WIZARD_BANNER)
    print(f"تم إنشاء لوحة معالج التثبيت: {OUTPUT_WIZARD_BANNER}")

    # الشعار الصغير أعلى يمين صفحات المعالج
    small_size = 55
    small = Image.new("RGB", (small_size, small_size), INK_NAVY[:3])
    small_logo_w = int(small_size * 0.82)
    small_logo_h = int(small_logo_w * logo.size[1] / logo.size[0])
    small_logo = logo.resize((small_logo_w, small_logo_h), Image.LANCZOS)
    small.paste(
        small_logo,
        ((small_size - small_logo_w) // 2, (small_size - small_logo_h) // 2),
        small_logo,
    )
    small.save(OUTPUT_WIZARD_SMALL)
    print(f"تم إنشاء الشعار الصغير للمعالج: {OUTPUT_WIZARD_SMALL}")


if __name__ == "__main__":
    build_icon()
    build_wizard_images()
