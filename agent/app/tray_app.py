"""
أيقونة النظام (System Tray) — الواجهة الرسومية التي يراها المستخدم
النهائي (العميل)، بدلًا من نافذة طرفية سوداء مليئة بسجلات تقنية.

هذا البرنامج **لا يقوم بالفحص بنفسه** — الفحص الفعلي يعمل في الخلفية
كخدمة Windows (aladil-agent.exe عبر NSSM، بلا أي واجهة). هذه الأيقونة
فقط تقرأ ملف الحالة المحلي (status.json) الذي تكتبه الخدمة بعد كل دورة
فحص، وتعرضه بصيغة مفهومة، مع رابط سريع لفتح لوحة التحكم الكاملة.

يُبنى هذا الملف عبر scripts/build_tray.py بخيار --windowed (بلا نافذة
طرفية مطلقًا، لا حتى للحظة واحدة عند التشغيل).
"""
from __future__ import annotations

import logging
import sys
import threading
import webbrowser
from pathlib import Path

import pystray
from PIL import Image, ImageDraw

from agent.app.config import AgentConfig
from agent.app.status_writer import read_status

logger = logging.getLogger("aladil.tray")


def _assets_dir() -> Path:
    """
    عند التجميد عبر PyInstaller (--onefile)، تُستخرَج ملفات --add-data
    إلى مجلد مؤقت يُشار إليه عبر sys._MEIPASS، وليس عبر __file__ العادي
    (الذي لا يقابل ملفًا حقيقيًا على القرص داخل الحزمة المجمَّعة).
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "agent" / "app" / "assets"
    return Path(__file__).resolve().parent / "assets"


LOGO_PATH = _assets_dir() / "logo.png"

_POLL_INTERVAL_SECONDS = 5


def _load_icon_image() -> Image.Image:
    """يحمّل شعار ADIL الفعلي إن كان مُرفقًا مع البناء، وإلا يرسم أيقونة
    بديلة بسيطة (دائرة كحلية) حتى لا ينهار البرنامج بدون الشعار."""
    if LOGO_PATH.exists():
        try:
            return Image.open(LOGO_PATH).convert("RGBA")
        except Exception:  # noqa: BLE001
            logger.warning("تعذّر تحميل شعار النظام، سيُستخدم بديل بسيط.")

    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((4, 4, 60, 60), fill=(11, 31, 58, 255))
    draw.text((20, 24), "A", fill=(255, 255, 255, 255))
    return img


def _format_status_text(status: dict | None) -> str:
    if not status:
        return "الحماية نشطة — بانتظار أول دورة فحص..."
    if not status.get("ok", True):
        return f"⚠ خطأ في آخر فحص: {status.get('error_message', 'غير معروف')}"

    devices = status.get("devices_found", 0)
    high_risk = status.get("high_risk_count", 0)
    when = status.get("last_scan_at", "—")
    if high_risk > 0:
        return f"⚠ {high_risk} جهاز بخطورة مرتفعة من أصل {devices} — آخر فحص: {when}"
    return f"✅ الحماية نشطة — {devices} جهاز تحت المراقبة — آخر فحص: {when}"


class TrayApp:
    def __init__(self) -> None:
        self.cfg = AgentConfig()
        self.icon = pystray.Icon(
            "AlAdilCybersecurity",
            _load_icon_image(),
            "AlAdil Cybersecurity",
            menu=self._build_menu(),
        )
        self._stop_event = threading.Event()

    def _build_menu(self) -> pystray.Menu:
        status = read_status()
        status_text = _format_status_text(status)
        return pystray.Menu(
            pystray.MenuItem(status_text, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("فتح لوحة التحكم", self._open_dashboard),
            pystray.MenuItem("تحديث الحالة", self._refresh),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("خروج", self._quit),
        )

    def _open_dashboard(self, _icon=None, _item=None) -> None:
        webbrowser.open(self.cfg.server_url)

    def _refresh(self, _icon=None, _item=None) -> None:
        self.icon.menu = self._build_menu()
        status = read_status()
        self.icon.title = _format_status_text(status)

    def _quit(self, _icon=None, _item=None) -> None:
        self._stop_event.set()
        self.icon.stop()

    def _poll_loop(self) -> None:
        while not self._stop_event.wait(_POLL_INTERVAL_SECONDS):
            try:
                self._refresh()
            except Exception:  # noqa: BLE001
                logger.exception("خطأ أثناء تحديث حالة أيقونة النظام")

    def run(self) -> None:
        poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        poll_thread.start()
        self.icon.run()


def main() -> None:
    logging.basicConfig(level=logging.WARNING)  # صامت إلا عند الأخطاء - لا طرفية لعرضه أصلًا
    TrayApp().run()


if __name__ == "__main__":
    main()
