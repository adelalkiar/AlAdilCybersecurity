"""
إعدادات العميل (Agent): عنوان الخادم، مفتاح الترخيص، دورية الفحص.

ملاحظتان مهمتان:

1) **مسار الإعدادات**: عند تثبيت العميل كخدمة Windows (LocalSystem) أو
   كخدمة systemd على لينكس، لا يوجد "مستخدم مسجّل دخول" ذو ملف تعريف
   ثابت — `Path.home()` قد تُرجع مسار حساب النظام (SYSTEM) وليس مجلد أي
   مستخدم حقيقي. لذلك نخزّن الإعدادات في مسار على مستوى الجهاز
   (ProgramData على ويندوز، /etc/aladil على لينكس/macOS عند التشغيل
   كـ root)، مع رجوع احتياطي لمجلد المستخدم الحالي عند التشغيل اليدوي
   بصلاحيات عادية (وضع التطوير/الاختبار).

2) **التشفير عند السكون**: الملف (الذي يحوي مفتاح الترخيص) يُخزَّن
   مشفّرًا (Fernet/AES) وليس كنص صريح، لإخفاء معلومات العميل عن أي قراءة
   عرضية للملف على القرص. مفتاح التشفير يُولَّد محليًا ويُخزَّن في ملف
   منفصل بصلاحيات مقيَّدة قدر الإمكان - هذا تشفير "عند السكون" يحمي من
   التصفح العرضي للملف، وليس بديلًا عن حماية الوصول للجهاز نفسه.
"""
from __future__ import annotations

import json
import os
import platform
import socket
import stat
import uuid
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _is_root_or_system() -> bool:
    if _is_windows():
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:  # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _system_config_dir() -> Path:
    if _is_windows():
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(base) / "AlAdilCybersecurity"
    if _is_root_or_system():
        return Path("/etc/aladil")
    return Path.home() / ".aladil"


CONFIG_DIR = _system_config_dir()
CONFIG_PATH = CONFIG_DIR / "agent_config.enc"
KEY_PATH = CONFIG_DIR / "agent_config.key"


def _restrict_permissions(path: Path) -> None:
    """يحاول تقييد صلاحيات الملف للمالك فقط؛ يتجاهل الفشل بصمت على
    الأنظمة/الأذونات التي لا تسمح بذلك (مثل عدم صلاحيات مدير)."""
    try:
        if _is_windows():
            import subprocess

            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r",
                 f"{os.environ.get('USERNAME', 'SYSTEM')}:F", "SYSTEM:F", "Administrators:F"],
                capture_output=True, check=False,
            )
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:  # noqa: BLE001
        pass


def _load_or_create_key() -> bytes:
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    KEY_PATH.write_bytes(key)
    _restrict_permissions(KEY_PATH)
    return key


class AgentConfig:
    def __init__(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self._fernet = Fernet(_load_or_create_key())
        data = self._load()

        self.agent_id: str = data.get("agent_id") or str(uuid.uuid4())
        self.server_url: str = data.get("server_url", "http://localhost:8000")
        self.license_key: str = data.get("license_key", "")
        self.scan_interval_seconds: int = data.get("scan_interval_seconds", 900)
        # معرّف الجهاز المُرسَل للخادم مُجهول الهوية (UUID عشوائي ثابت)
        # بدل اسم الجهاز الحقيقي، لإخفاء هوية جهاز العميل عن الخادم ذاته
        # إن أمكن استضافته من طرف غير موثوق مستقبلًا.
        self.hostname: str = socket.gethostname()
        self.platform: str = f"{platform.system()} {platform.release()}"
        self.version: str = "0.1.0"

        self._save()

    def _load(self) -> dict:
        if not CONFIG_PATH.exists():
            return {}
        try:
            raw = self._fernet.decrypt(CONFIG_PATH.read_bytes())
            return json.loads(raw.decode("utf-8"))
        except (InvalidToken, ValueError, json.JSONDecodeError):
            # ملف تالف أو مفتاح غير متطابق (مثلًا بعد نقل الملف لجهاز آخر
            # بدون مفتاحه) - نبدأ بإعدادات افتراضية بدل تعطّل العميل.
            return {}

    def _save(self) -> None:
        payload = json.dumps(
            {
                "agent_id": self.agent_id,
                "server_url": self.server_url,
                "license_key": self.license_key,
                "scan_interval_seconds": self.scan_interval_seconds,
            },
            ensure_ascii=False,
        ).encode("utf-8")
        CONFIG_PATH.write_bytes(self._fernet.encrypt(payload))
        _restrict_permissions(CONFIG_PATH)

    def set_license_key(self, key: str) -> None:
        self.license_key = key
        self._save()

    def set_server_url(self, url: str) -> None:
        self.server_url = url
        self._save()
