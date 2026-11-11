"""
نقطة التشغيل "كما يظهر عند العميل تمامًا" - مباشرة من مجلد المشروع، دون
المرور بخطوات البناء/التثبيت/التفعيل الكاملة.

يشغّل: (1) خادم لوحة التحكم (FastAPI) تلقائيًا في عملية خلفية منفصلة إن لم
يكن يعمل أصلًا - خاص بهذه المعاينة المحلية فقط (العميل الحقيقي يتصل بخادم
الشركة المركزي البعيد، لا بخادم محلي)، (2) حلقة الفحص الخلفية بنفس كود
aladil-agent.exe في Thread منفصل، (3) أيقونة النظام الرسومية (tray) في
الـ Thread الرئيسي - تمامًا كما سيراها العميل بعد تثبيت النظام فعليًا،
بلا أي نافذة طرفية.

الاستخدام: انقر مرتين على هذا الملف (يعمل عبر pythonw.exe تلقائيًا على
ويندوز بفضل امتداد .pyw فيُشغَّل بلا نافذة طرفية)، أو من الطرفية:
    python AlAdilCybersecurity.pyw
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from scripts.dev_launch_utils import ensure_project_venv

ensure_project_venv(ROOT, Path(__file__))

import asyncio
import os
import socket
import subprocess
import threading
import time
from urllib.parse import urlparse

from agent.app.config import CONFIG_DIR, AgentConfig
from agent.app.main import run_forever
from agent.app.tray_app import TrayApp

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _ensure_local_server_running(server_url: str) -> None:
    """خادم لوحة التحكم (FastAPI) جهة منفصلة عن العميل في البنية الحقيقية
    (العميل عند التثبيت الفعلي يتصل بخادم الشركة المركزي عبر الإنترنت/
    الشبكة الداخلية، وليس بخادم على جهازه هو). لكن من أجل المعاينة
    المحلية الكاملة بنقرة واحدة على هذا الجهاز فقط، نُشغّله تلقائيًا في
    الخلفية إن كان عنوان الخادم المُعدّ يشير لهذا الجهاز نفسه ولم يكن
    يعمل أصلًا، حتى يعمل زر "فتح لوحة التحكم" مباشرة دون خطوة يدوية."""
    parsed = urlparse(server_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8000
    if host not in _LOCAL_HOSTS:
        return  # عنوان خادم بعيد (حالة العميل الحقيقي) - لا نحاول تشغيل شيء محليًا
    if _is_port_open(host, port):
        return  # خادم يعمل بالفعل (ربما شغّله المطوّر يدويًا) - لا نكرر التشغيل

    venv_python = ROOT / ".venv" / "Scripts" / "python.exe"
    python_exe = str(venv_python) if venv_python.exists() else sys.executable
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    log_path = CONFIG_DIR / "server.log"
    log_file = open(log_path, "a", encoding="utf-8")
    subprocess.Popen(
        [python_exe, "-m", "uvicorn", "server.app.main:app", "--host", host, "--port", str(port)],
        cwd=str(ROOT),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
    )
    for _ in range(20):  # ينتظر حتى 10 ثوانٍ حتى يبدأ الخادم بالاستماع فعليًا
        if _is_port_open(host, port):
            break
        time.sleep(0.5)


def _start_background_scanning() -> None:
    """يشغّل حلقة الفحص المستمرة (نفس منطق aladil-agent.exe) في Thread
    منفصل بحلقة asyncio خاصة بها، حتى لا تحجب أيقونة النظام في الواجهة
    الرئيسية."""

    def _runner() -> None:
        cfg = AgentConfig()
        asyncio.run(run_forever(cfg, []))

    thread = threading.Thread(target=_runner, daemon=True, name="aladil-scan-loop")
    thread.start()


def main() -> None:
    _ensure_local_server_running(AgentConfig().server_url)
    _start_background_scanning()
    TrayApp().run()  # يحجب الـ Thread الرئيسي حتى يختار المستخدم "خروج"


if __name__ == "__main__":
    main()
