"""
يبني الواجهة الرسومية (أيقونة النظام) التي يراها المستخدم النهائي -
بدون أي نافذة طرفية سوداء على الإطلاق (--windowed)، بعكس aladil-agent.exe
(الذي يبقى بوضع الطرفية لأغراض debugging/الخدمة، التي تُدار عبر NSSM
وتُحوَّل سجلاتها لملف أصلًا، فلا نافذة تظهر منه أيضًا عند تشغيله كخدمة).

الاستخدام:
    python scripts/build_tray.py
الناتج:
    dist/aladil-tray.exe
"""
from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    system = platform.system()
    if system != "Windows":
        print(f"بناء الواجهة الرسومية مدعوم حاليًا لويندوز فقط (النظام الحالي: {system}).")
        return

    icon_args = []
    ico_path = ROOT / "installers" / "windows" / "aladil.ico"
    if ico_path.exists():
        icon_args = ["--icon", str(ico_path)]

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",  # لا نافذة طرفية مطلقًا - هذا هو المطلوب صراحةً
        "--name", "aladil-tray",
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT / "build"),
        "--add-data", f"{ROOT / 'shared'}{';' if system == 'Windows' else ':'}shared",
        "--add-data",
        f"{ROOT / 'agent' / 'app' / 'assets'}{';' if system == 'Windows' else ':'}agent/app/assets",
        str(ROOT / "agent" / "app" / "tray_app.py"),
        *icon_args,
    ]
    print("تشغيل:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print("\nتم البناء بنجاح. الملف الناتج: dist/aladil-tray.exe (بلا نافذة طرفية).")


if __name__ == "__main__":
    main()
