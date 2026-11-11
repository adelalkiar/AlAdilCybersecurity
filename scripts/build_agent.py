"""
يبني ملفًا تنفيذيًا واحدًا للعميل (Agent) عبر PyInstaller لنظام التشغيل
الحالي الذي يُنفَّذ عليه السكربت. يجب تشغيله على كل نظام مستهدف على حدة
(Windows exe على ويندوز، إلخ) لأن PyInstaller لا يدعم التجميع المتقاطع.

الاستخدام:
    python scripts/build_agent.py
الناتج:
    dist/aladil-agent[.exe]
"""
from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    system = platform.system()
    icon_args: list[str] = []
    if system == "Windows":
        icon_args = []  # أضف --icon=path/to/icon.ico عند توفر أيقونة بصيغة ico

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "aladil-agent",
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build"),
        "--specpath", str(ROOT / "build"),
        "--add-data", f"{ROOT / 'shared'}{';' if system == 'Windows' else ':'}shared",
        str(ROOT / "agent" / "app" / "main.py"),
        *icon_args,
    ]
    print("تشغيل:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print(f"\nتم البناء بنجاح لنظام {system}. الملف الناتج في مجلد dist/.")


if __name__ == "__main__":
    main()
