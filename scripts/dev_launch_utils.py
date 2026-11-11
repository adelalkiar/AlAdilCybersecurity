"""
أداة مشتركة لنقاط التشغيل المحلية (AlAdilCybersecurity.pyw وInstallerBuilder.pyw):
عند تشغيل أي منهما عبر النقر المزدوج، يستخدمها ويندوز بمفسّر بايثون
النظام العام (عبر ارتباط .pyw)، وهو لا يملك مكتبات المشروع المثبَّتة في
.venv الخاصة بالمشروع فقط. هذه الدالة تكتشف ذلك وتعيد تشغيل الملف
بمفسّر .venv الصحيح تلقائيًا.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def ensure_project_venv(root: Path, entry_file: Path) -> None:
    venv_python = root / ".venv" / "Scripts" / (
        "pythonw.exe" if Path(sys.executable).stem.lower() != "python" else "python.exe"
    )
    if not venv_python.exists():
        return  # لا توجد بيئة مشروع؛ نستمر بما هو متاح ونترك الخطأ واضحًا إن حدث
    if Path(sys.executable).resolve() == venv_python.resolve():
        return  # نعمل فعليًا من بيئة المشروع الصحيحة
    # نتجنّب os.execv على ويندوز: تمريره مسارات تحتوي مسافات غير موثوق
    # (يُفسَّر سطر الأوامر الناتج بشكل خاطئ)، فنستخدم subprocess بدلًا
    # منه مع قائمة argv مباشرة (بلا قشرة) ثم نخرج بنفس كود الإنهاء.
    result = subprocess.run([str(venv_python), str(entry_file.resolve())])
    sys.exit(result.returncode)
