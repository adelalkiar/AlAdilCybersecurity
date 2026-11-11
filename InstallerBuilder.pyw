"""
صانع المثبتات والتراخيص - واجهة رسومية احترافية لمجلد المشروع.

يُغلّف scripts/build_installer.py (الذي يبني العميل + الواجهة الرسومية +
مثبّت Inno Setup ويُصدر ترخيصًا إن طُلب) بواجهة مرئية بدل سطر الأوامر:
اختيار نظام التشغيل المستهدف، مدة الترخيص (بما فيها خطة "مدى الحياة")،
عدد الأجهزة، ومتابعة سجل البناء الكامل مباشرة أثناء العمل.

الاستخدام: انقر مرتين على هذا الملف.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from scripts.dev_launch_utils import ensure_project_venv

ensure_project_venv(ROOT, Path(__file__))

import subprocess
import tkinter as tk
from tkinter import messagebox, ttk

INK_NAVY = "#0B1F3A"
ROUTE_TEAL = "#00C2A8"
LIGHT_BG = "#F5F6F8"
LIGHT_GRAY = "#8A94A6"

DURATION_LABELS = {
    "minute": "دقيقة", "hour": "ساعة", "day": "يوم", "week": "أسبوع",
    "month": "شهر", "year": "سنة", "lifetime": "مدى الحياة (بلا انتهاء)",
}

RELEASE_LOG_PATH = ROOT / "releases" / "release_log.json"
LOGO_PATH = ROOT / "agent" / "app" / "assets" / "logo.png"


class InstallerBuilderApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("AlAdil Cybersecurity — صانع المثبتات والتراخيص")
        self.root.configure(bg=INK_NAVY)
        self.root.geometry("760x680")
        self.root.minsize(700, 600)

        self._build_icon()
        self._build_header()
        self._build_form()
        self._build_log_area()
        self._load_release_log()

        self._build_proc: subprocess.Popen | None = None

    # ---------- بناء الواجهة ----------

    def _build_icon(self) -> None:
        if LOGO_PATH.exists():
            try:
                self._icon_img = tk.PhotoImage(file=str(LOGO_PATH))
                self.root.iconphoto(True, self._icon_img)
            except tk.TclError:
                pass

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=INK_NAVY, pady=16, padx=20)
        header.pack(fill="x")
        if hasattr(self, "_icon_img"):
            tk.Label(header, image=self._icon_img, bg=INK_NAVY).pack(side="right", padx=(0, 12))
        title_box = tk.Frame(header, bg=INK_NAVY)
        title_box.pack(side="right")
        tk.Label(
            title_box, text="AlAdil Cybersecurity", bg=INK_NAVY, fg="white",
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="e")
        tk.Label(
            title_box, text="صانع المثبتات والتراخيص", bg=INK_NAVY, fg=ROUTE_TEAL,
            font=("Segoe UI", 11),
        ).pack(anchor="e")

    def _build_form(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabelframe", background=LIGHT_BG, foreground=INK_NAVY)
        style.configure("TLabelframe.Label", background=LIGHT_BG, foreground=INK_NAVY,
                         font=("Segoe UI", 10, "bold"))
        style.configure("TFrame", background=LIGHT_BG)
        style.configure("TLabel", background=LIGHT_BG, foreground=INK_NAVY, font=("Segoe UI", 10))
        style.configure("TRadiobutton", background=LIGHT_BG, foreground=INK_NAVY)
        style.configure("Teal.TButton", font=("Segoe UI", 11, "bold"))

        body = tk.Frame(self.root, bg=LIGHT_BG, padx=20, pady=16)
        body.pack(fill="both", expand=False)

        # --- نظام التشغيل المستهدف ---
        os_frame = ttk.LabelFrame(body, text="نظام التشغيل المستهدف")
        os_frame.pack(fill="x", pady=(0, 12))
        self.os_var = tk.StringVar(value="windows")
        ttk.Radiobutton(os_frame, text="Windows (.exe) — متاح", variable=self.os_var,
                        value="windows").pack(side="right", padx=10, pady=8)
        ttk.Radiobutton(os_frame, text="Linux (.deb/AppImage) — قريبًا", variable=self.os_var,
                        value="linux", state="disabled").pack(side="right", padx=10, pady=8)
        ttk.Radiobutton(os_frame, text="macOS (.pkg) — قريبًا", variable=self.os_var,
                        value="macos", state="disabled").pack(side="right", padx=10, pady=8)

        # --- بيانات العميل والترخيص ---
        lic_frame = ttk.LabelFrame(body, text="بيانات العميل والترخيص (اختياري - اتركها فارغة لبناء بلا ترخيص)")
        lic_frame.pack(fill="x", pady=(0, 12))

        self.customer_name = self._labeled_entry(lic_frame, "اسم العميل", 0)
        self.customer_email = self._labeled_entry(lic_frame, "البريد الإلكتروني", 1)
        self.max_agents = self._labeled_entry(lic_frame, "عدد الأجهزة المسموح بها", 2, default="1")
        self.server_url = self._labeled_entry(lic_frame, "عنوان الخادم", 3, default="http://localhost:8000")

        duration_row = tk.Frame(lic_frame, bg=LIGHT_BG)
        duration_row.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10, pady=6)
        tk.Label(duration_row, text="مدة الترخيص:", bg=LIGHT_BG, fg=INK_NAVY,
                 font=("Segoe UI", 10)).pack(side="right", padx=(0, 8))
        self.duration_unit = tk.StringVar(value="month")
        unit_combo = ttk.Combobox(
            duration_row, textvariable=self.duration_unit, state="readonly", width=22,
            values=list(DURATION_LABELS.values()),
        )
        unit_combo.set(DURATION_LABELS["month"])
        unit_combo.pack(side="right", padx=4)
        self._unit_combo = unit_combo

        self.duration_count = tk.StringVar(value="1")
        self._count_entry = tk.Entry(duration_row, textvariable=self.duration_count, width=6,
                                      justify="center")
        self._count_entry.pack(side="right", padx=4)
        unit_combo.bind("<<ComboboxSelected>>", self._on_duration_unit_change)

        for i in range(2):
            lic_frame.columnconfigure(i, weight=1)

        # --- رقم الإصدار ---
        bump_frame = ttk.LabelFrame(body, text="رفع رقم الإصدار قبل البناء")
        bump_frame.pack(fill="x", pady=(0, 12))
        self.bump_var = tk.StringVar(value="none")
        for value, label in [("none", "بلا رفع (استخدم الإصدار الحالي)"), ("patch", "تصحيح (patch)"),
                              ("minor", "ثانوي (minor)"), ("major", "رئيسي (major)")]:
            ttk.Radiobutton(bump_frame, text=label, variable=self.bump_var, value=value).pack(
                side="right", padx=8, pady=6
            )

        # --- زر البناء ---
        self.build_btn = tk.Button(
            body, text="🚀 بناء المثبت", command=self._on_build_click,
            bg=ROUTE_TEAL, fg=INK_NAVY, activebackground=ROUTE_TEAL, font=("Segoe UI", 12, "bold"),
            relief="flat", padx=20, pady=10, cursor="hand2",
        )
        self.build_btn.pack(fill="x", pady=(4, 0))

        self.status_label = tk.Label(body, text="", bg=LIGHT_BG, fg=INK_NAVY, font=("Segoe UI", 9))
        self.status_label.pack(fill="x", pady=(6, 0))

    def _labeled_entry(self, parent, label: str, row: int, default: str = "") -> tk.Entry:
        tk.Label(parent, text=label, bg=LIGHT_BG, fg=INK_NAVY, font=("Segoe UI", 10)).grid(
            row=row, column=1, sticky="e", padx=10, pady=6
        )
        entry = tk.Entry(parent, font=("Segoe UI", 10), justify="right")
        entry.insert(0, default)
        entry.grid(row=row, column=0, sticky="ew", padx=10, pady=6)
        return entry

    def _on_duration_unit_change(self, _event=None) -> None:
        is_lifetime = self._unit_combo.get() == DURATION_LABELS["lifetime"]
        self._count_entry.configure(state="disabled" if is_lifetime else "normal")

    def _build_log_area(self) -> None:
        log_frame = tk.Frame(self.root, bg=INK_NAVY, padx=20)
        log_frame.pack(fill="both", expand=True, pady=(0, 16))
        tk.Label(log_frame, text="سجل البناء والتراخيص الأخيرة", bg=INK_NAVY, fg=ROUTE_TEAL,
                 font=("Segoe UI", 10, "bold")).pack(anchor="e", pady=(0, 6))
        self.log_text = tk.Text(
            log_frame, bg="#06152A", fg="#D7DEE8", font=("Consolas", 9), wrap="word",
            insertbackground="white", relief="flat",
        )
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")

    def _load_release_log(self) -> None:
        if not RELEASE_LOG_PATH.exists():
            return
        try:
            entries = json.loads(RELEASE_LOG_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        self._append_log("=== سجل الإصدارات السابقة ===")
        for entry in entries[-5:]:
            name = entry.get("customer_name") or "(بلا عميل - بناء تطوير فقط)"
            self._append_log(f"  v{entry.get('version')} — {name} — {entry.get('built_at')}")
        self._append_log("")

    # ---------- منطق البناء ----------

    def _resolve_duration_unit(self) -> str:
        label = self._unit_combo.get()
        for key, value in DURATION_LABELS.items():
            if value == label:
                return key
        return "day"

    def _on_build_click(self) -> None:
        if self.os_var.get() != "windows":
            messagebox.showinfo(
                "غير متاح بعد",
                "بناء مثبّتات Linux/macOS غير مُنفَّذ في هذا الإصدار من المشروع - "
                "يتطلب كل نظام تشغيل بيئة بناء خاصة به (لا يمكن تجميعه من ويندوز). "
                "هذه الخيارات معروضة لإظهار خطة التوسّع المستقبلية فقط.",
            )
            return

        customer_name = self.customer_name.get().strip()
        customer_email = self.customer_email.get().strip()
        if bool(customer_name) != bool(customer_email):
            messagebox.showwarning("بيانات ناقصة", "أدخل اسم العميل والبريد الإلكتروني معًا، أو اتركهما فارغين.")
            return

        args = [sys.executable, str(ROOT / "scripts" / "build_installer.py")]
        if self.bump_var.get() != "none":
            args += ["--bump", self.bump_var.get()]
        if customer_name and customer_email:
            duration_unit = self._resolve_duration_unit()
            args += [
                "--customer-name", customer_name,
                "--customer-email", customer_email,
                "--max-agents", self.max_agents.get().strip() or "1",
                "--duration-unit", duration_unit,
                "--duration-count", self.duration_count.get().strip() or "1",
                "--server-url", self.server_url.get().strip() or "http://localhost:8000",
            ]

        self.build_btn.configure(state="disabled", text="جارٍ البناء...")
        self.status_label.configure(text="يعمل الآن - قد يستغرق بضع دقائق (أول مرة أبطأ بسبب تنزيل NSSM)...")
        self._append_log("\n" + "=" * 70)
        self._append_log(f"بدء البناء: {' '.join(args)}")

        threading.Thread(target=self._run_build, args=(args,), daemon=True).start()

    def _run_build(self, args: list[str]) -> None:
        import os

        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        try:
            proc = subprocess.Popen(
                args, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1, env=env,
            )
            self._build_proc = proc
            for line in proc.stdout:  # type: ignore[union-attr]
                self.root.after(0, self._append_log, line.rstrip("\n"))
            proc.wait()
            ok = proc.returncode == 0
        except Exception as exc:  # noqa: BLE001
            ok = False
            self.root.after(0, self._append_log, f"خطأ غير متوقع: {exc}")

        self.root.after(0, self._on_build_finished, ok)

    def _on_build_finished(self, ok: bool) -> None:
        self.build_btn.configure(state="normal", text="🚀 بناء المثبت")
        if ok:
            self.status_label.configure(text="✅ اكتمل البناء بنجاح.", fg=ROUTE_TEAL)
            self._append_log("\n✅ اكتمل البناء بنجاح. راجع مجلد dist/ للمثبّت، و releases/cards/ لبطاقة التسليم إن أُصدر ترخيص.")
            self._load_release_log()
        else:
            self.status_label.configure(text="❌ فشل البناء - راجع السجل أعلاه.", fg="#D7263D")
            self._append_log("\n❌ فشل البناء.")

    def _append_log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")


def main() -> None:
    root = tk.Tk()
    InstallerBuilderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
