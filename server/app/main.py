"""نقطة الدخول للخادم المركزي — AlAdil Cybersecurity."""
from __future__ import annotations

import os
import secrets
import sys

# يضمن أن الطرفية على ويندوز (أو أي ترميز غير utf-8) تستطيع طباعة النصوص
# العربية دون فشل الإقلاع (UnicodeEncodeError على cp1252 الافتراضي).
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from server.app.api import agents, auth, devices, licenses, scans, trusted_networks
from server.app.core.config import settings
from server.app.core.security import hash_password
from server.app.db.database import SessionLocal, init_db
from server.app.models.user import User

app = FastAPI(title=settings.app_name, version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(scans.router)
app.include_router(licenses.router)
app.include_router(agents.router)
app.include_router(trusted_networks.router)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    _bootstrap_admin_user()


def _bootstrap_admin_user() -> None:
    """ينشئ حساب مشرف أول عند أول تشغيل إن لم يوجد أي مستخدم بعد، ويطبع
    كلمة المرور العشوائية المولَّدة مرة واحدة في السجل (console)."""
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        password = secrets.token_urlsafe(12)
        admin = User(username="admin", hashed_password=hash_password(password), is_admin=True)
        db.add(admin)
        db.commit()
        print("=" * 60)
        print(f"  تم إنشاء حساب المشرف الأول: admin / {password}")
        print("  يرجى تغيير كلمة المرور فورًا بعد أول تسجيل دخول.")
        print("=" * 60)
    finally:
        db.close()


@app.get("/")
def root():
    return FileResponse(os.path.join(static_dir, "dashboard", "index.html"))


@app.get("/api/info")
def info():
    return {
        "system": settings.app_name,
        "status": "running",
        "logo": "/static/branding/logo-fill.png",
    }


@app.get("/health")
def health():
    return {"ok": True}
