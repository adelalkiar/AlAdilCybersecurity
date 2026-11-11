"""إعداد اتصال قاعدة البيانات (SQLAlchemy). الافتراضي SQLite لسهولة البدء؛
يمكن تحويله إلى PostgreSQL عبر ALADIL_DATABASE_URL في بيئات الإنتاج."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from server.app.core.config import settings

if settings.database_url.startswith("sqlite"):
    db_path = settings.database_url.split("///")[-1]
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
else:
    engine = create_engine(settings.database_url, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from server.app.models import device, license as license_models, user  # noqa: F401

    Base.metadata.create_all(bind=engine)
