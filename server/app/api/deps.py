"""اعتماديات مشتركة لنقاط النهاية (DB session + المستخدم الحالي)."""
from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from server.app.core.security import decode_access_token
from server.app.db.database import get_db
from server.app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    username = decode_access_token(token)
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "جلسة غير صالحة أو منتهية")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "المستخدم غير موجود")
    return user
