from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from server.app.api.deps import get_current_user
from server.app.core.security import create_access_token, hash_password, verify_password
from server.app.db.database import get_db
from server.app.models.user import User

router = APIRouter(prefix="/api/auth", tags=["auth"])


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        # نسجّل محاولة الدخول الفاشلة في سلسلة المساءلة أيضًا
        from server.app.core.audit_chain import record_event
        record_event("login_failed", {"username": form_data.username})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "بيانات الدخول غير صحيحة")
    token = create_access_token(subject=user.username)
    from server.app.core.audit_chain import record_event
    record_event("login", actor=user.username)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "كلمة المرور الحالية غير صحيحة")
    if len(body.new_password) < 8:
        raise HTTPException(400, "كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل")
    current_user.hashed_password = hash_password(body.new_password)
    db.commit()
    return {"ok": True}
