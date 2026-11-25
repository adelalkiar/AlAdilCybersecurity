"""
واجهة مختبر التشفير الكلاسيكي وتحليل الشفرات (الفصل 4) - للمشرفين.
تعليمية بالكامل: تشفير/فك كلاسيكي، كسر قيصر بتحليل التكرار، وفحص قيم
بحثًا عن ترميز ضعيف. لا تتعامل مع أي سرّ حقيقي للنظام.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from server.app.api.deps import get_current_user
from shared.crypto_lab.classic_ciphers import (
    caesar_decrypt,
    caesar_encrypt,
    columnar_decrypt,
    columnar_encrypt,
    substitution_decrypt,
    substitution_encrypt,
)
from shared.crypto_lab.weak_encoding import break_caesar, scan_value

router = APIRouter(
    prefix="/api/crypto-lab", tags=["crypto-lab"], dependencies=[Depends(get_current_user)]
)


class CipherRequest(BaseModel):
    algorithm: str  # caesar | substitution | columnar
    mode: str       # encrypt | decrypt
    text: str
    key: str = ""
    shift: int = 3


@router.post("/cipher")
def run_cipher(req: CipherRequest):
    try:
        if req.algorithm == "caesar":
            out = (caesar_encrypt if req.mode == "encrypt" else caesar_decrypt)(req.text, req.shift)
        elif req.algorithm == "substitution":
            out = (substitution_encrypt if req.mode == "encrypt" else substitution_decrypt)(req.text, req.key)
        elif req.algorithm == "columnar":
            out = (columnar_encrypt if req.mode == "encrypt" else columnar_decrypt)(req.text, req.key)
        else:
            return {"ok": False, "error": "خوارزمية غير مدعومة"}
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "result": out}


class BreakRequest(BaseModel):
    ciphertext: str


@router.post("/break-caesar")
def break_caesar_endpoint(req: BreakRequest):
    """كسر قيصر بهجوم «النص المشفَّر فقط» (تحليل التكرار)."""
    shift, plain = break_caesar(req.ciphertext)
    return {"inferred_shift": shift, "recovered": plain}


class ScanRequest(BaseModel):
    key_name: str = "value"
    value: str


@router.post("/scan-weak-encoding")
def scan_weak_encoding(req: ScanRequest):
    """يفحص قيمة واحدة بحثًا عن ترميز ضعيف (Base64/ROT13/قيصر) قابل للكسر."""
    result = scan_value(req.key_name, req.value)
    return {"found": result is not None, "finding": result}
