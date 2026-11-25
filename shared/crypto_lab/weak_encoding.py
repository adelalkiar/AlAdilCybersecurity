"""
كاشف الترميز الضعيف (الفصل 4 - تحليل الشفرات): يفحص قيمًا نصّية (من ملفات
إعدادات أو بانرات خدمات) بحثًا عن أسرار «مُشفَّرة» بطرق ضعيفة قابلة للكسر
دون مفتاح (Base64 / ROT13 / قيصر)، ويكسرها بهجوم «النص المشفَّر فقط»
(تحليل التكرار) ويعرض المفتاح المستنتَج، مع توصية باستبدالها بتشفير حديث.

كل هذا تعليمي ودفاعي: يكشف أن ما يظنّه المستخدم «تشفيرًا» لكلمة مروره في
ملف إعداد هو مجرد ترميز قابل للعكس فورًا، فينبّهه لاستخدام تشفير حقيقي.
"""
from __future__ import annotations

import base64
import binascii
import re

from shared.crypto_lab.classic_ciphers import caesar_decrypt

# تكرار الحروف في الإنجليزية (تقريبي) لهجوم تحليل التكرار
_ENGLISH_FREQ_ORDER = "etaoinshrdlcumwfgypbvkjxqz"

# أنماط تدل على أن القيمة سرّ (اسم المفتاح يحوي كلمات حسّاسة)
_SECRET_KEY_HINT = re.compile(r"(pass|pwd|secret|token|key|api|cred|auth)", re.I)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for c in text if 32 <= ord(c) < 127)
    return printable / len(text)


def try_base64(value: str) -> str | None:
    """يحاول فك Base64؛ يرجع النص الناتج إن كان نصًّا مقروءًا، وإلا None."""
    s = value.strip()
    if len(s) < 8 or len(s) % 4 != 0 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        return None
    try:
        decoded = base64.b64decode(s, validate=True).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if _printable_ratio(decoded) > 0.9 and decoded != s:
        return decoded
    return None


def break_caesar(ciphertext: str) -> tuple[int, str]:
    """
    هجوم «النص المشفَّر فقط» على قيصر: يجرّب كل الإزاحات الـ26 ويختار التي
    تُنتج نصًّا أقرب لتوزيع تكرار الإنجليزية. يرجع (الإزاحة المستنتَجة، النص).
    """
    letters_only = [c.lower() for c in ciphertext if c.isalpha()]
    best_shift, best_score = 0, -1.0
    for shift in range(26):
        candidate = caesar_decrypt("".join(letters_only), shift)
        # درجة = مجموع أوزان تكرار الأحرف (الأعلى = أقرب للإنجليزية)
        score = sum(
            (26 - _ENGLISH_FREQ_ORDER.index(c)) if c in _ENGLISH_FREQ_ORDER else 0
            for c in candidate
        )
        if score > best_score:
            best_score, best_shift = score, shift
    return best_shift, caesar_decrypt(ciphertext, best_shift)


def scan_value(key_name: str, value: str) -> dict | None:
    """
    يفحص قيمة واحدة. يرجع نتيجة إن بدت سرًّا مُرمَّزًا ترميزًا ضعيفًا، وإلا
    None. النتيجة: {key_name, original, method, decoded, inferred_key,
    recommendation}.
    """
    if not isinstance(value, str) or len(value.strip()) < 6:
        return None

    looks_secret = bool(_SECRET_KEY_HINT.search(key_name))

    # 1) Base64
    decoded = try_base64(value)
    if decoded is not None:
        return {
            "key_name": key_name, "original": value, "method": "Base64",
            "decoded": decoded, "inferred_key": "(بلا مفتاح - ترميز قابل للعكس مباشرة)",
            "is_secret_name": looks_secret,
            "recommendation": "Base64 ترميز لا تشفير؛ أي شخص يفكّه فورًا. "
                              "استبدله بتخزين مُجزّأ (bcrypt لكلمات المرور) أو تشفير AES-GCM.",
        }

    # 2) قيصر/ROT13 - فقط إن كانت القيمة حروفًا إنجليزية غالبًا واسم المفتاح سرّي
    alpha = [c for c in value if c.isalpha()]
    if looks_secret and len(alpha) >= 6 and len(alpha) / len(value) > 0.7:
        shift, plain = break_caesar(value)
        if shift != 0 and _printable_ratio(plain) > 0.9:
            method = "ROT13" if shift == 13 else f"قيصر (إزاحة {shift})"
            return {
                "key_name": key_name, "original": value, "method": method,
                "decoded": plain, "inferred_key": f"إزاحة = {shift}",
                "is_secret_name": looks_secret,
                "recommendation": "قيصر/ROT13 يُكسَر بتحليل التكرار بلا مفتاح. "
                                  "لا تستخدمه لأي سرّ؛ استعمل تجزئة قوية أو AES-GCM.",
            }
    return None


def scan_config_dict(config: dict, prefix: str = "") -> list[dict]:
    """يفحص قاموس إعدادات (متداخل) ويرجع قائمة الترميزات الضعيفة المكتشفة."""
    findings: list[dict] = []
    for key, value in config.items():
        full = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            findings.extend(scan_config_dict(value, full))
        elif isinstance(value, str):
            res = scan_value(full, value)
            if res:
                findings.append(res)
    return findings
