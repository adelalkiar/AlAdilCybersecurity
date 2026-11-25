"""
التشفير الكلاسيكي (الفصل 4): الإبدال (Substitution/قيصر) والتبديل
(Transposition العمودي) تشفيرًا وفكًّا. تعليمي بحت - لإظهار ضعف هذه
الطرق مقابل التشفير الحديث (AES-GCM / Ed25519) المستخدم في النظام.
"""
from __future__ import annotations


# ------------------------------------------------------------- قيصر (إزاحة)
def caesar_encrypt(text: str, shift: int) -> str:
    """تشفير قيصر: يزيح كل حرف إنجليزي بمقدار shift (يحافظ على الحالة
    وغير الحروف كما هي)."""
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


def rot13(text: str) -> str:
    """ROT13 = قيصر بإزاحة 13 (التشفير والفك متماثلان)."""
    return caesar_encrypt(text, 13)


# ------------------------------------------------- الإبدال العام (مفتاح 26 حرفًا)
def substitution_encrypt(text: str, key: str) -> str:
    """إبدال عام: key سلسلة 26 حرفًا تمثّل ترتيب الأبجدية المُستبدَلة
    (key[0] بديل 'a' ... key[25] بديل 'z')."""
    key = key.lower()
    if len(key) != 26 or len(set(key)) != 26:
        raise ValueError("مفتاح الإبدال يجب أن يكون 26 حرفًا فريدًا")
    table = {chr(97 + i): key[i] for i in range(26)}
    out = []
    for ch in text:
        low = ch.lower()
        if low in table:
            sub = table[low]
            out.append(sub.upper() if ch.isupper() else sub)
        else:
            out.append(ch)
    return "".join(out)


def substitution_decrypt(text: str, key: str) -> str:
    key = key.lower()
    if len(key) != 26 or len(set(key)) != 26:
        raise ValueError("مفتاح الإبدال يجب أن يكون 26 حرفًا فريدًا")
    inverse = {key[i]: chr(97 + i) for i in range(26)}
    out = []
    for ch in text:
        low = ch.lower()
        if low in inverse:
            orig = inverse[low]
            out.append(orig.upper() if ch.isupper() else orig)
        else:
            out.append(ch)
    return "".join(out)


# ----------------------------------------------- التبديل العمودي (Transposition)
def columnar_encrypt(text: str, key: str, pad: str = "x") -> str:
    """
    التبديل العمودي: يُكتب النص في صفوف بعرض len(key)، ثم يُقرأ عموديًا
    بترتيب أحرف المفتاح أبجديًا. يُهمَل الفراغ ويُحشى آخر صف بـ pad.
    """
    if not key:
        raise ValueError("المفتاح مطلوب")
    cols = len(key)
    cleaned = "".join(text.split())
    while len(cleaned) % cols != 0:
        cleaned += pad
    rows = [cleaned[i:i + cols] for i in range(0, len(cleaned), cols)]
    # ترتيب الأعمدة حسب ترتيب أحرف المفتاح أبجديًا (مع فهرس للاستقرار)
    order = sorted(range(cols), key=lambda i: (key[i], i))
    out = []
    for col in order:
        for row in rows:
            out.append(row[col])
    return "".join(out)


def columnar_decrypt(ciphertext: str, key: str) -> str:
    if not key:
        raise ValueError("المفتاح مطلوب")
    cols = len(key)
    if len(ciphertext) % cols != 0:
        raise ValueError("طول النص المشفَّر لا يوافق عرض المفتاح")
    rows_count = len(ciphertext) // cols
    order = sorted(range(cols), key=lambda i: (key[i], i))
    # نملأ الأعمدة بالترتيب الذي قُرئت به
    columns: dict[int, str] = {}
    pos = 0
    for col in order:
        columns[col] = ciphertext[pos:pos + rows_count]
        pos += rows_count
    # نعيد بناء الصفوف
    out = []
    for r in range(rows_count):
        for c in range(cols):
            out.append(columns[c][r])
    return "".join(out)
