"""
سلسلة تجزئة للسجلات (Hash-chained audit log) - لتحقيق «عدم الإنكار
والمساءلة» (الفصل 1 من المنهج): كل سطر في السجل يحمل تجزئة SHA-256 للسطر
السابق، فأي حذف أو تعديل أو إعادة ترتيب لسطر يكسر السلسلة ويُكتشَف.

وحدة نقيّة من المنطق (hashlib/json فقط) يشترك فيها سجل التفويض لدى العميل
وسجل أحداث الخادم. لا تمنع التلاعب (من يملك الملف يستطيع إعادة بناء
السلسلة كاملة)، لكنها تكشف أي تعديل جزئي أو حذف لسطر دون إعادة توقيع
السلسلة بأكملها - وهو ما يحتاجه سجل المساءلة.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS_HASH = "0" * 64


def _canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def compute_hash(prev_hash: str, seq: int, timestamp: str, data: dict) -> str:
    """يحسب تجزئة سطر بدلالة السطر السابق ورقمه ووقته وبياناته (دالة نقيّة)."""
    material = f"{prev_hash}|{seq}|{timestamp}|{_canonical(data)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _read_lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries: list[dict] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            entries.append(json.loads(raw))
        except json.JSONDecodeError:
            entries.append({"_corrupt": raw})
    return entries


def append_entry(path: Path, data: dict, timestamp: str) -> dict:
    """يضيف سطرًا جديدًا مربوطًا بتجزئة آخر سطر. يرجع السطر المُضاف."""
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = _read_lines(path)
    if entries and "hash" in entries[-1]:
        prev_hash = entries[-1]["hash"]
        seq = entries[-1].get("seq", len(entries) - 1) + 1
    else:
        prev_hash = GENESIS_HASH
        seq = 0
    entry = {
        "seq": seq,
        "ts": timestamp,
        "data": data,
        "prev_hash": prev_hash,
        "hash": compute_hash(prev_hash, seq, timestamp, data),
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def verify_chain(path: Path) -> dict:
    """
    يتحقق من سلامة السلسلة كاملة. يرجع:
      {ok, total, broken_at, reason}
    broken_at = رقم أول سطر مكسور (seq) أو None إن كانت سليمة.
    """
    entries = _read_lines(path)
    if not entries:
        return {"ok": True, "total": 0, "broken_at": None, "reason": "السجل فارغ"}

    prev_hash = GENESIS_HASH
    expected_seq = 0
    for entry in entries:
        if "_corrupt" in entry or "hash" not in entry:
            return {"ok": False, "total": len(entries), "broken_at": expected_seq,
                    "reason": "سطر تالف أو غير مكتمل"}
        if entry.get("prev_hash") != prev_hash:
            return {"ok": False, "total": len(entries), "broken_at": entry.get("seq"),
                    "reason": "انقطاع السلسلة: تجزئة السطر السابق لا تطابق (حذف أو إعادة ترتيب)"}
        recomputed = compute_hash(prev_hash, entry.get("seq"), entry.get("ts", ""), entry.get("data", {}))
        if recomputed != entry.get("hash"):
            return {"ok": False, "total": len(entries), "broken_at": entry.get("seq"),
                    "reason": "تجزئة السطر لا تطابق محتواه (تعديل)"}
        if entry.get("seq") != expected_seq:
            return {"ok": False, "total": len(entries), "broken_at": entry.get("seq"),
                    "reason": "ترقيم غير متسلسل (حذف سطر)"}
        prev_hash = entry["hash"]
        expected_seq += 1

    return {"ok": True, "total": len(entries), "broken_at": None, "reason": "السلسلة سليمة"}
