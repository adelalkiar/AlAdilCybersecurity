"""اختبارات وحدة لسلسلة التجزئة (عدم الإنكار والمساءلة - الفصل 1):
تكشف التعديل والحذف وإعادة الترتيب."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.integrity import append_entry, verify_chain


def _chain(tmp_path, n=3):
    p = tmp_path / "audit.log"
    for i in range(n):
        append_entry(p, {"event": f"e{i}", "value": i}, timestamp=f"2026-01-0{i+1}T00:00:00Z")
    return p


def test_fresh_chain_verifies_ok(tmp_path):
    p = _chain(tmp_path, 4)
    r = verify_chain(p)
    assert r["ok"] is True
    assert r["total"] == 4
    assert r["broken_at"] is None


def test_empty_chain_is_ok(tmp_path):
    r = verify_chain(tmp_path / "nope.log")
    assert r["ok"] is True and r["total"] == 0


def test_each_entry_links_to_previous(tmp_path):
    p = _chain(tmp_path, 3)
    lines = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["prev_hash"] == "0" * 64
    assert lines[1]["prev_hash"] == lines[0]["hash"]
    assert lines[2]["prev_hash"] == lines[1]["hash"]


def test_modification_is_detected(tmp_path):
    p = _chain(tmp_path, 3)
    lines = p.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["data"]["value"] = 999  # عدّل بيانات السطر الأوسط دون إعادة التجزئة
    lines[1] = json.dumps(tampered, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = verify_chain(p)
    assert r["ok"] is False
    assert r["broken_at"] == 1


def test_deletion_is_detected(tmp_path):
    p = _chain(tmp_path, 4)
    lines = p.read_text(encoding="utf-8").splitlines()
    del lines[1]  # احذف سطرًا من المنتصف
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = verify_chain(p)
    assert r["ok"] is False
    assert r["broken_at"] is not None


def test_reorder_is_detected(tmp_path):
    p = _chain(tmp_path, 3)
    lines = p.read_text(encoding="utf-8").splitlines()
    lines[0], lines[1] = lines[1], lines[0]  # اعكس أول سطرين
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = verify_chain(p)
    assert r["ok"] is False


def test_appending_more_keeps_chain_valid(tmp_path):
    p = _chain(tmp_path, 2)
    append_entry(p, {"event": "later"}, timestamp="2026-02-01T00:00:00Z")
    r = verify_chain(p)
    assert r["ok"] is True and r["total"] == 3
