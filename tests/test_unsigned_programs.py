"""اختبارات وحدة للأجزاء النقيّة (بلا I/O) من كاشف البرامج غير الموقَّعة،
كما توصي به .claude/skills/unsigned-program-detection/SKILL.md قسم
"Testing": تحليل PE، الإنتروبيا، فك Zone.Identifier، والتسجيل."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.app.discovery.unsigned_programs import (
    entropy,
    parse_zone,
    pe_info,
    score_finding,
)


def test_entropy_of_empty_is_zero():
    assert entropy(b"") == 0.0


def test_entropy_of_repeated_byte_is_zero():
    # بايت واحد مكرر = لا عشوائية إطلاقًا
    assert entropy(b"\x00" * 1000) == 0.0


def test_entropy_of_random_like_data_is_high():
    random_bytes = os.urandom(4096)
    assert entropy(random_bytes) > 7.5


def test_pe_info_rejects_non_pe_data():
    assert pe_info(b"not a pe file at all") == {"pe": False}


def test_pe_info_rejects_too_short_mz():
    assert pe_info(b"MZ") == {"pe": False}


def test_pe_info_parses_minimal_valid_header():
    # ترويسة DOS دنيا (64 بايت) تُشير لإزاحة PE عند 64، ثم ترويسة PE
    # دنيا صالحة لجهاز x64 (0x8664) بلا أقسام وبدون وقت ترجمة
    import struct

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 64)  # e_lfanew يشير مباشرة بعد هذه الترويسة
    pe_header = b"PE\0\0" + struct.pack("<HHI", 0x8664, 0, 0) + b"\x00" * 16
    data = bytes(dos_header) + pe_header

    info = pe_info(data)
    assert info["pe"] is True
    assert info["machine"] == "x64"
    assert info["compiled_utc"] is None  # وقت الترجمة = صفر يعني غير متوفر


def test_parse_zone_internet_download():
    text = "[ZoneTransfer]\nZoneId=3\nHostUrl=http://example.com/payload.exe\n"
    parsed = parse_zone(text)
    assert parsed["ZoneId"] == "3"
    assert parsed["ZoneName"] == "الإنترنت"
    assert parsed["HostUrl"] == "http://example.com/payload.exe"


def test_parse_zone_handles_none():
    assert parse_zone(None) == {}


def test_score_unsigned_in_user_writable_folder_is_flagged():
    score, level, reasons = score_finding(
        path=r"C:\Users\test\AppData\Local\Temp\WindowsService.exe",
        file_info={"sig": "NotSigned"},
        launchers=[],
        processes=[],
        analysis={},
    )
    assert score >= 35  # غير موقَّع (20) + مجلد قابل للكتابة (15) + اسم يوهم أنه Windows (15)
    assert level in ("suspect", "danger")
    assert any("غير موقّع" in r for r in reasons)


def test_score_signed_valid_store_app_is_not_penalized_for_signature():
    score, level, reasons = score_finding(
        path=r"C:\Program Files\WindowsAppS\SomeApp\app.exe",
        file_info={"sig": "NotSigned"},  # تطبيقات المتجر تظهر NotSigned لكل ملف رغم توقيعها كحزمة
        launchers=[],
        processes=[],
        analysis={},
    )
    assert any("متجر Microsoft" in r for r in reasons)
    assert score < 35  # لا عقوبة توقيع لتطبيقات المتجر، فالدرجة تبقى منخفضة


def test_score_miner_indicators_reach_danger_level():
    score, level, reasons = score_finding(
        path=r"C:\Users\test\AppData\Roaming\svc\miner.exe",
        file_info={"sig": "NotSigned"},
        launchers=[{"hidden": True, "name": "\\Microsoft\\Windows\\UpdateTask"}],
        processes=[],
        analysis={"indicator_score": 35, "indicators": ["يحمل اسم برنامج أو خوارزمية تعدين معروفة"]},
    )
    assert level == "danger"
    assert score >= 60


def test_score_hollow_process_is_flagged():
    score, level, reasons = score_finding(
        path="(داخل cmd.exe)",
        file_info={"sig": "Valid"},
        launchers=[],
        processes=[{"hollow": True, "name": "cmd.exe", "connections": [{"ra": "31.7.60.154", "rp": 85}]}],
        analysis={},
    )
    assert score >= 30
    assert any("مختبئًا" in r for r in reasons)
    assert any("منفذ غير معتاد" in r for r in reasons)


def test_score_capped_at_100():
    score, _level, _reasons = score_finding(
        path=r"C:\Users\test\AppData\Local\Temp\windows_update_service.exe",
        file_info={"sig": "NotSigned"},
        launchers=[{"hidden": True, "level": "highest"}],
        processes=[{"hollow": True, "name": "svchost.exe", "connections": [{"ra": "1.2.3.4", "rp": 9999}]}],
        analysis={
            "indicator_score": 35 + 35 + 30,
            "indicators": ["a", "b", "c"],
            "has_encrypted_sibling": True,
        },
    )
    assert score == 100
