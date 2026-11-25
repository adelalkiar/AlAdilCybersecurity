"""اختبارات وحدة لمختبر التشفير الكلاسيكي وتحليل الشفرات (الفصل 4)."""
from __future__ import annotations

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.crypto_lab.classic_ciphers import (
    caesar_decrypt,
    caesar_encrypt,
    columnar_decrypt,
    columnar_encrypt,
    rot13,
    substitution_decrypt,
    substitution_encrypt,
)
from shared.crypto_lab.weak_encoding import break_caesar, scan_config_dict, scan_value, try_base64


# ----- قيصر
def test_caesar_roundtrip():
    assert caesar_decrypt(caesar_encrypt("Hello, World!", 3), 3) == "Hello, World!"


def test_caesar_wraps_and_keeps_nonletters():
    assert caesar_encrypt("xyz ABC!", 3) == "abc DEF!"


def test_rot13_is_self_inverse():
    assert rot13(rot13("Attack at dawn")) == "Attack at dawn"


# ----- الإبدال
def test_substitution_roundtrip():
    key = "qwertyuiopasdfghjklzxcvbnm"
    enc = substitution_encrypt("Secret Message", key)
    assert substitution_decrypt(enc, key) == "Secret Message"


def test_substitution_rejects_bad_key():
    import pytest
    with pytest.raises(ValueError):
        substitution_encrypt("x", "short")


# ----- التبديل العمودي
def test_columnar_roundtrip_simple():
    key = "ZEBRA"
    ct = columnar_encrypt("WEAREDISCOVEREDFLEEATONCE", key)
    pt = columnar_decrypt(ct, key)
    assert pt.startswith("WEAREDISCOVEREDFLEEATONCE")


def test_columnar_changes_text():
    ct = columnar_encrypt("HELLOWORLD", "KEY")
    assert ct != "HELLOWORLD"


# ----- كاشف الترميز الضعيف
def test_try_base64_decodes_text():
    enc = base64.b64encode(b"SuperSecret123").decode()
    assert try_base64(enc) == "SuperSecret123"


def test_try_base64_rejects_plain_text():
    assert try_base64("just a normal value") is None


def test_break_caesar_recovers_shift():
    plain = "the quick brown fox jumps over the lazy dog many times here"
    cipher = caesar_encrypt(plain, 7)
    shift, recovered = break_caesar(cipher)
    assert shift == 7
    assert recovered == plain


def test_scan_value_flags_base64_password():
    enc = base64.b64encode(b"hunter2password").decode()
    r = scan_value("db_password", enc)
    assert r is not None
    assert r["method"] == "Base64"
    assert r["decoded"] == "hunter2password"


def test_scan_value_ignores_non_secret_plain():
    assert scan_value("app_name", "AlAdilCybersecurity") is None


def test_scan_config_dict_nested():
    cfg = {
        "database": {"db_password": base64.b64encode(b"secretpw12345").decode()},
        "app_name": "normal",
    }
    findings = scan_config_dict(cfg)
    assert len(findings) == 1
    assert findings[0]["key_name"] == "database.db_password"
