"""اختبارات وحدة لتصنيف الهواتف (دالة نقيّة بلا I/O)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.models import DeviceFingerprint, DeviceType, ScannedDevice
from shared.vuln_db.device_classify import classify_mobile


def _device(vendor=None, hostname=None, device_type=DeviceType.UNKNOWN):
    return ScannedDevice(
        fingerprint=DeviceFingerprint(vendor=vendor, hostname=hostname),
        device_type=device_type,
    )


def test_samsung_vendor_is_android_mobile():
    d = classify_mobile(_device(vendor="Samsung Electronics Co.,Ltd"))
    assert d.device_type == DeviceType.MOBILE
    assert d.fingerprint.os_guess == "Android"


def test_xiaomi_vendor_is_android():
    d = classify_mobile(_device(vendor="Xiaomi Communications Co Ltd"))
    assert d.device_type == DeviceType.MOBILE
    assert d.fingerprint.os_guess == "Android"


def test_iphone_hostname_is_ios_mobile():
    d = classify_mobile(_device(vendor="Apple, Inc.", hostname="Ahmeds-iPhone"))
    assert d.device_type == DeviceType.MOBILE
    assert d.fingerprint.os_guess == "iOS / iPadOS"


def test_android_hostname_without_known_vendor():
    d = classify_mobile(_device(hostname="android-3f9a2b"))
    assert d.device_type == DeviceType.MOBILE
    assert d.fingerprint.os_guess == "Android"


def test_apple_vendor_without_phone_hint_stays_untyped():
    # Apple لكن بلا دليل أنه هاتف - لا نفرض MOBILE (قد يكون Mac)
    d = classify_mobile(_device(vendor="Apple, Inc.", hostname="Johns-MacBook-Pro"))
    assert d.device_type == DeviceType.UNKNOWN
    assert "Apple" in d.fingerprint.os_guess


def test_router_type_is_not_overwritten():
    d = classify_mobile(_device(vendor="Samsung", hostname="router", device_type=DeviceType.ROUTER))
    assert d.device_type == DeviceType.ROUTER  # تصنيف mDNS الأدق محفوظ


def test_unknown_device_stays_unknown():
    d = classify_mobile(_device(vendor="Dell Inc.", hostname="office-pc"))
    assert d.device_type == DeviceType.UNKNOWN
    assert d.fingerprint.os_guess is None


def test_existing_os_guess_is_preserved():
    d = _device(vendor="Samsung")
    d.fingerprint.os_guess = "Android 14"
    classify_mobile(d)
    assert d.fingerprint.os_guess == "Android 14"  # لا نكتب فوق تخمين أدق موجود
