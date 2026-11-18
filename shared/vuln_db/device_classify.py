"""
تصنيف أدق لنوع الجهاز ونظام تشغيله اعتمادًا على الشركة المصنّعة (OUI من
عنوان MAC) واسم المضيف - خاصةً تمييز الهواتف المحمولة (Android / iOS)
التي تظهر غالبًا بنوع "غير معروف" عند اكتشافها عبر ARP/Wi-Fi.

دالة نقيّة بالكامل (بلا I/O): تُعدّل حقول ScannedDevice مباشرة بناءً على
بصمته فقط، فيسهل اختبارها بمعزل عن الشبكة.
"""
from __future__ import annotations

from shared.models import DeviceType, ScannedDevice

# كلمات تدل على مُصنّع هواتف Android في اسم الشركة من OUI
_ANDROID_VENDOR_KEYWORDS = (
    "samsung", "xiaomi", "redmi", "poco", "huawei", "honor", "oneplus", "oppo",
    "vivo", "realme", "motorola", "nokia", "hmd", "google", "pixel",
    "sony mobile", "tecno", "infinix", "zte", "meizu", "lenovo mobile", "nothing",
)
# كلمات تدل على هاتف Android في اسم المضيف
_ANDROID_HOST_KEYWORDS = (
    "android", "galaxy", "redmi", "poco", "oneplus", "pixel", "huawei", "honor",
    "oppo", "vivo", "realme", "moto", "infinix", "tecno", "samsung",
)
_IOS_HOST_KEYWORDS = ("iphone", "ipad", "ipod")


def classify_mobile(device: ScannedDevice) -> ScannedDevice:
    """
    يحدّد ما إذا كان الجهاز هاتفًا محمولًا ويضبط device_type=MOBILE
    و os_guess (Android / iOS) حين يكون التمييز واضحًا. لا يلمس نوع جهاز
    سبق تحديده بوضوح (راوتر/طابعة... من mDNS مثلًا): يعمل فقط حين يكون
    النوع الحالي "غير معروف" أو "هاتف"، حتى لا يفسد تصنيفًا أدق سابقًا.
    """
    vendor = (device.fingerprint.vendor or "").lower()
    hostname = (device.fingerprint.hostname or "").lower()

    is_apple_vendor = "apple" in vendor
    is_android_vendor = any(k in vendor for k in _ANDROID_VENDOR_KEYWORDS)
    is_android_host = any(k in hostname for k in _ANDROID_HOST_KEYWORDS)
    is_ios_host = any(k in hostname for k in _IOS_HOST_KEYWORDS)

    settable = device.device_type in (DeviceType.UNKNOWN, DeviceType.MOBILE)

    if is_ios_host or (is_apple_vendor and is_ios_host):
        device.fingerprint.os_guess = device.fingerprint.os_guess or "iOS / iPadOS"
        if settable:
            device.device_type = DeviceType.MOBILE
    elif is_android_vendor or is_android_host:
        device.fingerprint.os_guess = device.fingerprint.os_guess or "Android"
        if settable:
            device.device_type = DeviceType.MOBILE
    elif is_apple_vendor:
        # جهاز Apple لكن يتعذّر الجزم أهو هاتف/لوحي أم Mac - نوضّح النظام
        # دون فرض نوع "هاتف" قد يكون خاطئًا
        device.fingerprint.os_guess = device.fingerprint.os_guess or "Apple (iPhone/iPad/Mac)"

    return device


def classify_all(devices: list[ScannedDevice]) -> list[ScannedDevice]:
    return [classify_mobile(d) for d in devices]
