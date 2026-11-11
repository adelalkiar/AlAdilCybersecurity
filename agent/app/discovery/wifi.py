"""
اكتشاف شبكات Wi-Fi القريبة (ليس الأجهزة المتصلة بالشبكة المحلية، بل نقاط
الوصول/الشبكات اللاسلكية المجاورة). يعتمد على أوامر النظام لأن بايثون لا
يملك واجهة موحّدة عبر الأنظمة الثلاثة لمسح Wi-Fi على مستوى الطبقة الفيزيائية.

Windows: netsh wlan show networks mode=bssid
Linux:   nmcli -f SSID,BSSID,SIGNAL,SECURITY dev wifi list
macOS:   /System/Library/.../airport -s
"""
from __future__ import annotations

import asyncio
import logging
import platform
import re
from datetime import datetime

from shared.models import ConnectionMedium, DeviceFingerprint, DeviceType, ScannedDevice

logger = logging.getLogger("aladil.discovery.wifi")


async def _run(cmd: list[str]) -> str:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        logger.debug("أمر فحص Wi-Fi فشل (%s): %s", cmd[0], stderr.decode(errors="ignore"))
    return stdout.decode(errors="ignore")


async def wifi_scan() -> list[ScannedDevice]:
    system = platform.system()
    now = datetime.utcnow()
    devices: list[ScannedDevice] = []

    try:
        if system == "Windows":
            output = await _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
            devices = _parse_windows(output, now)
        elif system == "Linux":
            output = await _run(
                ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list"]
            )
            devices = _parse_linux(output, now)
        elif system == "Darwin":
            output = await _run(
                [
                    "/System/Library/PrivateFrameworks/Apple80211.framework/"
                    "Versions/Current/Resources/airport",
                    "-s",
                ]
            )
            devices = _parse_macos(output, now)
    except FileNotFoundError:
        logger.warning("أداة فحص Wi-Fi غير متوفرة على هذا النظام (%s).", system)

    return devices


def _parse_windows(output: str, now: datetime) -> list[ScannedDevice]:
    devices = []
    ssid, bssid, signal = None, None, None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SSID"):
            ssid = line.split(":", 1)[1].strip()
        elif line.startswith("BSSID"):
            bssid = line.split(":", 1)[1].strip()
        elif line.startswith("Signal"):
            sig = re.sub(r"[^\d]", "", line.split(":", 1)[1])
            signal = int(sig) if sig else None
            if bssid:
                devices.append(
                    ScannedDevice(
                        fingerprint=DeviceFingerprint(
                            mac_address=bssid, hostname=ssid or "Unknown SSID"
                        ),
                        device_type=DeviceType.ROUTER,
                        connection_medium=ConnectionMedium.WIFI,
                        first_seen=now,
                        last_seen=now,
                        signal_strength_dbm=signal,
                    )
                )
    return devices


def _parse_linux(output: str, now: datetime) -> list[ScannedDevice]:
    devices = []
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        ssid, bssid, signal, *_ = parts
        devices.append(
            ScannedDevice(
                fingerprint=DeviceFingerprint(mac_address=bssid, hostname=ssid or "Unknown SSID"),
                device_type=DeviceType.ROUTER,
                connection_medium=ConnectionMedium.WIFI,
                first_seen=now,
                last_seen=now,
                signal_strength_dbm=-int(100 - int(signal)) if signal.isdigit() else None,
            )
        )
    return devices


def _parse_macos(output: str, now: datetime) -> list[ScannedDevice]:
    devices = []
    lines = output.splitlines()[1:]  # أول سطر هو العنوان
    for line in lines:
        cols = line.split()
        if len(cols) < 2:
            continue
        ssid, bssid = cols[0], cols[1]
        rssi = int(cols[2]) if len(cols) > 2 and cols[2].lstrip("-").isdigit() else None
        devices.append(
            ScannedDevice(
                fingerprint=DeviceFingerprint(mac_address=bssid, hostname=ssid),
                device_type=DeviceType.ROUTER,
                connection_medium=ConnectionMedium.WIFI,
                first_seen=now,
                last_seen=now,
                signal_strength_dbm=rssi,
            )
        )
    return devices
