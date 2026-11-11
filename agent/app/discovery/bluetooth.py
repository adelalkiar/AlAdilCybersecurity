"""
اكتشاف أجهزة Bluetooth Low Energy (BLE) القريبة عبر مكتبة bleak، التي
تدعم Windows/macOS/Linux بواجهة واحدة غير متزامنة.
"""
from __future__ import annotations

import logging
from datetime import datetime

from bleak import BleakScanner

from shared.models import ConnectionMedium, DeviceFingerprint, DeviceType, ScannedDevice

logger = logging.getLogger("aladil.discovery.bluetooth")


async def bluetooth_scan(duration_seconds: float = 6.0) -> list[ScannedDevice]:
    now = datetime.utcnow()
    devices: list[ScannedDevice] = []
    try:
        discovered = await BleakScanner.discover(timeout=duration_seconds, return_adv=True)
    except Exception as exc:  # noqa: BLE001  # قد يفشل إن لم يوجد مهيّئ Bluetooth
        logger.warning("تعذّر فحص Bluetooth: %s", exc)
        return devices

    for device, adv in discovered.values():
        devices.append(
            ScannedDevice(
                fingerprint=DeviceFingerprint(
                    mac_address=device.address,
                    hostname=device.name or adv.local_name or "Unknown BLE Device",
                ),
                device_type=DeviceType.BLUETOOTH_PERIPHERAL,
                connection_medium=ConnectionMedium.BLUETOOTH,
                first_seen=now,
                last_seen=now,
                signal_strength_dbm=adv.rssi,
            )
        )
    return devices
