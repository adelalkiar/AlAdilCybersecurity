"""
اكتشاف الأجهزة عبر mDNS/Bonjour/DNS-SD (طابعات، كاميرات، أجهزة IoT،
أجهزة Apple/Chromecast ...). يعمل بشكل غير متزامن عبر zeroconf.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from zeroconf import ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from shared.models import ConnectionMedium, DeviceFingerprint, DeviceType, ScannedDevice

logger = logging.getLogger("aladil.discovery.mdns")

COMMON_SERVICE_TYPES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_hap._tcp.local.",       # HomeKit
    "_device-info._tcp.local.",
    "_workstation._tcp.local.",
]

_TYPE_TO_DEVICE_TYPE = {
    "_printer._tcp.local.": DeviceType.PRINTER,
    "_ipp._tcp.local.": DeviceType.PRINTER,
    "_hap._tcp.local.": DeviceType.IOT,
    "_googlecast._tcp.local.": DeviceType.IOT,
}


async def mdns_scan(duration_seconds: float = 5.0) -> list[ScannedDevice]:
    found: dict[str, ScannedDevice] = {}
    now = datetime.utcnow()

    aiozc = AsyncZeroconf()

    def on_change(zeroconf: Zeroconf, service_type: str, name: str, state_change) -> None:
        if state_change is not ServiceStateChange.Added:
            return
        asyncio.ensure_future(_resolve(aiozc, service_type, name))

    async def _resolve(aiozc: AsyncZeroconf, service_type: str, name: str) -> None:
        info = AsyncServiceInfo(service_type, name)
        ok = await info.async_request(aiozc.zeroconf, 3000)
        if not ok or not info.parsed_addresses():
            return
        ip = info.parsed_addresses()[0]
        found[ip] = ScannedDevice(
            ip_address=ip,
            fingerprint=DeviceFingerprint(hostname=info.server),
            device_type=_TYPE_TO_DEVICE_TYPE.get(service_type, DeviceType.UNKNOWN),
            connection_medium=ConnectionMedium.WIFI,
            first_seen=now,
            last_seen=now,
        )

    browsers = [
        AsyncServiceBrowser(aiozc.zeroconf, st, handlers=[on_change])
        for st in COMMON_SERVICE_TYPES
    ]

    try:
        await asyncio.sleep(duration_seconds)
    finally:
        for browser in browsers:
            await browser.async_cancel()
        await aiozc.async_close()

    return list(found.values())
