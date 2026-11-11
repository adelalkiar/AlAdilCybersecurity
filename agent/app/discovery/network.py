"""
اكتشاف الأجهزة على الشبكة المحلية (Ethernet/Wi-Fi) عبر ARP.

نستخدم scapy لإرسال طلبات ARP broadcast على كل subnet محلي ومعالجة الردود.
العملية تُنفَّذ في executor لأن scapy يستخدم سوكيت خام (blocking) وغير
متوافق مباشرة مع asyncio.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from mac_vendor_lookup import MacLookup
from scapy.layers.l2 import ARP, Ether, srp

from shared.models import ConnectionMedium, DeviceFingerprint, DeviceType, ScannedDevice

logger = logging.getLogger("aladil.discovery.network")

_mac_lookup = MacLookup()


def _arp_scan_blocking(cidr: str, timeout: float = 3.0) -> list[tuple[str, str]]:
    """يُنفَّذ في thread منفصل: يرجع قائمة (ip, mac)."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(packet, timeout=timeout, verbose=False, retry=1)
    return [(received.psrc, received.hwsrc) for _, received in answered]


async def arp_scan(cidr: str, timeout: float = 3.0) -> list[ScannedDevice]:
    """فحص ARP غير متزامن لنطاق شبكة محلي (مثل 192.168.1.0/24)."""
    loop = asyncio.get_running_loop()
    try:
        results = await loop.run_in_executor(None, _arp_scan_blocking, cidr, timeout)
    except PermissionError:
        logger.error(
            "فحص ARP يتطلب صلاحيات مرتفعة (مشرف/root) للوصول إلى سوكيت خام."
        )
        return []
    except Exception as exc:  # noqa: BLE001
        logger.exception("فشل فحص ARP على %s: %s", cidr, exc)
        return []

    devices: list[ScannedDevice] = []
    now = datetime.utcnow()
    for ip, mac in results:
        vendor = None
        try:
            vendor = await loop.run_in_executor(None, _mac_lookup.lookup, mac)
        except Exception:  # noqa: BLE001  # الشركة غير معروفة في قاعدة OUI
            vendor = None

        devices.append(
            ScannedDevice(
                ip_address=ip,
                fingerprint=DeviceFingerprint(mac_address=mac, vendor=vendor),
                device_type=DeviceType.UNKNOWN,
                connection_medium=ConnectionMedium.ETHERNET,
                first_seen=now,
                last_seen=now,
            )
        )
    return devices


MAX_ARP_SCAN_HOSTS = 1024  # يحدّ نطاق ARP لأي subnet بحد أقصى /22 تقريبًا


async def discover_local_subnets() -> list[str]:
    """
    يحدّد الشبكات الفرعية المحلية المتصلة بواجهات الجهاز الحالي، مع
    استبعاد:
      - عناوين loopback (127.x).
      - نطاق APIPA/link-local الكامل (169.254.0.0/16) الذي تضيفه أنظمة
        التشغيل تلقائيًا لمحولات افتراضية (Hyper-V/VirtualBox/VPN) بلا
        DHCP فعلي؛ فحصه بالكامل (65536 عنوانًا) غير مجدٍ ويستهلك وقتًا
        طويلًا جدًا دون فائدة أمنية حقيقية.
      - أي subnet أكبر من MAX_ARP_SCAN_HOSTS عنوانًا (مثل /16 أو أكبر من
        واجهة بإعداد خاطئ) لتفادي تجميد الفحص على جهاز العميل.
    """
    import ipaddress

    import psutil

    link_local = ipaddress.ip_network("169.254.0.0/16")
    subnets: list[str] = []

    for _, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name != "AF_INET":
                continue
            if addr.address.startswith("127."):
                continue
            try:
                network = ipaddress.ip_network(
                    f"{addr.address}/{addr.netmask}", strict=False
                )
            except (ValueError, TypeError):
                continue

            if network.subnet_of(link_local):
                logger.info("تجاوز نطاق link-local غير مفيد للفحص: %s", network)
                continue
            if network.num_addresses > MAX_ARP_SCAN_HOSTS:
                logger.warning(
                    "تجاوز subnet ضخم (%d عنوان) لتفادي تجميد الفحص: %s",
                    network.num_addresses, network,
                )
                continue

            subnets.append(str(network))
    return list(set(subnets))
