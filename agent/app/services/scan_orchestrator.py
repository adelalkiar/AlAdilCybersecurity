"""
منسّق الفحص: يشغّل كل وحدات الاكتشاف (شبكة محلية، mDNS، Wi-Fi، Bluetooth،
فحص منافذ، مطابقة ثغرات) بالتوازي عبر asyncio.gather، ثم يمرّر النتائج على
محرّك تقييم المخاطر، ويُنتج تقرير فحص موحّد (ScanReport) جاهزًا للإرسال
إلى الخادم المركزي.

كل هدف خارج الشبكات المحلية المباشرة للجهاز يُمرَّر أولًا عبر
shared.authorization_gate.ensure_authorized قبل أي محاولة فحص فعلية.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from agent.app.discovery.bluetooth import bluetooth_scan
from agent.app.discovery.host_activity import annotate_host_activity
from agent.app.discovery.mdns import mdns_scan
from agent.app.discovery.network import arp_scan, discover_local_subnets
from agent.app.discovery.portscan import scan_many_hosts_ports
from agent.app.discovery.unsigned_programs import scan_unsigned_programs
from agent.app.discovery.vuln_audit import run_security_audit
from agent.app.discovery.vuln_registry import update_local_registry
from agent.app.discovery.wifi import wifi_scan
from shared.authorization_gate import AuthorizationRequiredError, ensure_authorized
from shared.models import ConnectionMedium, ScanReport, ScanTarget, ScannedDevice
from shared.vuln_db.cve_client import lookup_many
from shared.vuln_db.risk_scoring import score_all

logger = logging.getLogger("aladil.scan_orchestrator")


def _merge_devices(groups: list[list[ScannedDevice]]) -> list[ScannedDevice]:
    """يدمج نتائج الاكتشاف المختلفة، مفضّلًا تجميع نفس الجهاز إن ظهر بعدة
    طرق (مثلًا عبر ARP و mDNS معًا) باستخدام عنوان MAC أو IP كمفتاح."""
    merged: dict[str, ScannedDevice] = {}
    for group in groups:
        for device in group:
            key = device.fingerprint.mac_address or device.ip_address or id(device)
            if key in merged:
                existing = merged[key]
                existing.open_ports.extend(device.open_ports)
                existing.vulnerabilities.extend(device.vulnerabilities)
                if device.ip_address and not existing.ip_address:
                    existing.ip_address = device.ip_address
                if device.signal_strength_dbm is not None:
                    existing.signal_strength_dbm = device.signal_strength_dbm
            else:
                merged[key] = device
    return list(merged.values())


async def _enrich_with_ports_and_vulns(
    devices: list[ScannedDevice], agent_cfg: "AgentScanConfig"
) -> None:
    ip_devices = {d.ip_address: d for d in devices if d.ip_address}
    if not ip_devices:
        return

    port_results = await scan_many_hosts_ports(
        list(ip_devices.keys()),
        max_concurrent_hosts=agent_cfg.max_concurrent_hosts,
        max_concurrent_ports_per_host=agent_cfg.max_concurrent_ports_per_host,
    )
    for ip, ports in port_results.items():
        ip_devices[ip].open_ports.extend(ports)

    # مطابقة الثغرات: نتجنّب عمدًا البحث باسم الخدمة المجرّد (مثل "http" أو
    # "dns" بلا إصدار) لأن NVD يُرجع عندها عشرات الثغرات العامة غير
    # المرتبطة فعليًا بهذا الجهاز (أي CVE يذكر الكلمة في وصفه)، ما يُضخّم
    # درجة الخطورة زيفًا ويُصنّف كل جهاز تقريبًا "حرج". لذلك نكتفي بمطابقة
    # الثغرات فقط حين يوجد دليل تعريف حقيقي (رقم إصدار واضح في الـ banner
    # المُستلَم فعليًا من الخدمة)، وإلا نكتفي بعرض "منفذ مفتوح" بدون ادّعاء
    # ثغرة لم نتحقق منها.
    for device in ip_devices.values():
        for port in device.open_ports:
            product, version = _extract_product_version(port)
            if product and version:
                port.product = product
                port.version = version

    product_targets: list[tuple[str, str | None]] = []
    for device in ip_devices.values():
        for port in device.open_ports:
            if port.product and port.version:
                product_targets.append((port.product, port.version))

    if product_targets and agent_cfg.enable_cve_lookup:
        vuln_map = await lookup_many(product_targets, api_key=agent_cfg.nvd_api_key)
        for device in ip_devices.values():
            for port in device.open_ports:
                if not (port.product and port.version):
                    continue
                key = f"{port.product}:{port.version or ''}"
                found = vuln_map.get(key, [])
                for v in found:
                    v.affected_port = port.port
                device.vulnerabilities.extend(found)


_BANNER_PATTERNS = [
    # SSH-2.0-OpenSSH_8.9p1 -> openssh / 8.9p1
    (r"SSH-[\d.]+-(\w+)[_/]([\w.]+)", 1, 2),
    # Apache/2.4.58, nginx/1.24.0
    (r"(Apache|nginx|lighttpd)/([\d.]+)", 1, 2),
    # "220 ... FTP server (vsftpd 3.0.5)"
    (r"(vsftpd|ProFTPD|Pure-FTPd)[\s(]*([\d.]+)", 1, 2),
    # MySQL/MariaDB banner يحمل رقم إصدار بروتوكول مبكرًا، مثل "5.7.31-log"
    (r"(\d+\.\d+\.\d+)-?(MariaDB)?", 1, 1),
]


def _extract_product_version(port) -> tuple[str | None, str | None]:
    """يحاول استخراج اسم منتج + رقم إصدار دقيقين من نص الـ banner الفعلي
    فقط (وليس من اسم الخدمة المخمَّن)، لتفادي مطابقة ثغرات زائفة."""
    import re

    if not port.banner:
        return None, None
    for pattern, product_group, version_group in _BANNER_PATTERNS:
        match = re.search(pattern, port.banner, re.IGNORECASE)
        if match:
            try:
                product = match.group(product_group) or port.service
                version = match.group(version_group)
            except IndexError:
                continue
            if version and any(c.isdigit() for c in version):
                return product.lower(), version
    return None, None


class AgentScanConfig:
    def __init__(
        self,
        max_concurrent_hosts: int = 32,
        max_concurrent_ports_per_host: int = 100,
        enable_cve_lookup: bool = True,
        nvd_api_key: str | None = None,
        mdns_duration: float = 5.0,
        bluetooth_duration: float = 6.0,
    ) -> None:
        self.max_concurrent_hosts = max_concurrent_hosts
        self.max_concurrent_ports_per_host = max_concurrent_ports_per_host
        self.enable_cve_lookup = enable_cve_lookup
        self.nvd_api_key = nvd_api_key
        self.mdns_duration = mdns_duration
        self.bluetooth_duration = bluetooth_duration


async def run_full_scan(
    agent_id: str,
    targets: list[ScanTarget],
    config: AgentScanConfig | None = None,
) -> ScanReport:
    config = config or AgentScanConfig()
    started_at = datetime.utcnow()
    errors: list[str] = []

    local_subnets = await discover_local_subnets()

    # تحقّق من التفويض لكل هدف خارجي قبل أي عملية فحص
    verified_targets: list[ScanTarget] = []
    for target in targets:
        try:
            verified_targets.append(ensure_authorized(target, local_subnets))
        except AuthorizationRequiredError as exc:
            errors.append(str(exc))
            logger.warning(str(exc))

    # تشغيل كل وسائل الاكتشاف بالتوازي (شبكة محلية + mDNS + Wi-Fi + Bluetooth)
    local_cidrs = [
        t.cidr_or_host for t in verified_targets if t.medium == ConnectionMedium.ETHERNET
    ] or local_subnets

    # آخر عنصرين في القائمة ليسا من نوع ScannedDevice: فحص البرامج غير
    # الموقَّعة ثم التدقيق الأمني - نعزلهما قبل دمج الأجهزة
    results = await asyncio.gather(
        *(arp_scan(cidr) for cidr in local_cidrs),
        mdns_scan(config.mdns_duration),
        wifi_scan(),
        bluetooth_scan(config.bluetooth_duration),
        scan_unsigned_programs(),
        run_security_audit(),
        return_exceptions=True,
    )

    audit_result = results[-1]
    audit_findings: list = []
    if isinstance(audit_result, Exception):
        errors.append(str(audit_result))
        logger.exception("خطأ أثناء التدقيق الأمني", exc_info=audit_result)
    elif isinstance(audit_result, list):
        audit_findings = audit_result

    unsigned_result = results[-2]
    unsigned_findings: list = []
    if isinstance(unsigned_result, Exception):
        errors.append(str(unsigned_result))
        logger.exception("خطأ أثناء فحص البرامج غير الموقَّعة", exc_info=unsigned_result)
    elif isinstance(unsigned_result, list):
        unsigned_findings = unsigned_result

    device_groups: list[list[ScannedDevice]] = []
    for result in results[:-2]:
        if isinstance(result, Exception):
            errors.append(str(result))
            logger.exception("خطأ أثناء أحد مسارات الاكتشاف المتوازية", exc_info=result)
            continue
        if isinstance(result, list):
            device_groups.append(result)

    all_devices = _merge_devices(device_groups)
    await _enrich_with_ports_and_vulns(all_devices, config)
    try:
        annotate_host_activity(all_devices)
    except Exception as exc:  # noqa: BLE001
        logger.warning("تعذّرت مراقبة سلوك الوصول لجهاز النظام: %s", exc)
    score_all(all_devices)

    # سجل الثغرات المحلي: نراكم نتائج التدقيق عبر الزمن على هذا الجهاز نفسه
    # (محلي فقط - لا يُرفع لأي خادم مركزي ولا يُشارك عبر أجهزة أخرى)
    try:
        update_local_registry(audit_findings, unsigned_findings)
    except Exception as exc:  # noqa: BLE001
        logger.warning("تعذّر تحديث سجل الثغرات المحلي: %s", exc)

    finished_at = datetime.utcnow()
    primary_target = verified_targets[0] if verified_targets else ScanTarget(
        cidr_or_host=local_subnets[0] if local_subnets else "unknown",
        medium=ConnectionMedium.ETHERNET,
    )

    return ScanReport(
        agent_id=agent_id,
        started_at=started_at,
        finished_at=finished_at,
        target=primary_target,
        devices=all_devices,
        errors=errors,
        unsigned_program_findings=unsigned_findings,
        security_audit_findings=audit_findings,
    )
