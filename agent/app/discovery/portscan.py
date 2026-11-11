"""
فحص المنافذ المتوازي (TCP connect scan) لجهاز معيّن باستخدام asyncio مع
Semaphore للحد من عدد الاتصالات المتزامنة (تجنّب إغراق الشبكة/الجهاز
المستهدف). يحاول أيضًا قراءة "بانر" الخدمة (banner grabbing) لتحديد
المنتج والإصدار بشكل تقريبي عندما تسمح الخدمة بذلك.
"""
from __future__ import annotations

import asyncio
import logging

from shared.models import OpenPort

logger = logging.getLogger("aladil.discovery.portscan")

# أشهر المنافذ المرتبطة بتهديدات/خدمات شائعة (قابلة للتوسعة من الواجهة)
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
    5985, 6379, 8080, 8443, 8888, 9000, 9200, 27017,
]

_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "smtp-submission", 631: "ipp", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    5985: "winrm", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9200: "elasticsearch",
    27017: "mongodb",
}


async def _probe_port(
    ip: str, port: int, semaphore: asyncio.Semaphore, connect_timeout: float
) -> OpenPort | None:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=connect_timeout
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

        banner = None
        try:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=1.0)
            banner = data.decode(errors="ignore").strip() or None
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            writer.close()

        return OpenPort(
            port=port,
            protocol="tcp",
            service=_SERVICE_NAMES.get(port, "unknown"),
            banner=banner,
        )


async def scan_ports(
    ip: str,
    ports: list[int] | None = None,
    max_concurrent: int = 200,
    connect_timeout: float = 1.5,
) -> list[OpenPort]:
    """
    فحص متوازٍ لقائمة منافذ على جهاز واحد. يُستخدم max_concurrent للحد من
    التحميل الزائد على الشبكة أثناء تنفيذ عدد كبير من اتصالات asyncio بالتوازي.
    """
    ports = ports or DEFAULT_PORTS
    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = [_probe_port(ip, port, semaphore, connect_timeout) for port in ports]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


async def scan_many_hosts_ports(
    ip_list: list[str],
    ports: list[int] | None = None,
    max_concurrent_hosts: int = 32,
    max_concurrent_ports_per_host: int = 100,
) -> dict[str, list[OpenPort]]:
    """
    معالجة متوازية على مستوى الأجهزة أيضًا: يفحص عدة أجهزة في آنٍ واحد،
    وكل جهاز بدوره يفحص منافذه بالتوازي (معالجة متوازية متداخلة).
    """
    host_semaphore = asyncio.Semaphore(max_concurrent_hosts)

    async def _scan_one(ip: str) -> tuple[str, list[OpenPort]]:
        async with host_semaphore:
            ports_found = await scan_ports(
                ip, ports, max_concurrent=max_concurrent_ports_per_host
            )
            return ip, ports_found

    results = await asyncio.gather(*(_scan_one(ip) for ip in ip_list))
    return dict(results)
