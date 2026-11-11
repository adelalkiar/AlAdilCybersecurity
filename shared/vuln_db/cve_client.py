"""
عميل مطابقة الثغرات: يستعلم من قاعدة NVD (National Vulnerability Database)
العلنية عبر HTTPS للحصول على ثغرات معروفة (CVE) مرتبطة بخدمة/منتج معيّن تم
اكتشافه أثناء فحص المنافذ، مع تخزين مؤقّت (cache) محلي لتقليل عدد الطلبات
وتسريع الفحوصات اللاحقة.

المستخدم يمكنه أيضًا إضافة حلول/ملاحظات بحث عنها بنفسه عبر
add_manual_finding()، وتُخزَّن بشكل دائم في قاعدة بيانات الخادم (ليست هنا).
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from shared.models import ThreatLevel, Vulnerability

logger = logging.getLogger("aladil.vuln_db.cve_client")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_cache: dict[str, tuple[float, list[Vulnerability]]] = {}
_CACHE_TTL_SECONDS = 6 * 3600


def _cvss_to_severity(score: float | None) -> ThreatLevel:
    if score is None:
        return ThreatLevel.INFO
    if score >= 9.0:
        return ThreatLevel.CRITICAL
    if score >= 7.0:
        return ThreatLevel.HIGH
    if score >= 4.0:
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


def _extract_cvss(metrics: dict[str, Any]) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0]["cvssData"]["baseScore"]
    return None


async def lookup_vulnerabilities(
    product: str,
    version: str | None = None,
    api_key: str | None = None,
    max_results: int = 10,
) -> list[Vulnerability]:
    """
    يبحث عن ثغرات معروفة لمنتج/إصدار معيّن. يُنصَح بشدة باستخدام مفتاح NVD
    API (مجاني) لرفع الحد الأقصى للطلبات (من 5 إلى 50 طلب كل 30 ثانية).
    """
    cache_key = f"{product}:{version or ''}"
    cached = _cache.get(cache_key)
    if cached and (time.time() - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    keyword = f"{product} {version or ''}".strip()
    params = {"keywordSearch": keyword, "resultsPerPage": str(max_results)}
    headers = {"apiKey": api_key} if api_key else {}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(NVD_API_URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("فشل الاستعلام من NVD لـ '%s': %s", keyword, exc)
        return []

    vulnerabilities: list[Vulnerability] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )
        score = _extract_cvss(cve.get("metrics", {}))
        vulnerabilities.append(
            Vulnerability(
                cve_id=cve_id,
                title=cve_id or "Unknown CVE",
                description=description,
                cvss_score=score,
                severity=_cvss_to_severity(score),
                affected_product=product,
                recommended_fix=(
                    "راجع صفحة NVD الرسمية لهذا الثغرة لمعرفة التصحيح "
                    "(patch) أو الإجراء المضاد الموصى به من المورّد."
                ),
                source="nvd",
            )
        )

    _cache[cache_key] = (time.time(), vulnerabilities)
    return vulnerabilities


async def lookup_many(
    products: list[tuple[str, str | None]], api_key: str | None = None
) -> dict[str, list[Vulnerability]]:
    """مطابقة متوازية لعدة منتجات/خدمات دفعة واحدة (معالجة متوازية)."""
    # NVD يحدّ من معدل الطلبات، لذا نحدّ من التزامن بدل تركه بلا سقف.
    semaphore = asyncio.Semaphore(4 if api_key else 1)

    async def _one(product: str, version: str | None):
        async with semaphore:
            return f"{product}:{version or ''}", await lookup_vulnerabilities(
                product, version, api_key
            )

    results = await asyncio.gather(*(_one(p, v) for p, v in products))
    return dict(results)


def build_manual_finding(
    title: str,
    description: str,
    recommended_fix: str,
    severity: ThreatLevel = ThreatLevel.MEDIUM,
    affected_port: int | None = None,
    affected_product: str | None = None,
) -> Vulnerability:
    """
    يبني سجل ثغرة أضافه المستخدم بعد بحثه الخاص عن حل أقوى/أحدث، لتخزينه
    في قاعدة بيانات النظام عبر server/app/api/vulnerabilities.py.
    """
    return Vulnerability(
        title=title,
        description=description,
        severity=severity,
        affected_port=affected_port,
        affected_product=affected_product,
        recommended_fix=recommended_fix,
        source="community",
        added_by_user=True,
    )
