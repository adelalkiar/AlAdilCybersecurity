"""
نماذج بيانات مشتركة بين الخادم المركزي (server) والعميل (agent).
تُستخدم Pydantic لضمان التحقق من صحة البيانات وتوحيد الشكل بين كل المكونات.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, IPvAnyAddress


class DeviceType(str, Enum):
    ROUTER = "router"
    COMPUTER = "computer"
    MOBILE = "mobile"
    IOT = "iot"
    PRINTER = "printer"
    CAMERA = "camera"
    BLUETOOTH_PERIPHERAL = "bluetooth_peripheral"
    UNKNOWN = "unknown"


class ConnectionMedium(str, Enum):
    ETHERNET = "ethernet"
    WIFI = "wifi"
    BLUETOOTH = "bluetooth"
    EXTERNAL = "external"  # نطاق/عنوان خارجي أدخله المستخدم يدويًا


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IntruderStatus(str, Enum):
    """تصنيف محاولات الوصول غير المصرح بها."""
    NONE = "none"
    ACTIVE_THREAT = "active_threat"          # اتصال ناجح + سلوك مشبوه مستمر
    DORMANT_INEFFECTIVE = "dormant_ineffective"  # محاولات فاشلة متكررة دون نجاح فعلي
    BLOCKED = "blocked"


class OpenPort(BaseModel):
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


class Vulnerability(BaseModel):
    cve_id: Optional[str] = None
    title: str
    description: str = ""
    cvss_score: Optional[float] = None
    severity: ThreatLevel = ThreatLevel.INFO
    affected_port: Optional[int] = None
    affected_product: Optional[str] = None
    recommended_fix: str = ""
    source: str = "nvd"          # nvd | manual | community
    added_by_user: bool = False  # حل أضافه المستخدم يدويًا بعد بحثه الخاص
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class DeviceFingerprint(BaseModel):
    mac_address: Optional[str] = None
    vendor: Optional[str] = None       # من OUI الخاص بعنوان MAC
    os_guess: Optional[str] = None
    hostname: Optional[str] = None
    ttl_observed: Optional[int] = None


class ScannedDevice(BaseModel):
    ip_address: Optional[str] = None
    fingerprint: DeviceFingerprint = Field(default_factory=DeviceFingerprint)
    device_type: DeviceType = DeviceType.UNKNOWN
    connection_medium: ConnectionMedium = ConnectionMedium.ETHERNET
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    open_ports: list[OpenPort] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    signal_strength_dbm: Optional[int] = None  # لـ Wi-Fi / Bluetooth

    # نتائج تحليل المخاطر (تُحسب في server/app/services/risk_service.py)
    access_likelihood_score: float = 0.0   # 0-100: احتمالية الوصول/التأثير
    potential_damage_score: float = 0.0    # 0-100: حجم الضرر المحتمل
    overall_threat_level: ThreatLevel = ThreatLevel.INFO
    intruder_status: IntruderStatus = IntruderStatus.NONE
    failed_connection_attempts: int = 0
    successful_connection_attempts: int = 0

    # هل هذا جهاز "مجهول" (لا اسم مضيف، لا شركة مصنّعة معروفة، لا نوع
    # محدَّد) - يُحسب في shared/vuln_db/risk_scoring.py لتسهيل التصفية
    # في الواجهة على "الأجهزة غير المعرَّفة" تحديدًا.
    is_unidentified: bool = False
    # ملاحظات وصفية عن قابلية استغلال الجهاز بناءً على المنافذ/الثغرات
    # المكتشفة فعليًا (تقييم مخاطر، وليست أداة استغلال فعلية)
    exploitability_notes: list[str] = Field(default_factory=list)

    # تحقّق هوية الجهاز: هل اسم المضيف المُعلَن يتطابق مع ما سبق رصده
    # لنفس عنوان MAC، أم أن جهازًا جديدًا بدأ فجأة يستخدم اسمًا كان
    # يستخدمه جهاز آخر موثوق سابقًا؟ (كشف انتحال هوية/اسم)
    identity_spoof_suspected: bool = False
    identity_spoof_note: Optional[str] = None

    # سلوك هذا الجهاز تجاه جهاز النظام نفسه (الجهاز الذي يعمل عليه
    # العميل) - يُحسب في agent/app/discovery/host_activity.py
    accessed_host_system: bool = False
    unusual_data_transfer_detected: bool = False
    host_activity_notes: list[str] = Field(default_factory=list)

    # مرحلة الهجوم التي يوافقها سلوك الجهاز (الفصل 2) + خط زمني للمهاجم
    attack_phase: str = "target_selection"  # target_selection|reconnaissance|attack
    attacker_timeline: list[dict] = Field(default_factory=list)


class UnsignedProgramFinding(BaseModel):
    """
    نتيجة فحص "البرامج غير الموقَّعة والمتخفّية" على جهاز النظام نفسه
    (وليس على جهاز بعيد على الشبكة) - قراءة واكتشاف فقط، بلا أي احتواء
    أو تعديل تلقائي. انظر .claude/skills/unsigned-program-detection/
    SKILL.md للمنهجية الكاملة التي يستند إليها هذا النموذج.
    """
    path: str
    display_name: str
    score: int = 0
    level: str = "review"  # danger | suspect | review
    reasons: list[str] = Field(default_factory=list)
    signature_status: Optional[str] = None
    signer: Optional[str] = None
    company: Optional[str] = None
    product: Optional[str] = None
    description: Optional[str] = None
    owner: Optional[str] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    sha256: Optional[str] = None
    zone_name: Optional[str] = None
    zone_host_url: Optional[str] = None
    indicators: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    has_encrypted_sibling: bool = False
    launchers: list[dict] = Field(default_factory=list)
    processes: list[dict] = Field(default_factory=list)


class SecurityAuditFinding(BaseModel):
    """
    نتيجة "تدقيق أمني للقراءة فقط" على جهاز النظام نفسه - تكشف نقاط ضعف
    في إعدادات الحماية (Defender، جدار الحماية، UAC، LSA، SmartScreen...)
    دون تنفيذ أي تعديل. أمر الإصلاح (fix_command) وأمر التراجع
    (undo_command) يُعرضان كنصّ فقط ليُنفّذهما المستخدم بنفسه في
    PowerShell كمسؤول إن أراد - النظام **لا يُعدّل أي إعداد نظام تلقائيًا**.

    مبنية على منهجية القسم الثاني من
    .claude/skills/unsigned-program-detection/SKILL.md (الكشف فقط - دون
    دالة apply التي تُطبّق الإصلاحات في المرجع الأصلي).
    """
    id: str
    title: str
    severity: str = "medium"  # critical | high | medium | low
    status: str = "vulnerable"  # vulnerable | ok | info
    evidence: str = ""
    impact: str = ""
    fix_command: Optional[str] = None
    undo_command: Optional[str] = None
    needs_reboot: bool = False
    fix_risk: str = "منخفض"
    # هل الإصلاح آمن وقابل للتراجع (يمكن للمستخدم تنفيذ fix_command بثقة)،
    # أم أنه يتطلب قرارًا يدويًا (BIOS، تعريفات...) فلا يوجد له أمر جاهز
    is_auto_safe: bool = True
    manual_steps: list[str] = Field(default_factory=list)


class FirewallProfileInfo(BaseModel):
    """حالة ملف تعريف واحد لجدار حماية ويندوز (Domain/Private/Public)."""
    name: str
    enabled: bool = False
    default_inbound: str = "NotConfigured"
    default_outbound: str = "NotConfigured"


class FirewallRuleClass(BaseModel):
    """
    قاعدة جدار ناري واحدة مُصنَّفة حسب أنواع الجدران النارية في المنهج
    (الفصل 3): تصفية الحزم / مستوى التطبيق / فحص الحالة.
    """
    display_name: str
    direction: str  # Inbound | Outbound
    profile: str = ""
    local_port: Optional[str] = None
    remote_address: Optional[str] = None
    protocol: Optional[str] = None
    program: Optional[str] = None
    classes: list[str] = Field(default_factory=list)  # أنواع الجدار التي تنطبق


class FirewallBoundary(BaseModel):
    """حدّ من حدود الجدار الناري (ما لا يستطيع الجدار وحده حمايته) والوحدة
    التي تغطّيه في النظام."""
    boundary: str
    covered_by: str
    note: str = ""


class FirewallAuditReport(BaseModel):
    """نتيجة تدقيق الجدار الناري للقراءة فقط (الفصل 3) على جهاز النظام."""
    profiles: list[FirewallProfileInfo] = Field(default_factory=list)
    classified_rules: list[FirewallRuleClass] = Field(default_factory=list)
    alerts: list["SecurityAuditFinding"] = Field(default_factory=list)
    boundaries: list[FirewallBoundary] = Field(default_factory=list)
    general_notes: list[str] = Field(default_factory=list)


class ScanTarget(BaseModel):
    """نطاق فحص يدخله المستخدم يدويًا (شبكة محلية أو خارجية)."""
    cidr_or_host: str
    medium: ConnectionMedium = ConnectionMedium.EXTERNAL
    authorized_by_user: bool = False
    authorization_note: Optional[str] = None


class ScanReport(BaseModel):
    agent_id: str
    started_at: datetime
    finished_at: datetime
    target: ScanTarget
    devices: list[ScannedDevice] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    # فحص الجهاز المحلي نفسه (وليس الأجهزة الأخرى على الشبكة) بحثًا عن
    # برامج غير موقَّعة أو متخفّية - قراءة فقط، بلا احتواء تلقائي
    unsigned_program_findings: list[UnsignedProgramFinding] = Field(default_factory=list)
    # تدقيق أمني للقراءة فقط على إعدادات حماية جهاز النظام - بلا تعديل تلقائي
    security_audit_findings: list[SecurityAuditFinding] = Field(default_factory=list)
    # تدقيق الجدار الناري (الفصل 3): حالة الملفات، تصنيف القواعد، التنبيهات
    firewall_audit: Optional[FirewallAuditReport] = None


class AgentInfo(BaseModel):
    agent_id: str
    hostname: str
    platform: str
    version: str
    license_key: str
