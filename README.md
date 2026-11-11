# AlAdil Cybersecurity

نظام مراقبة الأجهزة المتصلة بالشبكة (محلية وخارجية مُفوَّضة) عبر
Ethernet/Wi-Fi/Bluetooth، فحص ثغرات تلقائي، تقييم مخاطر، وكشف محاولات
التسلل غير الفعّالة — بمعمارية **خادم مركزي + عملاء (Agents)** وفحص
متوازٍ بالكامل عبر `asyncio`.

الهوية البصرية مأخوذة من شعار الشركة الأم (`logo/AdilCompanyWithFill..png`)
— التفاصيل في [docs/brand_identity.md](docs/brand_identity.md).

## البنية

```
shared/               نماذج بيانات مشتركة + بوابة التفويض + مطابقة الثغرات/تقييم المخاطر
agent/app/discovery/   وحدات الاكتشاف: ARP، mDNS، Wi-Fi، Bluetooth، فحص منافذ
agent/app/services/    منسّق الفحص المتوازي (scan_orchestrator)
server/app/            خادم FastAPI: API، قاعدة بيانات، تراخيص، لوحة تحكم ويب
installers/            أدلة تغليف المثبتات لكل نظام تشغيل
scripts/               سكربتات بناء (PyInstaller)
```

## التشغيل السريع (تطوير محلي)

### 1) الخادم المركزي
```bash
cd server
python -m venv .venv && source .venv/bin/activate   # أو .venv\Scripts\activate على ويندوز
pip install -r requirements.txt
cp ../.env.example ../.env   # عدّل القيم
uvicorn server.app.main:app --reload --app-dir ..
```
افتح `http://localhost:8000` — ستظهر لوحة التحكم. عند أول تشغيل يُطبع في
الطرفية اسم المستخدم/كلمة المرور لحساب المشرف الأول (`admin`).

### 2) إصدار ترخيص لعميل جديد
```bash
curl -X POST "http://localhost:8000/api/licenses?customer_name=Test&customer_email=test@example.com&max_agents=1" \
  -H "Authorization: Bearer <JWT من تسجيل الدخول>"
```

**متطلب على ويندوز:** فحص ARP (scapy) يحتاج [Npcap](https://npcap.com/#download) مثبّتًا
(فعّل خيار "WinPcap API-compatible mode" أثناء التثبيت)، وإلا سيفشل فحص الشبكة
المحلية بصمت ويكتفي النظام بنتائج mDNS/Wi-Fi/Bluetooth فقط.

### 3) تشغيل العميل (Agent) — يتطلب صلاحيات مرتفعة لفحص ARP
```bash
cd agent
pip install -r requirements.txt
sudo python app/main.py --server http://localhost:8000 --license-key "ALADIL-..." --once
```
بدون `--once` يعمل العميل بشكل دوري (كل 15 دقيقة افتراضيًا).

### فحص نطاق خارجي (يتطلب تفويضًا صريحًا)
```bash
python app/main.py --target 203.0.113.0/24 --authorize \
  --authorize-note "اتفاقية pentest رقم 2024-017 موقّعة مع العميل"
```
أي نطاق خارج الشبكة المحلية المباشرة للجهاز **يُرفض فحصه** ما لم يُمرَّر
`--authorize`، ويُسجَّل كل تفويض في `data/authorization_audit.log`.

## المميزات المطبَّقة في هذا الإصدار
- اكتشاف متوازٍ متعدد المسارات (ARP + mDNS + Wi-Fi + Bluetooth) عبر `asyncio.gather`.
- فحص منافذ متوازٍ على عدة أجهزة في آن واحد (`Semaphore` مزدوج: أجهزة × منافذ).
- مطابقة ثغرات تلقائية عبر NVD API مع تخزين مؤقت، وإمكانية إضافة حلول يدوية.
- تقييم مخاطر مزدوج (احتمالية وصول / ضرر محتمل) وتصنيف مخترقين "غير فعّالين".
- تراخيص موقَّعة رقميًا (Ed25519) يمكن التحقق منها محليًا بدون اتصال دائم بالخادم.
- لوحة تحكم ويب بالهوية البصرية لـ AlAdil، مرتّبة حسب الخطورة تلقائيًا.
- بوابة تفويض إلزامية + سجل تدقيق لكل فحص خارجي.

## لم يُنجز بعد (خطوات تالية مقترحة)
- مثبتات native فعلية لكل نظام (Inno Setup / pkgbuild / AppImage) — الأدلة جاهزة في `installers/README.md`، التنفيذ يحتاج تشغيلًا على كل نظام مستهدف.
- OS fingerprinting أدق (TTL + توقيع TCP/IP) بدل الاعتماد على MAC vendor فقط.
- دعم Bluetooth الكلاسيكي (BR/EDR) بجانب BLE.
- واجهة لإدارة التراخيص والمستخدمين من لوحة التحكم نفسها (حاليًا عبر API فقط).
- اختبارات آلية (pytest) للخادم ومنسّق الفحص.
