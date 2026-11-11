# حزم التثبيت متعددة الأنظمة

الأساس: `python scripts/build_agent.py` يبني ملفًا تنفيذيًا واحدًا (PyInstaller)
للعميل على نظام التشغيل الذي يُنفَّذ عليه. يجب تكراره على كل نظام مستهدف
على جهاز يحمل ذلك النظام فعليًا (أو عبر CI بثلاث منصات: windows-latest،
macos-latest، ubuntu-latest على GitHub Actions مثلًا) لأن PyInstaller لا
يدعم التجميع المتقاطع (cross-compilation).

## Windows — مثبّت .exe عبر Inno Setup

### الواجهة التي يراها المستخدم: أيقونة نظام رسومية، بلا نافذة طرفية
`aladil-tray.exe` ([agent/app/tray_app.py](../agent/app/tray_app.py), يُبنى عبر
`scripts/build_tray.py --windowed`) هو **الملف الوحيد الذي يجب أن يراه
العميل فعليًا** — أيقونة في شريط النظام (tray) بشعار ADIL، بلا أي نافذة
سوداء، تعرض حالة مبسّطة ("✅ الحماية نشطة — 7 أجهزة تحت المراقبة") وقائمة
بزر يمين: فتح لوحة التحكم / تحديث الحالة / خروج. الفحص الفعلي يعمل بشكل
منفصل تمامًا كخدمة Windows خلفية (`aladil-agent.exe` عبر NSSM، بلا أي
واجهة إطلاقًا) — الأيقونة فقط تقرأ ملف حالة محلي خفيف (`status.json`،
لا بيانات حسّاسة فيه) تكتبه الخدمة بعد كل دورة فحص.

المثبّت يضيف: اختصارًا على سطح المكتب + قائمة ابدأ + **بدء تلقائي عند كل
تسجيل دخول** (مجلد Startup الخاص بالمستخدم)، ويشغّل الأيقونة فورًا بعد
انتهاء التثبيت دون الحاجة لتسجيل خروج/دخول.

**⚠ قيد معروف غير محسوم بالكامل**: المثبّت يعمل بصلاحيات Administrator
كاملة (`PrivilegesRequired=admin`)، ولذلك يُحذّر Inno Setup أن اختصار
"البدء التلقائي" (مجلد Startup الخاص بمستخدم) قد لا يُكتب دائمًا لحساب
المستخدم التفاعلي الصحيح في كل سيناريوهات التثبيت (يعمل بشكل صحيح في
الحالة الشائعة: مستخدم عادي ينقر "Run as Administrator" بنفس حسابه —
لكن قد يختلف في تثبيت عبر حساب مختلف/Group Policy). إن لم يظهر الاختصار
تلقائيًا بعد إعادة تسجيل الدخول، أضفه يدويًا من قائمة ابدأ إلى مجلد
`shell:startup`.

**لا نُضمّن ملف Npcap
داخل حزمتنا إطلاقًا** — بدلًا من ذلك، يتحقق السكربت أثناء التثبيت إن كان
Npcap مثبَّتًا مسبقًا (عبر سجل النظام)، وإن لم يكن، **ينزّله تلقائيًا من
الموقع الرسمي `npcap.com`** على جهاز المستخدم نفسه ثم يشغّل مثبّته
الرسمي كما هو (بترخيصه المجاني الأصلي دون تعديل)، تمامًا كأن المستخدم
فتح المتصفح وحمّله بنفسه — فقط بخطوة آلية ضمن معالج التثبيت بدل تنزيل
يدوي منفصل. هذا يتجنّب تمامًا إشكال ترخيص "إعادة التوزيع" لأننا لسنا من
يوزّع الملف، المستخدم يحمّله من مصدره الرسمي مباشرة.

**ملاحظة:** مثبّت Npcap يظهر بواجهته الأصلية (ترخيصه الخاص يتطلب موافقة
المستخدم) — هذا مقصود ومتوافق مع الاستخدام الشخصي المجاني؛ لا نشغّله
بصمت قسري بأعلام غير موثّقة للنسخة المجانية. إن تعذّر التنزيل (لا اتصال
إنترنت مثلًا) يظهر تنبيه للمستخدم برابط التثبيت اليدوي، ويستمر تثبيت
بقية النظام بشكل طبيعي (العميل يعمل بلا ARP scan عندها فقط).

### إدارة الخدمة عبر NSSM (بدل sc.exe المباشر)
`aladil-agent.exe` برنامج عادي (حلقة asyncio) لا يتحدّث بروتوكول Service
Control Manager الخاص بويندوز، فتسجيله مباشرة عبر `sc.exe create` غير
موثوق (قد يبلّغ SCM فشلًا رغم عمل العملية فعليًا، أو لا يعيد تشغيله
تلقائيًا عند الانهيار). **NSSM** (Non-Sucking Service Manager) يُغلّفه
بغلاف صحيح البروتوكول، يعيد التشغيل تلقائيًا، ويحوّل stdout/stderr إلى
`{app}\logs\service.log` (بتدوير تلقائي عند 5 م.ب). رخصة NSSM: **public
domain** (nssm.cc) — يجوز تضمينه وتوزيعه بلا أي قيد، بخلاف Npcap.

### خطوات البناء (الطريقة الموصى بها: سكربت واحد يقوم بكل شيء)
```bash
python scripts/build_installer.py            # يستخدم رقم VERSION الحالي
python scripts/build_installer.py --bump patch   # يرفع 0.2.1 -> 0.2.2 تلقائيًا
```
هذا السكربت: (1) يبني `aladil-agent.exe` بأحدث كود، (2) ينزّل
`nssm.exe` تلقائيًا عند أول تشغيل فقط (يُخزَّن في
`installers/windows/redist/nssm.exe` لإعادة استخدامه لاحقًا دون إنترنت)،
(3) يُمرّر رقم الإصدار لـ Inno Setup، وينتج
`dist/AlAdilCybersecurity-Agent-Setup-<version>.exe`.

### خطوات يدوية (إن لم تُرد استخدام السكربت الموحّد)
1. `python scripts/build_agent.py` على ويندوز → ينتج `dist/aladil-agent.exe`.
2. حوّل `logo/AdilCompanyWithFill..png` إلى `installers/windows/aladil.ico`
   (مثال عبر Pillow: `python -c "from PIL import Image; Image.open('logo/AdilCompanyWithFill..png').convert('RGBA').save('installers/windows/aladil.ico', sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])"`).
3. تحقّق من رقم إصدار Npcap الحالي في `https://npcap.com/#download` وحدّث
   ثابت `NpcapVersion` أعلى `installers/windows/aladil.iss` إن تغيّر.
4. ضع `nssm.exe` (64-bit) في `installers/windows/redist/nssm.exe` —
   نزّله من `https://nssm.cc/download` (أو استخدم رابط البناء الثابت في
   `scripts/build_installer.py`).
5. ثبّت [Inno Setup](https://jrsoftware.org/isinfo.php) وشغّل:
   `ISCC.exe /DMyAppVersion=0.2.2 installers\windows\aladil.iss`

### ⚠️ لم يُختبر فعليًا بعد على جهاز حقيقي
بُني المثبّت ونجح تجميعه (ISCC compile) بلا أخطاء، لكن لم يُشغَّل فعليًا
لتثبيت خدمة حقيقية على أي جهاز في هذا الجلسة — ذلك يتطلب صلاحيات مدير
ويُعدّل إعدادات النظام (تسجيل خدمة Windows)، وهو إجراء لا يُنفَّذ إلا
بتأكيد صريح منك على كل جهاز تختبره عليه.

## macOS — حزمة .pkg
1. `python scripts/build_agent.py` على macOS → ينتج `dist/aladil-agent`.
2. استخدم `pkgbuild`/`productbuild` لبناء `.pkg`، مع `LaunchDaemon` plist لتشغيل
   العميل تلقائيًا في الخلفية.
3. للتوزيع خارج الـ App Store: التوقيع (`codesign`) والتدقيق (`notarytool`) مطلوبان
   حتى لا يحجبه Gatekeeper.

## Linux — AppImage / .deb
1. `python scripts/build_agent.py` على لينكس → ينتج `dist/aladil-agent`.
2. **AppImage**: استخدم `appimagetool` لتغليف الملف التنفيذي + أيقونة + `.desktop`.
3. **.deb**: استخدم `dpkg-deb` أو `fpm` (`fpm -s dir -t deb ...`) مع ملف
   `systemd` unit لتشغيل العميل كخدمة (`systemctl enable aladil-agent`).

## ملاحظات مهمة
- فحص ARP/الحزم الخام يتطلب صلاحيات مرتفعة (Administrator/root) على كل الأنظمة.
  وثّق هذا بوضوح في شاشة التثبيت واطلب الموافقة.
- مفتاح الترخيص يُدخَل أثناء التثبيت (حقل نصي) ويُخزَّن في
  `~/.aladil/agent_config.json` (أو المسار المكافئ على ويندوز).
- أيقونة كل حزمة تثبيت يجب أن تُشتق من `logo/AdilCompanyWithFill..png`
  (راجع `docs/brand_identity.md`).
