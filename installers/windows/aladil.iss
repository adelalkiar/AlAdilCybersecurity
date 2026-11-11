; مثبّت AlAdil Cybersecurity Agent لويندوز (Inno Setup)
;
; سلوك التحديث التلقائي: نفس ملف التثبيت هذا يتصرّف تلقائيًا كـ"تحديث"
; إن وجد تثبيتًا سابقًا لنفس AppId على الجهاز (Inno Setup يكتشف هذا عبر
; سجل النظام تلقائيًا، ونتحقق منه أيضًا صراحةً في [Code] عبر IsUpgrade):
;   - تثبيت أول مرة  -> يعرض صفحة إدخال عنوان الخادم ورمز التفعيل.
;   - تحديث على تثبيت سابق -> يتخطّى صفحة التفعيل تمامًا (الإعدادات
;     المحفوظة مسبقًا تبقى كما هي)، فقط يستبدل الملف التنفيذي ويعيد
;     تشغيل الخدمة.
;
; إدارة الخدمة عبر NSSM (Non-Sucking Service Manager) بدل sc.exe
; مباشرة: aladil-agent.exe برنامج عادي (asyncio) لا يتحدّث بروتوكول
; Service Control Manager الخاص بويندوز، فتسجيله مباشرة عبر "sc create"
; غير موثوق (قد تفشل SCM في اعتباره "بدأ بنجاح" خلال المهلة المتوقعة).
; NSSM يُغلّفه بغلاف يتحدّث مع SCM بشكل صحيح، ويعيد تشغيله تلقائيًا عند
; الانهيار، ويحوّل stdout/stderr إلى ملفات سجل قابلة للتدوير. رخصة NSSM:
; "public domain" (nssm.cc) - يجوز تضمينه وتوزيعه بلا أي قيد.
;
; سياسة Npcap: لا نُضمّن ملفه في الحزمة - يُنزَّل من npcap.com مباشرة على
; جهاز المستخدم إن لم يكن مثبَّتًا (راجع installers/README.md).
;
; المتطلبات قبل البناء: استخدم scripts/build_installer.py بدل تشغيل
; ISCC مباشرة؛ هو يُزامن رقم الإصدار من ملف VERSION في جذر المشروع
; ويبني العميل تلقائيًا قبل التغليف. يتطلب أيضًا وجود
; installers/windows/redist/nssm.exe (نزّله build_installer.py تلقائيًا
; إن كان غائبًا).

#define AppGUID "B6A6B6E1-6A9D-4C6E-9B1A-ALADILCYBER01"
#define MyAppName "AlAdil Cybersecurity Agent"
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif
#define MyAppPublisher "Al-Adil Systems"
#define NpcapVersion "1.90"
#define NpcapDownloadUrl "https://npcap.com/dist/npcap-" + NpcapVersion + ".exe"

[Setup]
AppId={{B6A6B6E1-6A9D-4C6E-9B1A-ALADILCYBER01}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\AlAdilCybersecurity\Agent
DefaultGroupName={#MyAppName}
OutputBaseFilename=AlAdilCybersecurity-Agent-Setup-{#MyAppVersion}
OutputDir=..\..\dist
SetupIconFile=aladil.ico
WizardImageFile=wizard_banner.bmp
WizardSmallImageFile=wizard_small.bmp
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern

[Languages]
Name: "arabic"; MessagesFile: "compiler:Languages\Arabic.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Dirs]
Name: "{app}\logs"

[Files]
Source: "..\..\dist\aladil-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\aladil-tray.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "redist\nssm.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; أيقونة صريحة على سطح المكتب وقائمة ابدأ - الواجهة الوحيدة التي يراها
; المستخدم النهائي فعليًا (أيقونة نظام رسومية، بلا نافذة طرفية إطلاقًا)
Name: "{autodesktop}\AlAdil Cybersecurity"; Filename: "{app}\aladil-tray.exe"; \
    IconFilename: "{app}\aladil-tray.exe"
Name: "{group}\AlAdil Cybersecurity"; Filename: "{app}\aladil-tray.exe"; \
    IconFilename: "{app}\aladil-tray.exe"
; تبدأ تلقائيًا عند كل تسجيل دخول لهذا المستخدم (أيقونة النظام فقط - لا
; علاقة لها بالفحص نفسه الذي يعمل بالخلفية كخدمة Windows دائمًا)
Name: "{userstartup}\AlAdil Cybersecurity"; Filename: "{app}\aladil-tray.exe"; \
    IconFilename: "{app}\aladil-tray.exe"

[Run]
; يوقف الخدمة قبل استبدال الملف (فقط إن كانت موجودة أصلًا، أي تحديث)
Filename: "{app}\nssm.exe"; Parameters: "stop AlAdilAgent"; Flags: runhidden; \
    StatusMsg: "إيقاف الخدمة الحالية قبل التحديث..."; Check: ServiceExists

; يسجّل الخدمة عبر NSSM فقط إن لم تكن مُسجَّلة مسبقًا (تثبيت أول مرة)
Filename: "{app}\nssm.exe"; Parameters: "install AlAdilAgent ""{app}\aladil-agent.exe"""; \
    StatusMsg: "تسجيل خدمة AlAdil Agent..."; Flags: runhidden; Check: not ServiceExists

; إعداد تفاصيل الخدمة - يُعاد تطبيقها في كل تثبيت/تحديث لضمان بقاء
; الإعدادات صحيحة حتى لو عُدِّلت يدويًا بالخطأ سابقًا
Filename: "{app}\nssm.exe"; Parameters: "set AlAdilAgent DisplayName ""AlAdil Cybersecurity Agent"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set AlAdilAgent Description ""يراقب الأجهزة المتصلة بالشبكة ويكشف التهديدات - AlAdil Cybersecurity"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set AlAdilAgent AppDirectory ""{app}"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set AlAdilAgent Start SERVICE_AUTO_START"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set AlAdilAgent AppStdout ""{app}\logs\service.log"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set AlAdilAgent AppStderr ""{app}\logs\service.log"""; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set AlAdilAgent AppRotateFiles 1"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set AlAdilAgent AppRotateBytes 5242880"; Flags: runhidden
; يعيد تشغيل العميل تلقائيًا إن انهار (AppExit Default = أي كود خروج)
Filename: "{app}\nssm.exe"; Parameters: "set AlAdilAgent AppExit Default Restart"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "set AlAdilAgent AppRestartDelay 15000"; Flags: runhidden

; يحفظ عنوان الخادم ورمز التفعيل فقط عند التثبيت الأول (الحقول تُقرأ من
; الصفحة المخصَّصة أدناه)، ثم يخرج فورًا دون فحص (--configure-only)
Filename: "{app}\aladil-agent.exe"; \
    Parameters: "--server ""{code:GetServerURL}"" --license-key ""{code:GetLicenseKey}"" --configure-only"; \
    StatusMsg: "حفظ إعدادات التفعيل..."; Flags: runhidden; Check: not IsUpgrade

; يشغّل/يعيد تشغيل الخدمة بعد التثبيت أو التحديث
Filename: "{app}\nssm.exe"; Parameters: "start AlAdilAgent"; Flags: runhidden; \
    StatusMsg: "تشغيل الخدمة..."

; يشغّل أيقونة النظام الرسومية فورًا دون انتظار تسجيل خروج/دخول - هذه
; هي الواجهة الوحيدة التي يراها المستخدم، بدون أي نافذة طرفية
Filename: "{app}\aladil-tray.exe"; Description: "تشغيل AlAdil Cybersecurity الآن"; \
    Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\nssm.exe"; Parameters: "stop AlAdilAgent"; Flags: runhidden; RunOnceId: "StopAlAdilAgentService"
Filename: "{app}\nssm.exe"; Parameters: "remove AlAdilAgent confirm"; Flags: runhidden; RunOnceId: "RemoveAlAdilAgentService"

[Code]
var
  ActivationPage: TInputQueryWizardPage;

function ServiceExists: Boolean;
var
  ResultCode: Integer;
begin
  { استخدام sc.exe هنا فقط للاستعلام عن وجود الخدمة (يعمل بغضّ النظر
    عن الأداة التي أنشأتها) - التثبيت/الإزالة الفعليان عبر NSSM أعلاه }
  Result := Exec('sc.exe', 'query AlAdilAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0);
end;

function IsUpgrade: Boolean;
begin
  { إن وُجد مفتاح إلغاء التثبيت لنفس AppId، فهذا تحديث على تثبيت سابق،
    وكذلك إن كانت الخدمة مُسجَّلة أصلًا (حتى إن أزيلت بيانات AppId يدويًا) }
  { ملاحظة: الأقواس المعقوفة هنا نص Pascal عادي، لا تحتاج أي هروب خاص
    بـ Inno (ذلك مطلوب فقط داخل قيم توجيهات [Setup]/[Files]/[Run]) }
  Result := RegKeyExists(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{{#AppGUID}}_is1')
    or ServiceExists;
end;

function GetInstalledVersion: String;
begin
  if not RegQueryStringValue(HKLM,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{{#AppGUID}}_is1',
    'DisplayVersion', Result) then
    Result := '';
end;

function InitializeSetup: Boolean;
var
  installedVersion: String;
begin
  Result := True;
  installedVersion := GetInstalledVersion;
  if (installedVersion <> '') and (installedVersion = '{#MyAppVersion}') then
  begin
    MsgBox('الإصدار {#MyAppVersion} من AlAdil Cybersecurity مثبَّت بالفعل ' +
           'على هذا الجهاز وهو محدَّث. لا حاجة لإعادة التثبيت.',
           mbInformation, MB_OK);
    Result := False;  { يُلغي التثبيت بالكامل دون أي تغيير على الجهاز }
  end;
end;

function GetServerURL(Param: String): String;
begin
  if Assigned(ActivationPage) then
    Result := ActivationPage.Values[0]
  else
    Result := '';
end;

function GetLicenseKey(Param: String): String;
begin
  if Assigned(ActivationPage) then
    Result := ActivationPage.Values[1]
  else
    Result := '';
end;

procedure InitializeWizard;
begin
  ActivationPage := CreateInputQueryPage(wpSelectDir,
    'تفعيل AlAdil Cybersecurity', 'أدخل بيانات التفعيل المرسلة إليك',
    'يُستخدم رمز التفعيل مرة واحدة فقط عند أول تثبيت لهذا الجهاز. ' +
    'التحديثات اللاحقة لن تطلبه مجددًا.');
  ActivationPage.Add('عنوان الخادم المركزي (مثال: https://server.example.com):', False);
  ActivationPage.Add('رمز التفعيل (License Key):', False);
  ActivationPage.Values[0] := 'http://localhost:8000';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  { نتخطّى صفحة التفعيل بالكامل عند التحديث - الإعدادات المحفوظة سابقًا
    (المشفَّرة في ProgramData) تبقى كما هي ولا حاجة لإعادة إدخالها }
  Result := (ActivationPage <> nil) and (PageID = ActivationPage.ID) and IsUpgrade;
end;

function NpcapInstalled: Boolean;
begin
  Result := RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Npcap');
end;

function DownloadNpcap(const DestFile: String): Boolean;
var
  ResultCode: Integer;
  Command: String;
begin
  Command := '-NoProfile -ExecutionPolicy Bypass -Command "' +
    '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; ' +
    'Invoke-WebRequest -Uri ''' + '{#NpcapDownloadUrl}' + ''' -OutFile ''' + DestFile + ''' -UseBasicParsing"';
  Result := Exec('powershell.exe', Command, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0) and FileExists(DestFile);
end;

procedure InstallNpcapIfMissing;
var
  TempFile: String;
  ResultCode: Integer;
begin
  if NpcapInstalled then
    Exit;

  WizardForm.StatusLabel.Caption := 'جارٍ تنزيل مكوّن فحص الشبكة (Npcap) من npcap.com...';
  TempFile := ExpandConstant('{tmp}\npcap-setup.exe');

  if DownloadNpcap(TempFile) then
  begin
    if not Exec(TempFile, '/winpcap_mode=1', '', SW_SHOWNORMAL, ewWaitUntilTerminated, ResultCode) then
      MsgBox('تعذّر تشغيل مثبّت Npcap. يمكنك تثبيته لاحقًا يدويًا من ' +
             'https://npcap.com/#download لتفعيل فحص الشبكة المحلية (ARP).',
             mbInformation, MB_OK);
  end
  else
  begin
    MsgBox('تعذّر تنزيل Npcap تلقائيًا (تحقّق من اتصال الإنترنت). يمكنك ' +
           'تثبيته لاحقًا يدويًا من https://npcap.com/#download لتفعيل ' +
           'فحص الشبكة المحلية (ARP) — بقية ميزات النظام تعمل بدونه.',
           mbInformation, MB_OK);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    { يُنهي أي نسخة سابقة من أيقونة النظام قبل نسخ الملفات مباشرة - وإلا
      يفشل نسخ aladil-tray.exe أثناء التحديث لأن الملف "قيد الاستخدام"
      من قبل النسخة القديمة العاملة. يتجاهل بأمان إن لم تكن تعمل أصلًا. }
    Exec('taskkill.exe', '/F /IM aladil-tray.exe', '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode);
  end;
  if CurStep = ssPostInstall then
    InstallNpcapIfMissing;
end;
