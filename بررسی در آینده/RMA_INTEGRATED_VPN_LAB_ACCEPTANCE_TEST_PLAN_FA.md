# R&MA Integrated VPN — Lab Acceptance & Test Plan

- وضعیت: طرح پذیرش آزمایشگاه؛ هنوز هیچ آزمون میزبانی یا اندرویدی اجرا نشده است.
- دامنه: سهمیه مشترک، مرز packet، offload، DNS/IPv6، Telegram-only و اعلان‌ها.
- محیط: ابتدا VMهای محلی disposable؛ سپس فقط میزبان آزمایشی مجاز.
- ممنوع: production، داده کاربر، firewall شبکه واقعی، gateway زنده، peer مشتری یا پرداخت واقعی.

## 1. هدف و قواعد ایمنی

باید ثابت شود چند peer متعلق به یک entitlement یک سقف بایت مشترک دارند و پس از exhaustion، هیچ بسته جدیدی از هیچ peer آن entitlement عبور نمی‌کند. اختلاف شمارنده‌ها، overshoot، توقف agent، reboot و مسیرهای bypass نیز باید قابل مشاهده و اندازه‌گیری باشند.

1. فاز اول فقط در VM یا network namespace محلی با رابط‌های مجازی و آدرس‌های آزمایشی اجرا شود.
2. پیش از هر آزمون snapshot قابل بازگشت تهیه شود؛ ruleset میزبان اصلی تغییر نکند.
3. fault injection، حذف peer و reboot فقط در محیط disposable انجام شود.
4. دسترسی اینترنت عمومی آزمایشگاه در صورت عدم نیاز بسته باشد.
5. هر run شامل شناسه، commit، نسخه kernel/nftables، تنظیمات، زمان UTC، artifact و نتیجه باشد.
6. تا پذیرش آزمایشگاه، هیچ تغییر در host agent، backend، schema، firewall تولید یا اپ Android محصول انجام نشود.

## 2. توپولوژی

### فاز A — شبیه‌سازی محلی
- یک Linux VM یا میزبان disposable با namespaceهای client، gateway و traffic sink.
- دو peer آزمایشی Device A و B متصل به یک entitlement مشترک.
- Device C به entitlement مستقل برای کنترل منفی.
- WireGuard فقط در شبکه مجازی آزمایشگاه؛ کلیدها و آدرس‌ها آزمایشی و غیرقابل استفاده در محیط واقعی.
- nftables table/chain مختص lab؛ بدون تغییر سرویس firewall یا interface عمومی میزبان.
- مولد ترافیک TCP/UDP دوطرفه و ثبت packet/byte در هر لایه.

### فاز B — میزبان آزمایشی مجاز
فقط پس از پاسخ کتبی ارائه‌دهنده و تأیید مجوز استفاده، VM مستقل با kernel و nftables مشخص انتخاب شود. این VM نباید production، میزبان اشتراکی کاربران یا دارای route متصل به شبکه سرویس باشد. ابتدا قابلیت‌ها فقط خوانده و ثبت شوند؛ نصب agent یا اعمال rule نیازمند برنامه تغییر و rollback جداگانه است.

## 3. معیارهای پذیرش سهمیه مشترک

فرض: A و B یک entitlement و quota object مشترک دارند؛ C سهمیه مستقل دارد.

| شناسه | آزمون | انتظار |
|---|---|---|
| Q-01 | فقط A ترافیک می‌فرستد | مصرف aggregate افزایش یابد |
| Q-02 | A و B هم‌زمان ترافیک می‌فرستند | هر دو در یک quota مشترک شمرده شوند |
| Q-03 | C هم‌زمان ترافیک می‌فرستد | فقط quota مستقل C تغییر کند |
| Q-04 | هر دو جهت RX/TX | تعریف واحد و مستند محصولی رعایت شود |
| Q-05 | چند جریان TCP/UDP و CPU | رقابت باعث lost update یا عبور نامحدود نشود |
| Q-06 | peer جدید حین مصرف اضافه می‌شود | فقط پس از اتصال معتبر به entitlement از quota مشترک استفاده کند |
| Q-07 | یک peer revoke می‌شود | peer لغوشده متوقف و peer مجاز دیگر فعال بماند |
| Q-08 | quota تمام می‌شود | تمام peerهای entitlement مسدود و entitlement مستقل فعال بماند |

قبولی: هیچ packet بعد از نقطه enforce که مطابق تعریف رسمی quota است forward نشود. اختلاف nftables با WireGuard و backend باید اندازه‌گیری شود؛ clamp حسابداری backend به‌تنهایی قبولی فنی نیست.

## 4. مرز packet و overshoot

nftables quota بر اساس طول skb در hook خود می‌شمارد؛ این الزاماً برابر WireGuard transfer counters یا billable bytes نیست. packet عبورکننده از سقف ممکن است در شمارنده لحاظ شود، هرچند drop شده باشد. بسته‌هایی که پیش از exhaustion پذیرفته شده‌اند ممکن است در صف باشند.

آزمون‌ها:
- سقف‌های کوچک و تکرارپذیر برای آشکارکردن مرز packet.
- packet size و MTU متفاوت؛ fragmentation در صورت پشتیبانی توپولوژی.
- TCP/UDP، هر دو جهت و چند جریان موازی.
- ثبت هم‌زمان nftables counters، خروجی wg، مولد ترافیک و UsageRecord آزمایشی.
- تفکیک accepted، dropped، queued/in-flight و reported bytes.
- exhaustion در میانه جریان و هنگام burst.
- ثبت packet boundary و بیشترین اختلاف مشاهده‌شده؛ تعریف دقیق لایه بایت billable.

قبولی: overshoot باید محدود، تکرارپذیر و کمتر از آستانه عددی باشد که پیش از فاز B تصویب می‌شود. تا پیش از اندازه‌گیری هیچ عددی SLA نیست.

## 5. Fail-closed و بازیابی

| شناسه | تزریق خطا | انتظار |
|---|---|---|
| F-01 | توقف agent اندازه‌گیری | stale/offline تشخیص داده شود؛ دسترسی نامحدود ادامه نیابد |
| F-02 | قطع backend | registry/فرمان منقضی یا نامعتبر شود و سیاست fail-closed اجرا شود |
| F-03 | شکست revoke/remove peer | هشدار بحرانی و عدم قطعیت آشکار؛ ادعای توقف موفق ممنوع |
| F-04 | reboot میزبان lab | quota state و rules فقط با ترتیب امن restore شوند |
| F-05 | restart nftables | نبود policy لازم باعث fail-open نشود |
| F-06 | تکرار usage event/ACK | idempotency حفظ و دوباره‌شماری رخ ندهد |
| F-07 | دیسک read-only یا outbox پر | رخداد از دست نرود یا خطای بحرانی آشکار شود |
| F-08 | registry revision قدیمی/replay | نسخه قدیمی رد و peer ناشناس غیرفعال بماند |

## 6. Flowtable و hardware offload

در فاز اول flowtable و hardware offload خاموش می‌مانند. سپس فقط در آزمایش جداگانه فعال می‌شوند تا روشن شود کدام hookها دور زده می‌شوند و quota تمام packetها را می‌بیند یا خیر.

- baseline بدون offload تثبیت شود.
- software flowtable در VM disposable جداگانه آزمایش شود.
- hardware offload فقط اگر سخت‌افزار آزمایشگاهی مستقل موجود بود بررسی شود.
- packet counters، conntrack offload state و quota counters مقایسه شوند.
- هر bypass یا اختلاف توضیح‌ناپذیر یعنی رد آن حالت و باقی‌ماندن offload خاموش.

## 7. DNS، IPv4/IPv6 و Telegram-only

### ماتریس Android
حداقل دو نسخه اصلی Android و ترجیحاً دو سازنده متفاوت بررسی شوند. مدل دستگاه، build fingerprint، patch level، نسخه Telegram و نوع شبکه ثبت شود.

| محور | حالت‌ها | انتظار |
|---|---|---|
| App scope | Telegram stable رسمی / برنامه غیرمجاز | فقط package تأییدشده وارد VPN شود |
| Package | org.telegram.messenger | روی دستگاه واقعی نصب و package name تأیید شود |
| Beta/clone | beta، Telegram X، fork | تا آزمون جداگانه خارج از پشتیبانی |
| DNS | Private DNS Off / Automatic / Strict | بدون fallback ناامن؛ ناسازگاری fail-closed |
| IP family | IPv4 و IPv6 | خانواده پشتیبانی‌نشده به direct leak منجر نشود |
| شبکه | Wi-Fi، mobile data، handover | route و tunnel پس از تغییر شبکه دوباره بررسی شود |
| چرخه عمر | screen-off، Doze، resume، process kill، reboot | وضعیت واقعی و بازیابی قابل مشاهده باشد |
| VPN دیگر | VPN پیشین فعال | تعارض و جایگزینی با توضیح و رضایت روشن |

### DNS و Private DNS
- تنظیم global Private DNS دستگاه تغییر داده نشود.
- Android system resolver حفظ شود؛ DNS client سفارشی در نسخه اول ساخته نشود.
- در Off، Automatic و Strict موفقیت resolution، مسیر resolver و رفتار قطع تونل ثبت شود.
- Strict mode ممکن است نیازمند دسترسی resolver از داخل و خارج VPN باشد؛ ناسازگاری باید خطا دهد، نه fallback به DNS ناامن یا مسیر مستقیم پنهان.
- آزمون leak با DNS endpoint کنترل‌شده و packet capture آزمایشگاهی انجام شود؛ نتیجه UI به‌تنهایی کافی نیست.

### اعلان‌ها و FCM
Google Play Services/FCM به allow-list تلگرام اضافه نشود. جداگانه آزمایش شود:
- Telegram در foreground و background؛
- screen-off و Doze؛
- process kill و battery restrictions؛
- تأخیر/عدم تحویل push در شرایط مختلف؛
- بازکردن Telegram از اعلان و برقراری اتصال داخل VPN.

موفقیت push به‌تنهایی معیار موفقیت تونل Telegram نیست؛ مسیر push سیستمی و ترافیک خود برنامه جدا گزارش شوند.

## 8. Artifact هر اجرا

هر run باید شامل شناسه، commit، تاریخ UTC، مجری، kernel release/config، nftables/iproute2/WireGuard versions، توپولوژی، MTU، تعداد peer و quota، counters قبل/بعد، packet capture، generator output، UsageRecord، latency exhaustion تا آخرین packet پذیرفته‌شده، نتیجه pass/fail، log redacted و شناسه snapshot/rollback باشد.

هیچ private key، provisioning token، bot token، HMAC secret، شناسه کاربر واقعی یا داده شخصی در artifact ثبت نشود.

## 9. دروازه‌های پذیرش

1. G0 ایمنی: توپولوژی disposable، snapshot و جداسازی شبکه تأیید شود.
2. G1 quota: Q-01 تا Q-08 بدون bypass و با counters قابل توضیح موفق باشند.
3. G2 overshoot: packet boundary اندازه‌گیری و آستانه عددی تصویب شود.
4. G3 fail-closed: F-01 تا F-08 هیچ fail-open ناشناخته‌ای نشان ندهند.
5. G4 offload: حالت بدون offload تأیید؛ هر offload فقط با اثبات پوشش کامل پذیرفته شود.
6. G5 Android/DNS: ماتریس DNS، IPv4/IPv6، Telegram-only و lifecycle روی دستگاه واقعی ثبت و قبول شود.
7. G6 پیاده‌سازی: گزارش بازبینی شود؛ این گیت مجوز production یا انتشار اپ نیست.

هر direct leak، peer ناشناس، packet عبوری پس از enforce، فقدان audit یا عدم قطع قابل اثبات موجب توقف و بازگشت به طراحی است.

## 10. ترتیب اجرا

1. topology محلی disposable و baseline.
2. آزمون بدون quota برای اعتبارسنجی generator و counters.
3. named quota مشترک برای دو peer و quota مستقل برای C.
4. packet boundary، burst و concurrency.
5. fault injection و reboot/restore.
6. offload فقط پس از قبولی مسیر پایه.
7. ماتریس Android روی دستگاه‌های مجاز.
8. گزارش پذیرش/رد و فهرست اصلاحات؛ هیچ مرحله‌ای خودکار به production منتقل نمی‌شود.

## 11. وضعیت اجرا و محدودیت فعلی

- این فایل طرح آزمایش است، نه گزارش اجرای آزمون.
- میزبان مجاز هنوز تأیید نشده؛ پاسخ انسانی Hetzner درباره eligibility و کاربرد تجاری VPN باید پیش از سفارش/نصب دریافت شود.
- هیچ kernel، nftables، firewall، flowtable، offload، WireGuard peer، host agent، database، Android app یا تنظیم DNS در این مرحله تغییر نکرده است.
- فاز A محلی نیز تا اجرای جداگانه و ثبت artifact، انجام‌شده محسوب نمی‌شود.
- overshoot، latency و SLA هنوز اندازه‌گیری یا تصویب نشده‌اند.


## پیشرفت فاز A — اسکلت آزمایشگاه محلی

- مسیر `lab/phase-a/README.md`: دستورالعمل توپولوژی disposable، پیش‌نیازها، توالی G0/Q-01 تا Q-05 و artifactهای لازم.
- مسیر `lab/phase-a/phase-a-lab.sh`: scaffold برای ساخت namespaceهای مستقل A، B، C، gateway و sink؛ A و B از یک named quota و C از quota مستقل استفاده می‌کنند.
- فایروال فقط در namespace دروازهٔ آزمایشگاه تعریف می‌شود؛ chain با policy drop است و rule عمومی established/related برای دورزدن شمارش وجود ندارد.
- commitهای ایجاد فایل: `5b9cc9b347e7554136e16366feae9464798d32db` و `182147ae05600df2123e80970bff5532d4a1aa7e`.
- **وضعیت:** scaffold در شاخه ثبت شده، اما هنوز روی Linux VM اجرا نشده؛ هیچ تست شبکه‌ای یا quota به‌عنوان موفق گزارش نمی‌شود. گام بعدی بازبینی ایستا و افزودن traffic/counter harness است؛ سپس اجرا در VM disposable.
