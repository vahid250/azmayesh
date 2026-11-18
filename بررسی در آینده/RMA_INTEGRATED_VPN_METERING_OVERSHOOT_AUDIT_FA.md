# ممیزی دقت Metering، اعمال سهمیه و مصرف اضافه — R&MA Integrated VPN

- تاریخ: 2026-11-18
- شاخه: `rebuild/rma-hardening-from-dashboard`
- محدوده: کد موجود host agent، endpoint مصرف، منطق entitlement و مستندات عملیاتی
- روش: خواندن کد و مستندات؛ بدون اجرای میزبان، بدون تغییر کد/دیتابیس/تنظیمات
- وضعیت: ممیزی اولیه؛ نتایج عددی هنوز باید با آزمایش واقعی gateway تأیید شوند.

## 1. خلاصهٔ اجرایی

سامانهٔ فعلی مصرف را از counterهای واقعی WireGuard در سمت میزبان می‌خواند، RX+TX را جمع می‌کند، اختلاف دو نمونه را به backend می‌فرستد و با outbox پایدار و event ID ثابت retry می‌کند. backend نیز quota را با UPDATE شرطی اتمیک کنترل می‌کند، eventهای تکراری را idempotent می‌سازد و مصرف حسابداری را از سقف خریداری‌شده بالاتر نمی‌برد.

اما **سقف حسابداری با سقف فیزیکی انتقال داده یکی نیست**. پس از عبور واقعی از سهمیه، تا زمانی که عامل آن را نمونه‌برداری کند، backend وضعیت entitlement را exhausted کند و host agent در چرخهٔ بعدی peer را حذف کند، دادهٔ اضافه می‌تواند منتقل شود.

نتیجه: پیاده‌سازی فعلی برای metering بازه‌ای و کنترل best-effort مناسب است؛ اما هنوز quota enforcement دقیق یا byte-perfect نیست و برای فروش سهمیه با تضمین «قطع دقیق در آخرین بایت» قابل قبول نیست.

## 2. مسیر واقعی موجود

1. عامل میزبان با `wg show <interface> dump` counterهای RX و TX هر peer را می‌خواند.
2. مجموع RX+TX هر peer با آخرین baseline پایدار در SQLite مقایسه می‌شود.
3. delta مثبت به‌صورت event دارای شناسهٔ یکتا در outbox ذخیره می‌شود.
4. درخواست با HMAC به `POST /api/v1/internal/metering/usage` ارسال می‌شود؛ retry همان event ID و همان body را نگه می‌دارد.
5. backend مالک peer را از دیتابیس پیدا می‌کند و entitlement متصل را به‌روزرسانی می‌کند؛ شناسهٔ entitlement از کلاینت پذیرفته نمی‌شود.
6. اگر delta از ماندهٔ سهمیه عبور کند، backend کل interval اندازه‌گیری‌شده را برای audit ثبت می‌کند، مقدار مصرف حسابداری را روی quota سقف می‌زند و entitlement را `exhausted` می‌کند.
7. پاسخ موفق metering به عامل می‌رسد و event acknowledge می‌شود.
8. در چرخهٔ بعدی، عامل رجیستری را دوباره می‌گیرد؛ backend peerهای entitlement تمام‌شده را در فهرست حذف می‌گذارد و عامل با `wg set <interface> peer <key> remove` آنها را از رابط زنده حذف می‌کند.

نکتهٔ کلیدی: در پاسخ موفق همان event که entitlement را exhausted می‌کند، host agent بلافاصله یک fetch رجیستری دیگر انجام نمی‌دهد؛ حذف معمولاً در چرخهٔ بعدی اتفاق می‌افتد.

## 3. زمان‌بندی و تخمین overshoot

تنظیمات کد فعلی:
- `RMA_POLL_INTERVAL_SECONDS`: پیش‌فرض 15 ثانیه، حداقل 5 و حداکثر 300 ثانیه.
- `RMA_METERING_MAX_OUTAGE_SECONDS`: پیش‌فرض 120 ثانیه.
- عامل در هر چرخه ابتدا registry را sync می‌کند، سپس usage outbox را retry می‌کند، counterها را sample می‌کند و delta جدید را ارسال می‌کند؛ پس از پایان چرخه، به اندازهٔ poll interval می‌خوابد.

### 3.1 حالت سالم: API و WireGuard در دسترس

تأخیر از لحظهٔ عبور از quota تا حذف peer می‌تواند شامل دو بازه باشد:
- تا نمونه‌برداری بعدی: حداکثر تقریباً یک poll interval؛
- پس از ثبت موفق event و exhausted شدن entitlement تا sync بعدی registry: تقریباً یک poll interval دیگر.

بنابراین تخمین محافظه‌کارانه در حالت سالم:

`T_overshoot_detection_and_remove ≈ 2 × poll_interval + processing/network jitter`

| poll interval | تخمین دو بازه، بدون زمان پردازش |
|---:|---:|
| 5 ثانیه | حدود 10 ثانیه |
| 15 ثانیه (پیش‌فرض) | حدود 30 ثانیه |
| 60 ثانیه | حدود 120 ثانیه |
| 300 ثانیه (حداکثر مجاز) | حدود 600 ثانیه |

این جدول **SLA یا حد قطعی نیست**؛ زمان اجرای API، زمان پردازش چرخه، scheduling و اجرای فرمان حذف به آن اضافه می‌شود. مقدار بایت اضافه به نرخ واقعی عبور ترافیک وابسته است:

`overshoot_bytes ≈ actual_aggregate_throughput_bytes_per_second × delay_seconds`

برای نمونه، در نرخ پایدار 10 Mbps، هر 10 ثانیه حدود 12.5 MB و هر 30 ثانیه حدود 37.5 MB داده منتقل می‌شود. این فقط تبدیل نرخ به حجم است، نه ادعای سرعت gateway فعلی.

### 3.2 قطعی API پس از عبور از سهمیه

اگر usage یا registry endpoint از دسترس خارج شود، عامل تا پنجرهٔ outage پیکربندی‌شده retry می‌کند و سپس تلاش می‌کند peer را حذف کند. با poll interval برابر I و outage window برابر O، یک تخمین برنامه‌ریزی برای بدترین حالت معمول:

`T_outage ≈ I + O + processing/scheduling jitter`

با مقادیر فعلی پیش‌فرض، حدود 135 ثانیه؛ با بیشترین poll interval مجاز، حدود 420 ثانیه. این تخمین به ترتیب رخدادها وابسته است و تضمین نیست. اگر سرویس agent اجرا نشود یا دستور حذف شکست بخورد، حد زمانی قابل اتکا نداریم.

### 3.3 شکست حذف peer

کد در صورت شکست `wg set ... remove` خطای CRITICAL ثبت می‌کند و دخالت اپراتور را لازم می‌داند. در این وضعیت، هیچ سقف overshoot قطعی وجود ندارد. لاگ به‌تنهایی کنترل ایمنی نیست؛ production به alert فوری، health monitoring و runbook اپراتوری نیاز دارد.

## 4. نقاط قوت تأییدشده در کد

- counter از `wg show ... dump` سمت gateway می‌آید، نه از کلاینت.
- RX و TX هر دو در محاسبه لحاظ می‌شوند.
- outbox SQLite با WAL و synchronous FULL برای حفظ eventهای pending وجود دارد.
- retry با همان event ID و body انجام می‌شود؛ baseline تا زمان ack بی‌دلیل جلو برده نمی‌شود.
- backend event تکراری را با کلید یکتا کنترل می‌کند.
- افزایش consumed_bytes به‌صورت UPDATE شرطی انجام می‌شود تا از سقف quota عبور نکند.
- وقتی interval از ماندهٔ quota بیشتر است، full measured interval برای audit ثبت می‌شود اما consumed_bytes روی quota cap و entitlement exhausted می‌شود.
- registry peerهای exhausted/expired/revoked را برای حذف اعلام می‌کند.
- در خطای دائمی metering، عامل peer را برای جلوگیری از ترافیک بدون حساب حذف می‌کند.
- در outage طولانی یا شکست sampling نیز مسیر fail-closed برای حذف peer وجود دارد.

## 5. شکاف‌ها و ریسک‌های باقی‌مانده

### 5.1 interval metering ذاتاً overshoot دارد
هیچ سازوکار kernel-level فعلی هر بسته را در برابر ماندهٔ quota مشترک entitlement بررسی نمی‌کند. نمونه‌برداری دوره‌ای پس از عبور از سقف متوجه می‌شود.

### 5.2 حذف به sync بعدی registry موکول است
پس از پاسخ موفقی که entitlement را exhausted می‌کند، عامل در همان لحظه peer را حذف نمی‌کند. در حالت سالم، یک poll interval اضافی تا sync بعدی وجود دارد.

### 5.3 چند دستگاه روی یک entitlement
quota در سطح entitlement مشترک است، نه لزوماً یک peer. چند peer می‌توانند هم‌زمان داده منتقل کنند و هر کدام counter جدا دارند. backend اتمیک از ثبت حسابداری بیش از quota جلوگیری می‌کند، اما enforce فیزیکی مشترک در لحظهٔ عبور هنوز وجود ندارد. هر طرح enforcement آینده باید مصرف همهٔ peerهای یک entitlement را به‌صورت aggregate لحاظ کند؛ سهمیهٔ مستقل و اشتباه برای هر peer ایجاد نشود.

### 5.4 شکست یا توقف خود agent
تا زمانی که عامل زنده و قادر به اجرای `wg` باشد، پنجرهٔ outage می‌تواند به حذف peer منجر شود. اگر process متوقف بماند، سیستم‌عامل/host به‌خودی‌خود از این کد quota را enforce نمی‌کند. systemd restart policy، watchdog و هشدار عدم heartbeat باید پیش از rollout واقعی تعریف و آزمایش شوند.

### 5.5 restart رابط/میزبان و counter reset
کد در صورت کاهش counter مقدار جدید را delta تازه تلقی می‌کند. این رفتار ممکن است پس از reset باعث دوباره‌شماری یا under/over-count شود؛ باید در سناریوهای reboot و interface recreation با تست دقیق تثبیت شود. identity و generation مربوط به interface/peer در نسخهٔ بعدی باید در baseline لحاظ شود.

### 5.6 شکست فرمان حذف
اگر حذف peer شکست بخورد، عامل فقط CRITICAL log می‌دهد. باید alert بیرونی و تأیید مستقل وضعیت peer در WireGuard وجود داشته باشد؛ log بدون action کافی نیست.

### 5.7 زمان‌بندی و چند عامل
برای هر interface فقط یک agent مجاز است. دو agent هم‌زمان می‌توانند baseline، outbox و عملیات peer را ناسازگار کنند؛ singleton lock/lease و monitoring باید قبل از نصب production بررسی شود.

## 6. پیشنهاد معماری مرحلهٔ بعد

### گزینه A — سخت‌گیری interval برای rollout محدود
- برای Integrated VPN مقدار poll interval جدا و کوچک‌تر از legacy انتخاب شود؛ ابتدا 5 ثانیه به‌عنوان نقطهٔ آزمایش، نه تضمین نهایی.
- max outage برای peerهای مشتری به‌صورت سیاست مستقل و متناسب با تحمل outage تعیین شود.
- پس از هر usage event که consumed به quota می‌رسد یا entitlement exhausted می‌شود، عامل می‌تواند فوراً registry را refresh کند تا peer removal منتظر چرخهٔ بعدی نماند؛ این کار باید rate-limit و idempotent باشد و در outage مسیر fail-closed داشته باشد.
- این گزینه overshoot را کاهش می‌دهد اما حذف دقیق در آخرین بایت را تضمین نمی‌کند.

### گزینه B — enforcement در لایهٔ kernel/network
- بررسی امکان اعمال quota بایتی per-entitlement در لایهٔ kernel، با کنترل همهٔ peerهای متعلق به همان entitlement.
- گزینه‌های قابل بررسی در آزمایشگاه: nftables quota objects/rules، traffic control/eBPF یا مکانیزم معادل؛ هیچ‌کدام هنوز برای این محصول انتخاب یا اعتبارسنجی نشده‌اند.
- باید شمارش RX+TX، ترافیک چند peer، reset/restart، atomic update، حذف/اضافه peer و سازگاری namespace را پوشش دهد.
- چون quota ممکن است بین چند دستگاه مشترک باشد، سهمیهٔ محلی مستقل برای هر peer بدون coordinator قابل قبول نیست.
- تا وقتی گزینهٔ kernel در آزمایشگاه اثبات نشده، در محصول نباید «قطع دقیق» تبلیغ شود.

### گزینه C — حاشیهٔ ایمنی در طراحی بسته‌ها
- اگر enforcement kernel دقیق قابل اتکا نباشد، بخشی از quota به‌عنوان reserve داخلی برای overshoot/latency نگه داشته شود و دسترسی کاربر کمی قبل از حد حسابداری متوقف شود.
- مقدار reserve باید از توزیع اندازه‌گیری‌شدهٔ overshoot در آزمون‌های واقعی و در بارهای متفاوت استخراج شود؛ عدد حدسی یا ثابت بدون داده تعیین نشود.
- UI باید حجم قابل‌استفادهٔ واقعی را صادقانه نشان دهد؛ نباید سهمیهٔ قابل‌مصرف را بزرگ‌تر از حد قابل تضمین نمایش دهد.

## 7. آزمون‌های اجباری قبل از پذیرش

1. quota کوچک و نرخ ترافیک کنترل‌شده؛ اندازه‌گیری بایت از لحظهٔ عبور تا حذف واقعی peer.
2. poll intervalهای 5، 15 و 60 ثانیه؛ 300 ثانیه فقط در تست ایمنی و نه برای کاربر واقعی.
3. quota مشترک با 2، 5 و 10 peer هم‌زمان؛ ثبت مجموع RX+TX و زمان قطع همهٔ peerها.
4. قطع API فقط usage، فقط registry و هر دو؛ زمان واقعی تا حذف peer اندازه‌گیری شود.
5. restart agent، kill -9، reboot میزبان و restart interface؛ baseline و outbox نباید مصرف را گم یا دوباره‌شماری کنند.
6. شبیه‌سازی شکست `wg set peer remove`؛ alert باید بیرون از همان process دریافت شود و peer باقی‌مانده قابل کشف باشد.
7. retry، پاسخ‌های 4xx/5xx، duplicate event و event دیررس؛ هیچ مصرفی silently drop نشود.
8. race چند usage event برای یک entitlement؛ هیچ event معتبر گم نشود و consumed_bytes از quota عبور نکند.
9. اثبات اینکه پس از exhausted شدن، همهٔ peerهای entitlement حذف می‌شوند، نه فقط peer آخرین event.
10. ثبت raw counter، event delta، backend acknowledgment، registry revision و زمان حذف با timestampهای قابل مقایسه.

## 8. معیار پذیرش پیشنهادی

- **حسابداری:** consumed_bytes هرگز از quota عبور نکند؛ تمام intervalهای اندازه‌گیری‌شده در audit قابل ردیابی باشند.
- **اجرای فیزیکی:** حداکثر overshoot با آزمایش بار واقعی و چند peer اندازه‌گیری و یک حد عملیاتی مستند شود.
- **Fail-closed:** در قطع API/sampling/agent و شکست حذف، alert و رفتار اپراتوری مشخص باشد؛ هیچ وضعیت مبهم به‌عنوان قطع موفق ثبت نشود.
- **چند دستگاه:** quota در سطح entitlement تجمیع شود و همهٔ peerهای مربوطه هنگام exhaustion حذف شوند.
- **وضعیت محصول:** تا پیش از این آزمون‌ها فقط «کنترل سهمیهٔ بازه‌ای» قابل ادعاست، نه «قطع دقیق در آخرین بایت».

## 9. منابع کد بررسی‌شده

- `backend/host_agent/rma_wg_meter.py`
- `backend/host_agent/README.md`
- `backend/app/main.py`
- `backend/app/billing.py`
- `backend/tests/test_metering.py`
- `backend/BILLING_AND_METERING.md`

## 10. مرز این ممیزی

این سند صرفاً یافته و پیشنهاد است. هیچ تنظیم poll، outage window، agent، peer، firewall، kernel rule، migration، کد یا سروری تغییر نکرده است. زمان‌های محاسبه‌شده بر اساس ترتیب فعلی کد و تنظیمات اعلام‌شده‌اند و باید با تست واقعی تأیید شوند.
