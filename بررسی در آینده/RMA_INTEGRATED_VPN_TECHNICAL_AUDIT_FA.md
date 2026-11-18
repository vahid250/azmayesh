# ممیزی فنی پیش‌نیازهای R&MA Integrated VPN

- تاریخ ممیزی: 2026-11-18
- شاخهٔ بررسی: `rebuild/rma-hardening-from-dashboard`
- نوع کار: خواندن کد و مستندات موجود؛ بدون اجرای سرور، تغییر دیتابیس، نصب سرویس یا استقرار
- نتیجه: زیرساخت backend و host agent پایه‌های مفیدی دارند، اما هنوز برای کلاینت native تلگرام‌محور آمادهٔ اتصال عملیاتی نیستند.

## خلاصهٔ اجرایی

**نقطهٔ قوت:** چرخهٔ پایهٔ WireGuard peer، entitlement، رجیستری امضاشدهٔ host agent، HMAC، outbox پایدار و گزارش مصرف server-side در شاخهٔ آزمایشی وجود دارد.

**موانع اصلی پیش از توسعهٔ کلاینت:**
1. مسیر فعلی WireGuard کلید خصوصی را سمت backend تولید و رمزگذاری می‌کند؛ اپ همراه جدید باید private key را روی خود دستگاه بسازد و فقط public key را ارسال کند.
2. API وضعیت peer در حال حاضر handshake و counters زنده را ارائه نمی‌کند و صریحاً `connectivity_verified=false` می‌دهد.
3. agent و enforcement سهمیه روی میزبان واقعی نصب/آزموده نشده‌اند؛ metering بازه‌ای است و تاخیر نمونه‌برداری می‌تواند overshoot ایجاد کند.
4. ساختار فعلی peer و host agent فقط یک IPv4 /32 را در رجیستری می‌پذیرد، در حالی که کانفیگ فعلی کلاینت routeهای IPv4 و IPv6 را هم‌زمان درج می‌کند. برای محصول جدید باید طرح IPv6 یا حذف امن route IPv6 مشخص شود؛ در غیر این صورت خطر نشت/عدم اتصال وجود دارد.
5. هنوز مدل مستقل device registration و توکن provisioning یک‌بارمصرف/کوتاه‌عمر دیده نشد.
6. حالت Telegram-only به allow-list واقعی بستهٔ نصب‌شده نیاز دارد؛ نام package و نسخه‌های مختلف Telegram باید روی دستگاه‌ها آزموده شوند.

## یافته‌های تفصیلی

### A. WireGuard و کلیدها

- `backend/app/wireguard.py` تابع `generate_keypair()` را در backend اجرا می‌کند.
- `issue_wireguard_config()` private key و کل config را رمزگذاری‌شده در دیتابیس نگه می‌دارد و config را به فراخواننده برمی‌گرداند.
- این الگو برای کلاینت native که باید private key را فقط در دستگاه نگه دارد مناسب نیست و نباید reuse شود.
- راه آینده: endpoint ثبت public key دستگاه؛ private key در Android Keystore/ذخیره‌سازی امن مناسب تولید و نگهداری شود. backend فقط public key، شناسهٔ دستگاه، IP تخصیص‌یافته و metadata مجاز را نگه دارد.
- باید lifecycle تعویض کلید، انتقال دستگاه، حذف امن و revoke مستقل هر device تعریف شود.

### B. API و وضعیت اتصال

- endpointهای فعلی ساخت/فهرست/دریافت config، status و revoke برای WireGuard موجودند.
- `get_wireguard_peer_status()` در حالت واقعی نیز handshake را گزارش نمی‌کند؛ فیلدهای handshake و byte counters نامعلوم‌اند و اتصال تأییدشده نیست.
- پیش از UI «متصل»، باید API وضعیت از منبع معتبر host agent/gateway دادهٔ freshness-aware بگیرد: آخرین handshake، RX/TX، زمان آخرین مشاهده و وضعیت peer.
- هیچ‌گاه صرفاً با پاسخ موفق API provisioning، وضعیت اتصال موفق نمایش داده نشود.

### C. metering و سهمیه

- `backend/app/metering.py` امضای HMAC درخواست‌های داخلی را بررسی می‌کند.
- `backend/app/main.py` گزارش مصرف را به client و entitlement مالک آن متصل می‌کند؛ شناسهٔ entitlement از درخواست کاربر پذیرفته نمی‌شود.
- `UsageRecord` روی `(source, source_event_id)` یکتا است و جلوی دوباره‌شماری event تکراری را می‌گیرد.
- host agent دارای SQLite WAL، outbox پایدار و retry با event/body ثابت است.
- عامل مصرف RX+TX را در بازه‌های زمانی نمونه‌برداری می‌کند. مستند خود پروژه تصریح می‌کند بین آخرین نمونه و حذف peer ممکن است ترافیک اضافه عبور کند؛ پس قطع دقیق در آخرین بایت تضمین نشده است.
- پیش از عرضه باید حداکثر overshoot اندازه‌گیری و در سیاست محصول/سهمیه لحاظ شود؛ قطع سهمیه باید fail-closed و همراه هشدار مانیتورینگ باشد.
- کلید مشترک HMAC فقط روی backend و host نگهداری می‌شود؛ هرگز در Android، Mini App یا Bot قرار نگیرد.

### D. IPv4 و IPv6

- تخصیص فعلی IP در backend فقط IPv4 انجام می‌دهد.
- اعتبارسنجی `allowed_ips` در host agent فقط IPv4 /32 را می‌پذیرد.
- کانفیگ فعلی WireGuard شامل `AllowedIPs = 0.0.0.0/0, ::/0` است.
- برای قابلیت Telegram-only باید تصمیم معماری گرفته شود: پشتیبانی end-to-end از IPv6 شامل address allocation, routes, firewall, DNS و metering؛ یا عدم advertise کردن IPv6 route تا زمانی که پشتیبانی کامل فراهم شود. حالت نیمه‌کاره قابل قبول نیست.
- آزمون DNS و IPv6 leak جزو معیار پذیرش اجباری است.

### E. Telegram-only و Android

- مستندات Android امکان allow-list برنامه‌ها با `VpnService.Builder.addAllowedApplication()` را تأیید می‌کند؛ فهرست باید پیش از `establish()` اعمال شود و برنامه باید روی دستگاه نصب باشد.
- نام package رسمی Telegram نباید از روی حدس hardcode شود؛ فهرست نسخه‌های رسمی و variantهای قابل پشتیبانی باید از منابع رسمی و آزمون دستگاهی تأیید شود.
- Android VPN service باید با `BIND_VPN_SERVICE` و intent filter مربوط تعریف شود و مجوز سیستم از مسیر `VpnService.prepare()` گرفته شود.
- اگر کاربر VPN دیگری فعال داشته باشد، تجربهٔ جایگزینی و هشدار باید روشن باشد.
- Google Play برای VpnService مستلزم آن است که VPN کارکرد اصلی اپ باشد، استفاده در فهرست فروشگاه افشا شود، ترافیک تا endpoint رمزنگاری شود و داده‌های حساس با disclosure برجسته و رضایت صریح پردازش شوند. مسیر توزیع باید قبل از توسعهٔ انتشار تعیین شود.

### F. زیرساخت میزبان و مرز اعتماد

- host agent فقط روی VPN host اجرا می‌شود؛ Cloudflare Worker نباید دستورات `wg` را اجرا کند.
- مستند agent توصیه می‌کند process با حساب اختصاصی و حداقل capability اجرا شود و برای production به جداسازی network namespace توجه شود.
- agent دقیقاً یک نمونه برای هر WireGuard interface فرض می‌کند.
- preflight با `--check` طراحی شده که باید فقط خواندن انجام دهد؛ اجرای آن در این ممیزی انجام نشده چون میزبان و secret واقعی هنوز موجود/مجاز نیست.
- هیچ shared secret تولید یا پیکربندی نشده و هیچ سروری تماس گرفته نشده است.

## تصمیم‌های معماری پیشنهادی

1. مدل `Device` مستقل از `WireGuardClient` ایجاد شود؛ هر device به Telegram user و entitlement متصل باشد و revoke مستقل داشته باشد.
2. endpointهای provisioning جداگانه طراحی شوند: ثبت device، شروع challenge، مبادلهٔ one-time token، ثبت public key، صدور peer، status و revoke.
3. token کوتاه‌عمر، یک‌بارمصرف، audience-bound، device-bound و replay-resistant باشد؛ فقط hash آن در دیتابیس ذخیره شود.
4. کلید خصوصی روی Android تولید شود؛ backend هرگز آن را دریافت نکند.
5. status از host agent/gateway و با timestamp تازگی داده ارائه شود.
6. تصمیم IPv6 پیش از پیاده‌سازی قطعی شود.
7. metering و peer enforcement ابتدا در آزمایشگاه و با entitlement آزمایشی آزموده شود؛ overshoot و قطع هنگام outage مستند شود.
8. Telegram-only با allow-list واقعی و تست چند نسخهٔ Telegram پیاده‌سازی شود.
9. قبل از انتخاب مسیر انتشار، الزامات Google Play و حریم خصوصی/حقوقی بررسی شود.

## ترتیب اقدام بعدی

- [ ] **A1:** طراحی مدل Device و lifecycle کلید/peer (فقط سند، بدون migration).
- [ ] **A2:** طراحی قرارداد API و threat model provisioning.
- [ ] **A3:** تصمیم IPv6/DNS/firewall و سیاست fail-closed.
- [ ] **A4:** تعریف منبع status/handshake و تازگی telemetry.
- [ ] **A5:** تعریف سناریوهای آزمون metering و حداکثر overshoot.
- [ ] **A6:** تعیین package allow-list و ماتریس دستگاه/Telegram از طریق آزمون معتبر.
- [ ] **A7:** بررسی حقوقی/میزبان و مسیر توزیع اپ پیش از هر هزینه.

## منابع کد بررسی‌شده

- `backend/app/wireguard.py`
- `backend/app/metering.py`
- `backend/app/models.py`
- `backend/app/main.py`
- `backend/host_agent/README.md`
- `backend/host_agent/rma_wg_meter.py`
- `backend/tests/test_wireguard.py`
- `backend/tests/test_metering.py`
- `backend/BILLING_AND_METERING.md`

## منابع رسمی بیرونی

- Android VPN guide: https://developer.android.com/develop/connectivity/vpn
- Android VpnService: https://developer.android.com/reference/android/net/VpnService
- Android VpnService.Builder: https://developer.android.com/reference/android/net/VpnService.Builder
- Google Play VPN policy: https://support.google.com/googleplay/android-developer/answer/16909972
