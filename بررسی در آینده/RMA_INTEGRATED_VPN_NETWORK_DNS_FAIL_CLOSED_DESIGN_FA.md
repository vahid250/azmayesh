# طراحی شبکه، DNS و Fail-Closed برای R&MA Integrated VPN (Telegram-only)

- تاریخ: 2026-11-18
- شاخه: `rebuild/rma-hardening-from-dashboard`
- نوع کار: تحلیل مستندات رسمی Android و ممیزی خواندنی کد موجود؛ طراحی، بدون تغییر کد اجرایی/مهاجرت/دیتابیس/سرور
- وضعیت: پیشنهاد معماری برای بازبینی؛ هنوز روی دستگاه واقعی آزمایش نشده و مجوز پیاده‌سازی صادر نشده است.

## 1. تصمیم اجرایی پیشنهادی

برای نسخهٔ اول Telegram-only، معماری **IPv4-only روی تونل، همراه با مسدودسازی IPv6 برای اپ‌های داخل VPN** پیشنهاد می‌شود؛ نه اینکه IPv6 بدون پشتیبانی end-to-end به اینترنت عادی نشت کند.

- فقط package معتبر و نصب‌شدهٔ Telegram در allow-list مربوط به `VpnService.Builder.addAllowedApplication()` قرار می‌گیرد.
- همهٔ اپ‌های دیگر خارج از allow-list می‌مانند و طبق رفتار per-app VPN اندروید از شبکهٔ عادی دستگاه استفاده می‌کنند.
- برای تونل فقط رابط/آدرس IPv4، مسیر IPv4 و DNS IPv4 تعریف می‌شود.
- تا زمانی که IPv6 در backend allocation، host agent، peer registry، firewall/NAT، gateway، metering و آزمون انتهابه‌انتها کامل نشده، هیچ `addAddress`، `addRoute`، `addDnsServer` یا `allowFamily` مربوط به IPv6 فراخوانی نمی‌شود.
- در این حالت، مستندات Android تصریح می‌کند خانوادهٔ آدرسی که برای VPN هیچ address/route/DNS ندارد، برای ترافیک خروجی مسدود می‌شود. این رفتار باید روی نسخه‌ها و OEMهای هدف آزمایش شود؛ صرفاً از روی سند، تضمین سازگاری همهٔ دستگاه‌ها صادر نمی‌کنیم.
- مسیر IPv4 پیش‌فرض Telegram به TUN می‌رود و از طریق WireGuard به gateway منتقل می‌شود.
- DNS از resolver سیستم با DNS IPv4 مشخص‌شده در VPN استفاده می‌کند؛ DNS server باید از داخل تونل قابل دسترسی باشد و در gateway/firewall فقط مسیر لازم به آن باز باشد.
- socket بیرونی WireGuard باید با `VpnService.protect()` از TUN محافظت شود تا بسته‌های خود تونل دوباره به خودش route نشوند. این socket عمداً روی شبکهٔ زیرین حمل می‌شود؛ ترافیک برنامهٔ Telegram همچنان باید درون WireGuard رمزگذاری شود.
- `allowBypass()` نباید فراخوانی شود؛ این قابلیت می‌تواند امکان دورزدن VPN را برای برنامه‌ها ایجاد کند.

این تصمیم با زیرساخت فعلی سازگارتر از IPv6 نیمه‌کاره است: backend فعلی client IPv4 /32 تخصیص می‌دهد و host agent نیز allowed IP را به IPv4 /32 محدود کرده است. کانفیگ legacy که `0.0.0.0/0, ::/0` می‌سازد برای کلاینت native جدید نباید reuse شود.

## 2. جداسازی ترافیک برنامه‌ها

### 2.1 Allow-list

- فهرست مجاز باید پیش از `Builder.establish()` اعمال شود.
- فقط package IDهای Telegram که واقعاً روی دستگاه نصب‌اند و در ماتریس سازگاری رسمی R&MA تأیید شده‌اند پذیرفته شوند.
- نام package نباید از روی حدس یا ورودی دلخواه Mini App گرفته شود.
- نسخه‌های رسمی، Telegram X، نسخه‌های کلون، نسخهٔ کاری/Work Profile و نصب چندگانه رفتار یکسان فرض نمی‌شوند؛ هر variant باید صریحاً بررسی و در صورت پشتیبانی، جداگانه allow-list شود.
- اگر package نصب نیست یا نسخه ناشناخته است، اتصال باید fail-closed شود؛ به‌جای آنکه بی‌صدا کل دستگاه وارد VPN شود.
- هیچ اپ همراه، مرورگر، ابزار import یا package دلخواه دیگری نباید به فهرست اضافه شود.
- package خود R&MA در allow-list قرار نمی‌گیرد؛ socket حمل WireGuard با `protect()` از TUN خارج می‌شود.

### 2.2 رفتار اپ‌های خارج از فهرست

مستند رسمی Android می‌گوید وقتی allow-list استفاده شود، فقط اپ‌های افزوده‌شده از VPN استفاده می‌کنند و بقیه مانند حالتی که VPN فعال نیست از شبکهٔ سیستم استفاده می‌کنند. این دقیقاً با خواستهٔ Telegram-only سازگار است، مشروط بر اینکه کاربر از محدودیت VPN دیگری آگاه باشد.

## 3. IPv4، IPv6 و DNS

### 3.1 IPv4

- یک IPv4 تونلی اختصاصی برای device/peer ثبت‌شده در backend لازم است.
- Android TUN باید حداقل یک IPv4 address داشته باشد.
- مسیر `0.0.0.0/0` برای ترافیک IPv4 برنامهٔ مجاز به TUN داده شود.
- سمت WireGuard peer فقط routeهای لازم برای عبور IPv4 را دریافت کند؛ تخصیص IP و AllowedIPs سرور باید با peer inventory یکتا و anti-spoofing هماهنگ باشد.
- gateway باید forwarding، NAT/egress، firewall و محدودیت‌های peer را به‌صورت قابل‌آزمون اعمال کند.
- endpoint تونل و socket بیرونی باید از route loop محافظت شوند؛ `protect()` برای socket WireGuard الزامی است و شکست protect باید اتصال را متوقف کند.

### 3.2 IPv6 در نسخهٔ اول

- backend فعلی IPv6 client address allocation ندارد و host agent فعلی فقط IPv4 /32 می‌پذیرد.
- افزودن route IPv6 به کلاینت در چنین وضعیتی خطر blackhole یا نشت/رفتار نامشخص دارد.
- سیاست اولیه: IPv6 برای Telegram داخل VPN مسدود بماند، با اتکا به رفتار مستند `VpnService.Builder` وقتی هیچ IPv6 address/route/DNS به Builder اضافه نشده است.
- هیچ `allowFamily(AF_INET6)` فراخوانی نشود؛ این API می‌تواند خانوادهٔ آدرس را آزاد کند تا ترافیک به شبکهٔ زیرین fall-through کند.
- اگر در آینده IPv6 end-to-end انتخاب شد، باید هم‌زمان allocation، peer registry، host agent، gateway، firewall، metering، DNS و آزمون leak توسعه یابد. فعال‌سازی جزئی ممنوع است.

### 3.3 DNS

- DNS server باید از داخل IPv4 tunnel قابل دسترسی باشد؛ آدرس آن در زمان provisioning از تنظیمات معتبر gateway به کلاینت برسد، نه اینکه کلاینت یک resolver عمومی دلخواه hardcode کند.
- DNS resolver سیستم Android ترجیح دارد؛ از پیاده‌سازی DNS سفارشی یا DoH داخل اپ بدون ضرورت و threat model جداگانه پرهیز شود.
- `addDnsServer()` برای DNS IPv4 پیش از `establish()` تنظیم شود. چون DNS server می‌تواند family متناظر را برای VPN فعال کند، DNS IPv6 در نسخهٔ IPv4-only اضافه نشود.
- firewall سمت gateway فقط DNS مورد نیاز را از peerهای مجاز بپذیرد و درخواست DNS از peer revoked یا خارج از سهمیه را قبول نکند.
- Private DNS اندروید (Off/Automatic/Strict)، DNS-over-TLS، captive portal، شبکه‌های دارای DNS interception و تغییر Wi-Fi/mobile باید در آزمایش واقعی بررسی شوند؛ از روی وجود `addDnsServer` به‌تنهایی نمی‌توان ادعای «عدم نشت DNS در همهٔ دستگاه‌ها» کرد.
- معیار پذیرش: queryهای DNS ایجادشده توسط Telegram نباید روی شبکهٔ زیرین به‌صورت plaintext یا به resolver خارج از سیاست R&MA مشاهده شوند. آزمون باید هم packet capture روی gateway و هم capture/تحلیل سمت شبکهٔ زیرین را پوشش دهد.

## 4. قطع تونل و سیاست Fail-Closed — محدودیت مهم Android

باید دو حالت خرابی را جدا کنیم:

### 4.1 خرابی gateway/WireGuard در حالی که Android TUN هنوز برقرار است

- اپ VpnService زنده می‌ماند و TUN برقرار است.
- اگر handshake از دست رفت، peer revoke شد، quota تمام شد یا gateway unavailable شد، موتور تونل نباید بسته‌های Telegram را به شبکهٔ عادی forward کند.
- بسته‌های Telegram در TUN نگه داشته/دور ریخته شوند؛ هیچ fallback به direct socket برای ترافیک برنامه مجاز نیست.
- UI وضعیت را «اتصال قطع است؛ ترافیک تلگرام متوقف شده» نشان دهد، نه «متصل».
- در صورت از دست رفتن backend، مجوز/lease محلی فقط تا زمان انقضای کوتاه و از پیش تعریف‌شده معتبر است؛ پس از انقضا peer باید fail-closed شود. زمان دقیق lease باید در طراحی quota/status تعیین شود.
- سایر برنامه‌ها خارج از allow-list همچنان اینترنت عادی دارند.

### 4.2 توقف/کشته‌شدن VpnService، بسته‌شدن TUN یا revoke سیستمی

- مستندات Android می‌گوید وقتی file descriptor بسته شود یا VPN process crash/kill شود، شبکه به‌طور خودکار restore می‌شود؛ در نتیجه Telegram ممکن است دوباره از شبکهٔ عادی استفاده کند.
- بنابراین per-app allow-list به‌تنهایی یک تضمین دائمی «Telegram هرگز direct نمی‌شود» نیست.
- Always-on VPN همراه با «Block connections without VPN» یا lockdown می‌تواند ترافیک خارج از VPN را مسدود کند، اما در ترکیب با allow-list فقط Telegram، سایر برنامه‌هایی که خارج از VPN هستند نیز ممکن است اینترنت خود را از دست بدهند.
- پس lockdown سراسری، راه‌حل پیش‌فرض R&MA نیست؛ با نیاز «سایر اپ‌ها آنلاین بمانند» تعارض دارد.
- برای نسخهٔ اول، باید این محدودیت صادقانه در UX گفته شود: هنگام توقف/لغو VPN توسط سیستم یا کاربر، محافظت Telegram-only ممکن است از بین برود؛ اپ باید فوراً هشدار دهد و اتصال را تا دریافت مجوز/وضعیت معتبر دوباره برقرار نکند.
- اگر محصول شرط سخت‌گیرانهٔ «حتی در مرگ process نیز Telegram هرگز direct نشود، در حالی که سایر اپ‌ها direct بمانند» را الزامی بداند، VpnService عمومی Android به‌تنهایی این تضمین را ارائه نمی‌کند. باید یا الزام محصول تغییر کند، یا راهکار device-management/OS-level دیگری با بررسی حقوقی و سازگاری جداگانه انتخاب شود. ادعای fail-closed مطلق بدون چنین راهکاری ممنوع است.

## 5. VPN دیگری و مجوز سیستم

- Android در هر user/profile فقط یک VPN فعال دارد؛ شروع R&MA ممکن است VPN موجود را جایگزین کند.
- پیش از درخواست مجوز، UI باید نام VPN فعال را در صورت امکان نشان دهد و توضیح دهد که R&MA جایگزین آن می‌شود.
- اولین بار، `VpnService.prepare()` ممکن است dialog سیستمی رضایت نشان دهد؛ کاربر می‌تواند هر زمان VPN را revoke/خاموش کند.
- هیچ تلاش برای دورزدن dialog یا فعال‌سازی پنهان مجوز سیستم مجاز نیست.
- حالت Always-on/lockdown موجود روی دستگاه باید تشخیص داده و پیش از اتصال با پیام روشن مدیریت شود؛ اپ نباید فرض کند کاربر آن را خاموش کرده است.

## 6. ماتریس آزمون اجباری

| حوزه | سناریو | نتیجهٔ مورد انتظار |
|---|---|---|
| App routing | Telegram مجاز، مرورگر و سایر اپ‌ها خارج از فهرست | فقط Telegram وارد TUN شود |
| Package | Telegram نصب نیست یا package ناشناخته است | اتصال رد شود؛ هیچ full-device fallback |
| IPv4 | Telegram به مقصد IPv4 متصل می‌شود | مسیر فقط از WireGuard gateway |
| IPv6 | Telegram به مقصد IPv6 تلاش می‌کند | در نسخهٔ اول داخل VPN مسدود؛ direct fallback مشاهده نشود |
| DNS | DNS معمولی و Private DNS در حالت‌های Off/Automatic/Strict | نتیجه و مسیر DNS ثبت شود؛ leak مطابق معیار رد شود |
| Tunnel loss | gateway خاموش، UDP blocked، handshake منقضی | TUN باقی بماند و بسته‌های Telegram drop شوند |
| Service loss | force-stop، crash، revoke، بستن TUN | محدودیت Android ثبت شود؛ direct fallback بررسی و به کاربر هشدار داده شود |
| Network change | Wi-Fi به mobile و بالعکس | socket تونل مجدداً برقرار؛ تا زمان handshake، Telegram عبور نکند |
| VPN conflict | VPN دیگر فعال یا lockdown روشن | رفتار روشن و رضایت صریح؛ هیچ جایگزینی بی‌خبر |
| Socket loop | endpoint تونل داخل route VPN | socket بیرونی با protect از TUN خارج شود؛ هیچ loop رخ ندهد |
| Quota/revoke | سهمیه تمام یا device revoked | peer از gateway حذف/مسدود؛ TUN ترافیک Telegram را drop کند |
| Other apps | ترافیک سایر برنامه‌ها هنگام tunnel outage | طبق سیاست Telegram-only روی شبکهٔ عادی بماند، مگر کاربر lockdown سراسری را آگاهانه انتخاب کرده باشد |

## 7. معیارهای پذیرش

1. package allow-list پیش از establish تنظیم شده و فقط variantهای تأییدشدهٔ Telegram را شامل شود.
2. هیچ مسیر import کانفیگ یا route تمام‌دستگاه برای نسخهٔ Telegram-only وجود نداشته باشد.
3. IPv4 tunnel واقعی، handshake و egress از gateway با packet capture اثبات شود.
4. IPv6 برای Telegram تا تکمیل پشتیبانی end-to-end مسدود باشد؛ تست IPv6 leak روی شبکهٔ dual-stack انجام شود.
5. DNS در حالت‌های Private DNS مختلف بررسی شود و هیچ ادعای کلی بدون evidence منتشر نشود.
6. در خرابی gateway با TUN زنده، بسته‌های Telegram هرگز direct نشوند.
7. محدودیت توقف/crash/revoke سرویس و رفتار Android در UI و اسناد محصول آشکار باشد.
8. socket بیرونی WireGuard از TUN محافظت شود و `allowBypass()` استفاده نشود.
9. VPN conflict، Always-on و lockdown قبل از اتصال مدیریت شود.
10. تمام نتایج روی ماتریس دستگاه/نسخهٔ Android ثبت و بازتولیدپذیر باشند.

## 8. موارد باز برای مرحلهٔ بعد

- [ ] بررسی رفتار دقیق Android Private DNS روی نسخه‌ها و OEMهای هدف با نمونهٔ آزمایشگاهی.
- [ ] تعیین package ID و ماتریس نسخه‌های Telegram که رسماً پشتیبانی می‌شوند.
- [ ] تعیین اینکه push notificationهای Telegram در حالت Telegram-only چه وابستگی‌هایی به سرویس‌های سیستمی/Google Play Services دارند؛ افزودن package دیگر به allow-list بدون تحلیل دامنهٔ دسترسی ممنوع است.
- [ ] انتخاب و ثبت lease کوتاه‌مدت status/peer برای قطع backend.
- [ ] تعریف state machine کلاینت: permission_pending, connecting, connected_verified, degraded, tunnel_lost_drop, revoked, system_vpn_revoked.
- [ ] طراحی status معتبر بر پایهٔ handshake تازه و counter gateway؛ پاسخ provisioning به‌تنهایی «متصل» نیست.
- [ ] طراحی و آزمون اندازه‌گیری quota و حداکثر overshoot؛ این سند فقط به رفتار drop در پایان سهمیه اشاره می‌کند و جایگزین ممیزی metering نیست.

## 9. منابع رسمی بررسی‌شده

- Android VPN guide: https://developer.android.com/develop/connectivity/vpn
- Android VpnService.Builder: https://developer.android.com/reference/android/net/VpnService.Builder
- Android VpnService: https://developer.android.com/reference/android/net/VpnService
- Android DNS security guidance: https://developer.android.com/privacy-and-security/risks/bad-dns

## 10. مرز این سند

این سند طراحی و تحلیل است. هیچ کد Android، backend، migration، تنظیم gateway، firewall، DNS، secret یا سرور ایجاد/تغییر نداده است. رفتار نهایی باید در آزمایشگاه واقعی و با packet capture اثبات شود. هیچ ادعای «عدم نشت مطلق» یا «fail-closed در تمام حالت‌های crash/revoke» تا آن زمان مجاز نیست.
