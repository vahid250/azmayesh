# طراحی سازگاری Telegram، Private DNS و سهمیهٔ kernel-level — R&MA Integrated VPN

- تاریخ: 2026-11-18
- شاخه: `rebuild/rma-hardening-from-dashboard`
- نوع کار: بررسی مستندات رسمی Android/Telegram و مستندات/کد kernel؛ طراحی غیرمخرب
- وضعیت: تصمیم پیشنهادی برای نسخهٔ اول؛ هیچ دستگاه، سرور یا gateway واقعی آزمایش نشده است.

## 1. تصمیم‌های کلیدی

1. نسخهٔ اول فقط **Telegram Android stable رسمی** را هدف بگیرد؛ package ID اصلی `org.telegram.messenger` است. نسخهٔ beta با `org.telegram.messenger.beta` جداگانه و فقط پس از تست صریح قابل پشتیبانی است.
2. Telegram X، نسخه‌های کلون، forkها، packageهای تغییرنام‌یافته و Work Profile در نسخهٔ اول پشتیبانی نشوند.
3. Google Play Services/FCM به allow-list VPN اضافه نشود. این سرویس متعلق به Telegram نیست و افزودنش دامنهٔ ترافیک خارج از هدف «فقط تلگرام» را گسترش می‌دهد.
4. اعلان‌ها به‌عنوان قابلیت مستقل آزموده شوند. Telegram API از FCM و Simple Push نیز پشتیبانی می‌کند؛ ممکن است پیام push از زیرساخت سیستم خارج از تونل برسد و سپس خود اپ Telegram برای دریافت اطلاعات از VPN استفاده کند. این رفتار نباید حدس زده شود.
5. برای DNS، Android system resolver حفظ شود؛ DNS client سفارشی، DoH سفارشی یا دستکاری global Private DNS در اپ R&MA انجام نشود.
6. Private DNS در حالت strict یک ریسک سازگاری واقعی است: مستند Android می‌گوید resolver باید هم از داخل و هم از خارج VPN قابل دسترسی باشد؛ اگر نباشد، ممکن است resolution سیستم مختل شود. بنابراین تضمین «همهٔ DNSهای مرتبط فقط داخل تونل» برای همهٔ تنظیمات دستگاه فعلاً قابل ادعا نیست.
7. برای enforcement سهمیه، **nftables named quota object** گزینهٔ اول آزمایشگاهی است؛ eBPF گزینهٔ دوم فقط اگر nftables نیازهای تطبیق/کارایی را برآورده نکند. هیچ‌کدام بدون آزمایش روی kernel و نسخهٔ nftables میزبان انتخاب نهایی نیست.

## 2. ماتریس package و دامنهٔ پشتیبانی

| برنامه/نسخه | package ID شناخته‌شده | تصمیم نسخهٔ اول |
|---|---|---|
| Telegram Android stable رسمی | `org.telegram.messenger` | هدف اصلی؛ نصب و امضای package باید روی دستگاه تأیید شود |
| Telegram Android beta | `org.telegram.messenger.beta` | فعلاً خارج از پشتیبانی؛ پس از تست مستقل قابل افزودن |
| Telegram X | باید از منبع رسمی و package واقعی نصب‌شده تأیید شود | خارج از پشتیبانی |
| Forkها و cloneها | متغیر | خارج از پشتیبانی |
| Google Play Services / FCM | package سیستمی مستقل | به VPN allow-list اضافه نشود |
| Telegram Web/Desktop | package Android متفاوت یا مرورگر | خارج از پشتیبانی |

نکات:
- Android می‌خواهد package name canonical و در همان لحظه نصب‌شده باشد؛ نبود package باید provisioning را متوقف کند.
- برای مقاوم‌سازی در برابر package spoofing، package name به‌تنهایی کافی نیست. اپ باید signing certificate digest و نسخهٔ package را در ماتریس پشتیبانی بررسی کند؛ منبع گواهی معتبر و rotation باید مدیریت شود.
- R&MA نباید package دلخواه را از Mini App دریافت کند. package allow-list باید ثابت، نسخه‌دار و در release خود اپ باشد.
- اگر کاربر Telegram را uninstall/reinstall یا از stable به beta تبدیل کند، allow-list باید دوباره بررسی و VPN interface مطابق API از نو establish شود.
- Work Profile/کلون‌سازی ممکن است UID/package متفاوت بسازد؛ در نسخهٔ اول fail-closed و عدم پشتیبانی صریح.

## 3. اعلان‌ها و FCM

Telegram API مستند می‌کند که دستگاه می‌تواند با `account.registerDevice` token نوع FCM یا Simple Push ثبت کند و برای tokenهای FCM به تنظیمات Firebase نیاز است. این یعنی push notification یک مسیر جانبی مستقل از اتصال مستقیم اپ است.

سیاست پیشنهادی:
- فقط Telegram app در allow-list VPN باشد.
- Google Play Services یا کل زیرساخت push به allow-list افزوده نشود؛ این کار ممکن است ترافیک غیرمرتبط را وارد تونل کند.
- آزمون‌ها جدا باشند:
  1. اپ در foreground و tunnel فعال؛ پیام و تماس.
  2. اپ background، screen off و Doze؛ notification delivery.
  3. process اپ کشته‌شده؛ دریافت push و wakeup.
  4. Google Play Services موجود/غایب و Telegram build از Play در برابر telegram.org.
  5. tunnel فعال/غیرفعال و Wi-Fi/mobile switching.
- ثبت شود که push ممکن است از مسیر شبکهٔ عادی سیستم تحویل شود، در حالی که اتصال بعدی خود Telegram باید از VPN عبور کند. اگر محصول شرط کند «تمام ترافیک مرتبط با Telegram و push باید از تونل باشد»، این شرط با per-app Telegram-only به‌تنهایی محقق نمی‌شود و باید جداگانه طراحی شود؛ فعلاً چنین وعده‌ای داده نشود.
- متن UI: «ترافیک شبکهٔ خود برنامهٔ Telegram از تونل عبور می‌کند؛ تحویل اعلان ممکن است تابع سرویس push سیستم و تنظیمات Android باشد.»

## 4. Private DNS و resolver سیستم

### 4.1 یافتهٔ رسمی

- Android توصیه می‌کند DNS را به سیستم‌عامل بسپاریم؛ پیاده‌سازی DNS سفارشی ممکن است امنیت transport را دور بزند.
- از Android 9، Private DNS مبتنی بر DNS-over-TLS در سطح سیستم وجود دارد؛ نسخه‌های جدیدتر resolver امکانات transport بیشتری دارند.
- API `VpnService.Builder.addDnsServer()` DNS server مربوط به VPN را تعیین می‌کند و اضافه‌کردن DNS از یک خانوادهٔ آدرس، همان خانواده را برای VPN مجاز می‌کند.
- Android در حالت Private DNS strict از hostname مشخص و IPهای اعتبارسنجی‌شدهٔ resolver استفاده می‌کند.
- راهنمای DevicePolicyManager هشدار می‌دهد اگر VPN و Private DNS با هم استفاده شوند، resolver باید از داخل و خارج VPN قابل دسترسی باشد؛ وگرنه ممکن است resolution سیستم از کار بیفتد.

### 4.2 سیاست پیشنهادی R&MA

- اپ global Private DNS setting کاربر را تغییر ندهد و از کاربر نخواهد بی‌دلیل Private DNS را خاموش کند.
- از Android system resolver استفاده شود؛ DNS stack اختصاصی در اپ نوشته نشود.
- DNS IPv4 اختصاص‌یافته به VPN باید از داخل تونل قابل دسترسی باشد و firewall سمت gateway آن را محدود کند.
- اگر strict Private DNS با شبکهٔ VPN ناسازگار است، اتصال نباید با DNS fallback ناامن ادامه یابد؛ وضعیت `dns_policy_incompatible` یا `dns_unverified` نمایش داده شود و اتصال fail-closed شود تا کاربر یا سیستم وضعیت را اصلاح کند.
- حالت‌های Private DNS Off، Automatic/Opportunistic و Strict باید روی Android نسخه‌های هدف و حداقل دو OEM آزمایش شوند.
- packet capture باید هم سمت interface زیرین و هم سمت WireGuard gateway انجام شود. صرف اینکه مرورگر/تلگرام کار می‌کند اثبات عدم DNS leak نیست.
- queryهای DNS سیستم که برای سایر اپ‌ها هستند خارج از scope VPN تلگرام باقی می‌مانند؛ نباید آنها را به اشتباه به حساب Telegram نسبت داد.
- DNS leak claim فقط پس از ثبت packet capture و resolver telemetry در ماتریس تست مجاز است.

## 5. گزینهٔ اول enforcement: nftables named quota object

### 5.1 چرا گزینهٔ امیدوارکننده است

- nftables quota می‌تواند سقف byte تعریف کند و یک named quota object می‌تواند در چند rule یا map استفاده شود.
- پیاده‌سازی kernel از counter اتمیک 64-bit استفاده می‌کند؛ چند peer هم‌زمان می‌توانند به یک سهمیهٔ مشترک اشاره کنند.
- ارزیابی quota اندازهٔ `skb` را به counter اضافه می‌کند. وقتی counter از سقف عبور کند، rule آن packet را match نمی‌کند/از مسیر ACCEPT خارج می‌شود و policy بعدی باید آن را DROP کند.
- بنابراین packetی که counter را از حد عبور می‌دهد خودش باید DROP شود؛ شمارنده ممکن است اندازهٔ packet ردشده را نیز در مقدار مصرف‌شده نشان دهد، اما نباید packet عبورکننده از حد را ACCEPT کند. این رفتار باید روی kernel هدف با تست packet-level تأیید شود.
- چون همهٔ ترافیک peer در حالت routed از hook `forward` عبور می‌کند، یک quota object مشترک در مسیر هر دو جهت می‌تواند RX+TX همهٔ peerهای یک entitlement را در یک شمارنده جمع کند.

### 5.2 معماری آزمایشگاهی پیشنهادی

- برای هر entitlement یک quota object مستقل با سقف باقیمانده ایجاد شود.
- تمام IPv4های peerهای فعال آن entitlement در registry نگاشت شوند.
- ruleهای forward برای جهت peer→WAN و WAN→peer به همان quota object واحد ارجاع دهند؛ object جدا برای هر جهت یا peer ساخته نشود.
- match باید با interface ورودی/خروجی و آدرس peer محدود شود تا ترافیک دیگر میزبان وارد quota نشود.
- traffic باید دقیقاً یک بار در نقطهٔ حسابداری شمرده شود؛ مسیرهای local-input، host-originated، bridge و NAT باید از scope جدا یا به‌صورت روشن پشتیبانی شوند.
- پس از exhaustion، وضعیت quota object به backend/agent گزارش شود و peerهای entitlement در registry برای revoke اعلام شوند؛ enforcement kernel نباید منتظر حذف peer بماند.
- ایجاد/به‌روزرسانی quota و map باید atomic و versioned باشد؛ تغییر entitlement/peer نباید لحظه‌ای مسیر بدون quota ایجاد کند.
- در صورت نبود kernel module/config مربوط به NFT_QUOTA، نسخهٔ hard-enforcement باید fail deployment شود؛ silent fallback به poll metering مجاز نیست.

### 5.3 نکتهٔ حیاتی دربارهٔ ترتیب ruleها و packet عبورکننده از سقف

- قرار دادن quota expression در یک rule به‌تنهایی کافی نیست؛ وقتی quota از حد عبور کند، آن rule دیگر match نمی‌شود و ارزیابی به rule بعدی می‌رود. اگر بعداً یک `accept` عمومی وجود داشته باشد، ممکن است packet ناخواسته پذیرفته شود.
- مسیر quota-controlled باید chain اختصاصی با policy برابر `drop` داشته باشد؛ تنها ruleهای مجازکننده باید همان ruleهایی باشند که quota object مشترک را بررسی می‌کنند. هیچ broad ACCEPT بعد از rule quota نباید بتواند آن را دور بزند.
- برای هر packet فقط یک بار quota object مربوط به entitlement باید ارزیابی شود. دو جهت با شرط‌های غیرهم‌پوشان source/destination peer IP پوشش داده شوند.
- kernel quota از `atomic64_add_return(skb->len)` استفاده می‌کند و سپس نتیجه را با سقف مقایسه می‌کند. packetی که مجموع را از سقف عبور می‌دهد، باید در همان مسیر رد شود؛ مقدار داخلی شمارنده ممکن است شامل طول packet ردشده باشد. بنابراین شمارندهٔ kernel را بدون reconciliation، عیناً به‌عنوان بایت قابل‌فروش کاربر نمایش ندهیم.
- packetهایی که پیش از depletion از hook عبور کرده‌اند ممکن است هنوز در صف شبکه باشند و بعدتر روی رابط بیرونی ارسال شوند. معیار سخت‌گیرانه باید «هیچ packet جدیدی پس از depletion از hook quota پذیرفته نشود» باشد؛ تأخیر تخلیهٔ صف‌ها نیز در آزمون عملی اندازه‌گیری شود.

### 5.3 محدودیت‌ها و خطرهای nftables

1. quota بر اساس `skb->len` در hook انتخابی حساب می‌کند؛ تعریف آن لزوماً با WireGuard peer transfer counters یا حجم قابل‌نمایش/قابل‌فروش یکسان نیست. باید با packet capture و test traffic، نقطهٔ اندازه‌گیری و overhead دقیق تعریف شود.
2. اگر flowtable/hardware offload بسته‌های established را از hook مورد استفاده عبور ندهد، quota می‌تواند دور زده شود. تا زمان اثبات سازگاری، flowtable/offload برای ترافیک quota-controlled باید خاموش یا در نقطه‌ای enforce شود که bypass ممکن نباشد.
3. fragment، GSO/GRO، retransmission، ICMP، DNS، packetهای ردشده و packetهای داخلی باید در تعریف billable bytes مشخص شوند.
4. اگر مسیر شبکه از forward hook عبور نکند (مثلاً ترافیک به خود میزبان)، این rule آن را نمی‌شمارد.
5. reset/recreate quota object یا restore ruleset نباید مصرف قبلی را صفر کند؛ consumed bytes باید در backend durable باشد و restore از مقدار تأییدشده شروع شود.
6. quota object فقط یک شمارندهٔ packet-path است؛ ledger مالی/حسابداری همچنان در backend append-only باقی می‌ماند.
7. رفتار atomic counter، rule order، چند CPU و race باید با بار هم‌زمان تست شود؛ ادعای صفر overshoot فقط پس از اثبات اینکه packet عبورکننده از حد DROP می‌شود و هیچ bypass وجود ندارد مجاز است.

## 6. مقایسه با eBPF

| معیار | nftables quota | eBPF/tc |
|---|---|---|
| پیاده‌سازی اولیه | ساده‌تر و declarative | نیازمند برنامه، loader، maps و lifecycle |
| شمارش shared per entitlement | named object و map | BPF map مشترک |
| هم‌زمانی | quota kernel با atomic64 | atomic ops/locks و طراحی map لازم |
| تطبیق peerها | nft set/map | BPF map/tuple parsing |
| observability | nft list quota/counters | ابزار telemetry سفارشی |
| portability | وابسته به kernel/nft version و module | وابسته به BTF/kernel features/verifier |
| ریسک عملیاتی | قواعد nftables و flow offload | پیچیدگی lifecycle و verifier و pinning |

پیشنهاد: ابتدا nftables در lab ارزیابی شود. eBPF فقط وقتی بررسی عمیق‌تر شود که nftables به‌علت عملکرد، انعطاف یا محدودیت host نتواند معیارهای پذیرش را پاس کند. انتخاب فناوری نباید صرفاً به‌دلیل جدیدتر بودن eBPF انجام شود.

## 7. تعریف واحد مصرف

قبل از عرضه باید تصمیم محصولی مشخص شود:
- «حجم مصرفی» برابر مجموع IPv4/IPv6 inner packet bytes پذیرفته‌شده در نقطهٔ مشخص forward باشد یا byte counters WireGuard peer؟
- آیا packetهایی که در quota hook رد می‌شوند در صورتحساب مصرفی کاربر لحاظ می‌شوند؟ پیشنهاد: در مصرف قابل‌فروش لحاظ نشوند؛ در counter عملیاتی و audit جدا ثبت شوند.
- overhead رمزنگاری/UDP/IP بیرونی و handshakeها در حجم بستهٔ کاربر لحاظ نشود، مگر آنکه محصول صریحاً «حجم شبکهٔ واقعی» را بفروشد.
- جهت دریافت و ارسال هر دو به‌صورت مجموع در quota باشند.
- DNS و ICMP ایجادشده توسط Telegram اگر از تونل عبور می‌کنند، طبق تعریف روشن billable یا non-billable باشند.
- تمام ارقام UI، backend ledger، nftables counter و WireGuard counter باید با یک تبدیل تعریف‌شده و قابل توضیح مقایسه شوند؛ اعداد متفاوت نباید به‌عنوان یک مفهوم نمایش داده شوند.

## 8. ماتریس آزمون اجباری

### Telegram و notification
1. stable رسمی از Play Store و telegram.org؛ تأیید package و signing certificate.
2. beta به‌عنوان خارج از پشتیبانی و fail-closed.
3. Telegram X و forkها خارج از allow-list بمانند.
4. پیام، تماس، media، background sync، screen-off، Doze، process-kill و wakeup.
5. FCM در دسترس/غیرفعال و Google Play Services موجود/غایب؛ push مسیر خود را ثبت کند.
6. ثابت شود افزودن Telegram به allow-list باعث واردشدن GMS یا سایر اپ‌ها به VPN نمی‌شود.

### DNS
1. Private DNS Off، Automatic و Strict.
2. Wi-Fi و mobile، تغییر شبکه، captive portal، resolver unavailable و VPN endpoint DNS unreachable.
3. capture روی underlying interface و wg gateway.
4. عدم DNS fallback ناامن؛ strict incompatibility باید قابل تشخیص و fail-closed باشد.

### Kernel quota
1. NFT_QUOTA در kernel فعال/غیرفعال؛ نسخهٔ nftables و kernel ثبت شود.
2. یک peer، سپس 2/5/10 peer روی یک entitlement و دو جهت هم‌زمان.
3. quota بسیار کوچک با packetهای اندازه‌های مختلف؛ packetی که threshold را عبور می‌دهد باید drop شود.
4. ترافیک در چند CPU/queue؛ هیچ packet بعد از exhaustion پذیرفته نشود.
5. restart agent، reboot، reload ruleset، reset quota object، map update و peer churn.
6. flowtable و hardware offload روشن/خاموش؛ هر bypass باید آشکار شود و حالت ناامن رد شود.
7. مقایسه nft quota bytes با WireGuard peer counters و backend usage ledger.
8. quota مشترک چند peer با ایجاد/لغو هم‌زمان device.
9. packet fragmentation، GSO/GRO، TCP retransmission، UDP، DNS و ICMP.
10. quota exhaustion باید همهٔ peerهای entitlement را در مسیر data plane فوراً متوقف کند، حتی اگر API یا agent لحظه‌ای در دسترس نباشد.

## 9. معیار پذیرش

- نسخهٔ اول فقط stable Telegram package تأییدشده را پشتیبانی کند؛ سایر packageها رد شوند.
- اعلان‌ها مستقل از تونل و با توضیح دقیق دامنهٔ FCM آزمایش شوند.
- Private DNS کاربر دستکاری نشود؛ حالت strict ناسازگار باعث fallback ناامن نشود.
- nftables quota shared object در هر دو جهت و تمام peerهای entitlement به‌صورت aggregate شمارش کند.
- packet عبورکننده از threshold drop شود؛ هیچ flowtable/offload یا مسیر alternate آن را bypass نکند.
- تعریف billable bytes با backend ledger مستند و reconcile شود.
- اگر هر معیار روی kernel واقعی میزبان تأیید نشد، enforcement interval-based فقط به‌عنوان fallback محدود و با reserve/حد محافظه‌کارانه عرضه شود؛ هرگز به‌عنوان byte-perfect معرفی نشود.

## 10. منابع

- Android VPN guide: https://developer.android.com/develop/connectivity/vpn
- Android VpnService.Builder: https://developer.android.com/reference/android/net/VpnService.Builder
- Android insecure DNS guidance: https://developer.android.com/privacy-and-security/risks/bad-dns
- Android LinkProperties Private DNS: https://developer.android.com/reference/android/net/LinkProperties
- Android DevicePolicyManager Private DNS + VPN: https://developer.android.com/reference/android/app/admin/DevicePolicyManager
- Telegram Android source: https://github.com/TelegramOrg/Telegram-Android
- Telegram push API: https://core.telegram.org/api/push-updates
- nftables quota documentation: https://wiki.nftables.org/wiki-nftables/index.php/Quotas
- nftables manual: https://netfilter.org/projects/nftables/manpage.html
- Linux kernel nft quota implementation: https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/c7decec2f2d2ab0366567f9e30c0e1418cece43f/net/netfilter/nft_quota.c
- WireGuard Linux peer transfer counters: https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/netlink.c

## 11. مرز این سند

این سند تحلیل و طراحی است. هیچ package، Android app، DNS setting، nftables rule، kernel module، eBPF program، firewall، peer، migration، کد یا سرور تغییر نکرده است. همهٔ انتخاب‌ها باید روی میزبان آزمایشگاهی با packet capture، kernel version واقعی و Android device matrix اثبات شوند.
