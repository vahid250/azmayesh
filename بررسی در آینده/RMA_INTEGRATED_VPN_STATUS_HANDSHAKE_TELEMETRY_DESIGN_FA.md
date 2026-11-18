# طراحی Telemetry، Handshake و وضعیت واقعی اتصال — R&MA Integrated VPN

- تاریخ: 2026-11-18
- شاخه: `rebuild/rma-hardening-from-dashboard`
- نوع کار: ممیزی خواندنی کد و طراحی قرارداد آینده؛ بدون تغییر کد، دیتابیس، migration یا سرور
- وضعیت: پیشنهاد معماری؛ هنوز host واقعی و Android client برای آزمون وجود ندارد.

## 1. یافتهٔ ممیزی وضعیت فعلی

در کد فعلی:
- `get_wireguard_peer_status()` برای حالت واقعی نیز `handshake_seen=false`، `latest_handshake_epoch=null`، `rx_bytes=null`، `tx_bytes=null` و `connectivity_verified=false` برمی‌گرداند.
- host agent از `wg show <interface> dump` خروجی می‌گیرد، اما parser فعلی فقط فیلدهای RX و TX را می‌خواند و فیلد timestamp آخرین handshake را نادیده می‌گیرد.
- مدل legacy `WireGuardClient` فیلدهای status/handshake/counter ندارد.
- ACK فعلی peer-status فقط چرخهٔ ثبت/لغو peer را تأیید می‌کند؛ قرارداد telemetry زنده و مستقل نیست.
- `host_agent_online` در health پاسخ backend مقدار `not_verified` دارد؛ secret پیکربندی‌شده به‌تنهایی زنده‌بودن agent را اثبات نمی‌کند.

پس هیچ UI نباید از `peer_registered` یا پاسخ موفق provisioning نتیجه بگیرد که تونل واقعاً متصل است. رفتار فعلی صادقانه fail-closed است و باید حفظ شود تا telemetry معتبر اضافه شود.

## 2. مفاهیم وضعیت باید جدا بمانند

| مفهوم | معنی | چه چیزی آن را اثبات می‌کند |
|---|---|---|
| Provisioned | مجوز و peer سمت backend ایجاد شده | provisioning grant و peer record |
| Registered | peer در رابط WireGuard میزبان اعمال شده | ACK احرازشدهٔ host agent |
| Handshake recent | peer در بازهٔ زمانی قابل قبول handshake داشته | `latest_handshake` از WireGuard host |
| Traffic observed | counterهای RX/TX در نمونهٔ تازه افزایش یافته‌اند | اختلاف counterهای host-side |
| Tunnel verified | handshake تازه + مشاهدهٔ جریان دوطرفه/پاسخ معتبر در بازهٔ آزمون | telemetry میزبان و health probe تعریف‌شده |
| Telegram service reachable | خود سرویس Telegram از داخل تونل پاسخ می‌دهد | آزمون واقعی end-to-end که محدودیت‌های client و سرویس را رعایت کند؛ صرف handshake کافی نیست |

**واژه‌گذاری محصول:** در UI عمومی، «تونل R&MA فعال است» یا «تونل برقرار، ترافیک مشاهده شده» مناسب‌تر از «تلگرام قطعاً وصل است» است. سرور فقط می‌تواند peer و جریان بسته‌ها را مشاهده کند؛ از handshake به‌تنهایی نمی‌توان ورود موفق حساب Telegram یا دسترسی به همهٔ قابلیت‌های آن را نتیجه گرفت.

## 3. منبع حقیقت و مرز اعتماد

- منبع حقیقت handshake و byte counters فقط میزبان WireGuard و host agent مورد اعتماد است.
- Android client نباید بتواند با گزارش ساختگی، وضعیت اتصال یا مصرف را به backend تحمیل کند.
- host agent از `wg show <interface> dump` فیلدهای زیر را parse کند:
  - public key یا در V2 شناسهٔ پایدار peer؛
  - latest handshake epoch؛ مقدار صفر یعنی هنوز handshake مشاهده نشده؛
  - RX bytes و TX bytes؛
  - زمان نمونه‌برداری روی ساعت میزبان؛
  - agent identity، interface identity و registry revision.
- endpoint IP/port طرف مقابل، private key، shared HMAC secret و raw peer config نباید به کاربر نهایی برگردانده شوند.
- گزارش‌ها باید با HMAC و timestamp/event ID محافظت شوند؛ تکرار event باید idempotent و timestamp قدیمی رد شود.
- چون قرارداد فعلی V1 با `client_id` عددی و ACK محدود ساخته شده، telemetry جدید باید در Host Agent V2 با `peer_ref` پایدار، `agent_id`، `registry_revision` و schema version مستقل طراحی شود؛ V1 legacy دست‌نخورده بماند.

## 4. قرارداد دادهٔ پیشنهادی (مفهومی، نه API نهایی)

برای هر peer/device:
- `peer_ref`: UUID پایدار و غیرقابل‌حدس، بدون افشای client ID داخلی؛
- `agent_id`: شناسهٔ نصب/میزبان مجاز؛
- `interface_id`: شناسهٔ رابط WireGuard؛
- `registry_revision`: نسخهٔ monotonic آخرین رجیستری اعمال‌شده؛
- `observed_at`: زمان نمونه‌برداری UTC از میزبان؛
- `latest_handshake_epoch`: زمان Unix آخرین handshake یا صفر؛
- `rx_bytes`, `tx_bytes`: counter خام در لحظهٔ نمونه؛
- `counter_epoch`: شناسهٔ نسل counter که با restart/recreate رابط یا reset baseline تغییر می‌کند؛
- `event_id`: شناسهٔ یکتا برای retry؛
- `schema_version`: نسخهٔ قرارداد.

الزامات:
1. telemetry فقط برای peerهایی پذیرفته شود که در رجیستری مجاز همان agent/interface وجود دارند.
2. event متعلق به revision قدیمی یا agent لغوشده رد یا quarantine شود.
3. برای event تکراری، body یکسان پذیرفته و body متفاوت با همان event ID رد شود.
4. زمان میزبان باید با skew محدود بررسی شود؛ زمان دریافت backend نیز جدا ذخیره شود.
5. آخرین نمونهٔ معتبر و آخرین handshake معتبر جداگانه نگهداری شوند؛ دادهٔ قدیمی نباید با درخواست تازهٔ UI «تازه» جلوه داده شود.
6. counter کاهش‌یافته بدون تغییر counter_epoch نباید بی‌صدا delta مثبت تلقی شود؛ reset باید با generation/diagnostic event مشخص شود.
7. endpoint status فقط پس از احراز مالکیت Telegram account/device پاسخ دهد؛ کلید عمومی و endpoint شبکهٔ peer در پاسخ عمومی لازم نیست.

## 5. State machine پیشنهادی برای UI

وضعیت‌ها به‌صورت صریح و قابل تمایز:

- `not_provisioned`: هنوز مجوز یا peer ایجاد نشده.
- `permission_pending`: مجوز سیستمی Android لازم است.
- `provisioning`: pairing یا ایجاد peer در حال انجام است.
- `pending_peer_registration`: backend peer را ایجاد کرده، host هنوز ثبت را ACK نکرده.
- `registered_no_handshake`: peer در میزبان ثبت شده، اما handshake دیده نشده.
- `handshake_recent_idle`: handshake تازه است، اما در پنجرهٔ اخیر افزایش counter مشاهده نشده.
- `traffic_observed`: handshake تازه و تغییر counter مشاهده شده.
- `stale`: telemetry از زمان مجاز قدیمی‌تر است؛ اتصال فعلی قابل تأیید نیست.
- `tunnel_degraded`: ارتباط ناپایدار یا telemetry/handshake ناسازگار است.
- `quota_exhausted`: entitlement تمام شده و peer باید حذف شود.
- `revocation_pending`: درخواست لغو ثبت شده، اما میزبان هنوز ACK نداده.
- `revoked`: حذف peer از رابط میزبان تأیید شده.
- `agent_offline`: heartbeat/telemetry میزبان در مهلت مقرر نرسیده؛ وضعیت اتصال نامعلوم و نباید connected نشان داده شود.
- `system_vpn_revoked`: Android مجوز VPN را پس گرفته یا رابط TUN بسته شده؛ فقط کلاینت می‌تواند این وضعیت محلی را تشخیص دهد.

هیچ وضعیت نامعلوم یا stale نباید به‌عنوان connected نمایش داده شود.

## 6. Freshness و تشخیص اتصال

- threshold handshake نباید از روی حدس ثابت شود؛ با WireGuard keepalive، rekey، poll interval، NAT و شبکه‌های واقعی آزمایش شود.
- handshake و telemetry timestamp جدا هستند. ممکن است handshake قبلی هنوز از نظر WireGuard معتبر باشد اما گزارش agent قدیمی باشد؛ UI باید هر دو را لحاظ کند.
- `connected_verified` تنها وقتی مجاز است که agent معتبر و online باشد، آخرین نمونه تازه باشد، peer در revision فعال ثبت شده باشد و handshake در پنجرهٔ پذیرفته‌شده قرار گیرد.
- برای نمایش «ترافیک واقعاً عبور کرد»، افزایش RX/TX در دو یا چند نمونهٔ تازه لازم است؛ صرف non-zero counter تاریخی کافی نیست.
- برای health probe می‌توان endpoint کنترل‌شدهٔ R&MA را از داخل tunnel آزمایش کرد، اما این فقط مسیر tunnel تا آن endpoint را می‌سنجد و ثابت نمی‌کند Telegram backend در همان لحظه در دسترس است.
- برای تشخیص سرویس Telegram، probe نباید به جعل ترافیک کاربر، دورزدن محدودیت‌های Telegram یا افشای دادهٔ حساب متکی باشد. این بخش نیازمند طراحی جداگانه و احتمالاً فقط آزمون دستی/کاربرمحور است.
- وضعیت محلی VpnService و وضعیت سمت gateway باید در UI با هم سازگار شوند؛ اگر یکی unknown یا revoked باشد، نمایش اتصال قطعی ممنوع است.

## 7. Heartbeat و agent offline

- heartbeat میزبان باید حتی وقتی هیچ peer فعالی وجود ندارد ارسال شود؛ نبود traffic peer به معنی offline بودن agent نیست.
- heartbeat شامل agent_id، interface_id، software version، observed_at، registry_revision و سلامت اجرای sample/registry است؛ هیچ secret یا دادهٔ حساس شبکه در آن قرار نگیرد.
- مهلت offline بر اساس poll interval و jitter اندازه‌گیری‌شده تعیین شود؛ نباید صرفاً با یک مقدار ثابت بدون تست انتخاب شود.
- اگر heartbeat منقضی شد، backend status را `agent_offline`/unknown برگرداند و UI متصل نشان ندهد.
- در outage طولانی، peer removal و alert باید مستقل از status UI مدیریت شوند؛ UI جایگزین enforcement نیست.

## 8. آزمون‌های پذیرش

1. peer تازه ثبت‌شده بدون handshake، هرگز connected نمایش داده نشود.
2. handshake timestamp صفر، malformed، آینده‌دار یا قدیمی رد/نامعتبر شود.
3. counterهای non-zero قدیمی بدون delta تازه، به‌عنوان ترافیک جاری نمایش داده نشوند.
4. افزایش RX بدون TX و TX بدون RX در سناریوهای واقعی ثبت و تفسیر شود؛ هر دو جهت جدا قابل مشاهده باشند.
5. restart WireGuard/interface و counter reset با counter_epoch مدیریت شود؛ مصرف دوباره‌شماری یا گم نشود.
6. agent offline، API outage و stale telemetry به وضعیت unknown/degraded تبدیل شوند.
7. peer revoke شده در host و UI به ترتیب درست به revoked برسد؛ ACK حذف واقعی لازم است.
8. event تکراری و event با body متفاوت ولی ID یکسان آزموده شود.
9. device دیگر نتواند status دستگاه مالک دیگری را بخواند.
10. health probe فقط «مسیر tunnel تا probe» را گزارش کند، نه دسترسی قطعی به سرویس Telegram.
11. status API timestamp نمونه، timestamp دریافت و age داده را واضح برگرداند.
12. هیچ کلید خصوصی، secret، endpoint IP/port یا کانفیگ قابل‌استفاده در پاسخ status وجود نداشته باشد.

## 9. منابع کد بررسی‌شده

- `backend/app/wireguard.py`
- `backend/app/main.py`
- `backend/app/models.py`
- `backend/host_agent/rma_wg_meter.py`
- `backend/tests/test_wireguard.py`
- `backend/tests/test_metering.py`
- سند طراحی Host Agent V2

## 10. مرز این سند

این سند فقط طراحی است. parser، API، مدل داده، migration، heartbeat، telemetry، UI یا میزبان تغییر نکرده‌اند. thresholdها و state machine باید با دستگاه و gateway واقعی آزمایش شوند؛ هیچ status اتصال واقعی در حال حاضر قابل تأیید نیست.
