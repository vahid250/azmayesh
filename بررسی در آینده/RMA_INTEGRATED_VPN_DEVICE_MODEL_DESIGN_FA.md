# طراحی مدل Device و اتصال آن به WireGuard — R&MA Integrated VPN

- تاریخ: 2026-11-18
- شاخهٔ کاری: `rebuild/rma-hardening-from-dashboard`
- وضعیت: طراحی مبتنی بر ممیزی کد؛ بدون migration یا تغییر کد
- وابستگی: `RMA_INTEGRATED_VPN_PROVISIONING_PROTOCOL_FA.md`
- اصل قطعی: اپ همراه فقط peerهای صادرشده از مسیر رسمی R&MA را فعال می‌کند؛ private key کلاینت در دستگاه می‌ماند.

## 1. نتیجهٔ بررسی ساختار واقعی موجود

فایل‌های واقعی بررسی‌شده:
- `backend/app/models.py`
- `backend/app/wireguard.py`
- `backend/app/main.py`
- `backend/app/metering.py`
- `backend/host_agent/rma_wg_meter.py`
- `backend/host_agent/README.md`

یافته‌های مهم:
1. `Entitlement` هم‌اکنون `telegram_user_id`، `max_devices`، `quota_bytes`، `consumed_bytes`، `expires_at` و `status` دارد. پس حق دسترسی و سقف دستگاه باید به همین entitlement متصل شود؛ ساختن یک سیستم اشتراک موازی اشتباه است.
2. `WireGuardClient` هم‌اکنون `public_key` و `client_ip` دارد، اما `private_key_encrypted` و `config_encrypted` نیز اجباری‌اند. تابع `issue_wireguard_config()` کلید خصوصی را در backend می‌سازد و کانفیگ قابل دانلود برمی‌گرداند. این مدل برای کلاینت native با کلید خصوصی محلی مناسب نیست.
3. `WireGuardClientOwner` مالکیت فعلی را با Telegram ID و entitlement نگه می‌دارد؛ اما هویت مستقل نصب/دستگاه، وضعیت pairing و lifecycle کلید دستگاه ندارد.
4. `UserSession` نشست Mini App را با hash توکن و hash initData مدیریت می‌کند؛ این نشست مفید است، اما جایگزین device identity یا اثبات مالکیت کلید خصوصی دستگاه نیست.
5. `UsageRecord` به entitlement وصل است و event تکراری را با `(source, source_event_id)` رد می‌کند؛ اما انتساب صریح مصرف به device/peer ندارد.
6. Host agent فعلی peerها را با `client_id` عددی و public key/allowed IP از registry می‌شناسد و UsageEvent هم `client_id` دارد. افزودن peerهای native بدون طراحی شناسهٔ مرجع و قرارداد registry، ریسک برخورد شناسه و اشتباه در revoke/metering دارد.
7. endpoint فعلی `POST /api/v1/wireguard/configs` مسیر عمومی صدور کانفیگ است و در production فعلاً fail-closed است. Integrated VPN نباید آن را برای صدور کلید/کانفیگ reuse کند.

## 2. تصمیم معماری اصلی: مدل Device مستقل + peer inventory مشترکِ بدون private key

**پیشنهاد:** موجودیت `IntegratedVpnDevice` مستقل ایجاد شود؛ اما برای peer عملیاتی، از یک مدل inventory امن و مشترک استفاده شود که فقط public key، IP و lifecycle را نگه دارد. private key و config plaintext/encrypted سمت backend در این مسیر اصلاً وجود نداشته باشد.

دو راه بررسی شد:

- **راه A — reuse مستقیم `WireGuardClient`: رد می‌شود.** فیلدهای private key و config اجباری‌اند و منطق فعلی آن مدل به صدور config سمت سرور وابسته است. ذخیرهٔ مقدار ساختگی یا کلید خصوصی ساختگی برای دورزدن constraint غیرقابل قبول است.
- **راه B — peer table مستقل فقط برای Integrated VPN:** از نظر جداسازی ساده است، اما host agent، registry، metering، status و revoke باید دو منبع peer را جداگانه مدیریت کنند؛ احتمال تکرار منطق و اختلاف رفتار بالا می‌رود.
- **راه C — مدل Device مستقل + انتزاع peer inventory مشترک (پیشنهاد نهایی برای طراحی):** یک مدل peer عمومیِ بدون secret با `peer_id` پایدار و `peer_kind`/مالکیت منبع، که legacy peerهای فعلی و Integrated VPN را به شکل سازگار مدیریت کند. این تغییر باید در فاز پیاده‌سازی با migration افزایشی و سازگاری backward انجام شود؛ نه اکنون.

**نکته:** این تصمیم هنوز طراحی است. پیش از migration باید تمام مصرف‌کنندگان `WireGuardClient`، endpointهای registry، metering و تست‌های فعلی inventory به inventory abstraction جدید map شوند.

## 3. مدل‌های مفهومی پیشنهادی

### A. IntegratedVpnDevice

یک ردیف به‌ازای هر نصب ثبت‌شدهٔ اپ روی یک دستگاه/پروفایل Android. حذف و نصب مجدد اپ، دستگاه جدید محسوب می‌شود مگر recovery امن جداگانه طراحی شود.

فیلدهای پیشنهادی:
- `id`: UUID تصادفی backend، primary key.
- `telegram_user_id`: شناسهٔ مالک که فقط از session معتبرشدهٔ backend می‌آید؛ هرگز از body کلاینت اعتماد نشود.
- `entitlement_id`: FK به `entitlements.id` با `ON DELETE RESTRICT`; entitlement در هر زمان ممکن است تمدید/جایگزین شود، پس رابطهٔ جاری باید روشن و قابل تغییر کنترل‌شده باشد.
- `device_public_key`: کلید عمومی دستگاه؛ private key در backend ذخیره نمی‌شود.
- `key_fingerprint`: fingerprint یکتا برای نمایش و audit؛ خود public key همچنان مرجع cryptographic است.
- `platform`: فعلاً `android`.
- `app_version` و `app_signing_cert_digest`: metadata نسخه و گواهی امضای اپ؛ سیگنال ریسک، نه اثبات قطعی اصالت.
- `status`: فقط enum محدود مانند `pending`, `active`, `suspended`, `revocation_pending`, `revoked`.
- `created_at`, `last_seen_at`, `revoked_at`, `updated_at`.
- `device_label`: نام اختیاری و پاک‌سازی‌شده برای نمایش؛ هرگز شناسهٔ امنیتی نیست.

قیود و ایندکس‌ها:
- unique روی fingerprint یا public key فعال، تا یک کلید به چند Device متصل نشود.
- index روی `telegram_user_id, status` و `entitlement_id, status`.
- check برای statusهای مجاز و سازگاری `revoked_at` با status revoked.
- public key باید در لایهٔ سرویس با فرمت/طول WireGuard معتبرسازی شود؛ check constraint متنی به‌تنهایی کافی نیست.
- device row نباید شامل private key، handoff token، access token یا bot secret باشد.

### B. IntegratedVpnPairing

تراکنش کوتاه‌عمر اتصال Mini App به اپ Android؛ رکورد pairing از device پایدار جدا باشد.

فیلدهای پیشنهادی:
- `id`: UUID تصادفی.
- `telegram_user_id`, `entitlement_id`, `profile_id`.
- `handoff_code_hash`: hash امن کد تصادفی؛ هرگز raw code ذخیره نشود.
- `challenge_nonce_hash` یا metadata لازم برای challenge؛ raw nonce فقط در صورت نیاز کوتاه‌مدت و با حفاظت مناسب.
- `claimed_device_id`: FK nullable به Device.
- `status`: `pending`, `claimed_unverified`, `verified`, `provisioning`, `provisioned`, `expired`, `rejected`, `revoked`.
- `expires_at`, `claimed_at`, `consumed_at`, `created_at`.
- `idempotency_key` یا request fingerprint برای جلوگیری از ایجاد pairing تکراری ناخواسته.

قیود:
- unique روی hash handoff code.
- index روی owner/status/expiry برای cleanup و بررسی سریع.
- مصرف handoff باید در transaction اتمیک باشد؛ دو claim هم‌زمان نباید هر دو موفق شوند.
- pairing منقضی/مصرف‌شده هرگز دوباره فعال نشود.
- pairing به device نهایی bind می‌شود؛ تغییر device نیازمند pairing تازه است.

### C. IntegratedVpnGrant

مجوز server-side برای یک عملیات provisioning مشخص؛ grant bearer token بلندمدت نیست.

فیلدهای پیشنهادی:
- `id`: UUID.
- `pairing_id`: FK unique به pairing، مگر عملیات rotate/reprovision آینده با مدل grant generation مستقل طراحی شود.
- `device_id`, `entitlement_id`, `telegram_user_id`.
- `public_key_fingerprint`, `profile_id`, `server_id`, `scope`.
- `nonce_hash`, `idempotency_key`.
- `status`: `issued`, `applying`, `consumed`, `expired`, `revoked`, `failed`.
- `expires_at`, `consumed_at`, `created_at`.

قیود:
- یک grant فقط یک بار برای همان pairing مصرف شود.
- grant باید هنگام redeem دوباره entitlement، device status، public key و scope را بررسی کند.
- دسترسی host agent از grant خام به‌دست نمی‌آید؛ backend آن را به دستور registry احرازشده تبدیل می‌کند.
- token یا secret خام در این جدول نگهداری نشود.

### D. Peer inventory

موجودیت منطقی peer باید برای همهٔ مسیرها شناسهٔ پایدار و بدون secret داشته باشد:
- `peer_id`: UUID/شناسهٔ پایدار داخلی.
- `peer_kind`: مثلاً `legacy_config` یا `integrated_device`.
- `public_key`, `allowed_ip`, `interface/server_id`, `state`.
- owner/entitlement/device reference با قیود مناسب.
- `created_at`, `registered_at`, `revoked_at`.

برای Integrated VPN، هر Device در هر لحظه حداکثر یک peer فعال برای هر profile/server داشته باشد. کلید rotate با peer replacement کنترل‌شده انجام شود؛ unique public key و unique allowed IP در سطح interface حفظ شود.

**عدم ذخیره:** هیچ فیلد private key یا full client config در peer inventory جدید وجود نداشته باشد.

### E. AuditEvent

رخداد append-only برای عملیات حساس:
- actor type/id، action، target type/id، result، correlation ID، timestamp.
- metadata حداقلی مثل app version، server ID، reason code و risk signal.
- ممنوع: raw initData، Telegram bot token، handoff code، access/refresh token، private key یا کل WireGuard config.
- دسترسی update/delete محدود و retention مطابق سیاست حریم خصوصی.

## 4. ارتباط و cardinality

- Telegram account یک‌به‌چند Device دارد.
- Entitlement یک‌به‌چند Device مجاز دارد؛ هر Device برای سهمیهٔ جاری به یک entitlement فعال bind می‌شود.
- Device می‌تواند در طول عمر خود چند Pairing داشته باشد، اما هر Pairing فقط یک Device را claim می‌کند.
- Pairing موفق حداکثر یک Grant دارد.
- Device می‌تواند در زمان rotate/reprovision چند peer تاریخی داشته باشد، اما فقط یک peer فعال برای همان profile/server.
- Peer متعلق به یک Device و یک Entitlement است.
- Usage event به Entitlement وصل می‌ماند و باید peer/device را نیز برای audit و تشخیص مصرف ثبت کند.

## 5. قانون سقف دستگاه و race condition

`Entitlement.max_devices` مرجع سقف است؛ مقدار از Plan/Order snapshot شده و نباید از کلاینت گرفته شود.

تعریف شمارش پیشنهادی:
- فقط Deviceهای `active` یا `pending` که provisioning آنها هنوز تعیین تکلیف نشده، ظرفیت را اشغال کنند.
- `revoked`, `suspended`, `expired` ظرفیت فعال مصرف نکنند؛ سیاست suspended باید در محصول نهایی روشن شود.
- یک Device با چند Pairing نباید چند بار شمرده شود.
- Pairingهای orphan یا منقضی باید از ظرفیت آزاد شوند.

برای جلوگیری از race دو ثبت هم‌زمان:
1. entitlement row با lock مناسب (مثلاً SELECT FOR UPDATE در PostgreSQL) خوانده شود.
2. Deviceهای فعال/درحال provisioning همان entitlement در transaction شمارش شوند.
3. ظرفیت و status entitlement دوباره بررسی شود.
4. Device/Pairing ایجاد شود و transaction commit شود.
5. unique constraints و idempotency آخرین خط دفاع باشند.

صرفاً شمارش در Python بدون lock/قید دیتابیس کافی نیست. رفتار isolation و retry در Neon/Postgres باید در تست هم‌زمانی واقعی بررسی شود.

## 6. پیوند با مدل‌های موجود

| مدل فعلی | نقش فعلی | تصمیم برای Integrated VPN |
|---|---|---|
| `Entitlement` | مالک اشتراک، سقف دستگاه و سهمیه | reuse شود؛ مدل اشتراک جدید نسازیم. |
| `UserSession` | نشست کوتاه‌عمر Mini App | برای session وب استفاده شود؛ هویت/کلید Device را جایگزین نمی‌کند. |
| `WireGuardClient` | peer به‌همراه private key/config رمز‌شدهٔ server-side | مستقیم reuse نشود؛ برای native با private key محلی ناسازگار است. |
| `WireGuardClientOwner` | اتصال peer به Telegram user و entitlement | الگوی مالکیت مفید است، اما برای device-specific باید رابطهٔ صریح Device/Peer افزوده شود. |
| `UsageRecord` | event مصرف idempotent در سطح entitlement | توسعه یابد تا peer/device reference اختیاری و source معتبر داشته باشد؛ ledger فعلی حفظ شود. |
| Host agent registry | client_id، public key، allowed IP، state | به peer_id پایدار و peer_kind گسترش یابد؛ قرارداد backward برای legacy لازم است. |

## 7. مهم‌ترین شکاف host agent و metering

Agent فعلی در state و PendingEvent از `client_id: int` استفاده می‌کند و registry نیز مدل WireGuardClient را بازتاب می‌دهد. اگر Device مستقل بدون تغییر قرارداد agent اضافه شود، شناسه‌های جدول‌های مختلف ممکن است یکسان شوند و رویداد مصرف/حذف اشتباه به peer دیگری اعمال شود.

پیشنهاد:
- در قرارداد جدید از `peer_ref` غیرقابل‌ابهام با namespace استفاده شود؛ مثلاً `legacy:<id>` و `integrated:<uuid>`، یا یک UUID واحد از inventory مرکزی.
- event ID مصرف باید globally unique و idempotent باقی بماند.
- backend هنگام دریافت usage event، peer/device/entitlement را از registry معتبر resolve کند؛ entitlement_id ارسالی agent مبنای اعتماد نباشد.
- rollout با نسخهٔ پروتکل registry انجام شود؛ تا وقتی همهٔ agentها نسخهٔ جدید را نپذیرفته‌اند، مسیر legacy تغییر نکند.
- حذف peer باید بر اساس peer_ref و public key تطبیق داده شود؛ تنها client_id عددی کافی نیست.
- metering نهایی همچنان از counters میزبان می‌آید؛ اپ Android حق گزارش مصرف قابل‌قبول برای billing ندارد.

## 8. جداسازی مسیر legacy از Integrated VPN

- مسیر `/api/v1/wireguard/configs` و مدل فعلی legacy باقی می‌ماند تا تصمیم جداگانه دربارهٔ سرویس فعلی گرفته شود؛ Integrated VPN نباید از آن config بگیرد.
- endpointهای Integrated VPN namespace مستقل داشته باشند و تنها با auth session رسمی Telegram + device proof قابل استفاده باشند.
- اپ همراه هیچ UI/intent عمومی برای import config نداشته باشد.
- هیچ grant یا peer از طریق endpointهای legacy قابل تبدیل به Integrated VPN نشود.
- هر peer جدید Integrated باید دارای `peer_kind=integrated_device` و مرجع Device معتبر باشد.
- دسترسی‌های lab/mock از مسیر production provisioning جدا بمانند و نتوانند به entitlement یا peer واقعی تبدیل شوند.

## 9. توالی migration آینده (صرفاً طرح؛ اکنون اجرا نشود)

1. **Migration A — additive:** افزودن Device/Pairing/Grant/Audit و قیود/ایندکس‌ها؛ بدون تغییر یا backfill مخرب legacy.
2. **Migration B — peer abstraction:** افزودن شناسهٔ پایدار peer و نوع منبع؛ backfill امن legacy clientها با mapping یکتا و قابل rollback.
3. **Backend compatibility:** registry API نسخه‌دار که legacy و integrated peerها را بدون اختلاط resolve کند.
4. **Agent compatibility:** agent نسخه‌دار و dual-read/dual-write فقط در محیط آزمایش؛ تست restart/outbox/retry/revoke.
5. **Usage attribution:** افزودن device/peer reference nullable به UsageRecord و حفظ داده‌های تاریخی بدون حدس زدن owner.
6. **Cutover آزمایشگاهی:** فقط بعد از CI، concurrency، security و metering tests؛ production rollout مجوز جداگانه می‌خواهد.

## 10. آزمون‌های طراحی/پذیرش لازم

- [ ] Device public key تکراری رد شود.
- [ ] Device متعلق به Telegram user دیگر قابل استفاده نباشد.
- [ ] entitlement منقضی/لغو/سهمیه‌تمام‌شده نتواند Device جدید بسازد.
- [ ] دو درخواست هم‌زمان در آخرین slot فقط یک Device ایجاد کنند.
- [ ] چند Pairing برای یک Device ظرفیت را چندبار مصرف نکند.
- [ ] Pairing منقضی و consumed دوباره claim نشود.
- [ ] revoke Device تمام peerهای آن را در صف حذف قرار دهد و اتصال جدید را فوراً ممنوع کند.
- [ ] peer legacy و integrated با شناسه‌های هم‌شکل اشتباه resolve نشوند.
- [ ] duplicate usage event دوباره مصرف را افزایش ندهد.
- [ ] usage event برای peer revoked/ناشناخته reject/quarantine شود.
- [ ] private key یا config برای Integrated Device در DB، API response و log وجود نداشته باشد.
- [ ] host agent restart/outage باعث فعال ماندن peer نامجاز نشود.
- [ ] migration additive باشد و دادهٔ legacy را تغییر معنایی ندهد.

## 11. تصمیم‌های باز

1. سقف دستگاه‌ها همان `Entitlement.max_devices` است؛ اما آیا دستگاه suspended ظرفیت را نگه دارد؟ پیشنهاد: بله، تا زمان revoke صریح، برای جلوگیری از دورزدن سقف با suspend/resume.
2. آیا هر entitlement اجازهٔ چند دستگاه Android و چند profile را می‌دهد؟ فعلاً یک peer فعال برای هر Device در هر profile/server پیشنهاد می‌شود.
3. آیا account recovery اجازهٔ انتقال entitlement به دستگاه جدید را می‌دهد؟ پیشنهاد: pairing تازه + revoke دستگاه قدیمی، نه export/restore private key.
4. آیا یک Device می‌تواند بین entitlementهای متوالی منتقل شود؟ پیشنهاد: تنها با transaction صریح و revoke/renew peer؛ تاریخچه حفظ شود.
5. آیا Device خارج از Telegram login قابل ثبت خواهد بود؟ در فاز اول خیر؛ هویت اصلی Telegram است.

## 12. تصمیم نهایی این گام

- `Entitlement` و ledger مصرف موجود reuse می‌شوند.
- مدل فعلی `WireGuardClient` برای Integrated VPN مستقیم استفاده نمی‌شود، چون private key/config سمت سرور اجباری دارد.
- Device و Pairing و Grant مدل‌های مستقل خواهند بود.
- peer inventory و host-agent contract باید قبل از migration طراحی و نسخه‌دار شوند؛ تغییر صرفاً در backend ORM کافی نیست.
- در این گام هیچ کد، migration، دیتابیس یا سروری تغییر نکرده است.
