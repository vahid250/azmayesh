# طراحی پروتکل شناسایی و صدور مجوز اتصال — R&MA Integrated VPN

- تاریخ: 2026-11-18
- شاخه: `rebuild/rma-hardening-from-dashboard`
- وضعیت: طرح معماری پیشنهادی؛ هنوز پیاده‌سازی نشده
- دامنه: Telegram Mini App، اپ همراه Android، backend و VPN host/agent
- اصل حاکم: فقط زنجیرهٔ رسمی R&MA مجاز به ایجاد و فعال‌سازی peer است؛ کانفیگ‌های عمومی/شخص ثالث پذیرفته نمی‌شوند.

## 1. اهداف امنیتی

1. اثبات سمت سرور اینکه درخواست از یک Mini App معتبر R&MA و از دادهٔ احراز‌شدهٔ Telegram آمده است.
2. اتصال مجوز به Telegram account، entitlement، دستگاه مشخص و کلید عمومی همان دستگاه.
3. جلوگیری از استفادهٔ مجدد از شناسه، لینک handoff، challenge و provisioning token.
4. جلوگیری از ایجاد peer از مسیرهای عمومی یا خارج از backend provisioning رسمی.
5. نگه‌داشتن private key فقط روی دستگاه و فراهم‌کردن revoke مستقل برای هر دستگاه.
6. fail-closed در هر ابهام، خطای اعتبارسنجی، انقضا یا عدم تطبیق.
7. قابل حسابرسی بودن تمام تغییرات lifecycle بدون ثبت secretها در log.

## 2. موارد خارج از تضمین

- جلوگیری مطلق از مهندسی معکوس APK یا تقلید پروتکل توسط مهاجمی که کنترل کامل دستگاه را دارد، تضمین‌پذیر نیست.
- شناسهٔ پروفایل، نام اپ، امضای APK، obfuscation یا Play Integrity به‌تنهایی مرز امنیتی نیستند.
- هدف قابل آزمون این است که کپی APK، QR، فایل، کانفیگ یا لینک به‌تنهایی امکان ساخت peer یا اتصال ایجاد نکند.
- attestation سخت‌افزاری/Play Integrity فقط سیگنال تکمیلی ریسک است؛ نبود آن در برخی دستگاه‌ها باید با سیاست محصول روشن مدیریت شود، نه با fallback ناامن.

## 3. شناسه‌ها و موجودیت‌های مفهومی

| موجودیت | شرح و قاعده |
|---|---|
| `telegram_user_id` | شناسهٔ عددی کاربر که فقط از initData معتبرشدهٔ Telegram گرفته می‌شود؛ مقدار خام کلاینت معتبر نیست. |
| `rma_profile_id` | شناسهٔ عمومی/نسخه‌دار پروفایل R&MA؛ locator است و secret یا مجوز نیست. |
| `device_id` | شناسهٔ تصادفی backend برای هر نصب/ثبت دستگاه؛ قابل revoke و غیرقابل انتقال. |
| `device_public_key` | کلید عمومی ساخته‌شده روی دستگاه؛ fingerprint آن به device و peer bind می‌شود. |
| `pairing_id` | شناسهٔ یک تراکنش کوتاه‌عمر برای handoff از Mini App به اپ؛ به‌تنهایی bearer credential نیست. |
| `handoff_code` | secret تصادفی یک‌بارمصرف با entropy بالا؛ فقط hash آن ذخیره شود، TTL بسیار کوتاه داشته باشد و پس از claim فوراً مصرف شود. |
| `challenge_nonce` | nonce تصادفی سرور که اپ باید با کلید خصوصی دستگاه امضا کند؛ یک‌بارمصرف و وابسته به pairing باشد. |
| `provisioning_grant` | مجوز داخلی backend برای ایجاد/فعال‌سازی peer؛ به کاربر، entitlement، device، public key، سرور و scope مشخص bind می‌شود. |
| `peer_id` | شناسهٔ WireGuard peer ساخته‌شده از مسیر مجاز؛ هیچ endpoint عمومی برای ثبت peer آزاد وجود ندارد. |

شناسه‌ها باید از CSPRNG تولید شوند. شناسهٔ ترتیبی دیتابیس، Telegram user ID یا مقدار قابل حدس به‌عنوان secret استفاده نشود.

## 4. جریان پیشنهادی end-to-end

### مرحله A — احراز هویت Mini App

1. کاربر از داخل بات/صفحهٔ رسمی R&MA، Mini App را باز می‌کند و Connect را می‌زند.
2. Mini App، raw `Telegram.WebApp.initData` را به backend می‌فرستد؛ user object یا Telegram ID جداگانه مبنای اعتماد نیست.
3. backend امضای initData را با Bot Token و روش رسمی Telegram بررسی می‌کند؛ `auth_date`، عمر مجاز داده، ساختار، bot context و محدودیت replay/session را کنترل می‌کند.
4. backend حساب داخلی R&MA را به Telegram user ID معتبر نگاشت می‌کند و entitlement، محدودیت دستگاه، وضعیت حساب و سیاست منطقه/سرویس را بررسی می‌کند.
5. اگر هر کنترل رد شود، درخواست متوقف می‌شود و هیچ handoff یا peer ساخته نمی‌شود.

**قاعده:** initData یک مدرک ورود به backend است، نه توکن دائمی اپ Android. raw initData نباید در URL، deep link یا log قرار گیرد.

### مرحله B — ایجاد pairing و handoff

1. backend یک pairing transaction با وضعیت `pending` می‌سازد و آن را به user، entitlement، profile، زمان انقضا و درخواست اتصال bind می‌کند.
2. اپ همراه باید از طریق Android App Links دامنهٔ تأییدشدهٔ R&MA باز شود. deep link فقط دادهٔ لازم برای یافتن pairing و یک handoff code کوتاه‌عمر را حمل می‌کند؛ private key یا WireGuard config هرگز در آن قرار نمی‌گیرد.
3. handoff code حداقل 256 بیت تصادفی، یک‌بارمصرف، با TTL پیشنهادی 60 تا 90 ثانیه است. فقط hash آن در backend نگهداری می‌شود. مقدار دقیق TTL پس از آزمون تجربهٔ کاربر تثبیت شود.
4. اپ باید قبل از claim، کلید دستگاه را در Android Keystore ایجاد کند. ترجیح با کلید غیرقابل‌استخراج و hardware-backed در دستگاه‌های پشتیبانی‌شده است؛ قابلیت و سطح حفاظت واقعی باید از طریق APIهای رسمی سنجیده شود.
5. اپ با `pairing_id` و handoff code، public key و اطلاعات نسخه/امضای اپ به endpoint claim درخواست می‌دهد. backend code را اتمیک مصرف می‌کند و فقط یک claim موفق را می‌پذیرد.
6. برای جلوگیری از ربایش pairing، backend challenge تازه صادر می‌کند و اپ باید آن را با کلید خصوصی متناظر امضا کند. backend امضا را با public key ثبت‌شده در claim بررسی می‌کند. pairing تا پایان این مرحله به حالت `claimed_unverified` باقی می‌ماند.
7. backend باید وضعیت pairing را به Mini App اطلاع دهد؛ بسته به سیاست نهایی، تأیید نهایی در همان نشست Mini App می‌تواند لازم باشد. این گام دفاع تکمیلی در برابر لینک‌ربایی و claim ناخواسته است.

**نکتهٔ طراحی:** handoff code یک راز انتقال کوتاه‌عمر است، پس باید در access log، analytics، crash report و clipboard ثبت نشود. Android App Links، package verification و امضای اپ باید اعتبارسنجی شوند؛ وجود لینک به‌تنهایی اثبات اصالت اپ نیست.

### مرحله C — صدور provisioning grant و ایجاد peer

1. backend دوباره entitlement و وضعیت حساب/دستگاه را درست پیش از صدور grant بررسی می‌کند؛ نتیجهٔ مرحله A cache دائمی محسوب نمی‌شود.
2. grant به صورت رکورد server-side با وضعیت `issued` ایجاد می‌شود؛ حداقل شامل user، entitlement، device، public-key fingerprint، profile، server/region مجاز، scope، زمان انقضا و nonce است.
3. host agent فقط دستور معتبر و امضاشده/احرازاصالت‌شدهٔ backend را می‌پذیرد. هیچ ورودی مستقیم از Mini App یا Android برای اجرای `wg set` پذیرفته نمی‌شود.
4. backend peer را با public key دستگاه و IPهای تخصیص‌یافته ایجاد می‌کند. private key هرگز به backend یا host ارسال نمی‌شود.
5. پس از تأیید موفق host agent، grant به `consumed` و pairing به `provisioned` تغییر می‌کند. در صورت timeout یا نتیجهٔ مبهم، reconciliation idempotent لازم است و نباید peer دوم ساخته شود.
6. اپ فقط پس از دریافت پاسخ معتبر backend/وضعیت peer می‌تواند tunnel را بالا بیاورد. «صدور config» یا پاسخ HTTP موفق به‌تنهایی معادل اتصال نیست؛ handshake و telemetry معتبر باید وضعیت connected را تأیید کنند.

## 5. قرارداد API پیشنهادی (نام‌ها مفهومی‌اند؛ هنوز endpoint واقعی نیستند)

| عملیات | مسیر پیشنهادی | کنترل‌های اصلی |
|---|---|---|
| شروع pairing | `POST /api/v1/integrated-vpn/pairings` | Telegram initData معتبر، entitlement فعال، rate limit؛ ایجاد pairing و handoff |
| claim دستگاه | `POST /api/v1/integrated-vpn/pairings/{id}/claim` | handoff hash، TTL، مصرف اتمیک، public key معتبر، app identity signal |
| اثبات مالکیت کلید | `POST /api/v1/integrated-vpn/pairings/{id}/prove-key` | challenge nonce، امضای معتبر، جلوگیری replay |
| وضعیت pairing | `GET /api/v1/integrated-vpn/pairings/{id}` | session/device authorization؛ عدم افشای دادهٔ حساس |
| صدور/مصرف grant | داخلی backend فقط | entitlement re-check، idempotency، audit؛ غیرقابل فراخوانی مستقیم از کلاینت |
| وضعیت دستگاه | `GET /api/v1/integrated-vpn/devices/{id}` | دسترسی مالک، telemetry freshness |
| لغو دستگاه | `POST /api/v1/integrated-vpn/devices/{id}/revoke` | مالکیت/ادمین مجاز، revoke peer و sessionها |
| قطع اتصال | `POST /api/v1/integrated-vpn/devices/{id}/disconnect` | کنترل مالکیت، idempotent |

هیچ endpoint برای `import-config`، ثبت peer دلخواه، ارسال private key یا ساخت peer با Telegram user ID خام تعریف نمی‌شود.

## 6. مدل وضعیت و گذارهای مجاز

- Pairing: `pending → claimed_unverified → verified → provisioned`
- Pairing پایان‌یافته: `expired`، `rejected`، `consumed` یا `revoked`
- Device: `pending → active → revoked`؛ حالت‌های `suspended` و `quarantined` برای بررسی امنیتی قابل تعریف‌اند.
- Grant: `issued → consumed` یا `expired/revoked`.
- Peer: `requested → applying → active → revoked`؛ خطاها باید قابل reconcile باشند.
- هیچ گذار از `revoked` یا `expired` به `active` مجاز نیست؛ برای بازگشت باید pairing و grant تازه صادر شود.
- تغییر وضعیت و عملیات host باید idempotent و audit شوند.

## 7. حفاظت از کلید و نشست

- private key در Android Keystore تولید شود؛ export یا ارسال آن به backend ممنوع.
- ترجیح الگوریتم و قالب کلید باید با موتور WireGuard و قابلیت واقعی Keystore سازگار باشد؛ قبل از تصمیم، یک proof-of-concept آزمایشگاهی لازم است. نباید فرض شود هر API Keystore مستقیماً کلید WireGuard را پشتیبانی می‌کند.
- اگر کلید WireGuard به قالب/عملیات خاصی نیاز دارد که Keystore مستقیم پشتیبانی نمی‌کند، راهکار امن جایگزین باید جداگانه ارزیابی شود؛ ذخیرهٔ plaintext در فایل یا SharedPreferences پذیرفته نیست.
- access token اپ کوتاه‌عمر و محدود به device/scope باشد؛ refresh token در صورت نیاز rotate، revoke و در ذخیره‌سازی امن نگهداری شود.
- توکن‌ها و handoff codeها در URL analytics، log، clipboard، notification یا crash report ثبت نشوند.
- کلیدهای backend/host و Bot Token هرگز داخل APK، Mini App یا کانفیگ client قرار نگیرند.
- تعویض کلید باید با overlap محدود، اثبات کلید جدید، revoke کلید قدیم و audit انجام شود.

## 8. Telegram initData: قواعد اعتبارسنجی

- raw initData از کلاینت دریافت شود و در backend با روش رسمی Telegram و Bot Token مربوط به R&MA اعتبارسنجی شود.
- تمام فیلدهای لازم مطابق الگوریتم رسمی canonicalize و امضا بررسی شوند؛ parse کردن JSON یا اعتماد به user ID بدون اعتبارسنجی ممنوع.
- `auth_date` بررسی شود؛ پیشنهاد اولیه حداکثر عمر 5 دقیقه برای آغاز pairing است، با clock skew محدود و قابل پیکربندی. مقدار نهایی پس از تست Mini App و شرایط شبکه تعیین شود.
- initData موفق فقط برای ایجاد session/pairing backend استفاده شود؛ اپ Android باید مجوز device-bound جداگانه دریافت کند.
- initData و دادهٔ شخصی Telegram به حداقل مقدار لازم محدود و از log حذف شود.

## 9. تهدیدها و کنترل‌ها

| تهدید | کنترل لازم |
|---|---|
| جعل Telegram user ID | اعتبارسنجی cryptographic initData در backend؛ هرگز اعتماد به ID کلاینت نشود. |
| initData قدیمی/بازپخش‌شده | محدودیت auth_date، session/pairing یک‌بارمصرف، rate limit و ثبت مصرف. |
| کپی QR/لینک | handoff کوتاه‌عمر و یک‌بارمصرف، claim اتمیک و اثبات مالکیت کلید دستگاه. |
| claim توسط اپ/دستگاه مهاجم | App Links تأییدشده، challenge امضاشده، امکان تأیید در Mini App و سیگنال integrity تکمیلی. |
| سرقت provisioning token | token کوتاه‌عمر، hash-at-rest، device binding، scope محدود و revoke. |
| کپی فایل کانفیگ | عدم ارائهٔ import و عدم صدور config قابل انتقال؛ peer فقط به public key ثبت‌شده bind شود. |
| کلاینت دستکاری‌شده | کنترل‌های اصلی در backend و host؛ integrity/attestation فقط defense-in-depth. |
| replay دستور host | امضای درخواست، timestamp/nonce، idempotency key و ثبت event ID. |
| لغو اشتراک/دستگاه | re-check پیش از provisioning و enforcement سمت host؛ revoke فوری و fail-closed. |
| نشت token در log | redaction اجباری، ممنوعیت ثبت header/URL secret و تست log scanning. |
| race دو درخواست claim | transaction اتمیک و unique constraint برای handoff/pairing مصرف‌شده. |

## 10. سیاست خطا و fail-closed

- اعتبارسنجی ناموفق، انقضا، عدم تطبیق حساب/دستگاه، entitlement غیرفعال، signature نامعتبر یا وضعیت نامعلوم => peer جدید ایجاد نشود.
- اگر backend از host agent پاسخ قطعی نگیرد، نتیجهٔ عملیات `unknown/pending_reconcile` باشد؛ درخواست تکراری نباید peer تکراری بسازد.
- اگر revoke به host نرسد، دستگاه در backend فوراً revoked بماند، اتصال جدید ممنوع شود و هشدار عملیاتی تا تأیید حذف peer ادامه یابد.
- UI فقط وضعیت‌های تأییدشده را نمایش دهد؛ خطای شبکه را «متصل» نشان ندهد.
- پیام خطای کاربر عمومی باشد؛ علت فنی حساس فقط در audit امن ثبت شود.

## 11. داده‌های پیشنهادی برای مدل آینده (نه migration فعلی)

- Device: id، owner_user_id، status، public_key، key_fingerprint، platform، app_version، app_signing_cert_digest، created_at، last_seen_at، revoked_at.
- Pairing: id، owner_user_id، entitlement_id، profile_id، handoff_hash، challenge_hash/nonce metadata، status، expires_at، claimed_device_id، consumed_at.
- ProvisioningGrant: id، pairing_id، device_id، entitlement_id، peer_id، server_id، scope، status، expires_at، consumed_at، idempotency_key.
- AuditEvent: actor، action، target، result، correlation_id، timestamp و metadata حداقلی بدون secret.
- کلیدهای Telegram و backend secrets در secret manager مناسب نگهداری شوند؛ این جداول محل ذخیرهٔ secret خام نیستند.

## 12. آزمون‌های پذیرش قبل از پیاده‌سازی

- [ ] initData معتبر، نامعتبر، دستکاری‌شده، منقضی و متعلق به bot اشتباه.
- [ ] Telegram user ID خام و جعلی بدون initData معتبر رد شود.
- [ ] entitlement فعال/منقضی/لغوشده و محدودیت حداکثر دستگاه.
- [ ] handoff code نامعتبر، منقضی، دوباره‌مصرف‌شده و race دو claim هم‌زمان.
- [ ] pairing ID کپی‌شده بدون handoff code معتبر و اثبات کلید رد شود.
- [ ] challenge nonce تکراری، امضای اشتباه و امضای کلید دستگاه دیگر رد شود.
- [ ] deep link در اپ غیررسمی یا دامنه/امضای نامعتبر پذیرفته نشود.
- [ ] کپی APK یا فایل/link به دستگاه دوم peer جدید ایجاد نکند.
- [ ] revoke در backend، host agent و status API همگرا شود.
- [ ] خطا/timeout host، retry و reconciliation peer تکراری نسازد.
- [ ] log، crash report و analytics فاقد initData، handoff code، access token و private key باشد.
- [ ] هیچ مسیر import یا API عمومی برای کانفیگ/peer شخص ثالث وجود نداشته باشد.

## 13. تصمیم‌های باز پیش از پیاده‌سازی

1. آیا pairing بعد از claim اپ همراه، نیازمند تأیید نهایی کاربر در Mini App باشد؟ پیشنهاد امنیتی: برای اولین ثبت دستگاه بله؛ برای دستگاه‌های بعدی با سیاست risk-based.
2. سقف دستگاه‌های هم‌زمان هر اشتراک چند عدد باشد؟ باید در محصول/قیمت‌گذاری تعیین شود.
3. آیا پشتیبانی از دستگاه‌های فاقد hardware-backed Keystore مجاز است؟ پیشنهاد: سیاست سطح ریسک و fallback امن، نه پذیرش بی‌قید.
4. حداقل نسخه Android، نوع توزیع و گواهی امضای اپ چیست؟
5. آیا حساب کاربری R&MA خارج از Telegram نیز وجود خواهد داشت؟ اگر بله، پیوند حساب باید با flow مستقل و رضایت کاربر انجام شود؛ Telegram identity نباید تنها شناسهٔ دائمی فرض شود.
6. آیا Play Integrity در توزیع خارج از Google Play قابل اتکا/دسترس خواهد بود؟ نباید پیش از انتخاب مسیر توزیع به آن وابسته شویم.

## 14. منابع رسمی و مبنای طراحی

- Telegram Mini Apps — validating data received via Mini App: https://core.telegram.org/bots/webapps
- Android Keystore system: https://developer.android.com/privacy-and-security/keystore
- Android key attestation: https://source.android.com/docs/security/features/keystore/attestation
- Android App Links: https://developer.android.com/training/app-links
- این سند طراحی است و به‌معنای تأیید حقوقی، آماده‌بودن زیرساخت، یا مجوز شروع پیاده‌سازی نیست.
