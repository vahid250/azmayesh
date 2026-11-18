# طراحی قرارداد نسخه‌دار Backend ↔ WireGuard Host Agent برای Integrated VPN

- تاریخ: 2026-11-18
- شاخه: `rebuild/rma-hardening-from-dashboard`
- وضعیت: طراحی؛ بدون تغییر کد، secret، agent یا میزبان
- وابستگی: Device Model Design و Provisioning Protocol
- هدف: توسعهٔ کنترل peerهای native بدون شکستن metering و peerهای legacy

## 1. وضعیت فعلی که از کد تأیید شد

- endpoint رجیستری فعلی `POST /api/v1/internal/metering/peers` است.
- درخواست agent با HMAC روی method، path، timestamp، event ID و SHA-256 body امضا می‌شود.
- backend فقط WireGuardClientهای legacy را از طریق `client_id` عددی، `public_key` و `allowed_ips` به agent می‌دهد.
- گزارش مصرف فعلی با `client_id` و `bytes_used` ارسال می‌شود؛ backend مالکیت و entitlement را از DB resolve می‌کند.
- event مصرف با source/event ID در UsageRecord یکتا می‌شود.
- agent در SQLite از `client_id` عددی برای pending event و managed peer استفاده می‌کند.
- پاسخ registry شامل interface، generated_at، peers و remove_peers است؛ پاسخ فعلی امضای application-level جداگانه ندارد و بر HTTPS متکی است.
- endpoint acknowledgement هم `client_id` و `public_key` را برای ثبت/لغو تطبیق می‌دهد.

این قرارداد برای یک جدول peer کافی بوده، اما برای دو منبع peer با IDهای جداگانه و Device-native مناسب نیست.

## 2. تصمیم: قرارداد V2 با peer_ref پایدار

قرارداد V1 برای legacy باقی می‌ماند. V2 باید مسیر جدا و versioned داشته باشد تا agent قدیمی ناگهان payload ناشناخته نگیرد.

**شناسهٔ مرجع peer در V2:**
- `peer_ref`: UUID تصادفی و پایدار در inventory مرکزی backend.
- `peer_kind`: مقدار allow-list مانند `legacy_config` یا `integrated_device`.
- شناسهٔ جدول داخلی به agent ارسال نشود؛ agent به primary keyهای DB وابسته نباشد.
- برای هر `peer_ref` دقیقاً یک public key فعال و یک interface/server binding معتبر وجود داشته باشد.
- در state محلی agent، کلید اصلی peer_ref باشد؛ public key نیز برای تطبیق و safety check نگهداری شود.

**چرا namespace متنی مانند legacy:123 یا integrated:UUID کافی نیست؟** می‌تواند برای migration موقت مفید باشد، اما UUID inventory مرکزی ساده‌تر، یکتا و مستقل از schema است. نوع peer جداگانه حمل شود.

## 3. Endpointهای مفهومی V2

- `POST /api/v2/internal/wireguard/registry`
- `POST /api/v2/internal/wireguard/peer-ack`
- `POST /api/v2/internal/wireguard/usage`
- در آینده: `POST /api/v2/internal/wireguard/agent-heartbeat`

این‌ها نام‌های طراحی‌اند و هنوز route واقعی نیستند.

هر درخواست شامل:
- `protocol_version=2`
- `agent_id`: شناسهٔ نصب/پیکربندی‌شدهٔ agent که backend قبلاً مجاز کرده است.
- `interface`: باید با interface ثبت‌شده برای agent/server برابر باشد.
- `request_id`: تصادفی و یکتا برای correlation و audit.
- `sent_at`: timestamp UTC و کنترل clock skew.
- بدنهٔ canonical که در HMAC امضا می‌شود.

Backend باید ترکیب agent_id/interface/protocol_version را allow-list کند؛ secret مشترک به‌تنهایی نباید مجوز مدیریت هر interface دلخواه باشد.

## 4. شکل پاسخ registry

مفهوم payload (نمونهٔ غیرقابل استفاده، بدون secret واقعی):

```json
{
  "protocol_version": 2,
  "agent_id": "agent-uuid",
  "interface": "wg0",
  "registry_revision": 42,
  "generated_at": "2026-11-18T12:00:00Z",
  "peers": [
    {
      "peer_ref": "peer-uuid",
      "peer_kind": "integrated_device",
      "public_key": "base64-public-key",
      "allowed_ips": ["10.8.0.10/32"],
      "desired_state": "present",
      "entitlement_expires_at": "2026-11-19T12:00:00Z"
    }
  ],
  "remove_peers": [
    {
      "peer_ref": "peer-uuid",
      "public_key": "base64-public-key",
      "reason": "device_revoked"
    }
  ]
}
```

قواعد:
- نمونه فقط برای توضیح schema است؛ این مقادیر در production seed نمی‌شوند.
- هیچ private key، client config، Telegram ID، handoff token یا billing secret در پاسخ registry نباشد.
- allowed_ips فقط host routeهای مجاز باشد؛ validation سخت‌گیرانهٔ IPv4/IPv6 باید با تصمیم نهایی شبکه هماهنگ شود.
- `registry_revision` باید monotonic برای هر agent/interface باشد؛ agent پاسخ قدیمی‌تر از revision اعمال‌شده را رد کند.
- پاسخ ناقص، schema ناشناخته یا revision عقب‌تر نباید باعث پاک‌کردن همهٔ peerها شود.
- اگر فهرست از حد batch بزرگ‌تر شد، pagination/snapshot token طراحی شود؛ agent نباید با دریافت یک صفحهٔ ناقص، peerهای صفحه‌های دیگر را حذف کند.
- حذف peer صریح و دارای reason باشد؛ غیبت peer از یک صفحه به‌تنهایی فرمان حذف نیست.

## 5. امضا و اصالت پاسخ

در V1، agent با HTTPS به backend وصل می‌شود و درخواست را HMAC می‌کند. برای V2:
- TLS certificate validation اجباری می‌ماند.
- پاسخ registry نیز با HMAC کلید agent یا کلید اختصاصی server-to-agent امضا شود؛ signature روی canonical response body، protocol version، agent_id، request_id و registry_revision قرار گیرد.
- agent پاسخ را قبل از parse/اعمال تغییرات verify کند.
- اگر کلید پاسخ با کلید درخواست مشترک باشد، rotation و compromise blast radius بررسی شود؛ ترجیح با کلیدهای مشتق‌شدهٔ مستقل برای request-signing و response-signing یا کلید عمومی امضای پاسخ است.
- کلیدها per-agent باشند، نه یک secret یکسان برای تمام میزبان‌ها؛ rotation با key_id/version و دورهٔ overlap کنترل‌شده انجام شود.
- secret فقط در secret manager/فایل محدودشدهٔ میزبان و backend secret store نگهداری شود؛ هرگز در Git، DB عادی، Mini App یا APK قرار نگیرد.
- timestamp و request_id replay detection را تقویت کنند؛ عملیات stateful علاوه بر امضا idempotent باشند.

## 6. اعمال peer در agent

Agent باید برای هر رکورد:
1. schema و protocol version را بررسی کند.
2. agent_id و interface را با پیکربندی محلی تطبیق دهد.
3. peer_ref، public key و allowed IP را validate کند.
4. قبل از افزودن peer، بررسی کند public key به peer_ref دیگری یا IP به peer دیگری تخصیص داده نشده باشد.
5. عملیات را با ترتیب پایدار و قابل retry اجرا کند.
6. بعد از اعمال، وضعیت واقعی interface را دوباره بخواند و فقط پس از مشاهدهٔ نتیجه ACK بفرستد.
7. در هر mismatch، peer را quarantine کند و بدون تأیید backend ادعای registered نکند.

حذف:
- حذف فقط با `peer_ref + public_key` انجام شود.
- اگر peer_ref شناخته‌شده اما public key با مقدار محلی متفاوت باشد، حذف خودکار متوقف و incident ثبت شود؛ ممکن است نشانهٔ drift یا حمله باشد.
- برای revoke اضطراری، backend دستور explicit صادر می‌کند؛ agent پس از حذف واقعی و verification ACK می‌دهد.
- در outage، agent باید سیاست fail-closed موجود را حفظ کند؛ عدم دسترسی دائمی به registry/usage نباید peer ناشناس را باز نگه دارد.

## 7. Usage event V2

نمونهٔ مفهومی:

```json
{
  "protocol_version": 2,
  "agent_id": "agent-uuid",
  "peer_ref": "peer-uuid",
  "public_key": "base64-public-key",
  "event_id": "uuid",
  "bytes_used": 4096,
  "counter_window_started_at": "2026-11-18T11:59:45Z",
  "counter_window_ended_at": "2026-11-18T12:00:00Z"
}
```

قواعد:
- backend `peer_ref` را به inventory، Device و Entitlement resolve می‌کند؛ entitlement_id از agent قبول نمی‌شود.
- public key باید با peer_ref ثبت‌شده match باشد.
- source/event_id unique و idempotent باقی بماند.
- event مربوط به peer ناشناس، revoked، quarantine یا agent نامجاز رد و برای بررسی امن ثبت شود.
- مصرف به entitlement فعلی و peer/device تاریخی درست نسبت داده شود؛ تعویض entitlement نباید usage قبلی را به اشتراک جدید منتقل کند.
- timestampهای window برای audit هستند، نه مرجع اعتماد به مقدار bytes؛ counters فقط از میزبان خوانده می‌شوند.
- گزارش‌ها باید ترتیب، reset interface و counter rollback را پوشش دهند؛ event تکراری هرگز دوباره اعمال نشود.

## 8. ACK و state machine

ACK باید شامل:
- protocol_version، agent_id، request_id، peer_ref، public_key fingerprint، observed_state، operation_id، observed_at و result code.
- backend فقط ACKای را بپذیرد که agent مجاز، peer_ref/public key و transition مورد انتظار با هم match باشند.
- duplicate ACK برای همان operation idempotent باشد.
- ACK موفق بدون خواندن مجدد وضعیت واقعی WireGuard ممنوع.
- stateهای اصلی: `desired_present`, `applying`, `present`, `desired_absent`, `removing`, `absent`, `quarantined`, `error`.
- وضعیت desired در backend و observed در agent جدا نگه داشته شود؛ یک فیلد state نباید هر دو معنا را مخلوط کند.

## 9. SQLite و outbox نسخهٔ جدید agent

طرح محلی:
- `managed_peers(peer_ref PRIMARY KEY, peer_kind, public_key UNIQUE, allowed_ips, registry_revision, observed_state)`
- `peer_counters(peer_ref PRIMARY KEY, public_key, total_bytes, disabled)`
- `pending_events(event_id UNIQUE, peer_ref, public_key, body, created_at, failure_status)`
- `agent_state(key, value)` برای آخرین revision و health.
- migration محلی SQLite باید additive و crash-safe باشد.
- outbox payload پس از ایجاد immutable باشد؛ retry همان event_id و body را ارسال کند.
- agent نباید هنگام pending event baseline را جلو ببرد و delta را گم کند.
- تغییر public key یا peer_ref باید با عملیات rotate صریح انجام شود؛ reuse اشتباه baseline ممنوع.

## 10. مهاجرت V1 به V2 بدون قطع legacy

1. V1 بدون تغییر باقی بماند و endpointها/agent فعلی کار کنند.
2. V2 endpoint و مدل inventory در محیط تست اضافه شود.
3. agent جدید در حالت shadow فقط registry V2 را بخواند و diff گزارش کند؛ هیچ `wg set` یا remove انجام ندهد.
4. fixtureهای legacy و integrated با شناسه‌های متداخل آزمایش شوند.
5. agent V2 در lab روی interface آزمایشی peerهای آزمایشی را مدیریت کند.
6. metering، outbox، restart، outage، replay، ACK، revoke و quota exhaustion آزموده شوند.
7. فقط پس از آزمون موفق و مجوز rollout، یک گروه آزمایشی جدا منتقل شود؛ legacy peers تا زمان اثبات سازگاری از V1 خارج نشوند.
8. rollback باید agent و registry را به V1 برگرداند بدون حذف یا تغییر peerهای legacy.

## 11. آزمون‌های اجباری

- [ ] agent_id نامجاز یا interface اشتباه رد شود.
- [ ] امضای درخواست/پاسخ نامعتبر، timestamp خارج از پنجره و replay رد شود.
- [ ] registry revision قدیمی‌تر اعمال نشود.
- [ ] pagination ناقص باعث حذف peerهای غایب نشود.
- [ ] peer_ref تکراری، public key تکراری و IP تکراری fail-closed شود.
- [ ] mismatch peer_ref/public_key در حذف خودکار انجام نشود و incident بسازد.
- [ ] peer legacy و integrated با شناسه‌های داخلی هم‌شکل قاطی نشوند.
- [ ] usage event از agent دیگر یا peer دیگر رد شود.
- [ ] duplicate event فقط یک بار در UsageRecord اثر بگذارد.
- [ ] crash وسط اعمال peer با reconciliation به وضعیت درست برسد.
- [ ] outbox و baseline پس از restart/timeout داده را گم یا دوباره‌شماری نکنند.
- [ ] حذف peer واقعاً در interface مشاهده شود قبل از ACK.
- [ ] قطع backend/registry و usage در حد outage window سیاست fail-closed را اجرا کند.
- [ ] کلید per-agent rotate شود بدون آنکه تمام agentها هم‌زمان از دسترس خارج شوند.

## 12. تصمیم‌های باز

1. آیا هر VPN host یک agent_id و کلید مستقل دارد؟ پیشنهاد قطعی: بله.
2. آیا پاسخ registry با HMAC مستقل یا امضای نامتقارن تأیید شود؟ پیشنهاد: امضای پاسخ با کلید اختصاصی server signing و public key pin شده در agent، اگر عملیات توزیع/rotation آن قابل مدیریت باشد؛ در غیر این صورت HMAC مشتق‌شدهٔ مستقل per-agent با TLS و rotation دقیق.
3. سقف batch و pagination باید بر اساس تعداد peer و زمان reconcile تعیین شود؛ حد فعلی V1 یعنی 2000 رکورد نباید کورکورانه به V2 منتقل شود.
4. تصمیم IPv6 و مدل چند interface/server قبل از تثبیت schema نهایی شود.

## 13. نتیجهٔ این گام

- قرارداد فعلی V1 فقط legacy است و نباید برای Integrated VPN با افزودن چند فیلد بدون نسخه‌بندی تغییر کند.
- V2 با peer_ref مستقل، agent identity مستقل، پاسخ احرازاصالت‌شده، revision، usage attribution و ACK idempotent پیشنهاد می‌شود.
- agent V2 باید ابتدا shadow و سپس در محیط آزمایشگاهی اجرا شود.
- هنوز هیچ کد، migration، secret، agent یا VPN host تغییر نکرده است.
