# اتصال داشبورد به API

## اصل امنیتی
داشبورد در مرورگر/Telegram WebApp اجرا می‌شود؛ بنابراین **هیچ‌وقت API_KEY یا Telegram bot token را داخل HTML یا JavaScript قرار ندهید**. کلاینت فقط مقدار خام `Telegram.WebApp.initData` را در هدر `X-Telegram-Init-Data` می‌فرستد. اعتبارسنجی امضا فقط روی سرور انجام می‌شود.

## قرارداد API
Base path: `/api` (ترجیحاً reverse proxy هم‌مبدأ)

| Method | Path | کاربرد |
|---|---|---|
| GET | `/health` | وضعیت سرویس؛ عمومی، بدون ادعای اتصال |
| POST | `/api/v1/wireguard/configs` | صدور کانفیگ |
| GET | `/api/v1/wireguard/configs` | فهرست کلاینت‌ها بدون کلید خصوصی |
| GET | `/api/v1/wireguard/configs/{id}/config` | بازیابی کانفیگ رمزگشایی‌شده برای کاربر مجاز |
| GET | `/api/v1/wireguard/configs/{id}/status` | مشاهده Handshake و شمارنده‌های RX/TX سمت سرور |
| POST | `/api/v1/wireguard/configs/{id}/revoke` | ابطال Peer |

تمام مسیرهای `/api/v1` به Telegram initData معتبر نیاز دارند. API key فقط برای محیط آزمایش غیرتولیدی قابل استفاده است.

## فایل کلاینت
`frontend/rma-api.js` یک wrapper سبک است و هنوز به HTML اصلی تزریق نشده؛ ابتدا باید در HTML اصلی تگ زیر قرار گیرد و سپس فایل JS بارگذاری شود:

```html
<meta name="rma-api-base" content="/api">
<script src="/rma-api.js" defer></script>
```

استفاده نمونه در رویداد UI:

```javascript
const configs = await window.RMAApi.listWireGuardConfigs();
const result = await window.RMAApi.createWireGuardConfig("R&MA Android");
```

## محدودیت‌های فعلی
- وضعیت سرور WireGuard، handshake و RX/TX را می‌خواند؛ این موارد به‌تنهایی اثبات نمی‌کنند که DNS و HTTPS روی گوشی کار می‌کند.
- ابطال Peer فقط روی اینترفیس جاری `wg` اعمال می‌شود. برای ماندگاری پس از reboot باید تنظیمات persistent server و مدیریت فایل کانفیگ سرور در مرحله استقرار اضافه شود.
- مالکیت هر کانفیگ در جدول جداگانه به Telegram user ID متصل می‌شود؛ فهرست، بازیابی، وضعیت و ابطال فقط برای مالک همان کانفیگ مجاز است. در محیط آزمایش API key همه رکوردها را به کاربر محلی `lab-local` نسبت می‌دهد.
- هنوز برای انتشار عمومی باید محدودسازی نرخ، سیاست نگهداری داده و مهاجرت نسخه‌ای پایگاه داده تکمیل شود.
- CORS عمداً باز نشده است. reverse proxy هم‌مبدأ توصیه می‌شود.
