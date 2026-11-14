# R&MA Backend Lab

این پوشه نسخه آزمایشگاهی بک‌اند است و هنوز سامانه عملیاتی عمومی نیست.

## اجرای محلی

```bash
cd backend
python -m venv .venv
# فعال‌سازی محیط مجازی متناسب با سیستم‌عامل
pip install -r requirements.txt
cp .env.example .env
```

در `.env` یک `API_KEY` طولانی، توکن ربات تلگرام و یک کلید Fernet مستقل برای `ENCRYPTION_KEY` قرار دهید. مقدار پیش‌فرض برنامه `APP_ENV=production` است؛ برای تست محلی، `APP_ENV=development` را صریحاً در فایل `.env` تنظیم کنید. برای تولید کلید Fernet:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

اجرای محلی:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

در حالت پیش‌فرض `MOCK_MODE=true` است. کانفیگ تولیدشده در این حالت صرفاً برای تست قالب و مسیر برنامه است و به سرور واقعی وصل نمی‌شود. endpoint آزمایشی:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/wireguard/configs \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: YOUR_API_KEY' \
  -d '{"client_name":"RMA test device"}'
```

## ربات تلگرام و دستور /start

مسیر `POST /telegram/webhook` به‌روزرسانی‌های تلگرام را دریافت می‌کند. درخواست بدون هدر معتبر `X-Telegram-Bot-Api-Secret-Token` رد می‌شود. برای فعال‌سازی آن، این متغیرهای محیطی را در میزبان امن تنظیم کنید:

- `TELEGRAM_BOT_TOKEN`: توکن BotFather؛ فقط در secrets میزبان، نه در Git یا کد.
- `TELEGRAM_WEBHOOK_SECRET`: یک راز تصادفی جداگانه برای اعتبارسنجی webhook.
- `MINI_APP_URL`: فعلاً خالی بماند؛ فقط پس از میزبانی واقعی فرانت‌اند با HTTPS تنظیم شود.

تا زمانی که URL معتبر HTTPS وجود نداشته باشد، پاسخ `/start` پیام خوش‌آمدگویی می‌فرستد و دکمه مینی‌اپ نمایش نمی‌دهد. پس از استقرار روی میزبان HTTPS، باید webhook تلگرام با secret token تنظیم شود. در این تغییر هیچ webhook ثبت یا هیچ سرویسی deploy نشده است.

## حالت سرور واقعی

تنها پس از آماده‌سازی واقعی سرور لینوکس، نصب `wireguard-tools`، ایجاد و بالا بودن اینترفیس، فعال‌بودن IP forwarding و تنظیم NAT/firewall، می‌توان `MOCK_MODE=false` کرد و endpoint، کلید عمومی سرور و subnet واقعی را تنظیم نمود. این برنامه فعلاً Peer را با `wg set` ثبت می‌کند؛ پیکربندی routing/NAT/firewall را خودکار انجام نمی‌دهد.

حتی پس از ثبت Peer، وضعیت اینترنت تا مشاهده handshake، افزایش RX/TX و تست DNS/HTTPS تأییدشده محسوب نمی‌شود.

## امنیت

- فایل `.env`، پایگاه داده محلی و کلیدهای رمزنگاری را در Git ثبت نکنید.
- private key و متن کامل کانفیگ در دیتابیس به‌صورت Fernet-encrypted ذخیره می‌شوند.
- endpoint در حالت mock عمداً `mock.invalid` است تا به‌اشتباه به‌عنوان کانفیگ واقعی استفاده نشود.
- احراز هویت WebApp با اعتبارسنجی HMAC داده‌های Telegram initData پیاده‌سازی شده است؛ توکن ربات فقط در متغیر محیطی سرور قرار می‌گیرد.
- API key صرفاً برای محیط غیرتولیدی و تست محلی پذیرفته می‌شود؛ در APP_ENV=production مسیر API key غیرفعال است.
- فرانت‌اند باید مقدار خام Telegram.WebApp.initData را در هدر X-Telegram-Init-Data ارسال کند؛ هرگز bot token یا API key را در HTML/JavaScript قرار ندهید.
