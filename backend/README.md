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

در `.env` یک `API_KEY` طولانی و یک کلید Fernet مستقل برای `ENCRYPTION_KEY` قرار دهید. برای تولید کلید Fernet:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

اجرای محلی:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

در حالت پیش‌فرض `MOCK_MODE=true` است. کانفیگ تولیدشده در این حالت صرفاً برای تست قالب و مسیر برنامه است و به سرور واقعی وصل نمی‌شود. endpoint آزمایشی:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/wireguard/configs \\
  -H 'Content-Type: application/json' \\
  -H 'X-API-Key: YOUR_API_KEY' \\
  -d '{"client_name":"RMA test device"}'
```

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
