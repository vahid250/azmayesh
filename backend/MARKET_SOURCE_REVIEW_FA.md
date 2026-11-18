# گزارش بررسی منابع بازار USDT و USDC — R&MA

تاریخ بررسی: 2026-11-18  
وضعیت: بررسی مستندات و شواهد عمومی؛ **هیچ نگاشت یا دارایی فعال نشده است.**

## خلاصه تصمیم

در این مرحله هیچ نماد معاملاتی برای پایگاه داده یا تنظیمات اجرایی تأیید نمی‌شود. مستندات عمومی، ساختار API و برخی شواهد بازار را روشن می‌کنند؛ اما برای فعال‌سازی هر نگاشت باید پاسخ زنده و رسمی فهرست بازارها، جهت base/quote، وضعیت معامله و داده bid/ask تازه همان نماد ثبت و بازبینی شود.

## ماتریس شواهد فعلی

| منبع | USDT/USD | USDC/USD | نتیجه قابل اتکا |
|---|---|---|---|
| Coinbase Exchange | ممیزی زنده API رسمی: `USDT-USD`، وضعیت `online` و `trading_disabled=false` | در پاسخ کامل فهرست محصولات، کاندید مستقیم `USDC/USD` دیده نشد | USDT/USD کاندید زنده است؛ USDC/USD فعلاً در Coinbase قابل استفاده نیست |
| Kraken | ممیزی زنده: `altname=USDTUSD`، `wsname=USDT/USD`، `base=USDT`، `quote=ZUSD`، وضعیت `online` | ممیزی زنده: `altname=USDCUSD`، `wsname=USDC/USD`، `base=USDC`، `quote=ZUSD`، وضعیت `online` | `ZUSD` alias داخلی USD در پاسخ است؛ نماد و جهت باید همراه raw fields حفظ و در تست Ticker تأیید شوند |
| Bitstamp | ممیزی زنده: `usdtusd` با `trading=Enabled` و `matching=Enabled` | ممیزی زنده: `usdcusd` با `trading=Enabled` و `matching=Enabled` | وجود و وضعیت بازار تأیید شد؛ مصرف تجاری همچنان تا تعیین تکلیف کتبی مجوز ممنوع است |

## نکات رسمی و فنی

### Coinbase

صفحه رسمی Exchange Markets در زمان بررسی USDT-USD را Full Trading نشان می‌دهد. همان صفحه USDT-EUR را نیز Full Trading و USDT-USDC را Limit Only نشان می‌دهد. صفحه، USDC-EUR را هم نشان می‌دهد؛ بنابراین نباید از وجود USDC-EUR، وجود USDC-USD را نتیجه گرفت.

برای تأیید اجرایی باید از فهرست محصولات عمومی/Exchange یا endpoint محصول استفاده شود و حداقل این فیلدها ثبت شوند: product_id، base_currency، quote_currency، status، trading_disabled/limit_only در صورت ارائه، و بهترین bid/ask با timestamp. نماد محصول و وضعیت باید از پاسخ همان API گرفته شود، نه از حدس نام‌گذاری.

### Kraken

مستندات رسمی Kraken می‌گوید REST AssetPairs همه جفت‌های موجود و شکل‌های مختلف نام‌گذاری را ارائه می‌کند؛ از جمله کلید REST، altname و wsname و اجزای base و quote. نماد WebSocket با نماد REST ممکن است متفاوت باشد.

ممیزی زنده ۱۸ نوامبر ۲۰۲۶ دو بازار مستقیم را پیدا کرد: `USDTZUSD` با `altname=USDTUSD` و `wsname=USDT/USD`، و `USDCUSD` با `altname=USDCUSD` و `wsname=USDC/USD`. در هر دو، `quote=ZUSD` و `status=online` بود. `ZUSD` به‌عنوان alias داخلی USD حفظ می‌شود؛ اسکریپت هیچ نمادی را خودکار approve نمی‌کند. درخواست Ticker برای همان altname باید bid/ask واقعی را نیز تأیید کند.

### Bitstamp

مستندات رسمی Bitstamp endpoint فهرست بازارها را با market_symbol، base_currency، counter_currency، trading و matching معرفی می‌کند. طبق changelog رسمی 2026-11-09، trading به‌تنهایی وضعیت اجرای معامله را تضمین نمی‌کند: وضعیت عملیاتی کامل باید trading=Enabled و matching=Enabled باشد.

ممیزی زنده هر دو بازار `usdtusd` و `usdcusd` را با `trading=Enabled` و `matching=Enabled` پیدا کرد. بااین‌حال مستندات رسمی تصریح می‌کند شرکت‌هایی که داده بازار Bitstamp را برای مقاصد تجاری مصرف می‌کنند باید با `partners@bitstamp.net` تماس بگیرند و توافق‌نامه مجوز داده تجاری دریافت و امضا کنند. بنابراین وجود بازار و فعال‌بودن matching به‌تنهایی مجوز استفاده در محصول R&MA نیست.

## نتایج ممیزی زنده کاتالوگ رسمی — ۱۸ نوامبر ۲۰۲۶

اسکریپت فقط‌خواندنی `backend/scripts/audit_exchange_catalogs.py` در GitHub Actions اجرا شد:
- اجرای ممیزی: [44264845244](https://github.com/vahid250/azmayesh/actions/runs/44264845244) — نتیجه `success`.
- زمان تولید گزارش: `2026-11-18T08:11:26Z`.
- هر سه endpoint کاتالوگ با HTTP 200 پاسخ دادند.
- Coinbase: یک کاندید مستقیم USD برای دارایی‌های هدف؛ `USDT-USD`.
- Kraken: دو کاندید مستقیم USD؛ `USDTZUSD` و `USDCUSD`. فیلدهای alias/جهت در گزارش حفظ شده‌اند.
- Bitstamp: دو کاندید؛ `usdtusd` و `usdcusd`، هر دو با trading و matching فعال.
- SHA-256 پاسخ‌های خام:
  - Coinbase: `c24715e9b41be048a1434313df2e18a62810e7589940c97a49ce1ae4f1f2eacf`
  - Kraken: `454e651a30413fc1423fb383f3bf8fc87830bff74672c848b256fb6caaee4876`
  - Bitstamp: `f29aac0058941cbd8ae2e965dd1cf4816731853c6e85cad278dd44aba2b8b1a3`
- گزارش JSON به‌عنوان artifact با نام `rma-market-catalog-audit` نگهداری شده است.

این اجرا فقط وجود بازار و وضعیت کاتالوگ را بررسی کرد؛ هنوز ticker bid/ask، عمق بازار، spread، مجوز Bitstamp و تأیید انسانی نهایی نیست. بنابراین هیچ mapping یا PaymentAsset فعال نمی‌شود.

## شرط‌های تأیید هر نگاشت

پیش از افزودن یا فعال‌کردن هر ردیف ExchangeMarketMapping:

1. پاسخ زنده و رسمی فهرست بازار همان صرافی با زمان دریافت و شناسه/نسخه منبع ذخیره شود.
2. base و quote دقیقاً USD و دارایی پرداخت باشند؛ جفت‌های غیرمستقیم یا متقاطع پذیرفته نیستند.
3. نماد دقیق REST و در صورت نیاز WebSocket از پاسخ رسمی استخراج شود.
4. وضعیت بازار برای معامله فعال باشد؛ در Bitstamp هر دو trading و matching باید Enabled باشند.
5. ticker/order book همان بازار bid و ask معتبر و تازه داشته باشد؛ spread، عمق و timestamp کنترل شود.
6. برای Bitstamp، مجوز استفاده تجاری پیش از مصرف داده در محصول به‌صورت کتبی تعیین تکلیف شود.
7. هر سه منبع باید برای همان دارایی، همان ارز مظنه و جهت یکسان یا جهت قابل نرمال‌سازی معتبر داشته باشند.
8. بازبینی انسانی با reviewed_at و یادداشت شواهد انجام شود. صرف وجود نماد در وب‌سایت یا منبع ثانویه مجوز فعال‌سازی نیست.

## وضعیت اجرایی R&MA

- هیچ ردیفی در exchange_market_mappings seed یا فعال نشده است.
- هیچ شبکه یا PaymentAsset جدیدی فعال نشده است.
- هیچ نرخ ساختگی یا fallback تخمینی مجاز نیست.
- endpoint عمومی باید برای دارایی فاقد هر سه نگاشت معتبر، پاسخ unavailable بدهد.
- این گزارش فقط مستندسازی بررسی است؛ migration، تغییر پایگاه داده، پرداخت یا استقرار تولیدی انجام نمی‌دهد.

## منابع

**منابع رسمی**
- Coinbase Exchange Markets: https://exchange.coinbase.com/markets
- Coinbase Exchange API: https://docs.cdp.coinbase.com/exchange/docs
- Coinbase Advanced Trade public products: https://docs.cdp.coinbase.com/api-reference/advanced-trade-api/rest-api/public/list-public-products
- Kraken API symbols and tickers: https://support.kraken.com/in/articles/360000920306-api-symbols-and-tickers
- Kraken public AssetPairs: https://api.kraken.com/0/public/AssetPairs
- Kraken public Ticker: https://api.kraken.com/0/public/Ticker
- Bitstamp API documentation and commercial data licensing notice: https://www.bitstamp.net/api/

**منبع ثانویه — فقط برای سرنخ، نه تأیید نهایی**
- CoinPaprika Bitstamp markets: https://coinpaprika.com/exchange/Bitstamp

