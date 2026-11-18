# گزارش بررسی منابع بازار USDT و USDC — R&MA

تاریخ بررسی: 2026-11-18  
وضعیت: بررسی مستندات و شواهد عمومی؛ **هیچ نگاشت یا دارایی فعال نشده است.**

## خلاصه تصمیم

در این مرحله هیچ نماد معاملاتی برای پایگاه داده یا تنظیمات اجرایی تأیید نمی‌شود. مستندات عمومی، ساختار API و برخی شواهد بازار را روشن می‌کنند؛ اما برای فعال‌سازی هر نگاشت باید پاسخ زنده و رسمی فهرست بازارها، جهت base/quote، وضعیت معامله و داده bid/ask تازه همان نماد ثبت و بازبینی شود.

## ماتریس شواهد فعلی

| منبع | USDT/USD | USDC/USD | نتیجه قابل اتکا |
|---|---|---|---|
| Coinbase Exchange | صفحه رسمی بازارها، USDT-USD را با وضعیت Full Trading نشان می‌دهد | در خروجی قابل مشاهده صفحه، USDC-EUR دیده می‌شود؛ وجود یا نبود USDC-USD از این خروجی محدود قابل نتیجه‌گیری نیست | USDT-USD نامزد بررسی زنده است؛ USDC/USD هنوز تأیید نشده |
| Kraken | مستندات رسمی، AssetPairs را منبع فهرست کامل جفت‌ها معرفی می‌کند؛ ردیف زنده USDT/USD در این بررسی دریافت نشده | همان محدودیت؛ ردیف زنده USDC/USD دریافت نشده | هیچ نماد REST یا WebSocket را حدس نزنیم؛ ابتدا AssetPairs را بخوانیم و altname/wsname/base/quote را ثبت کنیم |
| Bitstamp | منبع داده ثانویه CoinPaprika، USDT/USD را گزارش می‌کند؛ این مدرک جای پاسخ رسمی Bitstamp را نمی‌گیرد | در همان منبع ثانویه، USDC/EUR و BTC/USDC دیده می‌شود؛ USDC/USD تأیید نشده | تا دریافت مجوز تجاری و بررسی رسمی، از داده Bitstamp در محصول استفاده نشود |

## نکات رسمی و فنی

### Coinbase

صفحه رسمی Exchange Markets در زمان بررسی USDT-USD را Full Trading نشان می‌دهد. همان صفحه USDT-EUR را نیز Full Trading و USDT-USDC را Limit Only نشان می‌دهد. صفحه، USDC-EUR را هم نشان می‌دهد؛ بنابراین نباید از وجود USDC-EUR، وجود USDC-USD را نتیجه گرفت.

برای تأیید اجرایی باید از فهرست محصولات عمومی/Exchange یا endpoint محصول استفاده شود و حداقل این فیلدها ثبت شوند: product_id، base_currency، quote_currency، status، trading_disabled/limit_only در صورت ارائه، و بهترین bid/ask با timestamp. نماد محصول و وضعیت باید از پاسخ همان API گرفته شود، نه از حدس نام‌گذاری.

### Kraken

مستندات رسمی Kraken می‌گوید REST AssetPairs همه جفت‌های موجود و شکل‌های مختلف نام‌گذاری را ارائه می‌کند؛ از جمله کلید REST، altname و wsname و اجزای base و quote. نماد WebSocket با نماد REST ممکن است متفاوت باشد.

برای هر دارایی، فقط ردیفی قابل قبول است که base و quote دقیقاً جفت مستقیم با USD باشند. مقدارهای alias و شناسه‌های داخلی باید همراه پاسخ خام ذخیره شوند. سپس Ticker یا feed عمومی همان نماد برای bid/ask و زمان مشاهده بررسی شود. صفحه قیمت عمومی USDC به‌تنهایی اثبات وجود جفت اسپات USDC/USD نیست.

### Bitstamp

مستندات رسمی Bitstamp endpoint فهرست بازارها را با market_symbol، base_currency، counter_currency، trading و matching معرفی می‌کند. طبق changelog رسمی 2026-11-09، trading به‌تنهایی وضعیت اجرای معامله را تضمین نمی‌کند: وضعیت عملیاتی کامل باید trading=Enabled و matching=Enabled باشد.

مستندات رسمی همچنین تصریح می‌کند شرکت‌هایی که داده بازار Bitstamp را برای مقاصد تجاری خود استفاده می‌کنند باید با partners@bitstamp.net تماس بگیرند و توافق‌نامه مجوز داده تجاری دریافت و امضا کنند. بنابراین حتی اگر نماد بازار در منبع ثانویه دیده شود، تا تعیین تکلیف کتبی مجوز، Bitstamp منبع قابل استفاده در محصول R&MA محسوب نمی‌شود.

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

