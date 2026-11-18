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

## نتایج Ticker زنده و کیفیت قیمت — اجرای ۱۸ نوامبر ۲۰۲۶

اجرای کامل ممیزی شامل دریافت Ticker عمومی هر کاندید و ثبت bid/ask بود:
- اجرای CI: [44265107643](https://github.com/vahid250/azmayesh/actions/runs/44265107643) — `success`.
- زمان نمونه‌برداری: حدود `2026-11-18T08:13:33Z` تا `08:13:34Z`.
- برای هر سه API کاتالوگ و همه پنج درخواست Ticker کاندید، HTTP 200 دریافت شد.

### USDT/USD

| منبع | Bid | Ask | Midpoint (USD/USDT) | Spread |
|---|---:|---:|---:|---:|
| Coinbase | 0.99889 | 0.99890 | 0.998895 | 0.1001 bps |
| Kraken | 0.99886 | 0.99887 | 0.998865 | 0.1001 bps |
| Bitstamp | 0.99885 | 0.99886 | 0.998855 | 0.1001 bps |

- اختلاف نسبی midpoint بین دو منبع اصلی Coinbase و Kraken: حدود **0.3004 bps**.
- بیشترین اختلاف بین هر جفت از سه منبع: حدود **0.4005 bps**.
- هر دو مقدار بسیار پایین‌تر از آستانه 150 bps فعلی هستند.
- در این snapshot، Coinbase بالاترین USD به‌ازای هر USDT را نشان می‌دهد؛ بنابراین با سیاست فعلی display، منبع نمایشی Coinbase خواهد بود، درحالی‌که مبلغ فاکتور بر اساس میانگین دو منبع اصلی محاسبه می‌شود.

### USDC/USD

| منبع | Bid | Ask | Midpoint (USD/USDC) | Spread |
|---|---:|---:|---:|---:|
| Kraken | 0.99970000 | 0.99980000 | 0.99975000 | 1.0003 bps |
| Bitstamp | 0.99974 | 0.99982 | 0.99978 | 0.8002 bps |

اختلاف نسبی midpoint این دو منبع حدود **0.3001 bps** است؛ اما Coinbase در snapshot کاتالوگ جفت مستقیم USDC/USD ارائه نکرد. دو منبع برای سیاست فعلی کافی نیستند و Bitstamp نیز تا تعیین تکلیف مجوز تجاری قابل استفاده در محصول نیست.

### محدودیت تفسیر

این اعداد یک snapshot عمومی و کوتاه‌مدت‌اند، نه تضمین نقدشوندگی یا قیمت اجرای سفارش. Ticker بهترین bid/ask را می‌دهد، اما عمق دفتر سفارش، حجم قابل‌اجرا، slippage، پایداری چندروزه و مجوز مصرف تجاری را اثبات نمی‌کند. هیچ سفارش واقعی ثبت نشده و هیچ‌یک از این نتایج به‌تنهایی مجوز فعال‌سازی PaymentAsset یا mapping نیست.

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



## بررسی منابع جایگزین Bitstamp — ۱۸ نوامبر ۲۰۲۶

هدف این بررسی یافتن جایگزینی برای مصرف تجاری در R&MA است، نه صرفاً API عمومی که از نظر فنی پاسخ می‌دهد. وجود endpoint عمومی به‌تنهایی مجوز تجاری محسوب نمی‌شود.

### نامزدهای صرافی مستقیم

| منبع | شواهد فنی بازار | وضعیت مجوز تجاری بر اساس اسناد عمومی | تصمیم فعلی |
|---|---|---|---|
| Gemini | فهرست رسمی زنده نمادها شامل `usdtusd` و `usdcusd` است؛ هر دو دارایی جفت مستقیم USD دارند. API رسمی Ticker و Symbols مستند است. | Market Data Agreement استفاده عمومی را به personal/internal، informational و analysis محدود می‌کند؛ استفاده تجاری نیازمند تماس با `bizdev@gemini.com` و توافق جداگانه است. | بهترین نامزد مستقیم برای استعلام کتبی؛ تا مجوز کتبی غیرفعال |
| Bitfinex | فهرست رسمی جفت‌ها نمادهای `USTUSD` و `UDCUSD` را نشان می‌دهد. API ticker، bid و ask را ارائه می‌کند. نام‌های UST/UDC باید با پاسخ رسمی asset metadata و Ticker تطبیق داده شوند؛ نباید آن‌ها را بدون بررسی به USDT/USDC نگاشت کرد. | اسناد عمومی API استفاده را مشروط به API Terms می‌کنند. صفحه رسمی Market Data Terms و API Terms در بررسی متنی فعلی مفاد قابل اتکایی درباره مجوز استفاده تجاری از ticker عمومی نشان نداد؛ قرارداد Bitfinex Terminal جداگانه استفاده را به مصارف داخلی محدود و توزیع/فروش را ممنوع می‌کند، اما نباید آن قرارداد را خودکار معادل مجوز REST API فرض کرد. | نامزد فنی مشروط؛ قبل از هر استفاده تجاری باید پاسخ کتبی درباره public REST ticker و commercial internal pricing دریافت شود |
| Crypto.com Exchange | API رسمی Exchange v1 دارای endpointهای بازار و فهرست instrument است؛ لازم است وجود جفت‌های spot مستقیم USDT/USD و USDC/USD در کاتالوگ زنده جداگانه اثبات شود. | شرایط رسمی Exchange Materials، شامل API و Exchange Market Data، استفاده برای نفع اشخاص دیگر و تجاری‌سازی/سودبرداری را بدون رضایت کتبی و توافق دوجانبه منع می‌کند. | بدون توافق کتبی، گزینه مجاز محسوب نمی‌شود |
| OKX | API عمومی بازار در دسترس است. | API Agreement استفاده از Market Data را به استفاده شخصی و غیرتجاری محدود می‌کند و عرضه/نمایش به ثالث را بدون رضایت کتبی منع می‌کند. | بدون مجوز کتبی کنار گذاشته شود |

### ارائه‌دهندگان داده تجاری مستقل از صرافی

| ارائه‌دهنده | قابلیت مستند | مجوز/هزینه عمومی | تناسب با R&MA |
|---|---|---|---|
| CoinGecko API | داده تجمیعی از صدها صرافی، REST/WebSocket و قیمت‌های دارایی؛ planهای تجاری دارای داده Real-time هستند. | صفحه قیمت‌گذاری، مجوز تجاری را در پلن‌های Analyst و بالاتر اعلام می‌کند؛ قیمت اعلام‌شده Analyst برابر 129 دلار ماهانه با پرداخت ماهانه و 103.20 دلار ماهانه در پرداخت سالانه در زمان بررسی است. مجوز استاندارد اجازه استفاده از داده در محصول پولی را می‌دهد، اما فروش/بازنشر خود API یا داده خام را مجاز نمی‌کند و attribution لازم دارد. | گزینه جایگزین قراردادی محتمل برای مرجع تجمیعی/کنترل قیمت؛ نه جایگزین یک صرافی مستقل و نه منبع bid/ask صرافی واحد |
| CoinAPI | مستندات محصول، Level 1 best bid/ask، Level 2 order book و داده صدها صرافی را معرفی می‌کند. | صفحه قیمت‌گذاری، پلن Startup را 79 دلار ماهانه نشان می‌دهد؛ توضیح رسمی CoinAPI استفاده تجاری در برنامه‌های پولی را مجاز می‌داند ولی فروش مجدد/بازنشر raw data را ممنوع می‌کند. دامنه دقیق مجوز باید با پلن و کاربرد واقعی R&MA تطبیق داده شود. | گزینه فنی قوی‌تر برای داده exchange-level/quotes؛ قبل از انتخاب، پوشش دقیق USDT/USD و USDC/USD، منبع constituent، حق استفاده برای محاسبه قیمت فاکتور و نمایش نتیجه، و شرایط بازنشر باید کتبی تأیید شود |
| Kaiko | داده زنده best bid/ask، Level 1/2، stream و REST را برای بازارهای CeFi ارائه می‌کند. | قیمت‌گذاری سفارشی سازمانی و قرارداد استاندارد لایسنس دارد؛ قیمت عمومی ثابت اعلام نشده است. | گزینه سازمانی با قابلیت‌های قوی؛ احتمالاً پرهزینه‌تر، برای مرحله رشد یا نیاز به SLA بررسی شود |

### نتیجه و مسیر پیشنهادی

1. **اولویت اول برای جایگزین مستقیم صرافی:** استعلام Gemini برای مجوز کتبی استفاده تجاری از tickerهای `usdtusd` و `usdcusd`. وجود هر دو نماد در فهرست رسمی زنده تأیید شده، اما مجوز تجاری هنوز اخذ نشده است.
2. **اولویت دوم:** استعلام Bitfinex درباره مجاز بودن مصرف REST public ticker صرفاً برای محاسبه داخلی نرخ و نیز تأیید رسمی معنای نمادهای `USTUSD` و `UDCUSD`. تا دریافت پاسخ روشن، استفاده ممنوع می‌ماند.
3. **مسیر جایگزین در صورت عدم امکان اخذ مجوز از صرافی‌ها:** درخواست پیشنهاد تجاری از CoinAPI و بررسی CoinGecko Analyst/Enterprise. این مسیر نیازمند اصلاح معماری است: provider تجمیعی نباید به‌عنوان «صرافی سوم مستقل» ثبت شود؛ باید منبعی با نوع `aggregated_reference` و provenance مشخص باشد و الگوریتم consensus سه صرافی برای آن بدون بازطراحی و تست تغییر نکند.
4. Crypto.com و OKX به‌دلیل محدودیت‌های صریح تجاری در شرایط عمومی، بدون توافق کتبی در فهرست گزینه‌های اجرایی قرار نمی‌گیرند.
5. اگر هیچ منبع سوم با مجوز معتبر و کیفیت کافی پیدا نشود، سیاست امن فعلی حفظ می‌شود: وقتی Coinbase و Kraken در محدوده مجاز توافق دارند، quote با همان دو منبع اصلی ساخته شود؛ اگر اختلاف آن‌ها از آستانه عبور کند و منبع سوم مجاز و تازه موجود نباشد، صدور quote متوقف شود. هرگز داده غیرمجاز یا قیمت تخمینی به‌عنوان fallback استفاده نشود.

### منابع رسمی این بررسی

- Gemini Market Data Agreement: https://www.gemini.com/legal/market-data-agreement
- Gemini List Symbols: https://developer.gemini.com/trading/rest-api/market-data/list-symbols
- Gemini REST Market Data: https://developer.gemini.com/trading/rest-api/market-data
- Bitfinex public pair catalog: https://api-pub.bitfinex.com/v2/conf/pub:list:pair:exchange
- Bitfinex ticker documentation: https://docs.bitfinex.com/reference/rest-public-tickers
- Bitfinex API Terms: https://www.bitfinex.com/legal/general/api-terms/
- Bitfinex Market Data Terms: https://www.bitfinex.com/legal/general/market-data/
- Crypto.com Exchange API: https://exchange-developer.crypto.com/exchange/v1/docs/api/rest/crypto-com-exchange-api-v-1
- Crypto.com Exchange Terms: https://static2.crypto.com/exchange/assets/documents/tnc.pdf
- OKX API Agreement: https://www.okx.com/help/okx-api-agreement
- CoinAPI pricing: https://www.coinapi.io/products/market-data-api/pricing
- CoinAPI commercial use explanation: https://www.coinapi.io/blog/coinapi-data-commercial-use-policy
- CoinAPI data types: https://www.coinapi.io/products/flat-files/faq
- CoinGecko API pricing and commercial license: https://www.coingecko.com/en/api/pricing
- Kaiko pricing and licensing: https://www.kaiko.com/about-kaiko/pricing-and-contracts
- Kaiko data dictionary: https://docs.kaiko.com/explore-our-data/data-dictionary

این بررسی فقط مستندسازی و تحقیق است. هیچ API جدیدی به مسیر قیمت‌دهی وصل نشده، هیچ کلید یا اشتراک پولی ایجاد نشده، هیچ مجوزی فرض یا فعال نشده و هیچ PaymentAsset یا mapping تغییر نکرده است.
