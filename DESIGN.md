# طراحی دقیق سرویس KMS — دخل (Dakhl)

این سند طراحی دقیق و **کامل برای پیاده‌سازی** سرویس KMS خودمیزبان (نه HashiCorp Vault) را مشخص می‌کند. با توجه به حداقل‌گرایی سخت‌افزاری (هدف: ۱ vCPU / ۱ گیگ رم) و نیاز واقعی محدود (فقط wrap/unwrap DEK)، یک سرویس اختصاصی و سبک با Go انتخاب شده است.

> **وضعیت:** این سند برای پیاده‌سازی مستقیم کافی است. تمام الگوریتم‌ها، فرمت بایت‌ها، فلوی راه‌اندازی، و قرارداد API مشخص شده‌اند. کد موجود در همین ریپو دقیقاً بر اساس همین سند نوشته شده است؛ برای نصب و راه‌اندازی عملی [README.md](README.md) را ببینید.

---

## ۱. هدف و محدوده

سرویس KMS فقط این کارها را انجام می‌دهد:
1. تولید و wrap کردن DEK جدید برای هر شرکت (envelope encryption)
2. unwrap کردن DEK موجود در لحظه نیاز به رمزگشایی فیلد
3. چرخش (rotation) کلید ریشه (KEK)
4. ثبت audit log تغییرناپذیر (hash-chained) برای هر عملیات

هیچ منطق دیگری (احراز هویت کاربر، پردازش فاکتور و غیره) در این سرویس جایی ندارد — این تفکیک عمدی است تا سطح حمله (attack surface) این سرور حداقلی بماند.

**دو صفحه‌ی جداگانه (مهم برای پیاده‌سازی):**
- **Data-plane (شبکه، mTLS):** فقط `generate`، `unwrap`، `health` — این‌ها را سرور App صدا می‌زند.
- **Control-plane (محلی، Unix domain socket روی خود سرور KMS):** `init`، `unseal`، `seal`، `status`، `rotate-kek`، `rekey-passphrase`، `set-totp`، `break-glass`، `verify-audit` — این‌ها را فقط یک بنیان‌گذار با دسترسی SSH به سرور KMS اجرا می‌کند. هیچ‌کدام از شبکه در دسترس نیستند. (`init` و `verify-audit` مستقیم با فایل SQLite کار می‌کنند و به سرویس در حال اجرا نیاز ندارند؛ بقیه از طریق socket به پروسه‌ی serve وصل می‌شوند.)

این تفکیک یعنی App هرگز نمی‌تواند KEK را بچرخاند، unseal کند، یا break-glass بزند — حتی اگر کامل نفوذ شود.

---

## ۲. اصل تفکیک داده (نکته کلیدی معماری)

| داده | محل نگهداری | دلیل |
|---|---|---|
| `wrapped_dek` هر شرکت | دیتابیس **App** | رمزنگاری‌شده با KEK است؛ نگهداری آن در App بی‌خطر است |
| کلید ریشه (KEK) | فقط سرور **KMS** | هرگز نباید جای دیگری باشد |
| audit log عملیات کلید | فقط سرور **KMS** | جدا از دیتابیس App تا حتی ادمین App هم نتواند تغییرش دهد |
| seed های TOTP بنیان‌گذاران | فقط سرور **KMS** (رمزنگاری‌شده زیر KEK) | برای break-glass دو‌نفره |

**نکته حیاتی:** KMS هیچ رجیستری‌ای از شرکت‌ها نگه نمی‌دارد. `company_id` صرفاً یک **برچسب** است که (الف) در audit log ثبت می‌شود، (ب) کلید rate-limit است، و (ج) — مهم‌ترین — به‌صورت **AAD در رمزنگاری bind می‌شود** (بخش ۳ را ببینید). یعنی درستیِ `company_id` به‌جای بررسی در برابر یک لیست، از طریق شکست تأیید GCM تضمین می‌شود. این هم یک مسئله امنیتی را حل می‌کند و هم نیاز به دیتابیس شرکت‌ها را حذف می‌کند.

نتیجه: سرویس KMS نیازی به دیتابیس سنگین ندارد؛ یک **SQLite** محلی کافی است.

---

## ۳. اصول رمزنگاری (پایه پیاده‌سازی)

این بخش قلب سند است — بدون این، پیاده‌سازی ممکن نیست.

### ۳.۱ اندازه و منبع کلیدها
- **DEK:** ۲۵۶ بیت (۳۲ بایت)، تولیدشده از `crypto/rand`.
- **KEK:** ۲۵۶ بیت (۳۲ بایت)، تولیدشده از `crypto/rand`.
- تمام nonce ها: ۹۶ بیت (۱۲ بایت) تصادفی از `crypto/rand`، **یک nonce تازه به‌ازای هر عملیات رمزنگاری** (هرگز تکرار نشود).
- تمام encoding های متنی در API: **base64 استاندارد** (نه url-safe).

### ۳.۲ wrap کردن DEK (KEK کلید DEK را می‌پیچد)
- **الگوریتم:** AES-256-GCM.
- **AAD (داده احرازشده اضافی):** رشته‌ی canonical زیر — این همان چیزی است که `company_id` را به‌صورت رمزنگاری‌شده bind می‌کند:
  ```
  aad = company_id + "|" + kek_version   (مثلاً "comp-001|3")
  ```
  هنگام unwrap، فراخواننده باید همان `company_id` و `kek_version` را بفرستد؛ اگر هرکدام فرق کند، تأیید GCM **شکست می‌خورد** و unwrap ناموفق می‌شود. (چرا GCM+AAD به‌جای AES-KW؟ چون AES-KW خاصیت bind کردن AAD را به‌این سادگی ندارد؛ ما به این binding نیاز داریم.)
- **ساختار بایت `wrapped_dek`** (قبل از base64):
  ```
  version(1 byte = 0x01) || nonce(12) || ciphertext(32) || tag(16)   =  61 بایت
  ```
  بایت version برای انعطاف آینده (تغییر الگوریتم بدون شکستن داده قدیم).

### ۳.۳ رمزنگاری KEK روی دیسک (`encrypted_key_material`)
KEK هرگز plaintext روی دیسک نیست. با کلیدی که از passphrase راه‌اندازی (unseal) مشتق می‌شود رمز می‌شود:
- **KDF:** Argon2id (حافظه‌سخت). پارامترهای پیشنهادی متناسب با سرور ۱ گیگ: `memory = 64 MiB`, `iterations = 3`, `parallelism = 1`, خروجی ۳۲ بایت. (کتابخانه: `golang.org/x/crypto/argon2`.)
- **رمزنگاری:** AES-256-GCM با کلید مشتق‌شده.
- **ساختار بایت `encrypted_key_material`** (BLOB خام در SQLite، خودتوصیف):
  ```
  version(1 = 0x01) || kdf_id(1) || salt(16) || nonce(12) || ciphertext(32) || tag(16)
  ```
  `kdf_id` به یک مجموعه پارامتر ثابت در کد نگاشت می‌شود (مثلاً `0x01` = پارامترهای بالا) تا تغییر پارامترها در آینده داده قدیم را نشکند. `salt` تصادفی و منحصربه‌فرد به‌ازای هر نسخه KEK.

### ۳.۴ فرمت رمزنگاری فیلد در App (سند همراه — برای عدم ابهام)
App با DEK هر شرکت، فیلدهای حساس را با AES-256-GCM رمز می‌کند. AAD هویت فیلد را bind می‌کند تا یک ciphertext را نتوان به ردیف/ستون دیگر منتقل کرد:
```
field_aad = company_id + "|" + table + "|" + column + "|" + row_id
```
ساختار بایت مقدار رمزشده‌ی فیلد (قبل از ذخیره/base64):
```
version(1) || nonce(12) || ciphertext(n) || tag(16)
```
> **هشدار عملیاتی:** اگر یک DEK بیش از ~۲³² مقدار رمز کند، به‌خاطر مرز birthday در nonce تصادفی GCM باید DEK آن شرکت چرخانده شود. برای این مقیاس فعلاً بسیار دور از دسترس است، اما در طراحی چرخش DEK لحاظ شود.

---

## ۴. Schema داخلی KMS (SQLite)

پیکربندی اتصال: **WAL mode** (`PRAGMA journal_mode=WAL`)، `PRAGMA busy_timeout=5000`، `PRAGMA foreign_keys=ON`.

### جدول `kek_versions`
| فیلد | نوع | توضیح |
|---|---|---|
| `id` | integer PK | شماره نسخه KEK (از ۱) |
| `status` | text | `active` \| `retired` |
| `encrypted_key_material` | blob | طبق ساختار ۳.۳ |
| `created_at` | text | RFC3339 UTC |
| `retired_at` | text \| null | |

**قید یک KEK فعال (اجبار در سطح دیتابیس):**
```sql
CREATE UNIQUE INDEX one_active_kek ON kek_versions(status) WHERE status = 'active';
```
نسخه‌های `retired` **حذف نمی‌شوند** — چون ممکن است هنوز DEKهای قدیمی زیر آن‌ها wrap شده باشند.

### جدول `admin_totp`
| فیلد | نوع | توضیح |
|---|---|---|
| `id` | integer PK | |
| `label` | text (UNIQUE) | مثلاً "founder_a" / "founder_b" |
| `encrypted_seed` | blob | seed مربوط به TOTP، رمزشده زیر KEK (ساختار مثل wrap: `version(1) || nonce(12) || ct || tag(16)`) |
| `kek_version` | integer | نسخه KEKی که seed زیر آن رمز شده (FK به `kek_versions`) |

**AAD رمزنگاری seed (اصلاحیه — قبلاً تعریف نشده بود):**
```
totp_aad = "totp" + "|" + label + "|" + kek_version
```
**نکته اصلاحی مهم:** هنگام `rotate-kek`، تمام seed ها باید در **همان transaction** با KEK جدید دوباره رمز شوند (`kek_version` به‌روز شود)؛ وگرنه برای همیشه به یک نسخه‌ی retired گره می‌خورند و پس از حذف نهایی آن نسخه، break-glass از کار می‌افتد.

### جدول `audit_log` (append-only، hash-chained)
| فیلد | نوع | توضیح |
|---|---|---|
| `id` | integer PK | |
| `ts` | text | RFC3339 UTC با دقت نانوثانیه |
| `operation` | text | `init` \| `generate_dek` \| `unwrap_dek` \| `rotate_kek` \| `break_glass` \| `set_totp` \| `unseal` \| `seal` \| `rekey_passphrase` |
| `company_id` | text | برای عملیات غیرشرکتی (`init`/`rotate_kek`/`set_totp`/`unseal`/`seal`/`rekey_passphrase`) **مقدار واقعی `-`** ذخیره می‌شود (نه NULL) تا دقیقاً با preimage هش یکی باشد |
| `kek_version` | integer | |
| `result` | text | `success` \| `denied` \| `error` |
| `prev_hash` | text | هش رکورد قبلی (۶۴ کاراکتر hex) |
| `hash` | text | طبق فرمول زیر |

**فرمول hash (canonical و بدون ابهام — با جداکننده `|`):**
```
preimage = prev_hash + "|" + id + "|" + ts + "|" + operation + "|" +
           (company_id or "-") + "|" + kek_version + "|" + result
hash = hex( SHA256(preimage) )
```
> هر فیلد به‌گونه‌ای است که نمی‌تواند خودش شامل `|` باشد (company_id شناسه‌ی تولیدی ماست، operation/result از enum ثابت‌اند، ts فرمت ثابت دارد، اعداد فقط رقم‌اند) — پس جداکننده بی‌ابهام است. کل رکورد (شامل `id` و `kek_version`) در هش پوشش داده می‌شود.

**رکورد جنسیس (اولین رکورد):** `prev_hash = "0" × 64` و `operation = "init"`.

**اجبار append-only:** کاربر دیتابیس فقط `INSERT` مجاز است. علاوه بر آن، دو trigger برای رد صریح:
```sql
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
```

**هرگز** plaintext DEK یا KEK یا seed در این جدول ذخیره نمی‌شود — فقط متادیتای عملیات.

---

## ۵. راه‌اندازی اولیه و چرخه عمر کلید (Bootstrapping)

این بخش قبلاً مفقود بود: **اولین KEK چطور به‌دنیا می‌آید؟**

### `kms init` (control-plane، سرویس هنوز serve نمی‌کند)
1. بررسی می‌کند که هیچ KEK موجود نباشد (وگرنه با خطا خارج می‌شود — idempotent guard).
2. passphrase راه‌اندازی را می‌گیرد (بخش ۸ — دو share).
3. با Argon2id کلید wrap مشتق می‌کند، KEK نسخه ۱ را تصادفی می‌سازد، آن را رمز می‌کند و با `status='active'` درج می‌کند.
4. رکورد جنسیس audit را می‌نویسد (`operation='init'`).
5. اختیاری: با `kms set-totp` دو seed بنیان‌گذاران را ثبت می‌کند (برای break-glass).

### چرخش KEK — `kms rotate-kek` (control-plane)
1. سرویس باید unsealed باشد.
2. **هر دو share دوباره وارد می‌شوند** (اصلاحیه: سرویس پس از unseal فقط KEKهای رمزگشایی‌شده را در RAM دارد، نه passphrase را؛ و چون هر نسخه salt مخصوص خود را دارد، رمز کردن KEK جدید بدون passphrase ممکن نیست). passphrase با رمزگشایی KEK فعال تأیید می‌شود.
3. KEK جدید تصادفی می‌سازد، رمز می‌کند، با `status='active'` درج می‌کند؛ نسخه قبلی به `retired` می‌رود (اما برای unwrap معتبر می‌ماند). در همان transaction، seed های TOTP زیر KEK جدید دوباره رمز می‌شوند (بخش ۴).
4. رکورد audit با `operation='rotate_kek'`.
5. کش DEK در App از طریق **انقضای TTL (حداکثر ۵ دقیقه)** بی‌اعتبار می‌شود — اصلاحیه: KMS هیچ اتصال خروجی ندارد (بخش ۱۰)، پس نمی‌تواند invalidation را push کند؛ «بی‌اعتبارسازی هنگام rotate» در App یعنی اتکا به TTL کوتاه، نه اطلاع‌رسانی فعال.

### rewrap تدریجی (job پس‌زمینه در App، نه بلادرنگ)
پس از هر rotate، یک job در App به‌مرور DEKهای شرکت‌ها را unwrap (با نسخه قدیم) و دوباره generate/wrap (با نسخه جدید) می‌کند و `wrapped_dek`/`kek_version` را در دیتابیس App به‌روز می‌کند. تدریجی و با نرخ کنترل‌شده تا فشار روی KMS نیاورد. وقتی هیچ DEKی زیر یک نسخه `retired` نماند، آن نسخه واقعاً قابل حذف است.

### تغییر passphrase بدون تغییر KEK — `kms rekey-passphrase`
**تمام نسخه‌های KEK (فعال و retired)** را با passphrase قدیم رمزگشایی و با passphrase جدید (salt های تازه) دوباره رمز می‌کند — اصلاحیه: فقط نسخه فعال کافی نیست، چون نسخه‌های retired هنوز برای unwrap لازم‌اند و باید با passphrase جدید قابل unseal باشند. برای وقتی که یک share لو رفته ولی نمی‌خواهیم KEK را بچرخانیم. وضعیت seal تغییری نمی‌کند و عملیات با `operation='rekey_passphrase'` در audit ثبت می‌شود.

---

## ۶. قرارداد API (Data-plane، mTLS)

فقط این سه endpoint روی listener شبکه‌ای هستند و همه از طریق **mTLS** (بخش ۱۰) و فقط از IP خصوصی سرور App پذیرفته می‌شوند.

### فرمت خطای مشترک
```json
{ "error": "ERROR_CODE", "message": "توضیح کوتاه" }
```
کدها: `SEALED` (۵۰۳)، `INVALID_REQUEST` (۴۰۰)، `UNWRAP_FAILED` (۴۰۰)، `KEK_VERSION_UNKNOWN` (۴۰۰)، `RATE_LIMITED` (۴۲۹)، `INTERNAL` (۵۰۰).

**اعتبارسنجی `company_id` (اصلاحیه — قبلاً فقط ادعا شده بود، اجبار نشده بود):** سرور باید `company_id` را با الگوی `^[A-Za-z0-9_-]{1,64}$` بسنجد و در غیر این صورت `INVALID_REQUEST` برگرداند. این تضمین می‌کند `|` (جداکننده AAD و preimage هش audit) هرگز در آن ظاهر نشود — بدون این اعتبارسنجی، ادعای «جداکننده بی‌ابهام است» در بخش ۴ اجرایی نیست. بدنه‌ی درخواست‌ها به حداکثر ۱۶ کیلوبایت محدود شود و timeout های خواندن/نوشتن HTTP تنظیم شوند.
> **مهم (اجتناب از oracle):** هر شکست رمزنگاری در unwrap — چه `company_id` اشتباه، چه `kek_version` غلط، چه blob خراب — همگی `UNWRAP_FAILED` عمومی برمی‌گردانند. تفکیک دقیق فقط در audit داخلی ثبت می‌شود، نه در پاسخ.

### `POST /v1/dek/generate`
تولید DEK جدید برای یک شرکت (هنگام ثبت‌نام یا rewrap).
**ورودی:**
```json
{ "company_id": "comp-001" }
```
**پاسخ (۲۰۰):**
```json
{ "wrapped_dek": "base64...", "kek_version": 3, "plaintext_dek": "base64..." }
```
> `plaintext_dek` فقط **همین یک‌بار** برگردانده می‌شود. App باید بلافاصله در RAM از آن استفاده کند و هرگز ذخیره‌اش نکند. `wrapped_dek` و `kek_version` کنار رکورد شرکت در دیتابیس App ذخیره می‌شوند. DEK با AES-256-GCM و AAD طبق ۳.۲ (با نسخه KEK فعال) wrap می‌شود.

### `POST /v1/dek/unwrap`
**ورودی:**
```json
{ "company_id": "comp-001", "wrapped_dek": "base64...", "kek_version": 3 }
```
**پاسخ (۲۰۰):**
```json
{ "plaintext_dek": "base64..." }
```
> منطق: نسخه KEK خواسته‌شده را از `kek_versions` می‌خواند (اگر نبود → `KEK_VERSION_UNKNOWN`)؛ با AAD ساخته‌شده از `company_id + "|" + kek_version` رمزگشایی می‌کند. اگر تأیید GCM شکست بخورد → `UNWRAP_FAILED` (این خودش تضمین‌کننده‌ی درستی `company_id` است). نسخه `retired` هم unwrap می‌شود. عملیات با `unwrap_dek` در audit ثبت می‌شود.

### `GET /v1/health`
برای مانیتورینگ و بررسی در‌دسترس‌بودن توسط App. بدون افشای هیچ رازی.
- unsealed: `200` → `{ "status": "ok", "sealed": false }`
- sealed: `503` → `{ "status": "sealed", "sealed": true }`

---

## ۷. کش احتیاطی DEK در App
برای کاهش رفت‌وبرگشت به KMS در هر request:
- App می‌تواند `plaintext_dek` را حداکثر **۵ دقیقه** فقط در حافظه (نه دیسک، نه Redis) به‌ازای هر شرکت کش کند.
- کش با ری‌استارت سرویس یا `rotate_kek` بی‌اعتبار می‌شود.
- هرگز در لاگ برنامه، فایل موقت، یا حافظه swap ظاهر نشود — در Go برای این بافر خاص از `mlock` (قفل صفحه حافظه) استفاده شود؛ حداقل باید از قرارگرفتن آن در ساختارهایی که سریالایز یا لاگ می‌شوند پرهیز شود. پس از پایان استفاده، بافر با صفر پر شود (zeroize).

---

## ۸. Unseal (راه‌اندازی سرویس)
- پس از هر ری‌استارت، سرویس در وضعیت **sealed** بالا می‌آید؛ data-plane پاسخ `SEALED` می‌دهد و `health` می‌گوید sealed تا unseal شود.
- Unseal فقط از طریق control-plane (Unix domain socket محلی روی خود سرور)، هرگز از شبکه.
- **طرح دو‌نفره (2-of-2):** passphrase کامل = `share_A || share_B` (ترتیب ثابت). هنگام unseal، هر بنیان‌گذار نیمه‌ی خود را وارد می‌کند. passphrase کامل به Argon2id داده می‌شود تا کلید wrap مشتق و KEK رمزگشایی شود. یک نفر به‌تنهایی نمی‌تواند unseal کند.
- **اصلاحیه — دامنه unseal:** unseal باید **تمام نسخه‌های KEK** (فعال + retired) را رمزگشایی و در RAM نگه دارد، چون unwrap ممکن است هر نسخه‌ای را بخواهد. چون هر نسخه salt جدا دارد، به‌ازای هر نسخه یک اجرای Argon2id لازم است (فقط هنگام unseal؛ کند بودنش پذیرفتنی است).
- **اصلاحیه — audit:** هر تلاش unseal (موفق: `result='success'`، passphrase غلط: `result='error'`) و همچنین `seal` در audit ثبت می‌شود — نرخ unseal ناموفق سیگنال حمله brute-force است.
  > **گزینه ارتقا:** Shamir 2-of-2 (مستقل از ترتیب، هر share کامل‌طول). برای شروع، الحاق ساده کافی است.
  > **قید عملیاتی مهم:** این طرح فقط 2-of-2 است (بدون recovery). اگر یک share گم شود، KEK غیرقابل‌بازیابی است. پس هر share باید امن بک‌آپ شود (مثلاً در Vaultwarden، هر share نزد شخص دیگر).

---

## ۹. دسترسی اضطراری (Break-glass)
**سناریو:** نیاز واقعی و نادر به رمزگشایی دستی داده یک شرکت خارج از فلوی عادی App (پشتیبانی/رفع باگ حاد). این یک کانال **ادمین**، جدا از App است.

- **پیاده‌سازی:** یک دستور control-plane محلی: `kms break-glass unwrap --company <id> --wrapped-dek <b64> --kek-version <n>`.
- **نیازمندی‌ها:** سرویس unsealed باشد **و** هر دو کد TOTP بنیان‌گذاران (`--totp-a`, `--totp-b`) در پنجره‌ی زمانی معتبر باشند (بررسی در برابر `admin_totp`، طبق RFC 6238؛ پنجره ±۱ گام ۳۰ ثانیه‌ای). دو کد باید متعلق به **دو label متمایز** باشند.
- **اصلاحیه — ضد-replay:** آخرین timestep پذیرفته‌شده به‌ازای هر label در حافظه نگه داشته می‌شود و کدِ همان گام یا قدیمی‌تر رد می‌شود — وگرنه یک کد شنودشده در پنجره‌ی ۳۰–۹۰ ثانیه‌ای قابل استفاده مجدد است. TOTP ناموفق با `result='denied'` در audit ثبت می‌شود.
- بنیان‌گذار `wrapped_dek` را از دیتابیس App می‌گیرد و به این دستور می‌دهد؛ خروجی `plaintext_dek` است.
- هر فراخوان با `operation='break_glass'` و برچسب جدا در audit ثبت می‌شود — قابل تشخیص از unwrap عادی.
- چون این کانال محلی و نیازمند SSH به سرور KMS + دو TOTP است، یک نفر یا یک App نفوذشده نمی‌تواند از آن استفاده کند.

هدف: بازدارندگی و شفافیت، نه جلوگیری صددرصدی — همان اصل واقع‌بینانه‌ی مدل تهدید: هیچ معماری یک ادمین مخرب با دسترسی مجاز را صد‌درصد متوقف نمی‌کند؛ هدف بالا بردن هزینه و ایجاد ردپا است.

---

## ۱۰. mTLS، PKI و شبکه

### PKI داخلی (برای mTLS)
- یک **CA داخلی خصوصی** ساخته می‌شود؛ کلید خصوصی CA روی هیچ‌کدام از دو سرور نگه‌داری نشود (روی یک ماشین مدیریتی آفلاین/جدا). این CA دو گواهی برگ امضا می‌کند:
  - `kms-server` (گواهی سرور، SAN = IP خصوصی KMS)
  - `app-client` (گواهی کلاینت برای سرور App)
- KMS: با `ca_cert` گواهی کلاینت را تأیید می‌کند و **علاوه بر آن** اثر انگشت (SHA-256) گواهی `app-client` را pin می‌کند (allowlist) — تا حتی گواهی بد صادرشده از همان CA هم رد شود.
- App: با `ca_cert` گواهی سرور KMS را تأیید و اثر انگشت آن را pin می‌کند.
- `TLS min version = 1.3`. گواهی‌های برگ اعتبار ۱ ساله؛ چرخش = صدور مجدد + به‌روزرسانی pin (یادآور تقویمی).

### فایروال و شبکه
- سرور KMS فقط پورت data-plane را به IP خصوصی سرور App باز می‌کند (`ufw`/`iptables`، سیاست `deny-all-except`).
- control-plane فقط روی Unix domain socket محلی است (با مجوز فایل‌سیستمی محدود به کاربر kms) — روی هیچ پورت شبکه‌ای نیست.
- SSH به سرور KMS فقط از IP مدیر یا از طریق تونل WireGuard — هرگز از اینترنت عمومی مستقیم.
- سرور KMS هیچ اتصال خروجی برقرار نمی‌کند جز NTP (برای هماهنگی زمان audit log).

---

## ۱۱. همزمانی و پایداری (نکات بحرانی پیاده‌سازی)

- **یکپارچگی زنجیره audit:** درج در `audit_log` یک عملیات read-modify-write است (خواندن آخرین `hash`، سپس درج رکورد جدید با `prev_hash` برابر آن). این باید **اتمیک** باشد: یک mutex در سطح پروسه دور این عملیات + یک transaction دیتابیس. بدون این، دو درخواست هم‌زمان زنجیره را خراب می‌کنند.
- **SQLite:** WAL mode، `busy_timeout=5000`. برای این حجم نوشتن، تک‌نویسنده‌ی SQLite کافی است.
- **بک‌آپ:** فایل SQLite (که فقط داده‌ی رمزشده و متادیتا دارد) به‌صورت دوره‌ای و رمزشده بک‌آپ شود. بدون passphrase، بک‌آپ بی‌ارزش برای مهاجم است — ولی همچنان جدا و محافظت‌شده نگه‌داری شود.
- **صفر کردن حافظه:** پس از استفاده از KEK/DEK/کلید مشتق‌شده در RAM، بافرها zeroize شوند.

---

## ۱۲. پیکربندی

### سرور KMS (متغیرهای محیطی)
- `KMS_LISTEN_ADDR` — آدرس data-plane، مثلاً `10.0.0.3:8443`
- `KMS_ADMIN_SOCKET` — مسیر Unix socket، مثلاً `/run/kms/admin.sock`
- `KMS_DB_PATH` — مسیر SQLite، مثلاً `/var/lib/kms/kms.db`
- `KMS_TLS_SERVER_CERT`, `KMS_TLS_SERVER_KEY` — گواهی/کلید سرور
- `KMS_TLS_CLIENT_CA` — CA برای تأیید کلاینت
- `KMS_TLS_CLIENT_PINS` — فهرست اثر انگشت‌های مجاز کلاینت (comma-separated SHA-256)
- `KMS_RATE_LIMIT_UNWRAP_PER_MIN` — پیش‌فرض مثلاً `120` (به‌ازای هر company_id)

### سرور App (بخش مرتبط با KMS)
- `APP_KMS_URL` — مثلاً `https://10.0.0.3:8443`
- `APP_KMS_CLIENT_CERT`, `APP_KMS_CLIENT_KEY`
- `APP_KMS_SERVER_CA`, `APP_KMS_SERVER_PIN`
- `APP_DEK_CACHE_TTL` — پیش‌فرض `5m`

**Rate-limit:** پیش‌فرض ۱۲۰ عملیات در دقیقه به‌ازای هر `company_id`. چون App خودش ۵ دقیقه کش می‌کند، نرخ پایدار بسیار کمتر است؛ عبور از این آستانه نشانه‌ی سوءاستفاده است → پاسخ `RATE_LIMITED` (۴۲۹) و ثبت audit با `result='denied'`.
- **اصلاحیه — دامنه:** همین محدودیت روی `generate` هم اعمال می‌شود (نه فقط `unwrap`) — وگرنه یک App نفوذشده می‌تواند با generate بی‌حد، دیسک/audit log را پر کند.
- **اصلاحیه — مهار حافظه:** تعداد bucket های rate-limit باید کران‌دار باشد (مثلاً حداکثر ۱۰۰هزار، با پاکسازی bucket های بی‌کار) تا company_id های ساختگی حافظه را تمام نکنند.

---

## ۱۳. وابستگی‌ها و runtime

- **زبان:** Go (کتابخانه استاندارد: `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/tls`, `crypto/sha256`, `database/sql`, `net`, `net/http`).
- **Argon2id:** `golang.org/x/crypto/argon2`.
- **SQLite:** ترجیحاً `modernc.org/sqlite` (pure-Go، بدون cgo — برای سرور مینیمال ساده‌تر و سبک‌تر).
- **TOTP:** یک کتابخانه‌ی سبک RFC 6238 یا پیاده‌سازی مستقیم (چند ده خط).
- بدون وابستگی سنگین دیگر — همسو با هدف حداقل‌گرایی.

---

## ۱۴. چک‌لیست پیاده‌سازی

**رمزنگاری**
- [ ] DEK و KEK هر دو ۲۵۶ بیت از `crypto/rand`
- [ ] wrap با AES-256-GCM و AAD = `company_id|kek_version`
- [ ] فرمت بایت `wrapped_dek` طبق ۳.۲ (version||nonce||ct||tag)
- [ ] KEK روی دیسک با Argon2id + AES-256-GCM، blob خودتوصیف طبق ۳.۳
- [ ] nonce تازه‌ی ۱۲ بایتی به‌ازای هر عملیات، بدون تکرار
- [ ] zeroize بافرهای کلید پس از استفاده

**دیتابیس و audit**
- [ ] فقط یک KEK فعال (partial unique index)
- [ ] نسخه‌های retired حذف نشوند تا rewrap کامل
- [ ] audit با hash chain، فرمول canonical طبق بخش ۴، رکورد جنسیس
- [ ] trigger های ضد UPDATE/DELETE روی audit_log
- [ ] mutex + transaction دور درج audit (یکپارچگی زنجیره)

**API و شبکه**
- [ ] فقط generate/unwrap/health روی شبکه؛ بقیه فقط روی Unix socket محلی
- [ ] unwrap: شکست GCM = درستی company_id؛ خطای عمومی UNWRAP_FAILED (بدون oracle)
- [ ] mTLS اجباری + pin اثر انگشت کلاینت، TLS 1.3
- [ ] rate-limit روی unwrap به‌ازای company_id، ثبت denied در audit
- [ ] health بدون افشای راز، ۵۰۳ در حالت sealed

**عملیات**
- [ ] `kms init` با idempotent guard + رکورد جنسیس
- [ ] unseal دو‌نفره (2-of-2)، فقط محلی، سرویس sealed تا unseal
- [ ] break-glass محلی با دو TOTP، برچسب جدا در audit
- [ ] job پس‌زمینه rewrap تدریجی پس از rotate
- [ ] کش DEK در App فقط RAM، TTL ۵ دقیقه، پاک‌شونده هنگام rotate
- [ ] بک‌آپ رمزشده‌ی SQLite، جدا نگه‌داری‌شده
- [ ] مانیتورینگ نرخ denied در audit (نشانه نفوذ)
- [ ] فرآیند unseal و break-glass مستند و **تمرین‌شده** (نه فقط تئوری)

---

## ۱۵. آنچه در این طراحی عمداً ساده نگه داشته شده

برای حفظ سازگاری با هدف ۱ گیگ رم / ۱ vCPU:
- بدون HSM فیزیکی (در آینده در صورت رشد قابل اضافه شدن).
- بدون clustering یا HA برای خود KMS (ریسک پذیرفته‌شده؛ اگر KMS پایین بیاید عملیات رمزنگاری/رمزگشایی متوقف می‌شود ولی داده در خطر نیست).
- بدون Vault و پیچیدگی‌های عملیاتی آن (unseal keys متعدد، policy engine و غیره) — نیاز واقعی محدود به همین عملیات ساده است.
- بدون key escrow فراتر از share های 2-of-2 — که یعنی بک‌آپ امن share ها یک الزام عملیاتی است، نه اختیاری.
