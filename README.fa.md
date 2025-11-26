# XMonitor – پنل مانیتورینگ ترافیک سرور

XMonitor یک پنل سبک و چندبخشی برای مانیتور کردن ترافیک سرورهاست که از این اجزا تشکیل شده:

- وب‌اپلیکیشن با **Flask**
- یک **ورکر پس‌زمینه** برای اتصال SSH به سرورها و خواندن ترافیک با `vnstat`
- یک **ربات تلگرام** برای مدیریت و مشاهده‌ی وضعیت از داخل تلگرام

این پروژه بیشتر برای هاستینگ‌ها و مدیران سرور طراحی شده که می‌خواهند مصرف ترافیک چند سرور مختلف را به صورت متمرکز مدیریت و کنترل کنند.

---

## قابلیت‌ها

- داشبورد وب با نقش‌های:
  - Admin (مدیر)
    پسورد دیفالت ادمین :
    Admin123
  - User (کاربر عادی)
- سیستم لایسنس:
  - پشتیبانی از نسخه‌ی آزمایشی (Trial) و کامل (Full)
- برای هر سرور:
  - تنظیم سقف مصرف ترافیک
  - تاریخ ریست ترافیک
- نمایش:
  - ترافیک لحظه‌ای
  - تاریخچه و نمونه‌های ترافیک
- ربات تلگرام:
  - لیست کردن سرورها
  - مشاهده‌ی رویدادها و هشدارها
  - تغییر محدودیت ترافیک (فقط Owner)
  - برخی تنظیمات مدیریت سرور
- ارسال نوتیف:
  - از طریق ایمیل (SMTP)
  - از طریق تلگرام (ربات)
- ورکر پس‌زمینه:
  - اتصال به سرورها از طریق SSH (کتابخانه‌ی `paramiko`)
  - خواندن داده‌ها از `vnstat`
  - ذخیره‌سازی نمونه‌ها در دیتابیس MySQL (با `SQLAlchemy`)
- استفاده از Redis برای کش کردن برخی داده‌ها و سبک کردن بار روی دیتابیس

---

## ساختار پروژه

```text
app.py                     # پنل وب Flask (SQLite + Redis + نوتیف تلگرام)
worker.py                  # ورکر SSH + vnstat (MySQL + SQLAlchemy)
bot.py                     # ربات تلگرام مستقل (python-telegram-bot)
db.py                      # ساخت engine و session برای SQLAlchemy (بر اساس DB_URL)
models.py                  # مدل‌های ORM: سرور، نمونه‌های ترافیک، رویدادها
migrate_sqlite_to_mysql.py # اسکریپت مهاجرت سرورها از SQLite به MySQL

templates/                 # تمپلیت‌های Jinja2 (داشبورد، لاگین، مدیریت و...)
static/                    # CSS و JS (از جمله اسکریپت مانیتور لایو)
.env.example               # نمونه متغیرهای محیطی (بدون اطلاعات حساس)
config.example.json        # نمونه تنظیمات لایسنس
requirements.txt           # لیست وابستگی‌های پایتون
docs/
  INSTALL.md               # راهنمای نصب و اجرای لوکال (انگلیسی)
  DEPLOYMENT.md            # راهنمای دیپلوی روی سرور (انگلیسی)
```

> نکته: برای استفاده‌ی داخلی/تجاری می‌توانید راهنماهای فارسی خودتان را هم داخل پوشه‌ی `docs/` اضافه کنید (مثلاً `INSTALL.fa.md`).

---

## پیش‌نیازها

برای اجرای کامل پنل، ورکر و ربات:

- Python 3.10 یا جدیدتر
- Git
- Redis
- SQLite (به‌صورت پیش‌فرض همراه Python موجود است)
- MySQL یا MariaDB (برای دیتابیس مانیتورینگ و ربات)
- `vnstat` روی هر سرور مقصدی که می‌خواهید مانیتور شود
- یک ربات تلگرام (Bot) و توکن آن

---

## نصب و راه‌اندازی (محیط توسعه / تست)

### ۱. کلون کردن ریپو

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/xmonitor.git
cd xmonitor
```

نام کاربری گیت‌هاب خودتان را جایگزین `YOUR_GITHUB_USERNAME` کنید.

---

### ۲. ساخت و فعال‌سازی virtualenv

```bash
python -m venv .venv
source .venv/bin/activate      # در ویندوز: .venv\Scripts\activate
```

---

### ۳. نصب وابستگی‌ها

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

### ۴. تنظیم فایل‌های `.env` و `config.json`

از روی فایل‌های نمونه، فایل‌های واقعی را بسازید:

```bash
cp .env.example .env
cp config.example.json config.json
```

سپس محتویات آن‌ها را ویرایش کنید:

#### مهم‌ترین متغیرهای `.env`

- `SECRET_KEY`  
  برای امنیت سشن و کوکی‌های Flask

- `DB_PASSWORD`  
  اگر از SQLite رمزگذاری شده استفاده می‌کنید (در غیر این صورت می‌تواند خالی بماند یا نادیده گرفته شود)

- `DB_URL`  
  آدرس اتصال SQLAlchemy برای دیتابیس MySQL/MariaDB. مثال:

  ```dotenv
  DB_URL=mysql+pymysql://xmonitor_user:STRONG_PASSWORD@127.0.0.1/xmonitor?charset=utf8mb4
  ```

- توکن‌ها و تنظیمات تلگرام:
  - `TELEGRAM_TOKEN`
  - `ADMIN_CHAT_ID`
  - `BOT_TOKEN`
  - `BOT_ADMINS`
  - `BOT_OWNER_ID`

- تنظیمات ایمیل (SMTP):
  - `EMAIL_FROM`
  - `EMAIL_PASSWORD`
  - `SMTP_SERVER`
  - `SMTP_PORT`

- تنظیمات ورکر:
  - `MONITOR_INTERVAL` (فاصله‌ی بین هر بار خواندن ترافیک، بر حسب ثانیه)
  - `SSH_KEEPALIVE` (در صورت نیاز)

- رمز اولیه Owner:
  - `OWNER_PASSWORD`

#### فایل `config.json`

- `license_key` – مقدار لایسنس
- `register_date` – تاریخ ثبت (مثلاً `"2025-01-01"`)
- `is_trial` – `true` یا `false` برای مشخص کردن اینکه لایسنس آزمایشی است یا کامل

---

## ساخت دیتابیس

### SQLite (برای پنل وب)

- برای اجرای `app.py` نیازی به ساخت دستی دیتابیس نیست.  
  اولین بار که `app.py` را اجرا کنید، فایل `database.db` به صورت خودکار ایجاد می‌شود.

### MySQL/MariaDB (برای مانیتورینگ و ربات)

در MySQL یک دیتابیس و یوزر بسازید، مثال:

```sql
CREATE DATABASE xmonitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'xmonitor_user'@'127.0.0.1' IDENTIFIED BY 'STRONG_PASSWORD';
GRANT ALL ON xmonitor.* TO 'xmonitor_user'@'127.0.0.1';
FLUSH PRIVILEGES;
```

سپس در `.env` مقدار `DB_URL` را طوری تنظیم کنید که به این دیتابیس اشاره کند:

```dotenv
DB_URL=mysql+pymysql://xmonitor_user:STRONG_PASSWORD@127.0.0.1/xmonitor?charset=utf8mb4
```

SQLAlchemy هنگام اجرای `worker.py` در صورت نیاز جدول‌ها را می‌سازد.

---

## اجرای پنل وب

```bash
source .venv/bin/activate
python app.py
```

به‌صورت پیش‌فرض پنل روی این آدرس در دسترس است:

- `http://0.0.0.0:5000`

اولین ورود به‌عنوان Owner با اطلاعاتی خواهد بود که از `.env` خوانده می‌شود (به‌خصوص `OWNER_PASSWORD`).

---

## اجرای ورکر مانیتورینگ

ورکر با SSH به سرورها وصل می‌شود، از `vnstat` ترافیک را می‌خواند و در MySQL ذخیره می‌کند:

```bash
source .venv/bin/activate
MONITOR_INTERVAL=10 python worker.py
```

نکات مهم:

- روی هر سرور مقصد:
  - `vnstat` باید نصب و کانفیگ شده باشد.
  - دسترسی SSH (یوزر و پسورد یا کلید) باید مطابق دیتای جدول `servers` باشد.
- مقدار `MONITOR_INTERVAL` بهتر است در محیط production بین ۱۰ تا ۶۰ ثانیه باشد (بسته به تعداد سرورها و منابع سرور مانیتورینگ).

---

## اجرای ربات تلگرام

```bash
source .venv/bin/activate
BOT_TOKEN=your_bot_token BOT_ADMINS=123456789 python bot.py
```

- `BOT_TOKEN` باید توکن رباتی باشد که از BotFather گرفته‌اید.
- `BOT_ADMINS` لیست آیدی عددی ادمین‌ها است (با کاما جدا شوند).
- `BOT_OWNER_ID` آیدی عددی Owner اصلی است.

با توجه به پیاده‌سازی فعلی، دستورات معمول می‌تواند شامل این‌ها باشد:

- `/start` – معرفی اولیه ربات
- `/list` – نمایش لیست سرورها
- `/events` – نمایش رویدادها/هشدارهای اخیر
- `/setlimit` – تغییر محدودیت ترافیک (فقط برای Owner)
- `/edit` – ویرایش تنظیمات سرور

---

## مهاجرت از SQLite به MySQL

اگر قبلاً سرورها را در `database.db` (SQLite) تعریف کرده‌اید و حالا می‌خواهید آن‌ها را به MySQL منتقل کنید، می‌توانید از اسکریپت `migrate_sqlite_to_mysql.py` استفاده کنید:

```bash
source .venv/bin/activate
export DB_URL='mysql+pymysql://user:pass@127.0.0.1/xmonitor?charset=utf8mb4'
python migrate_sqlite_to_mysql.py /path/to/database.db
```

این اسکریپت:

- در MySQL، جدول `servers` را می‌سازد (اگر نباشد)
- تمام رکوردهای جدول `servers` در SQLite را به MySQL کپی می‌کند

---

## دیپلوی روی سرور (Production)

برای استفاده‌ی واقعی روی یک سرور لینوکسی (مثلاً Ubuntu 22.04):

پیشنهاد می‌شود:

- اجرای Flask با `gunicorn`
- استفاده از `nginx` به‌عنوان reverse proxy و برای SSL
- ساخت سرویس‌های `systemd` برای:
  - وب‌اپ (gunicorn)
  - ورکر (`worker.py`)
  - ربات (`bot.py`)

یک نمونه‌ی کامل کانفیگ‌ها (service units و nginx config) در فایل زیر (به زبان انگلیسی) آمده:

- `docs/DEPLOYMENT.md`

با توجه به آن راهنما می‌توانید:

1. یوزر اختصاصی برای پروژه بسازید (`xmonitor`).
2. پروژه را در `/opt/xmonitor` کلون کنید.
3. virtualenv بسازید و وابستگی‌ها را نصب کنید.
4. سرویس‌های systemd را تعریف و فعال کنید.
5. nginx را تنظیم و برای دامنه‌ی خودتان فعال کنید.
6. در صورت نیاز TLS/SSL را با Let’s Encrypt تنظیم کنید.

---

## پیشنهاد منابع سخت‌افزاری

این اعداد تقریبی هستند و بستگی به شرایط واقعی دارند:

- تا حدود **۲۰ سرور مانیتور شده**:
  - 1 vCPU
  - 1–2 GB RAM
  - 20GB SSD

- حدود **۲۰ تا ۱۰۰ سرور**:
  - 2 vCPU
  - 4 GB RAM

- بیش از **۱۰۰ سرور**:
  - 4+ vCPU
  - 8+ GB RAM
  - تنظیم و بهینه‌سازی MySQL (bufferها، cacheها و…)

همچنین:

- اگر `MONITOR_INTERVAL` را خیلی کم (مثلاً ۱ ثانیه) بگذارید، مصرف منابع بالا می‌رود.
- اگر سرورها زیاد باشند و شبکه کند باشد، Threadها زمان بیشتری درگیر می‌شوند.

---

## نکات امنیتی و گیت

- فایل‌های زیر نباید داخل Git commit شوند:
  - `.env`
  - هر نوع فایل `.env.*`
  - `config.json`
  - `database.db`
  - لاگ‌ها (مثل `app.log`)
- یک فایل `.gitignore` مناسب در پروژه قرار داده شده که این موارد را پوشش می‌دهد.

---

## لایسنس

در حال حاضر نوع لایسنس این پروژه بسته به تصمیم شماست.  
برای اوپن‌سورس کردن رسمی، می‌توانید یکی از لایسنس‌های شناخته‌شده (مثل MIT, Apache-2.0 و…) را انتخاب کنید و یک فایل `LICENSE` در روت پروژه قرار دهید.
