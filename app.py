import asyncio
import datetime
import ipaddress
import json
import logging
import os
import platform
import random
import re
import secrets
import requests
import smtplib
import sqlite3
import subprocess
import threading
import time
from email.mime.text import MIMEText
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
import paramiko
import redis
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, MessageHandler, filters
from werkzeug.security import check_password_hash, generate_password_hash

import esxi_manager

# بارگذاری متغیرهای محیطی
load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
RECEIPT_UPLOAD_DIR = os.path.join("static", "uploads", "receipts")
os.makedirs(RECEIPT_UPLOAD_DIR, exist_ok=True)
DEFAULT_TELEGRAM_PROXY = os.getenv("TELEGRAM_PROXY", "socks5://CBZBWfWxTa:YZSIy26WQC@sub.rskhi.ir:12012")

# تنظیمات لاگ
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)

RESET_DATE_RE = re.compile(r"^\d{4}-\d{2}$")
IFACE_RE = re.compile(r"^[a-zA-Z0-9_.:-]+$")

# Redis cache
cache = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=int(os.getenv("REDIS_PORT", "6379")), db=0)


def invalidate_servers_cache():
    """Remove all cached server lists for all users/roles."""
    try:
        for key in cache.scan_iter("servers:*"):
            cache.delete(key)
    except Exception:
        pass


DEFAULT_ENV = {
    "SECRET_KEY": "change_this_secret_key_in_production",
    "TELEGRAM_TOKEN": "YOUR_BOT_TOKEN",
    "ADMIN_CHAT_ID": "YOUR_CHAT_ID",
    "EMAIL_FROM": "YOUR_E-MAIL",
    "EMAIL_PASSWORD": "Email_password",
    "SMTP_SERVER": "smtp.mailersend.net",
    "SMTP_PORT": "587",
    "DB_PASSWORD": "",
    "OWNER_PASSWORD": "ChangeMeOwner123!",
}

if not os.path.exists(".env"):
    with open(".env", "w", encoding="utf-8") as f:
        for key, value in DEFAULT_ENV.items():
            f.write(f"{key}={value}\n")
    logging.info("فایل .env با مقادیر پیش‌فرض ساخته شد.")

load_dotenv()

app.secret_key = os.getenv("SECRET_KEY", "change_this_secret_key_in_production")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
ADMIN_CHAT_ID = str(os.getenv("ADMIN_CHAT_ID", "")).strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.mailersend.net")
try:
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or 587)
except ValueError:
    SMTP_PORT = 587
CONFIG_FILE = "config.json"
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
OWNER_PASSWORD = os.getenv("OWNER_PASSWORD", "ChangeMeOwner123!")


def verify_password(stored_password: str, provided_password: str) -> bool:
    if not stored_password or provided_password is None:
        return False
    if stored_password.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_password, provided_password)
    return stored_password == provided_password


def detect_iface(ssh) -> str:
    try:
        _, stdout, _ = ssh.exec_command("ip -o -4 route show to default | awk '{print $5}'")
        nic = stdout.read().decode().strip().splitlines()[0] if stdout else ""
        if nic and IFACE_RE.match(nic):
            return nic
        return "ens34"
    except Exception:
        return "ens34"


def build_vnstat_monthly_cmd(nic: str, reset_date: str | None) -> str:
    safe_nic = nic if IFACE_RE.match(nic or "") else "ens34"
    if reset_date and RESET_DATE_RE.match(str(reset_date).strip()):
        clean_date = str(reset_date).strip()
        return (
            f"vnstat -m -i {safe_nic} | awk '/[0-9]{{4}}-[0-9]{{2}}/ && $1 >= \"{clean_date}\" && !/estimated/ "
            "{if ($9 == \"TiB\") sum += $8 * 1024; else sum += $8} END {print sum ? sum : 0}'"
        )
    return (
        f"vnstat -m -i {safe_nic} | awk '/[0-9]{{4}}-[0-9]{{2}}/ && !/estimated/ "
        "{if ($9 == \"TiB\") sum += $8 * 1024; else sum += $8} END {print sum ? sum : 0}'"
    )


def get_db_connection():
    conn = sqlite3.connect("database.db", check_same_thread=False)
    if DB_PASSWORD:
        try:
            conn.execute("PRAGMA key = ?", (DB_PASSWORD,))
        except Exception:
            pass
    return conn


def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            telegram_chat_id TEXT,
            active INTEGER DEFAULT 1
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS esxi_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            ip TEXT,
            port INTEGER DEFAULT 22,
            username TEXT DEFAULT 'root',
            password TEXT,
            default_datastore TEXT DEFAULT 'datastore1',
            default_network TEXT DEFAULT 'VM Network',
            template_vmdk TEXT,
            created_at TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS ip_pool (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            netmask TEXT DEFAULT '24',
            gateway TEXT,
            ipv6 TEXT DEFAULT NULL,
            ipv6_gateway TEXT DEFAULT NULL,
            mac_address TEXT DEFAULT NULL,
            is_allocated INTEGER DEFAULT 0,
            server_id INTEGER DEFAULT NULL,
            notes TEXT DEFAULT NULL,
            created_at TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY,
            name TEXT,
            ip TEXT,
            username TEXT,
            password TEXT,
            traffic_limit REAL DEFAULT 0,
            telegram_chat_id TEXT,
            active INTEGER DEFAULT 1,
            traffic_usage REAL DEFAULT 0,
            reset_date TEXT DEFAULT NULL,
            updated_at TEXT DEFAULT NULL,
            esxi_host_id INTEGER DEFAULT NULL,
            vmid INTEGER DEFAULT NULL,
            vm_name TEXT DEFAULT NULL,
            is_suspended INTEGER DEFAULT 0,
            netmask TEXT DEFAULT '24',
            gateway TEXT DEFAULT NULL,
            ipv6 TEXT DEFAULT NULL,
            ipv6_gateway TEXT DEFAULT NULL,
            extra_ips TEXT DEFAULT NULL,
            mac_address TEXT DEFAULT NULL
        )"""
    )
    c.execute("""CREATE TABLE IF NOT EXISTS user_servers (user_id INTEGER, server_id INTEGER, UNIQUE(user_id, server_id))""")
    c.execute(
        """CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY,
            license_key TEXT UNIQUE,
            expiry_date TEXT,
            trial_active INTEGER DEFAULT 0
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS telegram_users (
            chat_id TEXT PRIMARY KEY,
            first_name TEXT,
            username TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY,
            chat_id TEXT,
            message_id INTEGER,
            message_text TEXT,
            status TEXT DEFAULT 'open'
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS traffic_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER,
            usage_gib REAL,
            created_at TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER,
            level TEXT,
            message TEXT,
            created_at TEXT,
            notified INTEGER DEFAULT 0
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS vps_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            name_fa TEXT,
            name_en TEXT,
            cpus INTEGER DEFAULT 1,
            ram_gb INTEGER DEFAULT 2,
            disk_gb INTEGER DEFAULT 20,
            traffic_gib REAL DEFAULT 1000,
            price_toman INTEGER DEFAULT 1190000,
            badge TEXT DEFAULT NULL,
            active INTEGER DEFAULT 1
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS web_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            subject TEXT,
            message TEXT,
            admin_reply TEXT DEFAULT NULL,
            status TEXT DEFAULT 'open',
            created_at TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS payment_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            request_type TEXT NOT NULL,
            title TEXT NOT NULL,
            amount_toman INTEGER NOT NULL DEFAULT 0,
            receipt_filename TEXT NOT NULL,
            tracking_note TEXT DEFAULT NULL,
            payload_json TEXT DEFAULT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            reject_reason TEXT DEFAULT NULL,
            decided_by TEXT DEFAULT NULL,
            decided_at TEXT DEFAULT NULL,
            telegram_msg_id INTEGER DEFAULT NULL,
            fulfillment_note TEXT DEFAULT NULL,
            created_at TEXT NOT NULL
        )"""
    )
    now_init = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    default_settings = [
        ("telegram_proxy", DEFAULT_TELEGRAM_PROXY, now_init),
        ("telegram_bot_token", TELEGRAM_TOKEN if TELEGRAM_TOKEN != "YOUR_BOT_TOKEN" else "", now_init),
        ("admin_chat_id", ADMIN_CHAT_ID if ADMIN_CHAT_ID != "YOUR_CHAT_ID" else "", now_init),
        ("bank_card_number", "6037-9975-0000-0000", now_init),
        ("bank_card_holder", "مدیریت کلود کیوب", now_init),
        ("bank_sheba", "IR000000000000000000000000", now_init),
        ("bank_name", "بانک ملی / ملت", now_init),
    ]
    for sk, sv, st in default_settings:
        c.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)", (sk, sv, st))

    c.execute("PRAGMA table_info(servers)")
    cols = [info[1] for info in c.fetchall()]
    needed_cols = [
        ("reset_date", "TEXT DEFAULT NULL"),
        ("updated_at", "TEXT DEFAULT NULL"),
        ("esxi_host_id", "INTEGER DEFAULT NULL"),
        ("vmid", "INTEGER DEFAULT NULL"),
        ("vm_name", "TEXT DEFAULT NULL"),
        ("is_suspended", "INTEGER DEFAULT 0"),
        ("netmask", "TEXT DEFAULT '24'"),
        ("gateway", "TEXT DEFAULT NULL"),
        ("ipv6", "TEXT DEFAULT NULL"),
        ("ipv6_gateway", "TEXT DEFAULT NULL"),
        ("extra_ips", "TEXT DEFAULT NULL"),
        ("mac_address", "TEXT DEFAULT NULL"),
        ("plan_name", "TEXT DEFAULT NULL"),
        ("cpus", "INTEGER DEFAULT 2"),
        ("ram_mb", "INTEGER DEFAULT 2048"),
        ("disk_gb", "INTEGER DEFAULT 20"),
    ]
    for col_name, col_type in needed_cols:
        if col_name not in cols:
            try:
                c.execute(f"ALTER TABLE servers ADD COLUMN {col_name} {col_type}")
                logging.info(f"Added column {col_name} to servers table.")
            except Exception as e:
                logging.error(f"Error adding column {col_name}: {e}")

        c.execute("PRAGMA table_info(users)")
    ucols = [info[1] for info in c.fetchall()]
    if "wallet_balance" not in ucols:
        try:
            c.execute("ALTER TABLE users ADD COLUMN wallet_balance INTEGER DEFAULT 0")
        except Exception:
            pass

    default_plans = [
        ("bronze", "سرویس برنزی", "Bronze VPS", 1, 2, 20, 1000, 1190000, "اقتصادی", 1),
        ("silver", "سرویس نقره‌ای", "Silver VPS", 2, 2, 20, 1500, 1450000, "محبوب", 1),
        ("gold", "سرویس طلایی", "Gold VPS", 4, 4, 20, 2000, 2450000, "پرفروش‌ترین", 1),
        ("platinum", "سرویس پلاتینیوم", "Platinum VPS", 6, 6, 20, 3000, 3390000, "حرفه‌ای", 1),
    ]
    for dp in default_plans:
        c.execute(
            "INSERT OR IGNORE INTO vps_plans (code, name_fa, name_en, cpus, ram_gb, disk_gb, traffic_gib, price_toman, badge, active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            dp,
        )

    default_admin_chat = ADMIN_CHAT_ID if ADMIN_CHAT_ID and ADMIN_CHAT_ID != "YOUR_CHAT_ID" else "" 
    c.execute(
        "INSERT OR IGNORE INTO users (username, password, role, telegram_chat_id, active) VALUES (?, ?, ?, ?, ?)",
        ("marmmr", generate_password_hash(OWNER_PASSWORD), "owner", default_admin_chat, 1),
    )
    c.execute(
        "INSERT OR IGNORE INTO users (username, password, role, telegram_chat_id, active) VALUES (?, ?, ?, ?, ?)",
        ("admin", generate_password_hash("admin123"), "admin", default_admin_chat, 1),
    )
    conn.commit()
    conn.close()


def init_default_license():
    if not os.path.exists(CONFIG_FILE):
        default_license_key = "DEFAULT_5_DAY_LICENSE"
        now = datetime.datetime.now()
        expiry_date = (now + datetime.timedelta(days=5)).strftime("%Y-%m-%d")
        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO licenses (license_key, expiry_date, trial_active) VALUES (?, ?, 1)",
            (default_license_key, expiry_date),
        )
        conn.commit()
        conn.close()
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "license_key": default_license_key,
                    "register_date": now.strftime("%Y-%m-%d"),
                    "expiry_date": expiry_date,
                    "is_trial": True,
                },
                f,
            )
        logging.info("لایسنس 5 روزه پیش‌فرض ثبت شد.")


init_db()
init_default_license()


def send_email(subject, body, to_email="admin@example.com"):
    if not EMAIL_FROM or EMAIL_FROM == "YOUR_E-MAIL":
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.send_message(msg)
        logging.info(f"Email sent to {to_email}: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get("role") not in ["admin", "owner"]:
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)

    return decorated_function


def owner_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get("role") != "owner":
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)

    return decorated_function


def user_can_access_server(user_id: int, role: str, server_id: int) -> bool:
    if role in ["admin", "owner"]:
        return True
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM user_servers WHERE user_id=? AND server_id=?", (user_id, server_id))
    allowed = c.fetchone() is not None
    conn.close()
    return allowed


def telegram_user_can_access_server(chat_id: str | int, server_id: int) -> bool:
    chat_str = str(chat_id).strip()
    if ADMIN_CHAT_ID and chat_str == ADMIN_CHAT_ID:
        return True
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT 1 FROM servers s "
        "JOIN user_servers us ON s.id = us.server_id "
        "JOIN users u ON us.user_id = u.id "
        "WHERE u.telegram_chat_id=? AND s.id=? AND s.active=1 AND u.active=1",
        (chat_str, server_id),
    )
    allowed = c.fetchone() is not None
    conn.close()
    return allowed


def get_remaining_time():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
            is_trial = bool(config.get("is_trial", False))
            if config.get("expiry_date"):
                expiry_date = datetime.datetime.strptime(config["expiry_date"], "%Y-%m-%d")
            else:
                register_date = datetime.datetime.strptime(config["register_date"], "%Y-%m-%d")
                days_total = 5 if is_trial else 30
                expiry_date = register_date + datetime.timedelta(days=days_total)
            time_left = expiry_date - datetime.datetime.now()
            if time_left.total_seconds() <= 0:
                return {"days": 0, "hours": 0, "minutes": 0, "seconds": 0}, is_trial
            days = time_left.days
            hours, remainder = divmod(time_left.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            return {"days": days, "hours": hours, "minutes": minutes, "seconds": seconds}, is_trial
        except Exception as e:
            logging.error(f"Error reading license config: {e}")
    init_default_license()
    return {"days": 5, "hours": 0, "minutes": 0, "seconds": 0}, True


def is_license_expired() -> bool:
    time_left, _ = get_remaining_time()
    total_seconds = (
        time_left["days"] * 86400
        + time_left["hours"] * 3600
        + time_left["minutes"] * 60
        + time_left["seconds"]
    )
    return total_seconds <= 0


def startup_check():
    time_left, is_trial = get_remaining_time()
    if not is_license_expired():
        mode = "trial" if is_trial else "license"
        logging.info(f"زمان باقی‌مونده: {time_left['days']} روز ({mode})")
        return True
    return True


# ==============================================================================
# Dynamic System Settings, Proxy-Aware Telegram Client & Payment Receipt Engine
# ==============================================================================
def get_system_settings() -> dict:
    defaults = {
        "telegram_proxy": DEFAULT_TELEGRAM_PROXY,
        "telegram_bot_token": TELEGRAM_TOKEN if TELEGRAM_TOKEN != "YOUR_BOT_TOKEN" else "",
        "admin_chat_id": ADMIN_CHAT_ID if ADMIN_CHAT_ID != "YOUR_CHAT_ID" else "",
        "bank_card_number": "6037-9975-0000-0000",
        "bank_card_holder": "مدیریت کلود کیوب",
        "bank_sheba": "IR000000000000000000000000",
        "bank_name": "بانک ملی / ملت",
    }
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT key, value FROM system_settings")
        for k, v in c.fetchall():
            if v is not None:
                defaults[k] = v
        conn.close()
    except Exception:
        pass
    return defaults


def set_system_setting(key: str, value: str):
    now_s = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value.strip(), now_s),
    )
    conn.commit()
    conn.close()


def normalize_proxy_for_requests(proxy_url: str | None) -> dict | None:
    if not proxy_url or not proxy_url.strip():
        return None
    p = proxy_url.strip()
    # Use socks5h:// so DNS resolution for api.telegram.org also routes over the SOCKS5 proxy in Iran
    if p.startswith("socks5://"):
        p_req = "socks5h://" + p[len("socks5://") :]
    else:
        p_req = p
    return {"http": p_req, "https": p_req}


def tg_api_request(method: str, data: dict | None = None, files: dict | None = None, timeout: int = 18) -> dict:
    cfg = get_system_settings()
    token = (cfg.get("telegram_bot_token") or "").strip()
    if not token or token == "YOUR_BOT_TOKEN":
        return {"ok": False, "description": "Telegram bot token not configured"}
    proxies = normalize_proxy_for_requests(cfg.get("telegram_proxy"))
    url = f"https://api.telegram.org/bot{token}/{method}"
    try:
        resp = requests.post(url, data=data or {}, files=files, proxies=proxies, timeout=timeout)
        return resp.json()
    except Exception as e:
        logging.error(f"Telegram API error ({method}): {e}")
        return {"ok": False, "description": str(e)}


def save_validated_receipt(file_storage, user_id: int) -> tuple[bool, str]:
    """Validate receipt image extension and magic bytes, then save safely."""
    if not file_storage or not file_storage.filename:
        return False, "لطفاً تصویر فیش واریزی را انتخاب و بارگذاری کنید."
    orig_name = file_storage.filename.lower()
    ext = os.path.splitext(orig_name)[1]
    if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
        return False, "فرمت فایل فیش باید یکی از فرمت‌های تصویری JPG، PNG یا WEBP باشد."
    header = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    is_jpeg = header.startswith(b"\xff\xd8\xff")
    is_png = header.startswith(b"\x89PNG\r\n\x1a\n")
    is_webp = header.startswith(b"RIFF") and b"WEBP" in header[:16]
    if not (is_jpeg or is_png or is_webp):
        return False, "فایل بارگذاری‌شده یک تصویر معتبر نیست."

    os.makedirs(RECEIPT_UPLOAD_DIR, exist_ok=True)
    safe_name = f"receipt_u{user_id}_{int(time.time())}_{secrets.token_hex(4)}{ext}"
    full_path = os.path.join(RECEIPT_UPLOAD_DIR, safe_name)
    file_storage.save(full_path)
    return True, safe_name


def format_payment_caption(req_id: int, username: str, title: str, amount_toman: int, tracking_note: str, status_line: str = "⏳ در انتظار بررسی و تایید مدیر") -> str:
    return (
        f"💳 *درخواست تراکنش و فیش واریزی #{req_id}*\n\n"
        f"👤 *کاربر:* `{username}`\n"
        f"📌 *نوع سفارش:* {title}\n"
        f"💰 *مبلغ:* `{amount_toman:,} تومان`\n"
        f"🧾 *کد پیگیری / توضیحات:* `{tracking_note or 'ثبت نشده'}`\n\n"
        f"📍 *وضعیت:* {status_line}"
    )


def notify_admin_new_receipt(req_id: int, username: str, title: str, amount_toman: int, tracking_note: str, receipt_filename: str):
    cfg = get_system_settings()
    admin_chat = (cfg.get("admin_chat_id") or "").strip()
    if not admin_chat:
        return
    caption = format_payment_caption(req_id, username, title, amount_toman, tracking_note)
    kb = {
        "inline_keyboard": [
            [
                {"text": f"✅ تایید و انجام خودکار (#{req_id})", "callback_data": f"pay_approve:{req_id}"},
                {"text": f"❌ رد درخواست با ذکر علت (#{req_id})", "callback_data": f"pay_reject:{req_id}"},
            ]
        ]
    }
    photo_path = os.path.join(RECEIPT_UPLOAD_DIR, receipt_filename)
    msg_id = None
    if os.path.exists(photo_path):
        try:
            with open(photo_path, "rb") as pf:
                res = tg_api_request(
                    "sendPhoto",
                    data={
                        "chat_id": admin_chat,
                        "caption": caption,
                        "parse_mode": "Markdown",
                        "reply_markup": json.dumps(kb),
                    },
                    files={"photo": pf},
                )
            if res.get("ok") and res.get("result"):
                msg_id = res["result"].get("message_id")
        except Exception as e:
            logging.error(f"Error sending receipt photo to Telegram: {e}")

    if not msg_id:
        res = tg_api_request(
            "sendMessage",
            data={
                "chat_id": admin_chat,
                "text": caption,
                "parse_mode": "Markdown",
                "reply_markup": json.dumps(kb),
            },
        )
        if res.get("ok") and res.get("result"):
            msg_id = res["result"].get("message_id")

    if msg_id:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE payment_requests SET telegram_msg_id=? WHERE id=?", (msg_id, req_id))
        conn.commit()
        conn.close()


def _update_admin_telegram_receipt_status(req_row: dict, final_status_line: str):
    cfg = get_system_settings()
    admin_chat = (cfg.get("admin_chat_id") or "").strip()
    msg_id = req_row.get("telegram_msg_id")
    if not admin_chat or not msg_id:
        return
    new_caption = format_payment_caption(
        req_row["id"],
        req_row["username"],
        req_row["title"],
        req_row["amount_toman"],
        req_row["tracking_note"],
        status_line=final_status_line,
    )
    empty_kb = json.dumps({"inline_keyboard": []})
    res = tg_api_request(
        "editMessageCaption",
        data={
            "chat_id": admin_chat,
            "message_id": msg_id,
            "caption": new_caption,
            "parse_mode": "Markdown",
            "reply_markup": empty_kb,
        },
    )
    if not res.get("ok"):
        tg_api_request(
            "editMessageText",
            data={
                "chat_id": admin_chat,
                "message_id": msg_id,
                "text": new_caption,
                "parse_mode": "Markdown",
                "reply_markup": empty_kb,
            },
        )


def _execute_vps_provisioning(c, user_id: int, username: str, plan_id: int, vm_label: str, root_password: str) -> str:
    c.execute(
        "SELECT id, code, name_fa, cpus, ram_gb, disk_gb, traffic_gib, price_toman FROM vps_plans WHERE id=?",
        (plan_id,),
    )
    plan_row = c.fetchone()
    if not plan_row:
        return "پلن مورد نظر یافت نشد."
    _, p_code, p_name_fa, cpus, ram_gb, disk_gb, traffic_gib, _ = plan_row
    ram_mb = int(ram_gb) * 1024
    clean_name = re.sub(r"[^a-zA-Z0-9_-]", "-", vm_label or "") or f"cc-{p_code}-{int(time.time()) % 10000}"

    c.execute(
        "SELECT id, ip_address, netmask, gateway, ipv6, ipv6_gateway, mac_address FROM ip_pool WHERE is_allocated=0 ORDER BY id ASC LIMIT 1"
    )
    pool_row = c.fetchone()
    if pool_row:
        pool_id, primary_ip, netmask, gateway, ipv6, ipv6_gw, mac_addr = pool_row
    else:
        pool_id, primary_ip, netmask, gateway, ipv6, ipv6_gw, mac_addr = (
            None,
            "در انتظار تخصیص IP",
            "25",
            "185.42.212.129",
            "",
            "",
            "",
        )

    c.execute(
        "SELECT id, ip, port, username, password, default_datastore, default_network, template_vmdk FROM esxi_hosts ORDER BY id ASC LIMIT 1"
    )
    esxi_row = c.fetchone()
    esxi_host_id = esxi_row[0] if esxi_row else None
    vmid = None

    if esxi_row and pool_row:
        netplan_yaml = esxi_manager.generate_netplan_yaml(
            primary_ipv4=primary_ip,
            gateway_ipv4=gateway,
            netmask_or_prefix=netmask or "25",
            ipv6=ipv6,
            ipv6_gateway=ipv6_gw,
        )
        meta_d, user_d, net_d = esxi_manager.generate_cloud_init_configs(
            vm_name=clean_name,
            ssh_user="root",
            ssh_password=root_password,
            netplan_yaml=netplan_yaml,
        )
        seed_iso = esxi_manager.build_cloud_init_iso(meta_d, user_d, net_d)
        ok, created_vmid, _ = esxi_manager.create_vm_on_esxi(
            esxi_host=esxi_row[1],
            esxi_port=esxi_row[2],
            esxi_user=esxi_row[3],
            esxi_password=esxi_row[4],
            vm_name=clean_name,
            cpus=cpus,
            ram_mb=ram_mb,
            disk_gb=disk_gb,
            datastore=esxi_row[5],
            template_vmdk=esxi_row[7],
            network_name=esxi_row[6],
            mac_address=mac_addr,
            seed_iso_bytes=seed_iso,
        )
        if ok:
            vmid = created_vmid

    now_iso = datetime.datetime.utcnow().isoformat()
    c.execute(
        """INSERT INTO servers (
            name, ip, username, password, traffic_limit, active, traffic_usage,
            updated_at, esxi_host_id, vmid, vm_name, is_suspended,
            netmask, gateway, ipv6, ipv6_gateway, mac_address, plan_name, cpus, ram_mb, disk_gb
        ) VALUES (?, ?, 'root', ?, ?, 1, 0, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            clean_name,
            primary_ip,
            root_password,
            traffic_gib,
            now_iso,
            esxi_host_id,
            vmid,
            clean_name,
            netmask,
            gateway,
            ipv6,
            ipv6_gw,
            mac_addr,
            p_name_fa,
            cpus,
            ram_mb,
            disk_gb,
        ),
    )
    srv_id = c.lastrowid
    if pool_id:
        c.execute("UPDATE ip_pool SET is_allocated=1, server_id=? WHERE id=?", (srv_id, pool_id))
    c.execute("INSERT OR IGNORE INTO user_servers (user_id, server_id) VALUES (?, ?)", (user_id, srv_id))
    c.execute(
        "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
        (srv_id, f"سفارش {p_name_fa} ({clean_name}) برای کاربر {username} تایید و ساخته شد.", now_iso),
    )
    invalidate_servers_cache()
    return f"سرور {clean_name} با آی‌پی {primary_ip} ساخته و فعال شد."


def _execute_traffic_recharge(c, server_id: int, add_amount: float) -> str:
    c.execute(
        """SELECT s.traffic_limit, s.traffic_usage, s.is_suspended, s.vmid, s.name, h.ip, h.port, h.username, h.password
           FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if not row:
        return "سرور مورد نظر یافت نشد."
    curr_limit, _, is_suspended, vmid, srv_name, esxi_ip, esxi_port, esxi_user, esxi_pass = row
    new_limit = (curr_limit or 0.0) + float(add_amount)
    c.execute("UPDATE servers SET traffic_limit=? WHERE id=?", (new_limit, server_id))
    if is_suspended and vmid and esxi_ip:
        esxi_manager.set_vnic_connection(esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, connected=True)
        c.execute("UPDATE servers SET is_suspended=0 WHERE id=?", (server_id,))
    now_iso = datetime.datetime.utcnow().isoformat()
    c.execute(
        "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
        (server_id, f"ترافیک سرور {srv_name} به میزان {add_amount} GiB پس از تایید واریزی شارژ شد.", now_iso),
    )
    invalidate_servers_cache()
    return f"ترافیک سرور {srv_name} به میزان {add_amount:g} GiB افزایش یافت و پورت شبکه فعال شد."


def _execute_ip_service(c, server_id: int, op_type: str) -> str:
    c.execute(
        "SELECT id, name, ip, netmask, gateway, ipv6, ipv6_gateway, extra_ips, username, password FROM servers WHERE id=?",
        (server_id,),
    )
    s_row = c.fetchone()
    if not s_row:
        return "سرور مورد نظر یافت نشد."
    srv_id, srv_name, old_ip, old_mask, old_gw, old_v6, old_v6gw, old_extras, ssh_u, ssh_p = s_row
    c.execute(
        "SELECT id, ip_address, netmask, gateway, ipv6, ipv6_gateway FROM ip_pool WHERE is_allocated=0 ORDER BY id ASC LIMIT 1"
    )
    free_ip = c.fetchone()
    if not free_ip:
        return "هیچ آی‌پی آزادی در بانک آی‌پی موجود نیست."
    pool_id, new_ip, new_mask, new_gw, new_v6, new_v6gw = free_ip
    old_extras = old_extras or ""
    if op_type == "change_ip":
        c.execute("UPDATE ip_pool SET is_allocated=0, server_id=NULL WHERE ip_address=? AND server_id=?", (old_ip, server_id))
        c.execute("UPDATE ip_pool SET is_allocated=1, server_id=? WHERE id=?", (server_id, pool_id))
        c.execute(
            "UPDATE servers SET ip=?, netmask=?, gateway=?, ipv6=?, ipv6_gateway=? WHERE id=?",
            (new_ip, new_mask, new_gw, new_v6 or old_v6, new_v6gw or old_v6gw, server_id),
        )
        extra_list = [x.strip() for x in re.split(r"[,\n]", old_extras) if x.strip()]
        netplan_yaml = esxi_manager.generate_netplan_yaml(
            primary_ipv4=new_ip,
            gateway_ipv4=new_gw,
            netmask_or_prefix=new_mask,
            extra_ips=extra_list,
            ipv6=new_v6 or old_v6,
            ipv6_gateway=new_v6gw or old_v6gw,
        )
        esxi_manager.apply_netplan_to_vm(old_ip, ssh_u, ssh_p, netplan_yaml)
        invalidate_servers_cache()
        return f"آی‌پی اصلی سرور {srv_name} به {new_ip} تغییر یافت و در Netplan اعمال شد."
    else:
        c.execute("UPDATE ip_pool SET is_allocated=1, server_id=? WHERE id=?", (server_id, pool_id))
        current_extras = [x.strip() for x in re.split(r"[,\n]", old_extras) if x.strip()]
        current_extras.append(f"{new_ip}/{new_mask}")
        updated_extras = ", ".join(current_extras)
        c.execute("UPDATE servers SET extra_ips=? WHERE id=?", (updated_extras, server_id))
        netplan_yaml = esxi_manager.generate_netplan_yaml(
            primary_ipv4=old_ip,
            gateway_ipv4=old_gw or "185.42.212.129",
            netmask_or_prefix=old_mask or "25",
            extra_ips=current_extras,
            ipv6=old_v6,
            ipv6_gateway=old_v6gw,
        )
        esxi_manager.apply_netplan_to_vm(old_ip, ssh_u, ssh_p, netplan_yaml)
        invalidate_servers_cache()
        return f"آی‌پی اضافه {new_ip} به سرور {srv_name} متصل و در Netplan فعال شد."


def decide_payment_request(req_id: int, action: str, actor_label: str, reject_reason: str | None = None) -> tuple[bool, str]:
    """
    Atomic Single-Use Approval/Rejection Lock shared by Web Panel and Telegram Bot.
    1. Immediately locks and closes the request (`WHERE id=? AND status='pending'`).
    2. Prevents any second decision in either Bot or Panel.
    3. Requires a non-empty reject_reason on rejection.
    4. Runs the fulfillment action automatically on approval.
    """
    if action not in ("approve", "reject"):
        return False, "عملیات نامعتبر است."
    clean_reason = (reject_reason or "").strip()
    if action == "reject" and not clean_reason:
        return False, "وارد کردن علت رد شدن درخواست الزامی است."

    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    new_status = "approved" if action == "approve" else "rejected"

    conn = get_db_connection()
    c = conn.cursor()
    # Step 1: Atomic single-use lock!
    c.execute(
        """UPDATE payment_requests
           SET status=?, decided_by=?, decided_at=?, reject_reason=?
           WHERE id=? AND status='pending'""",
        (new_status, actor_label, now_str, clean_reason if action == "reject" else None, req_id),
    )
    if c.rowcount == 0:
        conn.close()
        return False, "این درخواست قبلاً تعیین تکلیف و بسته شده است و امکان تغییر مجدد آن وجود ندارد."
    conn.commit()

    # Step 2: Fetch request details to fulfill or notify
    c.execute(
        """SELECT p.id, p.user_id, p.username, p.request_type, p.title, p.amount_toman,
                  p.tracking_note, p.payload_json, p.telegram_msg_id, u.telegram_chat_id
           FROM payment_requests p
           LEFT JOIN users u ON p.user_id = u.id
           WHERE p.id=?""",
        (req_id,),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "درخواست یافت نشد."

    req_info = {
        "id": row[0],
        "user_id": row[1],
        "username": row[2],
        "request_type": row[3],
        "title": row[4],
        "amount_toman": row[5],
        "tracking_note": row[6],
        "payload_json": row[7],
        "telegram_msg_id": row[8],
        "user_chat_id": row[9],
    }

    if action == "approve":
        rtype = req_info["request_type"]
        payload = {}
        try:
            payload = json.loads(req_info["payload_json"] or "{}")
        except Exception:
            payload = {}

        if rtype == "wallet_charge":
            c.execute(
                "UPDATE users SET wallet_balance = COALESCE(wallet_balance, 0) + ? WHERE id=?",
                (req_info["amount_toman"], req_info["user_id"]),
            )
            fulfillment_note = f"کیف پول کاربر {req_info['username']} به مبلغ {req_info['amount_toman']:,} تومان شارژ شد."
        elif rtype == "buy_vps":
            fulfillment_note = _execute_vps_provisioning(
                c,
                req_info["user_id"],
                req_info["username"],
                int(payload.get("plan_id", 1)),
                payload.get("vm_name", ""),
                payload.get("root_password", "Ubuntu@12345"),
            )
        elif rtype == "recharge_traffic":
            fulfillment_note = _execute_traffic_recharge(
                c,
                int(payload.get("server_id", 0)),
                float(payload.get("add_amount", 100)),
            )
        elif rtype in ("change_ip", "add_extra_ip"):
            fulfillment_note = _execute_ip_service(
                c,
                int(payload.get("server_id", 0)),
                rtype,
            )
        else:
            fulfillment_note = "تایید شد."

        c.execute("UPDATE payment_requests SET fulfillment_note=? WHERE id=?", (fulfillment_note, req_id))
        conn.commit()
        conn.close()

        status_line = f"✅ تایید و بسته شد توسط {actor_label}\n⚙️ نتیجه: {fulfillment_note}"
        _update_admin_telegram_receipt_status(req_info, status_line)

        if req_info["user_chat_id"]:
            tg_api_request(
                "sendMessage",
                data={
                    "chat_id": req_info["user_chat_id"],
                    "text": (
                        f"✅ *درخواست شماره #{req_id} شما تایید شد!*\n\n"
                        f"📌 *سفارش:* {req_info['title']}\n"
                        f"💰 *مبلغ:* `{req_info['amount_toman']:,} تومان`\n"
                        f"⚙️ *نتیجه عملیات:* {fulfillment_note}"
                    ),
                    "parse_mode": "Markdown",
                },
            )
        return True, f"درخواست #{req_id} بسته شد و عملیات انجام گردید: {fulfillment_note}"

    else:
        fulfillment_note = f"رد شده توسط {actor_label} — علت: {clean_reason}"
        c.execute("UPDATE payment_requests SET fulfillment_note=? WHERE id=?", (fulfillment_note, req_id))
        conn.commit()
        conn.close()

        status_line = f"❌ رد و بسته شد توسط {actor_label}\n📝 علت رد: {clean_reason}"
        _update_admin_telegram_receipt_status(req_info, status_line)

        if req_info["user_chat_id"]:
            tg_api_request(
                "sendMessage",
                data={
                    "chat_id": req_info["user_chat_id"],
                    "text": (
                        f"❌ *درخواست شماره #{req_id} شما رد شد.*\n\n"
                        f"📌 *سفارش:* {req_info['title']}\n"
                        f"💰 *مبلغ:* `{req_info['amount_toman']:,} تومان`\n"
                        f"📝 *علت رد شدن:* {clean_reason}"
                    ),
                    "parse_mode": "Markdown",
                },
            )
        return True, f"درخواست #{req_id} با ذکر علت رد و بسته شد."


@app.context_processor
def inject_user_wallet():
    balance = 0
    pending_payments_count = 0
    sys_cfg = get_system_settings()
    if "user_id" in session:
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT wallet_balance FROM users WHERE id=?", (session["user_id"],))
            row = c.fetchone()
            if row and row[0] is not None:
                balance = int(row[0])
            if session.get("role") in ["admin", "owner"]:
                c.execute("SELECT COUNT(*) FROM payment_requests WHERE status='pending'")
                pending_payments_count = c.fetchone()[0] or 0
            conn.close()
        except Exception:
            pass
    return {
        "user_wallet": balance,
        "pending_payments_count": pending_payments_count,
        "sys_cfg": sys_cfg,
        "brand_name": "کلود کیوب",
        "brand_en": "Cloud Cube",
    }


def get_active_plans():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, code, name_fa, name_en, cpus, ram_gb, disk_gb, traffic_gib, price_toman, badge, active "
        "FROM vps_plans WHERE active=1 ORDER BY price_toman ASC"
    )
    plans = [
        {
            "id": r[0],
            "code": r[1],
            "name_fa": r[2],
            "name_en": r[3],
            "cpus": r[4],
            "ram_gb": r[5],
            "disk_gb": r[6],
            "traffic_gib": r[7],
            "price_toman": r[8],
            "badge": r[9],
            "active": bool(r[10]),
        }
        for r in c.fetchall()
    ]
    conn.close()
    return plans


@app.route("/", methods=["GET", "POST"])
def landing():
    if request.method == "POST":
        return login()
    plans = get_active_plans()
    return render_template("landing.html", plans=plans, logged_in=("user_id" in session), username=session.get("username", ""))


@app.route("/login", methods=["GET", "POST"])
def login():
    error_msg = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, username, password, role, active FROM users WHERE username=? AND active=1", (username,))
        user = c.fetchone()
        if user and verify_password(user[2], password):
            if not str(user[2]).startswith(("scrypt:", "pbkdf2:")):
                c.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(password), user[0]))
                conn.commit()
            conn.close()
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]
            logging.info(f"کاربر {username} وارد شد.")
            return redirect(url_for("dashboard"))
        conn.close()
        error_msg = "نام کاربری یا رمز عبور اشتباه است!"
    return render_template("login.html", error_msg=error_msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    error_msg = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
        if len(username) < 3 or len(password) < 4:
            error_msg = "نام کاربری باید حداقل ۳ کاراکتر و رمز عبور حداقل ۴ کاراکتر باشد."
        else:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE username=?", (username,))
            if c.fetchone():
                conn.close()
                error_msg = "این نام کاربری قبلاً ثبت شده است."
            else:
                c.execute(
                    "INSERT INTO users (username, password, role, telegram_chat_id, active, wallet_balance) VALUES (?, ?, 'user', ?, 1, 0)",
                    (username, generate_password_hash(password), telegram_chat_id),
                )
                uid = c.lastrowid
                conn.commit()
                conn.close()
                session["user_id"] = uid
                session["username"] = username
                session["role"] = "user"
                return redirect(url_for("dashboard"))
    return render_template("register.html", error_msg=error_msg)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("landing"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST":
        telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
        password = request.form.get("password", "").strip()
        if password:
            c.execute(
                "UPDATE users SET telegram_chat_id=?, password=? WHERE id=?",
                (telegram_chat_id, generate_password_hash(password), session["user_id"]),
            )
        else:
            c.execute("UPDATE users SET telegram_chat_id=? WHERE id=?", (telegram_chat_id, session["user_id"]))
        conn.commit()
        conn.close()
        return redirect(url_for("dashboard"))

    c.execute("SELECT telegram_chat_id FROM users WHERE id=?", (session["user_id"],))
    row = c.fetchone()
    conn.close()
    current_chat_id = row[0] if row and row[0] else ""
    return render_template("profile.html", telegram_chat_id=current_chat_id)


@app.route("/dashboard")
@login_required
def dashboard():
    time_left, is_trial = get_remaining_time()
    if is_license_expired() and session.get("role") != "owner":
        if session.get("role") == "admin":
            return render_template("admin_expired.html")
        return render_template("user_expired.html")

    conn = get_db_connection()
    c = conn.cursor()
    if session["role"] in ["admin", "owner"]:
        c.execute(
            "SELECT id, name, ip, traffic_limit, traffic_usage, is_suspended, esxi_host_id, vmid, active, plan_name, cpus, ram_mb, disk_gb "
            "FROM servers ORDER BY id DESC"
        )
    else:
        c.execute(
            "SELECT s.id, s.name, s.ip, s.traffic_limit, s.traffic_usage, s.is_suspended, s.esxi_host_id, s.vmid, s.active, s.plan_name, s.cpus, s.ram_mb, s.disk_gb "
            "FROM servers s JOIN user_servers us ON s.id = us.server_id "
            "WHERE us.user_id=? ORDER BY s.id DESC",
            (session["user_id"],),
        )
    servers = c.fetchall()

    c.execute(
        "SELECT id, title, amount_toman, status, reject_reason, fulfillment_note, created_at "
        "FROM payment_requests WHERE user_id=? ORDER BY id DESC LIMIT 8",
        (session["user_id"],),
    )
    my_requests = [
        {
            "id": r[0],
            "title": r[1],
            "amount_toman": r[2],
            "status": r[3],
            "reject_reason": r[4],
            "fulfillment_note": r[5],
            "created_at": r[6],
        }
        for r in c.fetchall()
    ]
    conn.close()
    plans = get_active_plans()

    return render_template(
        "dashboard.html",
        servers=servers,
        plans=plans,
        my_requests=my_requests,
        role=session["role"],
        time_left=time_left,
        is_trial=is_trial,
    )


@app.route("/wallet", methods=["GET", "POST"])
@login_required
def wallet_page():
    conn = get_db_connection()
    c = conn.cursor()
    msg = None
    error_msg = None

    if request.method == "POST":
        try:
            amount = int(request.form.get("amount", 0) or 0)
        except ValueError:
            amount = 0
        tracking_note = request.form.get("tracking_note", "").strip()
        receipt_file = request.files.get("receipt_file")

        if amount < 50000:
            error_msg = "حداقل مبلغ شارژ کیف پول ۵۰,۰۰۰ تومان است."
        else:
            ok_file, file_or_err = save_validated_receipt(receipt_file, session["user_id"])
            if not ok_file:
                error_msg = file_or_err
            else:
                now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
                title = f"شارژ کیف پول ({amount:,} تومان)"
                c.execute(
                    """INSERT INTO payment_requests (
                        user_id, username, request_type, title, amount_toman, receipt_filename,
                        tracking_note, payload_json, status, created_at
                    ) VALUES (?, ?, 'wallet_charge', ?, ?, ?, ?, '{}', 'pending', ?)""",
                    (session["user_id"], session.get("username", "user"), title, amount, file_or_err, tracking_note, now_str),
                )
                req_id = c.lastrowid
                conn.commit()
                notify_admin_new_receipt(req_id, session.get("username", "user"), title, amount, tracking_note, file_or_err)
                msg = f"فیش واریزی شما (کد درخواست #{req_id}) ثبت و برای مدیریت ارسال شد. پس از تایید، کیف پول شما شارژ خواهد شد."

    c.execute("SELECT wallet_balance FROM users WHERE id=?", (session["user_id"],))
    row = c.fetchone()
    balance = int(row[0] or 0) if row else 0

    c.execute(
        "SELECT id, request_type, title, amount_toman, receipt_filename, tracking_note, status, reject_reason, decided_at, fulfillment_note, created_at "
        "FROM payment_requests WHERE user_id=? ORDER BY id DESC LIMIT 20",
        (session["user_id"],),
    )
    history = [
        {
            "id": r[0],
            "request_type": r[1],
            "title": r[2],
            "amount_toman": r[3],
            "receipt_filename": r[4],
            "tracking_note": r[5],
            "status": r[6],
            "reject_reason": r[7],
            "decided_at": r[8],
            "fulfillment_note": r[9],
            "created_at": r[10],
        }
        for r in c.fetchall()
    ]
    conn.close()
    return render_template("wallet.html", wallet_balance=balance, message=msg, error_msg=error_msg, history=history)


@app.route("/order_vps", methods=["GET", "POST"])
@login_required
def order_vps_page():
    plans = get_active_plans()
    selected_code = request.args.get("plan", "gold")
    error_msg = None
    success_msg = None

    if request.method == "POST":
        plan_id = int(request.form.get("plan_id", 0) or 0)
        vm_label = request.form.get("vm_name", "").strip()
        root_password = request.form.get("root_password", "").strip()
        pay_method = request.form.get("pay_method", "receipt").strip()
        tracking_note = request.form.get("tracking_note", "").strip()

        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            "SELECT id, code, name_fa, cpus, ram_gb, disk_gb, traffic_gib, price_toman FROM vps_plans WHERE id=? AND active=1",
            (plan_id,),
        )
        plan_row = c.fetchone()
        c.execute("SELECT wallet_balance FROM users WHERE id=?", (session["user_id"],))
        u_row = c.fetchone()
        balance = int(u_row[0] or 0) if u_row else 0

        if not plan_row:
            conn.close()
            error_msg = "پلن انتخاب‌شده معتبر نیست."
        elif len(root_password) < 6:
            conn.close()
            error_msg = "رمز عبور سرور باید حداقل ۶ کاراکتر باشد."
        else:
            _, p_code, p_name_fa, cpus, ram_gb, disk_gb, traffic_gib, price_toman = plan_row
            clean_name = re.sub(r"[^a-zA-Z0-9_-]", "-", vm_label) or f"cc-{p_code}-{int(time.time()) % 10000}"

            if pay_method == "wallet":
                if session.get("role") not in ["admin", "owner"]:
                    c.execute(
                        "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id=? AND COALESCE(wallet_balance, 0) >= ?",
                        (price_toman, session["user_id"], price_toman),
                    )
                    if c.rowcount == 0:
                        conn.close()
                        error_msg = f"موجودی کیف پول شما کافی نیست ({price_toman:,} تومان). لطفاً روش «کارت به کارت و آپلود فیش» را انتخاب کنید."
                        return render_template("order_vps.html", plans=plans, selected_code=selected_code, error_msg=error_msg)

                _execute_vps_provisioning(c, session["user_id"], session.get("username", "user"), plan_id, clean_name, root_password)
                conn.commit()
                conn.close()
                return redirect(url_for("dashboard"))
            else:
                receipt_file = request.files.get("receipt_file")
                ok_file, file_or_err = save_validated_receipt(receipt_file, session["user_id"])
                if not ok_file:
                    conn.close()
                    error_msg = file_or_err
                else:
                    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
                    title = f"خرید {p_name_fa} ({clean_name})"
                    payload = json.dumps({"plan_id": plan_id, "vm_name": clean_name, "root_password": root_password})
                    c.execute(
                        """INSERT INTO payment_requests (
                            user_id, username, request_type, title, amount_toman, receipt_filename,
                            tracking_note, payload_json, status, created_at
                        ) VALUES (?, ?, 'buy_vps', ?, ?, ?, ?, ?, 'pending', ?)""",
                        (session["user_id"], session.get("username", "user"), title, price_toman, file_or_err, tracking_note, payload, now_str),
                    )
                    req_id = c.lastrowid
                    conn.commit()
                    conn.close()
                    notify_admin_new_receipt(req_id, session.get("username", "user"), title, price_toman, tracking_note, file_or_err)
                    success_msg = f"سفارش {p_name_fa} و فیش واریزی شما (#{req_id}) ثبت شد. به محض تایید ادمین، سرور به صورت خودکار ساخته و در پنل شما فعال می‌شود."

    return render_template("order_vps.html", plans=plans, selected_code=selected_code, error_msg=error_msg, success_msg=success_msg)


@app.route("/server/<int:server_id>/power/<action>", methods=["POST"])
@login_required
def user_power_action(server_id, action):
    if not user_can_access_server(session["user_id"], session.get("role", "user"), server_id):
        return "Forbidden", 403
    if action not in ["on", "off", "reboot"]:
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT s.ip, s.username, s.password, s.vmid, s.esxi_host_id, h.ip, h.port, h.username, h.password "
        "FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?",
        (server_id,),
    )
    row = c.fetchone()
    if row:
        srv_ip, ssh_u, ssh_p, vmid, host_id, esxi_ip, esxi_port, esxi_u, esxi_p = row
        if host_id and vmid and esxi_ip:
            esxi_manager.power_vm(esxi_ip, esxi_port, esxi_u, esxi_p, vmid, "reset" if action == "reboot" else action)
        elif action in ["reboot", "off"] and srv_ip:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(srv_ip, username=ssh_u, password=ssh_p, timeout=8)
                ssh.exec_command("sudo reboot" if action == "reboot" else "sudo shutdown -h now")
                ssh.close()
            except Exception:
                pass
        if action in ["on", "off"]:
            c.execute("UPDATE servers SET active=? WHERE id=?", (1 if action == "on" else 0, server_id))
            conn.commit()
            invalidate_servers_cache()
    conn.close()
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/server/<int:server_id>/user_rebuild", methods=["POST"])
@login_required
def user_rebuild_action(server_id):
    if not user_can_access_server(session["user_id"], session.get("role", "user"), server_id):
        return "Forbidden", 403

    new_pass = request.form.get("new_password", "").strip()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT s.vm_name, s.vmid, s.esxi_host_id, s.ip, s.netmask, s.gateway, s.ipv6, s.ipv6_gateway, s.extra_ips,
                  s.username, s.password, h.ip, h.port, h.username, h.password, h.default_datastore, h.template_vmdk
           FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if row:
        (
            vm_name, vmid, host_id, srv_ip, netmask, gateway, ipv6, ipv6_gw, extra_ips,
            ssh_user, ssh_pass, esxi_ip, esxi_port, esxi_user, esxi_pass, datastore, template
        ) = row
        final_pass = new_pass if len(new_pass) >= 6 else ssh_pass
        if new_pass and len(new_pass) >= 6:
            c.execute("UPDATE servers SET password=? WHERE id=?", (final_pass, server_id))

        if host_id and vmid and esxi_ip and template:
            extra_list = [x.strip() for x in re.split(r"[,\n]", extra_ips or "") if x.strip()]
            netplan_yaml = esxi_manager.generate_netplan_yaml(
                primary_ipv4=srv_ip,
                gateway_ipv4=gateway or "185.42.212.129",
                netmask_or_prefix=netmask or "25",
                extra_ips=extra_list,
                ipv6=ipv6,
                ipv6_gateway=ipv6_gw,
            )
            meta_d, user_d, net_d = esxi_manager.generate_cloud_init_configs(
                vm_name=vm_name or f"vm-{server_id}",
                ssh_user=ssh_user or "root",
                ssh_password=final_pass,
                netplan_yaml=netplan_yaml,
            )
            seed_iso = esxi_manager.build_cloud_init_iso(meta_d, user_d, net_d)
            esxi_manager.rebuild_vm_on_esxi(
                esxi_host=esxi_ip,
                esxi_port=esxi_port,
                esxi_user=esxi_user,
                esxi_password=esxi_pass,
                vmid=vmid,
                vm_name=vm_name,
                datastore=datastore,
                template_vmdk=template,
                seed_iso_bytes=seed_iso,
            )
        now_iso = datetime.datetime.utcnow().isoformat()
        c.execute(
            "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
            (server_id, f"ریبیلد خودکار اوبونتو برای سرور {vm_name or srv_ip} توسط کاربر انجام شد.", now_iso),
        )
        conn.commit()
    conn.close()
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/server/<int:server_id>/user_ip_service", methods=["GET", "POST"])
@login_required
def user_ip_service_page(server_id):
    if not user_can_access_server(session["user_id"], session.get("role", "user"), server_id):
        return "Forbidden", 403

    ip_service_fee = 340000
    conn = get_db_connection()
    c = conn.cursor()
    error_msg = None
    success_msg = None

    c.execute(
        "SELECT id, name, ip, netmask, gateway, ipv6, ipv6_gateway, extra_ips, username, password FROM servers WHERE id=?",
        (server_id,),
    )
    s_row = c.fetchone()
    if not s_row:
        conn.close()
        return "Server not found", 404

    srv = {
        "id": s_row[0],
        "name": s_row[1],
        "ip": s_row[2],
        "netmask": s_row[3] or "25",
        "gateway": s_row[4] or "",
        "ipv6": s_row[5] or "",
        "ipv6_gateway": s_row[6] or "",
        "extra_ips": s_row[7] or "",
        "username": s_row[8],
        "password": s_row[9],
    }

    if request.method == "POST":
        op_type = request.form.get("op_type", "change_ip")
        if op_type not in ("change_ip", "add_extra_ip"):
            op_type = "change_ip"
        pay_method = request.form.get("pay_method", "receipt").strip()
        tracking_note = request.form.get("tracking_note", "").strip()

        if pay_method == "wallet":
            c.execute("SELECT id FROM ip_pool WHERE is_allocated=0 LIMIT 1")
            if not c.fetchone():
                error_msg = "در حال حاضر آی‌پی آزادی در بانک آی‌پی موجود نیست."
            else:
                if session.get("role") not in ["admin", "owner"]:
                    c.execute(
                        "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id=? AND COALESCE(wallet_balance, 0) >= ?",
                        (ip_service_fee, session["user_id"], ip_service_fee),
                    )
                    if c.rowcount == 0:
                        error_msg = f"موجودی کیف پول شما کافی نیست ({ip_service_fee:,} تومان). لطفاً فیش واریزی بارگذاری کنید."
                if not error_msg:
                    success_msg = _execute_ip_service(c, server_id, op_type)
                    conn.commit()
                    # Refresh srv display
                    c.execute("SELECT ip, netmask, gateway, extra_ips FROM servers WHERE id=?", (server_id,))
                    ur = c.fetchone()
                    if ur:
                        srv["ip"], srv["netmask"], srv["gateway"], srv["extra_ips"] = ur[0], ur[1], ur[2], ur[3] or ""
        else:
            receipt_file = request.files.get("receipt_file")
            ok_file, file_or_err = save_validated_receipt(receipt_file, session["user_id"])
            if not ok_file:
                error_msg = file_or_err
            else:
                now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
                op_label = "تغییر آی‌پی اصلی" if op_type == "change_ip" else "خرید آی‌پی اضافه"
                title = f"{op_label} برای سرور {srv['name']}"
                payload = json.dumps({"server_id": server_id})
                c.execute(
                    """INSERT INTO payment_requests (
                        user_id, username, request_type, title, amount_toman, receipt_filename,
                        tracking_note, payload_json, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
                    (session["user_id"], session.get("username", "user"), op_type, title, ip_service_fee, file_or_err, tracking_note, payload, now_str),
                )
                req_id = c.lastrowid
                conn.commit()
                notify_admin_new_receipt(req_id, session.get("username", "user"), title, ip_service_fee, tracking_note, file_or_err)
                success_msg = f"فیش واریزی شما (#{req_id}) برای «{title}» ثبت شد و پس از تایید ادمین به صورت خودکار روی سرور اعمال می‌شود."

    conn.close()
    return render_template(
        "user_ip_service.html",
        server=srv,
        ip_service_fee=ip_service_fee,
        error_msg=error_msg,
        success_msg=success_msg,
    )


@app.route("/tickets", methods=["GET", "POST"])
@login_required
def tickets_page():
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        if subject and message:
            now_iso = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            c.execute(
                "INSERT INTO web_tickets (user_id, username, subject, message, status, created_at) VALUES (?, ?, ?, ?, 'open', ?)",
                (session["user_id"], session.get("username", "User"), subject, message, now_iso),
            )
            conn.commit()
            conn.close()
            return redirect(url_for("tickets_page"))

    if session.get("role") in ["admin", "owner"]:
        c.execute("SELECT id, user_id, username, subject, message, admin_reply, status, created_at FROM web_tickets ORDER BY id DESC")
    else:
        c.execute(
            "SELECT id, user_id, username, subject, message, admin_reply, status, created_at FROM web_tickets WHERE user_id=? ORDER BY id DESC",
            (session["user_id"],),
        )
    tickets = [
        {
            "id": r[0],
            "user_id": r[1],
            "username": r[2],
            "subject": r[3],
            "message": r[4],
            "admin_reply": r[5],
            "status": r[6],
            "created_at": r[7],
        }
        for r in c.fetchall()
    ]
    conn.close()
    return render_template("tickets.html", tickets=tickets)


@app.route("/tickets/<int:ticket_id>/reply", methods=["POST"])
@admin_required
def reply_web_ticket(ticket_id):
    reply_text = request.form.get("admin_reply", "").strip()
    conn = get_db_connection()
    c = conn.cursor()
    if reply_text:
        c.execute("UPDATE web_tickets SET admin_reply=?, status='answered' WHERE id=?", (reply_text, ticket_id))
        conn.commit()
    conn.close()
    return redirect(url_for("tickets_page"))


@app.route("/manage_plans", methods=["GET", "POST"])
@admin_required
def manage_plans_page():
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST":
        plan_id = request.form.get("plan_id")
        name_fa = request.form.get("name_fa", "").strip()
        cpus = int(request.form.get("cpus", 1) or 1)
        ram_gb = int(request.form.get("ram_gb", 2) or 2)
        disk_gb = int(request.form.get("disk_gb", 20) or 20)
        traffic_gib = float(request.form.get("traffic_gib", 1000) or 1000)
        price_toman = int(request.form.get("price_toman", 1190000) or 1190000)
        if plan_id:
            c.execute(
                "UPDATE vps_plans SET name_fa=?, cpus=?, ram_gb=?, disk_gb=?, traffic_gib=?, price_toman=? WHERE id=?",
                (name_fa, cpus, ram_gb, disk_gb, traffic_gib, price_toman, int(plan_id)),
            )
            conn.commit()
    c.execute("SELECT id, code, name_fa, name_en, cpus, ram_gb, disk_gb, traffic_gib, price_toman, badge, active FROM vps_plans ORDER BY price_toman ASC")
    plans = [
        {
            "id": r[0],
            "code": r[1],
            "name_fa": r[2],
            "name_en": r[3],
            "cpus": r[4],
            "ram_gb": r[5],
            "disk_gb": r[6],
            "traffic_gib": r[7],
            "price_toman": r[8],
            "badge": r[9],
            "active": bool(r[10]),
        }
        for r in c.fetchall()
    ]
    conn.close()
    return render_template("manage_plans.html", plans=plans)


@app.route("/admin_payments")
@admin_required
def admin_payments_page():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT id, user_id, username, request_type, title, amount_toman, receipt_filename,
                  tracking_note, status, reject_reason, decided_by, decided_at, fulfillment_note, created_at
           FROM payment_requests
           ORDER BY CASE WHEN status='pending' THEN 0 ELSE 1 END ASC, id DESC"""
    )
    requests_list = [
        {
            "id": r[0],
            "user_id": r[1],
            "username": r[2],
            "request_type": r[3],
            "title": r[4],
            "amount_toman": r[5],
            "receipt_filename": r[6],
            "tracking_note": r[7],
            "status": r[8],
            "reject_reason": r[9],
            "decided_by": r[10],
            "decided_at": r[11],
            "fulfillment_note": r[12],
            "created_at": r[13],
        }
        for r in c.fetchall()
    ]
    conn.close()
    flash_msg = request.args.get("msg")
    flash_err = request.args.get("err")
    return render_template("admin_payments.html", payment_requests=requests_list, flash_msg=flash_msg, flash_err=flash_err)


@app.route("/admin_payments/<int:req_id>/decide", methods=["POST"])
@admin_required
def admin_decide_payment(req_id):
    action = request.form.get("action", "").strip()
    reject_reason = request.form.get("reject_reason", "").strip()
    actor = f"پنل مدیریت ({session.get('username', 'admin')})"
    ok, message = decide_payment_request(req_id, action, actor, reject_reason=reject_reason)
    if ok:
        return redirect(url_for("admin_payments_page", msg=message))
    return redirect(url_for("admin_payments_page", err=message))


@app.route("/admin_settings", methods=["GET", "POST"])
@admin_required
def admin_settings_page():
    msg = None
    err = None
    if request.method == "POST":
        action = request.form.get("action", "save")
        if action == "save":
            fields = [
                "bank_card_number",
                "bank_card_holder",
                "bank_sheba",
                "bank_name",
                "telegram_bot_token",
                "admin_chat_id",
                "telegram_proxy",
            ]
            for f_key in fields:
                if f_key in request.form:
                    set_system_setting(f_key, request.form.get(f_key, ""))
            msg = "تنظیمات درگاه کارت‌به‌کارت، ربات تلگرام و پروکسی با موفقیت ذخیره و به صورت زنده اعمال شد."
        elif action == "test_telegram":
            res = tg_api_request("getMe", timeout=12)
            if res.get("ok"):
                bot_u = res.get("result", {}).get("username", "Bot")
                cfg = get_system_settings()
                if cfg.get("admin_chat_id"):
                    tg_api_request(
                        "sendMessage",
                        data={
                            "chat_id": cfg["admin_chat_id"],
                            "text": f"✅ اتصال ربات @{bot_u} از طریق پروکسی با موفقیت برقرار شد!",
                        },
                    )
                msg = f"اتصال به تلگرام از طریق پروکسی موفقیت‌آمیز بود! نام کاربری ربات: @{bot_u}"
            else:
                err = f"خطا در اتصال به تلگرام: {res.get('description', 'نامشخص')}"

    settings = get_system_settings()
    return render_template("admin_settings.html", settings=settings, message=msg, error_msg=err)


@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    time_left, is_trial = get_remaining_time()
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM servers")
    total_servers = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM servers WHERE active=1")
    active_servers = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM users WHERE active=1")
    active_users = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM ip_pool WHERE is_allocated=0")
    free_ips = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM ip_pool")
    total_ips = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM payment_requests WHERE status='pending'")
    pending_payments = c.fetchone()[0] or 0
    c.execute("SELECT COALESCE(SUM(amount_toman), 0) FROM payment_requests WHERE status='approved'")
    approved_revenue = c.fetchone()[0] or 0
    c.execute("SELECT COALESCE(SUM(traffic_usage), 0), COALESCE(SUM(traffic_limit), 0) FROM servers")
    tr_row = c.fetchone()
    total_traffic_used = round(float(tr_row[0] or 0), 2)
    total_traffic_limit = round(float(tr_row[1] or 0), 2)
    conn.close()

    return render_template(
        "admin_dashboard.html",
        time_left=time_left,
        is_trial=is_trial,
        total_servers=total_servers,
        active_servers=active_servers,
        total_users=total_users,
        active_users=active_users,
        free_ips=free_ips,
        total_ips=total_ips,
        pending_payments=pending_payments,
        approved_revenue=approved_revenue,
        total_traffic_used=total_traffic_used,
        total_traffic_limit=total_traffic_limit,
    )


# --- IP Pool Management ---
@app.route("/ip_pool", methods=["GET", "POST"])
@admin_required
def ip_pool_page():
    conn = get_db_connection()
    c = conn.cursor()
    error_msg = None

    if request.method == "POST":
        mode = request.form.get("mode", "single")
        netmask = request.form.get("netmask", "24").strip().lstrip("/")
        gateway = request.form.get("gateway", "").strip()
        ipv6 = request.form.get("ipv6", "").strip() or None
        ipv6_gateway = request.form.get("ipv6_gateway", "").strip() or None
        mac_address = request.form.get("mac_address", "").strip() or None
        notes = request.form.get("notes", "").strip() or None
        now_iso = datetime.datetime.utcnow().isoformat()

        if mode == "single":
            ip_addr = request.form.get("ip_address", "").strip()
            if ip_addr and gateway:
                try:
                    c.execute(
                        """INSERT INTO ip_pool (ip_address, netmask, gateway, ipv6, ipv6_gateway, mac_address, is_allocated, notes, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)""",
                        (ip_addr, netmask, gateway, ipv6, ipv6_gateway, mac_address, notes, now_iso),
                    )
                    conn.commit()
                except sqlite3.IntegrityError:
                    error_msg = f"آی‌پی {ip_addr} قبلاً در بانک ثبت شده است."
        elif mode == "range":
            start_ip_str = request.form.get("start_ip", "").strip()
            end_ip_str = request.form.get("end_ip", "").strip()
            try:
                start_ip = ipaddress.IPv4Address(start_ip_str)
                end_ip = ipaddress.IPv4Address(end_ip_str)
                if int(end_ip) < int(start_ip) or (int(end_ip) - int(start_ip)) > 1024:
                    error_msg = "بازه آی‌پی نامعتبر است یا بیش از ۱۰۲۴ آی‌پی دارد."
                else:
                    for ip_int in range(int(start_ip), int(end_ip) + 1):
                        ip_s = str(ipaddress.IPv4Address(ip_int))
                        c.execute(
                            """INSERT OR IGNORE INTO ip_pool (ip_address, netmask, gateway, ipv6_gateway, is_allocated, notes, created_at)
                               VALUES (?, ?, ?, ?, 0, ?, ?)""",
                            (ip_s, netmask, gateway, ipv6_gateway, notes, now_iso),
                        )
                    conn.commit()
            except ValueError:
                error_msg = "فرمت آی‌پی شروع یا پایان صحیح نیست."

        if not error_msg:
            conn.close()
            return redirect(url_for("ip_pool_page"))

    c.execute(
        """SELECT p.id, p.ip_address, p.netmask, p.gateway, p.ipv6, p.ipv6_gateway, p.mac_address,
                  p.is_allocated, p.server_id, p.notes, s.name
           FROM ip_pool p LEFT JOIN servers s ON p.server_id = s.id
           ORDER BY p.is_allocated ASC, p.id DESC"""
    )
    ips = [
        {
            "id": r[0],
            "ip_address": r[1],
            "netmask": r[2],
            "gateway": r[3],
            "ipv6": r[4],
            "ipv6_gateway": r[5],
            "mac_address": r[6],
            "is_allocated": bool(r[7]),
            "server_id": r[8],
            "notes": r[9],
            "server_name": r[10],
        }
        for r in c.fetchall()
    ]
    conn.close()
    return render_template("ip_pool.html", ips=ips, error_msg=error_msg)


@app.route("/ip_pool/release/<int:ip_id>")
@admin_required
def release_ip_pool(ip_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE ip_pool SET is_allocated=0, server_id=NULL WHERE id=?", (ip_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("ip_pool_page"))


@app.route("/ip_pool/delete/<int:ip_id>")
@admin_required
def delete_ip_pool(ip_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM ip_pool WHERE id=?", (ip_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("ip_pool_page"))


# --- ESXi Hosts Management ---
@app.route("/esxi_hosts", methods=["GET", "POST"])
@admin_required
def esxi_hosts_page():
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            name = request.form.get("name", "").strip()
            ip = request.form.get("ip", "").strip()
            port = int(request.form.get("port", 22) or 22)
            username = request.form.get("username", "root").strip()
            password = request.form.get("password", "").strip()
            datastore = request.form.get("default_datastore", "datastore1").strip()
            network = request.form.get("default_network", "VM Network").strip()
            template_vmdk = request.form.get("template_vmdk", "").strip()
            now_iso = datetime.datetime.utcnow().isoformat()
            c.execute(
                "INSERT INTO esxi_hosts (name, ip, port, username, password, default_datastore, default_network, template_vmdk, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, ip, port, username, password, datastore, network, template_vmdk, now_iso),
            )
            conn.commit()
            conn.close()
            return redirect(url_for("esxi_hosts_page"))

    c.execute("SELECT id, name, ip, port, username, default_datastore, default_network, template_vmdk FROM esxi_hosts ORDER BY id DESC")
    hosts = [
        {
            "id": r[0],
            "name": r[1],
            "ip": r[2],
            "port": r[3],
            "username": r[4],
            "default_datastore": r[5],
            "default_network": r[6],
            "template_vmdk": r[7],
        }
        for r in c.fetchall()
    ]
    conn.close()
    return render_template("esxi_hosts.html", esxi_hosts=hosts)


@app.route("/esxi_hosts/test/<int:host_id>")
@admin_required
def test_esxi_host(host_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, port, username, password FROM esxi_hosts WHERE id=?", (host_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"success": False, "message": "Host not found"}), 404
    success, msg = esxi_manager.test_esxi_connection(row[0], row[1], row[2], row[3])
    return jsonify({"success": success, "message": msg})


@app.route("/esxi_hosts/delete/<int:host_id>")
@admin_required
def delete_esxi_host(host_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM esxi_hosts WHERE id=?", (host_id,))
    c.execute("UPDATE servers SET esxi_host_id=NULL WHERE esxi_host_id=?", (host_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("esxi_hosts_page"))


# --- Automatic VM Creation on ESXi with IP Pool & Cloud-Init ---
@app.route("/create_vm", methods=["GET", "POST"])
@admin_required
def create_vm_page():
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST":
        esxi_host_id = int(request.form.get("esxi_host_id"))
        vm_name = request.form.get("vm_name", "").strip()
        datastore = request.form.get("datastore", "datastore1").strip()
        template_vmdk = request.form.get("template_vmdk", "").strip()
        network_name = request.form.get("network_name", "VM Network").strip()
        cpus = int(request.form.get("cpus", 2) or 2)
        ram_mb = int(request.form.get("ram_mb", 2048) or 2048)
        disk_gb = int(request.form.get("disk_gb", 30) or 30)

        ip_pool_choice = request.form.get("ip_pool_id", "manual").strip()
        selected_pool_id = None
        mac_address = request.form.get("mac_address", "").strip()
        primary_ip = request.form.get("primary_ip", "").strip()
        netmask = request.form.get("netmask", "25").strip()
        gateway = request.form.get("gateway", "").strip()
        ipv6 = request.form.get("ipv6", "").strip()
        ipv6_gateway = request.form.get("ipv6_gateway", "").strip()
        extra_ips = request.form.get("extra_ips", "").strip()

        if ip_pool_choice == "auto":
            c.execute(
                "SELECT id, ip_address, netmask, gateway, ipv6, ipv6_gateway, mac_address FROM ip_pool WHERE is_allocated=0 ORDER BY id ASC LIMIT 1"
            )
            pool_row = c.fetchone()
            if not pool_row:
                conn.close()
                return "هیچ آی‌پی آزادی در بانک آی‌پی وجود ندارد!", 400
            selected_pool_id, primary_ip, netmask, gateway, p_v6, p_v6gw, p_mac = pool_row
            ipv6 = ipv6 or (p_v6 or "")
            ipv6_gateway = ipv6_gateway or (p_v6gw or "")
            mac_address = mac_address or (p_mac or "")
        elif ip_pool_choice != "manual" and ip_pool_choice.isdigit():
            c.execute(
                "SELECT id, ip_address, netmask, gateway, ipv6, ipv6_gateway, mac_address FROM ip_pool WHERE id=? AND is_allocated=0",
                (int(ip_pool_choice),),
            )
            pool_row = c.fetchone()
            if not pool_row:
                conn.close()
                return "آی‌پی انتخاب‌شده در دسترس نیست!", 400
            selected_pool_id, primary_ip, netmask, gateway, p_v6, p_v6gw, p_mac = pool_row
            ipv6 = ipv6 or (p_v6 or "")
            ipv6_gateway = ipv6_gateway or (p_v6gw or "")
            mac_address = mac_address or (p_mac or "")

        if not primary_ip or not gateway:
            conn.close()
            return "آدرس IP و Gateway الزامی است.", 400

        ssh_user = request.form.get("username", "root").strip()
        ssh_password = request.form.get("password", "").strip()
        traffic_limit = float(request.form.get("traffic_limit", 1000) or 1000)
        user_id = request.form.get("user_id")

        c.execute("SELECT ip, port, username, password FROM esxi_hosts WHERE id=?", (esxi_host_id,))
        esxi_row = c.fetchone()
        if not esxi_row:
            conn.close()
            return "ESXi Host not found", 404

        # Build Netplan & Cloud-Init seed.iso for automatic IP + password injection on first boot
        extra_list = [x.strip() for x in re.split(r"[,\n]", extra_ips) if x.strip()]
        netplan_yaml = esxi_manager.generate_netplan_yaml(
            primary_ipv4=primary_ip,
            gateway_ipv4=gateway,
            netmask_or_prefix=netmask,
            extra_ips=extra_list,
            ipv6=ipv6,
            ipv6_gateway=ipv6_gateway,
        )
        meta_data, user_data, net_cfg = esxi_manager.generate_cloud_init_configs(
            vm_name=vm_name,
            ssh_user=ssh_user,
            ssh_password=ssh_password,
            netplan_yaml=netplan_yaml,
        )
        seed_iso_bytes = esxi_manager.build_cloud_init_iso(meta_data, user_data, net_cfg)

        success, vmid, message = esxi_manager.create_vm_on_esxi(
            esxi_host=esxi_row[0],
            esxi_port=esxi_row[1],
            esxi_user=esxi_row[2],
            esxi_password=esxi_row[3],
            vm_name=vm_name,
            cpus=cpus,
            ram_mb=ram_mb,
            disk_gb=disk_gb,
            datastore=datastore,
            template_vmdk=template_vmdk,
            network_name=network_name,
            mac_address=mac_address,
            seed_iso_bytes=seed_iso_bytes,
        )

        if not success:
            conn.close()
            return f"خطا در ساخت ماشین در ESXi: {message}", 500

        now_iso = datetime.datetime.utcnow().isoformat()

        c.execute(
            """INSERT INTO servers (
                name, ip, username, password, traffic_limit, active, traffic_usage,
                updated_at, esxi_host_id, vmid, vm_name, is_suspended,
                netmask, gateway, ipv6, ipv6_gateway, extra_ips, mac_address
            ) VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)""",
            (
                vm_name,
                primary_ip,
                ssh_user,
                ssh_password,
                traffic_limit,
                now_iso,
                esxi_host_id,
                vmid,
                vm_name,
                netmask,
                gateway,
                ipv6,
                ipv6_gateway,
                extra_ips,
                mac_address,
            ),
        )
        server_id = c.lastrowid

        if selected_pool_id:
            c.execute("UPDATE ip_pool SET is_allocated=1, server_id=? WHERE id=?", (server_id, selected_pool_id))

        if user_id:
            c.execute("INSERT OR IGNORE INTO user_servers (user_id, server_id) VALUES (?, ?)", (user_id, server_id))

        c.execute(
            "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
            (server_id, f"سرور مجازی {vm_name} با IP {primary_ip} از طریق Cloud-Init ایجاد شد.", now_iso),
        )
        conn.commit()
        conn.close()
        invalidate_servers_cache()
        return redirect(url_for("manage_servers"))

    c.execute("SELECT id, name, ip, default_datastore, default_network, template_vmdk FROM esxi_hosts")
    hosts = [
        {
            "id": r[0],
            "name": r[1],
            "ip": r[2],
            "default_datastore": r[3],
            "default_network": r[4],
            "template_vmdk": r[5],
        }
        for r in c.fetchall()
    ]
    c.execute("SELECT id, username FROM users WHERE active=1 AND username != 'marmmr'")
    users = c.fetchall()
    c.execute("SELECT id, ip_address, netmask, gateway, ipv6, ipv6_gateway, mac_address FROM ip_pool WHERE is_allocated=0 ORDER BY id ASC")
    free_ips = [
        {
            "id": r[0],
            "ip_address": r[1],
            "netmask": r[2],
            "gateway": r[3],
            "ipv6": r[4] or "",
            "ipv6_gateway": r[5] or "",
            "mac_address": r[6] or "",
        }
        for r in c.fetchall()
    ]
    conn.close()
    return render_template("create_vm.html", esxi_hosts=hosts, users=users, free_ips=free_ips)


# --- Rebuild Server on ESXi (with Cloud-Init IP Re-injection) ---
@app.route("/server/<int:server_id>/rebuild", methods=["GET", "POST"])
@admin_required
def rebuild_vm_action(server_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT s.vm_name, s.vmid, s.esxi_host_id, s.ip, s.netmask, s.gateway, s.ipv6, s.ipv6_gateway, s.extra_ips,
                  s.username, s.password, h.ip, h.port, h.username, h.password, h.default_datastore, h.template_vmdk
           FROM servers s JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if not row or not row[1]:
        conn.close()
        return "سرور مربوطه در ESXi پیکربندی نشده است.", 400

    (
        vm_name,
        vmid,
        _,
        srv_ip,
        netmask,
        gateway,
        ipv6,
        ipv6_gw,
        extra_ips,
        ssh_user,
        ssh_pass,
        esxi_ip,
        esxi_port,
        esxi_user,
        esxi_pass,
        datastore,
        template,
    ) = row

    seed_iso_bytes = None
    if srv_ip and gateway:
        extra_list = [x.strip() for x in re.split(r"[,\n]", extra_ips or "") if x.strip()]
        netplan_yaml = esxi_manager.generate_netplan_yaml(
            primary_ipv4=srv_ip,
            gateway_ipv4=gateway,
            netmask_or_prefix=netmask or "24",
            extra_ips=extra_list,
            ipv6=ipv6,
            ipv6_gateway=ipv6_gw,
        )
        meta_data, user_data, net_cfg = esxi_manager.generate_cloud_init_configs(
            vm_name=vm_name,
            ssh_user=ssh_user or "root",
            ssh_password=ssh_pass or "",
            netplan_yaml=netplan_yaml,
        )
        seed_iso_bytes = esxi_manager.build_cloud_init_iso(meta_data, user_data, net_cfg)

    success, msg = esxi_manager.rebuild_vm_on_esxi(
        esxi_host=esxi_ip,
        esxi_port=esxi_port,
        esxi_user=esxi_user,
        esxi_password=esxi_pass,
        vmid=vmid,
        vm_name=vm_name,
        datastore=datastore,
        template_vmdk=template,
        seed_iso_bytes=seed_iso_bytes,
    )

    now_iso = datetime.datetime.utcnow().isoformat()
    if success:
        c.execute(
            "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
            (server_id, f"ماشین مجازی {vm_name} با موفقیت ریبیلد و با آی‌پی {srv_ip} پیکربندی شد.", now_iso),
        )
        c.execute("UPDATE servers SET is_suspended=0 WHERE id=?", (server_id,))
        conn.commit()
    conn.close()
    return redirect(request.referrer or url_for("manage_servers"))


# --- Snapshot Management ---
@app.route("/server/<int:server_id>/snapshots", methods=["GET", "POST"])
@login_required
def snapshots_page(server_id):
    if not user_can_access_server(session["user_id"], session.get("role", "user"), server_id):
        return "Forbidden", 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT s.id, s.name, s.vmid, h.ip, h.port, h.username, h.password
           FROM servers s JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if not row or not row[2]:
        conn.close()
        return "این سرور به هاست ESXi متصل نیست.", 400

    srv_id, srv_name, vmid, esxi_ip, esxi_port, esxi_user, esxi_pass = row

    if request.method == "POST":
        snap_name = request.form.get("name", "").strip()
        snap_desc = request.form.get("description", "").strip()
        if snap_name:
            ok, msg = esxi_manager.create_snapshot(esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, snap_name, snap_desc)
            now_iso = datetime.datetime.utcnow().isoformat()
            if ok:
                c.execute(
                    "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
                    (server_id, f"اسنپ‌شات '{snap_name}' برای سرور {srv_name} ایجاد شد.", now_iso),
                )
                conn.commit()
        conn.close()
        return redirect(url_for("snapshots_page", server_id=server_id))

    ok, snaps, err_msg = esxi_manager.list_snapshots(esxi_ip, esxi_port, esxi_user, esxi_pass, vmid)
    conn.close()
    return render_template(
        "snapshots.html",
        server={"id": srv_id, "name": srv_name, "vmid": vmid},
        snapshots=snaps,
        error_msg=None if ok else err_msg,
    )


@app.route("/server/<int:server_id>/snapshots/revert/<int:snap_id>", methods=["POST"])
@login_required
def revert_snapshot_action(server_id, snap_id):
    if not user_can_access_server(session["user_id"], session.get("role", "user"), server_id):
        return "Forbidden", 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT s.vmid, s.name, h.ip, h.port, h.username, h.password
           FROM servers s JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if row and row[0]:
        vmid, srv_name, esxi_ip, esxi_port, esxi_user, esxi_pass = row
        ok, _ = esxi_manager.revert_snapshot(esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, snap_id)
        if ok:
            now_iso = datetime.datetime.utcnow().isoformat()
            c.execute(
                "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'warning', ?, ?)",
                (server_id, f"سرور {srv_name} به اسنپ‌شات #{snap_id} بازگردانی شد.", now_iso),
            )
            conn.commit()
    conn.close()
    return redirect(url_for("snapshots_page", server_id=server_id))


@app.route("/server/<int:server_id>/snapshots/delete/<int:snap_id>", methods=["POST"])
@login_required
def delete_snapshot_action(server_id, snap_id):
    if not user_can_access_server(session["user_id"], session.get("role", "user"), server_id):
        return "Forbidden", 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT s.vmid, s.name, h.ip, h.port, h.username, h.password
           FROM servers s JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if row and row[0]:
        vmid, srv_name, esxi_ip, esxi_port, esxi_user, esxi_pass = row
        esxi_manager.remove_snapshot(esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, snap_id)
    conn.close()
    return redirect(url_for("snapshots_page", server_id=server_id))


# --- Change IP & Add Secondary IP (supports IP Pool) ---
@app.route("/server/<int:server_id>/change_ip", methods=["GET", "POST"])
@admin_required
def change_ip_page(server_id):
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST":
        pool_choice = request.form.get("ip_pool_id", "manual").strip()
        primary_ip = request.form.get("primary_ip", "").strip()
        netmask = request.form.get("netmask", "25").strip()
        gateway = request.form.get("gateway", "").strip()
        ipv6 = request.form.get("ipv6", "").strip()
        ipv6_gateway = request.form.get("ipv6_gateway", "").strip()
        extra_ips = request.form.get("extra_ips", "").strip()
        apply_remote = request.form.get("apply_remote") == "1"

        c.execute("SELECT ip, username, password FROM servers WHERE id=?", (server_id,))
        srv_cred = c.fetchone()
        old_ip = srv_cred[0] if srv_cred else primary_ip

        if pool_choice != "manual" and pool_choice.isdigit():
            c.execute(
                "SELECT id, ip_address, netmask, gateway, ipv6, ipv6_gateway FROM ip_pool WHERE id=? AND is_allocated=0",
                (int(pool_choice),),
            )
            p_row = c.fetchone()
            if p_row:
                pool_id, primary_ip, netmask, gateway, p_v6, p_v6gw = p_row
                ipv6 = ipv6 or (p_v6 or "")
                ipv6_gateway = ipv6_gateway or (p_v6gw or "")
                # Release old IP and allocate new IP in pool
                c.execute("UPDATE ip_pool SET is_allocated=0, server_id=NULL WHERE server_id=?", (server_id,))
                c.execute("UPDATE ip_pool SET is_allocated=1, server_id=? WHERE id=?", (server_id, pool_id))

        if apply_remote and srv_cred:
            extra_list = [x.strip() for x in re.split(r"[,\n]", extra_ips) if x.strip()]
            netplan_yaml = esxi_manager.generate_netplan_yaml(
                primary_ipv4=primary_ip,
                gateway_ipv4=gateway,
                netmask_or_prefix=netmask,
                extra_ips=extra_list,
                ipv6=ipv6,
                ipv6_gateway=ipv6_gateway,
            )
            # Connect to current/old IP to push new Netplan config
            esxi_manager.apply_netplan_to_vm(old_ip, srv_cred[1], srv_cred[2], netplan_yaml)

        c.execute(
            """UPDATE servers SET ip=?, netmask=?, gateway=?, ipv6=?, ipv6_gateway=?, extra_ips=? WHERE id=?""",
            (primary_ip, netmask, gateway, ipv6, ipv6_gateway, extra_ips, server_id),
        )
        now_iso = datetime.datetime.utcnow().isoformat()
        c.execute(
            "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
            (server_id, f"تنظیمات شبکه و آی‌پی سرور به {primary_ip} به‌روزرسانی شد.", now_iso),
        )
        conn.commit()
        conn.close()
        invalidate_servers_cache()
        return redirect(url_for("manage_servers"))

    c.execute(
        "SELECT id, name, ip, netmask, gateway, ipv6, ipv6_gateway, extra_ips FROM servers WHERE id=?",
        (server_id,),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return "Server not found", 404
    srv = {
        "id": row[0],
        "name": row[1],
        "ip": row[2],
        "netmask": row[3],
        "gateway": row[4],
        "ipv6": row[5],
        "ipv6_gateway": row[6],
        "extra_ips": row[7],
    }
    c.execute("SELECT id, ip_address, netmask, gateway, ipv6, ipv6_gateway FROM ip_pool WHERE is_allocated=0 ORDER BY id ASC")
    free_ips = [
        {
            "id": r[0],
            "ip_address": r[1],
            "netmask": r[2],
            "gateway": r[3],
            "ipv6": r[4] or "",
            "ipv6_gateway": r[5] or "",
        }
        for r in c.fetchall()
    ]
    conn.close()
    return render_template("change_ip.html", server=srv, free_ips=free_ips)


# --- Toggle Network Suspension on ESXi ---
@app.route("/server/<int:server_id>/toggle_network")
@admin_required
def toggle_network_action(server_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT s.vmid, s.is_suspended, s.name, h.ip, h.port, h.username, h.password 
           FROM servers s JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if row and row[0]:
        vmid, is_suspended, name, host_ip, host_port, host_user, host_pass = row
        new_state = not bool(is_suspended)
        connect = bool(is_suspended)
        esxi_manager.set_vnic_connection(host_ip, host_port, host_user, host_pass, vmid, connected=connect)
        c.execute("UPDATE servers SET is_suspended=? WHERE id=?", (1 if new_state else 0, server_id))
        conn.commit()
    conn.close()
    return redirect(request.referrer or url_for("manage_servers"))


# --- Traffic Recharge (Customer Receipt / Verified Wallet & Admin, 750,000 Toman per 1000 GiB) ---
@app.route("/server/<int:server_id>/recharge_traffic", methods=["POST"])
@login_required
def recharge_traffic_action(server_id):
    if not user_can_access_server(session["user_id"], session.get("role", "user"), server_id):
        return "Forbidden", 403

    try:
        add_amount = float(request.form.get("add_amount", 100) or 100)
    except ValueError:
        add_amount = 100.0
    if add_amount <= 0 or add_amount > 100000:
        add_amount = 100.0
    cost_toman = int(add_amount * 750)  # 750,000 Tomans per 1000 GiB (1 TB)
    pay_method = request.form.get("pay_method", "receipt").strip()
    tracking_note = request.form.get("tracking_note", "").strip()

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT name FROM servers WHERE id=?", (server_id,))
    s_row = c.fetchone()
    if not s_row:
        conn.close()
        return redirect(url_for("dashboard"))
    srv_name = s_row[0]

    # Admin/Owner or Verified Wallet payment
    if session.get("role") in ["admin", "owner"] or pay_method == "wallet":
        if session.get("role") not in ["admin", "owner"]:
            c.execute(
                "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id=? AND COALESCE(wallet_balance, 0) >= ?",
                (cost_toman, session["user_id"], cost_toman),
            )
            if c.rowcount == 0:
                conn.close()
                return redirect(url_for("wallet_page"))
        _execute_traffic_recharge(c, server_id, add_amount)
        conn.commit()
        conn.close()
        return redirect(request.referrer or url_for("dashboard"))

    # Receipt upload payment (requires Admin Approval)
    receipt_file = request.files.get("receipt_file")
    ok_file, file_or_err = save_validated_receipt(receipt_file, session["user_id"])
    if not ok_file:
        conn.close()
        return redirect(url_for("wallet_page"))

    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    title = f"شارژ ترافیک +{add_amount:g} GiB برای سرور {srv_name}"
    payload = json.dumps({"server_id": server_id, "add_amount": add_amount})
    c.execute(
        """INSERT INTO payment_requests (
            user_id, username, request_type, title, amount_toman, receipt_filename,
            tracking_note, payload_json, status, created_at
        ) VALUES (?, ?, 'recharge_traffic', ?, ?, ?, ?, ?, 'pending', ?)""",
        (session["user_id"], session.get("username", "user"), title, cost_toman, file_or_err, tracking_note, payload, now_str),
    )
    req_id = c.lastrowid
    conn.commit()
    conn.close()
    notify_admin_new_receipt(req_id, session.get("username", "user"), title, cost_toman, tracking_note, file_or_err)
    return redirect(url_for("dashboard"))


@app.route("/add_server", methods=["GET", "POST"])
@admin_required
def add_server_page():
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        ip = request.form.get("ip", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        try:
            traffic_limit = float(request.form.get("traffic_limit", 0) or 0)
        except ValueError:
            traffic_limit = 0.0
        telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
        now_str = datetime.datetime.utcnow().isoformat()
        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            "INSERT INTO servers (name, ip, username, password, traffic_limit, telegram_chat_id, active, traffic_usage, reset_date, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, 0, NULL, ?)",
            (name, ip, username, password, traffic_limit, telegram_chat_id, now_str),
        )
        conn.commit()
        conn.close()
        invalidate_servers_cache()
        return redirect(url_for("admin_dashboard"))
    return render_template("add_server.html")


@app.route("/add_user", methods=["GET", "POST"])
@admin_required
def add_user_page():
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "user").strip()
        telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
        if role != "owner" and username and password:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute(
                "INSERT OR IGNORE INTO users (username, password, role, telegram_chat_id, active) VALUES (?, ?, ?, ?, 1)",
                (username, generate_password_hash(password), role, telegram_chat_id),
            )
            conn.commit()
            conn.close()
        return redirect(url_for("admin_dashboard"))
    return render_template("add_user.html")


@app.route("/assign_server", methods=["GET", "POST"])
@admin_required
def assign_server_page():
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST":
        user_id = request.form.get("user_id")
        server_id = request.form.get("server_id")
        if user_id and server_id:
            c.execute(
                "INSERT OR IGNORE INTO user_servers (user_id, server_id) VALUES (?, ?)",
                (user_id, server_id),
            )
            conn.commit()
            invalidate_servers_cache()
        conn.close()
        return redirect(url_for("assign_server_page"))

    c.execute("SELECT id, username FROM users WHERE active=1 AND username != 'marmmr'")
    users = c.fetchall()
    c.execute("SELECT id, name, ip FROM servers WHERE active=1 ORDER BY name ASC")
    servers = c.fetchall()
    c.execute(
        "SELECT us.user_id, u.username, us.server_id, s.name, s.ip "
        "FROM user_servers us JOIN users u ON us.user_id = u.id JOIN servers s ON us.server_id = s.id "
        "ORDER BY u.username ASC, s.name ASC"
    )
    assignments = c.fetchall()
    conn.close()
    return render_template("assign_server.html", users=users, servers=servers, assignments=assignments)


@app.route("/unassign_server/<int:user_id>/<int:server_id>")
@admin_required
def unassign_server(user_id, server_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM user_servers WHERE user_id=? AND server_id=?", (user_id, server_id))
    conn.commit()
    conn.close()
    invalidate_servers_cache()
    return redirect(url_for("assign_server_page"))


@app.route("/delete_server/<int:server_id>")
@admin_required
def delete_server(server_id):
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE ip_pool SET is_allocated=0, server_id=NULL WHERE server_id=?", (server_id,))
    c.execute("DELETE FROM user_servers WHERE server_id=?", (server_id,))
    c.execute("DELETE FROM traffic_samples WHERE server_id=?", (server_id,))
    c.execute("DELETE FROM events WHERE server_id=?", (server_id,))
    c.execute("DELETE FROM servers WHERE id=?", (server_id,))
    conn.commit()
    conn.close()
    invalidate_servers_cache()
    return redirect(url_for("manage_servers"))


@app.route("/manage_servers", methods=["GET", "POST"])
@admin_required
def manage_servers():
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST" and "edit_server_id" in request.form:
        server_id = request.form["edit_server_id"]
        name = request.form.get("name", "").strip()
        ip = request.form.get("ip", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        try:
            traffic_limit = float(request.form.get("traffic_limit", 0) or 0)
        except ValueError:
            traffic_limit = 0.0
        telegram_chat_id = request.form.get("telegram_chat_id", "").strip()

        if password:
            c.execute(
                "UPDATE servers SET name=?, ip=?, username=?, password=?, traffic_limit=?, telegram_chat_id=? WHERE id=?",
                (name, ip, username, password, traffic_limit, telegram_chat_id, server_id),
            )
        else:
            c.execute(
                "UPDATE servers SET name=?, ip=?, username=?, traffic_limit=?, telegram_chat_id=? WHERE id=?",
                (name, ip, username, traffic_limit, telegram_chat_id, server_id),
            )
        conn.commit()
        conn.close()
        invalidate_servers_cache()
        return redirect(url_for("manage_servers"))

    c.execute(
        """SELECT id, name, ip, username, password, traffic_limit, telegram_chat_id, active, traffic_usage, reset_date,
                  esxi_host_id, vmid, is_suspended, gateway, netmask, ipv6, extra_ips
           FROM servers ORDER BY name ASC"""
    )
    servers = c.fetchall()
    conn.close()
    return render_template("manage_servers.html", servers=servers)


@app.route("/servers/<int:server_id>/limit", methods=["POST"])
@owner_required
def update_server_limit(server_id):
    traffic_limit_raw = request.form.get("traffic_limit", "").strip()
    try:
        new_limit = float(traffic_limit_raw)
        if new_limit < 0:
            raise ValueError("negative limit")
    except (TypeError, ValueError):
        return redirect(request.referrer or url_for("manage_servers"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT s.traffic_usage, s.is_suspended, s.vmid, h.ip, h.port, h.username, h.password
           FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    c.execute("UPDATE servers SET traffic_limit=? WHERE id=?", (new_limit, server_id))

    if row:
        usage, is_suspended, vmid, esxi_ip, esxi_port, esxi_user, esxi_pass = row
        if is_suspended and new_limit > (usage or 0.0) and vmid and esxi_ip:
            esxi_manager.set_vnic_connection(esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, connected=True)
            c.execute("UPDATE servers SET is_suspended=0 WHERE id=?", (server_id,))

    conn.commit()
    conn.close()
    invalidate_servers_cache()
    return redirect(request.referrer or url_for("manage_servers"))


@app.route("/reset_traffic/<int:server_id>")
@admin_required
def reset_traffic(server_id):
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT s.ip, s.username, s.password, s.vmid, s.is_suspended, h.ip, h.port, h.username, h.password
           FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    server = c.fetchone()
    if server:
        ip, username, password, vmid, is_suspended, esxi_ip, esxi_port, esxi_user, esxi_pass = server
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=10)
            nic = detect_iface(ssh)
            ssh.exec_command(f"vnstat -i {nic} --reset")
            ssh.close()
            logging.info(f"Traffic reset for server {ip}")
        except Exception as e:
            logging.error(f"Failed to reset traffic for {ip}: {str(e)}")

        reset_date = datetime.datetime.now().strftime("%Y-%m")
        c.execute(
            "UPDATE servers SET traffic_usage=0, reset_date=?, updated_at=? WHERE id=?",
            (reset_date, datetime.datetime.utcnow().isoformat(), server_id),
        )

        if is_suspended and vmid and esxi_ip:
            esxi_manager.set_vnic_connection(esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, connected=True)
            c.execute("UPDATE servers SET is_suspended=0 WHERE id=?", (server_id,))

        conn.commit()
        invalidate_servers_cache()
    conn.close()
    return redirect(url_for("manage_servers"))


@app.route("/manage_users", methods=["GET", "POST"])
@admin_required
def manage_users():
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST" and "edit_user_id" in request.form:
        user_id = request.form["edit_user_id"]
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "user").strip()
        telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
        try:
            wallet_balance = int(request.form.get("wallet_balance", 0) or 0)
        except ValueError:
            wallet_balance = 0

        if role != "owner" and username != "marmmr":
            if password:
                c.execute(
                    "UPDATE users SET username=?, password=?, role=?, telegram_chat_id=?, wallet_balance=? WHERE id=?",
                    (username, generate_password_hash(password), role, telegram_chat_id, wallet_balance, user_id),
                )
            else:
                c.execute(
                    "UPDATE users SET username=?, role=?, telegram_chat_id=?, wallet_balance=? WHERE id=?",
                    (username, role, telegram_chat_id, wallet_balance, user_id),
                )
            conn.commit()
        conn.close()
        return redirect(url_for("manage_users"))

    c.execute("SELECT id, username, role, telegram_chat_id, active, COALESCE(wallet_balance, 0) FROM users WHERE username != 'marmmr'")
    users = c.fetchall()
    conn.close()
    return render_template("manage_users.html", users=users)


@app.route("/toggle_server/<int:server_id>")
@admin_required
def toggle_server(server_id):
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT active, vmid, esxi_host_id FROM servers WHERE id=?", (server_id,))
    row = c.fetchone()
    if row is not None:
        new_status = 0 if row[0] == 1 else 1
        c.execute("UPDATE servers SET active=? WHERE id=?", (new_status, server_id))
        conn.commit()

        if row[1] and row[2]:
            c.execute("SELECT ip, port, username, password FROM esxi_hosts WHERE id=?", (row[2],))
            h = c.fetchone()
            if h:
                action = "on" if new_status == 1 else "off"
                esxi_manager.power_vm(h[0], h[1], h[2], h[3], row[1], action)

        invalidate_servers_cache()
    conn.close()
    return redirect(url_for("manage_servers"))


@app.route("/delete_user/<int:user_id>")
@admin_required
def delete_user(user_id):
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    if user and user[0] != "marmmr":
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        c.execute("DELETE FROM user_servers WHERE user_id=?", (user_id,))
        conn.commit()
        invalidate_servers_cache()
    conn.close()
    return redirect(url_for("manage_users"))


@app.route("/toggle_user/<int:user_id>")
@admin_required
def toggle_user(user_id):
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT active, username FROM users WHERE id=?", (user_id,))
    result = c.fetchone()
    if result and result[1] != "marmmr":
        new_status = 0 if result[0] == 1 else 1
        c.execute("UPDATE users SET active=? WHERE id=?", (new_status, user_id))
        conn.commit()
    conn.close()
    return redirect(url_for("manage_users"))


@app.route("/live/<int:server_id>")
@login_required
def live_port(server_id):
    if is_license_expired() and session.get("role") != "owner":
        if session.get("role") == "admin":
            return render_template("admin_expired.html")
        return render_template("user_expired.html")

    if not user_can_access_server(session["user_id"], session["role"], server_id):
        return "Forbidden", 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM servers WHERE id=?", (server_id,))
    server = c.fetchone()
    conn.close()
    if server:
        return render_template("live_port.html", server_id=server_id)
    return "Server not found", 404


@app.route("/server/<int:server_id>")
@login_required
def server_detail(server_id):
    if is_license_expired() and session.get("role") != "owner":
        if session.get("role") == "admin":
            return render_template("admin_expired.html")
        return render_template("user_expired.html")

    if not user_can_access_server(session["user_id"], session["role"], server_id):
        return "Forbidden", 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, ip, traffic_limit, traffic_usage, active FROM servers WHERE id=?", (server_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return "Server not found", 404
    server_obj = {
        "id": row[0],
        "name": row[1],
        "ip": row[2],
        "traffic_limit": row[3] or 0.0,
        "traffic_usage": row[4] or 0.0,
        "active": bool(row[5]),
    }
    return render_template("server.html", server=server_obj)


@app.route("/api/servers")
@login_required
def api_servers():
    conn = get_db_connection()
    c = conn.cursor()
    if session.get("role") in ["admin", "owner"]:
        c.execute("SELECT id, name, ip, traffic_usage, traffic_limit, active, updated_at FROM servers ORDER BY name ASC")
    else:
        c.execute(
            "SELECT s.id, s.name, s.ip, s.traffic_usage, s.traffic_limit, s.active, s.updated_at "
            "FROM servers s JOIN user_servers us ON s.id = us.server_id "
            "WHERE us.user_id=? ORDER BY s.name ASC",
            (session["user_id"],),
        )
    rows = c.fetchall()
    conn.close()
    return jsonify(
        [
            {
                "id": r[0],
                "name": r[1],
                "ip": r[2],
                "usage": r[3] or 0.0,
                "limit": r[4] or 0.0,
                "active": bool(r[5]),
                "updated_at": r[6],
            }
            for r in rows
        ]
    )


@app.route("/api/server/<int:server_id>/series")
@login_required
def api_server_series(server_id):
    if not user_can_access_server(session["user_id"], session["role"], server_id):
        return jsonify({"error": "Forbidden"}), 403
    try:
        limit = min(int(request.args.get("limit", 3600)), 10000)
    except ValueError:
        limit = 3600
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT created_at, usage_gib FROM traffic_samples WHERE server_id=? ORDER BY id DESC LIMIT ?",
        (server_id, limit),
    )
    rows = list(reversed(c.fetchall()))
    conn.close()
    return jsonify([{"t": r[0], "traffic_gb": r[1]} for r in rows])


@app.route("/events")
@admin_required
def events_page():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT created_at, level, message FROM events ORDER BY id DESC LIMIT 200")
    rows = [{"created_at": r[0], "level": r[1], "message": r[2]} for r in c.fetchall()]
    conn.close()
    return render_template("events.html", events=rows)


@app.route("/monitor/<int:server_id>")
@login_required
def monitor_server(server_id):
    if is_license_expired() and session.get("role") != "owner":
        return jsonify({"error": "License expired", "server_status": "expired"}), 403

    if not user_can_access_server(session["user_id"], session["role"], server_id):
        return jsonify({"error": "Forbidden", "server_status": "forbidden"}), 403

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT ip, username, password, traffic_limit, telegram_chat_id, reset_date, name FROM servers WHERE id=?",
        (server_id,),
    )
    server = c.fetchone()
    if server:
        ip, username, password, traffic_limit, telegram_chat_id, reset_date, name = server
        traffic_limit = float(traffic_limit or 0.0)
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=10)
            nic = detect_iface(ssh)
            vnstat_monthly = build_vnstat_monthly_cmd(nic, reset_date)
            command = (
                "nproc && "
                "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' && "
                "free -m | awk '/Mem:/ {print $2}' && "
                "free -m | awk '/Mem:/ {print $3/$2 *100}' && "
                f"vnstat -tr 2 -i {nic} | grep 'rx' | awk '{{print $2}}' && "
                f"vnstat -tr 2 -i {nic} | grep 'tx' | awk '{{print $2}}' && "
                "df -BG / | awk 'NR==2 {gsub(\"G\",\"\",$2); print $2}' && "
                "iostat -d 1 2 | tail -n 1 | awk '{print $3}' && "
                "iostat -d 1 2 | tail -n 1 | awk '{print $4}' && "
                f"{vnstat_monthly}"
            )
            _, stdout, _ = ssh.exec_command(command)
            raw_output = stdout.read().decode().strip()
            output = raw_output.split("\n")

            def safe_float(idx: int) -> float:
                try:
                    return float(output[idx].strip().rstrip("G")) if len(output) > idx and output[idx].strip() else 0.0
                except ValueError:
                    return 0.0

            total_cpu = int(safe_float(0))
            cpu_usage = safe_float(1)
            total_ram = int(safe_float(2))
            ram_usage = safe_float(3)
            download = safe_float(4) / 8.0
            upload = safe_float(5) / 8.0
            total_network = upload + download
            total_disk = safe_float(6)
            disk_read = safe_float(7) / 1024.0
            disk_write = safe_float(8) / 1024.0
            traffic_usage = safe_float(9)

            now_iso = datetime.datetime.utcnow().isoformat()
            ping_result = subprocess.run(["ping", "-c", "1", "-W", "2", ip], capture_output=True, text=True)
            ping_time = (
                float(ping_result.stdout.split("time=")[1].split()[0])
                if "time=" in ping_result.stdout
                else 0.0
            )
            ssh.close()

            c.execute(
                "UPDATE servers SET traffic_usage=?, updated_at=? WHERE id=?",
                (traffic_usage, now_iso, server_id),
            )
            c.execute(
                "INSERT INTO traffic_samples (server_id, usage_gib, created_at) VALUES (?, ?, ?)",
                (server_id, traffic_usage, now_iso),
            )
            conn.commit()
            conn.close()

            data = {
                "total_cpu": total_cpu,
                "cpu_usage": cpu_usage,
                "total_ram": total_ram,
                "ram_usage": ram_usage,
                "upload": upload,
                "download": download,
                "total_network": total_network,
                "total_disk": total_disk,
                "disk_read": disk_read,
                "disk_write": disk_write,
                "traffic_limit": traffic_limit,
                "traffic_usage": traffic_usage,
                "ping_time": ping_time,
                "ping_france_time": 0.0,
                "server_status": "active",
            }
            return jsonify(data)
        except Exception as e:
            conn.close()
            error_msg = str(e)
            return jsonify({"error": error_msg, "server_status": "offline"}), 500
    conn.close()
    return jsonify({"error": "Server not found"}), 404


@app.route("/generate_license", methods=["GET", "POST"])
@owner_required
def generate_license():
    if request.method == "POST":
        raw_days = request.form.get("days_valid") or request.form.get("days") or "30"
        try:
            days_valid = max(1, int(raw_days))
        except ValueError:
            days_valid = 30
        license_key = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16))
        expiry_date = (datetime.datetime.now() + datetime.timedelta(days=days_valid)).strftime("%Y-%m-%d")
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO licenses (license_key, expiry_date, trial_active) VALUES (?, ?, 0)", (license_key, expiry_date))
        conn.commit()
        conn.close()
        return render_template("generate_license.html", license_key=license_key, days_valid=days_valid)
    return render_template("generate_license.html")


@app.route("/register_license", methods=["GET", "POST"])
@login_required
def register_license():
    if session.get("role") not in ["admin", "owner"]:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        license_key = request.form.get("license_key", "").strip()
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT license_key, expiry_date, trial_active FROM licenses WHERE license_key=?", (license_key,))
        result = c.fetchone()
        conn.close()
        if result:
            _, expiry_date, trial_active = result
            current_date = time.strftime("%Y-%m-%d")
            if expiry_date > current_date:
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "license_key": license_key,
                            "register_date": datetime.datetime.now().strftime("%Y-%m-%d"),
                            "expiry_date": expiry_date,
                            "is_trial": trial_active == 1,
                        },
                        f,
                    )
                return redirect(url_for("license_result", license_key=license_key, valid="True"))
        return redirect(url_for("license_result", license_key=license_key, valid="False"))
    return render_template("register_license.html")


@app.route("/license_result/<license_key>/")
@app.route("/license_result/<license_key>/<valid>")
@login_required
def license_result(license_key, valid=None):
    if valid is None:
        valid = request.args.get("valid", "False")
    is_valid = str(valid).lower() == "true"
    time_left, is_trial = get_remaining_time()
    return render_template(
        "license_result.html",
        license_key=license_key,
        valid=is_valid,
        time_left=time_left,
        days_left=time_left["days"],
        is_trial=is_trial,
    )


# ==============================================================================
# Proxy-Aware Dynamic Telegram Poller & Traffic Monitor Thread
# Supports socks5://CBZBWfWxTa:YZSIy26WQC@sub.rskhi.ir:12012 and live token updates
# ==============================================================================
ADMIN_REJECT_WAIT = {}  # {chat_id_str: payment_request_id}


def send_telegram_alert(chat_id: str | int, text: str):
    if not chat_id or str(chat_id) == "YOUR_CHAT_ID":
        return
    tg_api_request("sendMessage", data={"chat_id": str(chat_id), "text": text, "parse_mode": "Markdown"})


def _handle_tg_update(upd: dict):
    cfg = get_system_settings()
    admin_chat = (cfg.get("admin_chat_id") or "").strip()

    # 1. Handle Callback Queries (Approve / Reject Receipts & Server Menu)
    if "callback_query" in upd:
        cq = upd["callback_query"]
        cq_id = cq.get("id")
        data = cq.get("data", "")
        msg = cq.get("message", {})
        chat_id = str(msg.get("chat", {}).get("id", ""))
        message_id = msg.get("message_id")

        if data.startswith("pay_approve:"):
            if admin_chat and chat_id != admin_chat:
                tg_api_request("answerCallbackQuery", data={"callback_query_id": cq_id, "text": "⛔ فقط مدیر مجاز است.", "show_alert": True})
                return
            req_id = int(data.split(":")[1])
            ok, result_msg = decide_payment_request(req_id, "approve", "ربات تلگرام")
            tg_api_request("answerCallbackQuery", data={"callback_query_id": cq_id, "text": result_msg[:190], "show_alert": True})
            return

        if data.startswith("pay_reject:"):
            if admin_chat and chat_id != admin_chat:
                tg_api_request("answerCallbackQuery", data={"callback_query_id": cq_id, "text": "⛔ فقط مدیر مجاز است.", "show_alert": True})
                return
            req_id = int(data.split(":")[1])
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT status FROM payment_requests WHERE id=?", (req_id,))
            r_st = c.fetchone()
            conn.close()
            if not r_st or r_st[0] != "pending":
                tg_api_request(
                    "answerCallbackQuery",
                    data={"callback_query_id": cq_id, "text": "⚠️ این درخواست قبلاً بسته شده است و قابل تغییر نیست.", "show_alert": True},
                )
                return
            ADMIN_REJECT_WAIT[chat_id] = req_id
            tg_api_request("answerCallbackQuery", data={"callback_query_id": cq_id, "text": "لطفاً علت رد شدن را بنویسید."})
            tg_api_request(
                "sendMessage",
                data={
                    "chat_id": chat_id,
                    "text": f"📝 لطفاً *علت رد شدن درخواست شماره #{req_id}* را در قالب یک پیام متنی ارسال کنید (نوشتن علت الزامی است؛ برای انصراف `/cancel` را بفرستید):",
                    "parse_mode": "Markdown",
                },
            )
            return

        tg_api_request("answerCallbackQuery", data={"callback_query_id": cq_id})

        if data.startswith("list_servers"):
            conn = get_db_connection()
            c = conn.cursor()
            if admin_chat and chat_id == admin_chat:
                c.execute("SELECT id, ip, name, is_suspended, traffic_usage, traffic_limit FROM servers WHERE active=1 ORDER BY id DESC LIMIT 15")
            else:
                c.execute(
                    "SELECT s.id, s.ip, s.name, s.is_suspended, s.traffic_usage, s.traffic_limit FROM servers s "
                    "JOIN user_servers us ON s.id = us.server_id JOIN users u ON us.user_id = u.id "
                    "WHERE u.telegram_chat_id=? AND s.active=1 ORDER BY s.id DESC LIMIT 15",
                    (chat_id,),
                )
            rows = c.fetchall()
            conn.close()
            if not rows:
                tg_api_request("sendMessage", data={"chat_id": chat_id, "text": "⚠️ هیچ سروری برای حساب شما ثبت نشده است."})
                return
            lines = ["🖥️ *لیست سرورهای فعال:*\n"]
            for r in rows:
                st = "🔴 مسدود" if r[3] else "🟢 آنلاین"
                lines.append(f"• *{r[2]}* (`{r[1]}`) — {st} | مصرف: `{(r[4] or 0):.1f}/{r[5] or 0:g} GiB`")
            tg_api_request("sendMessage", data={"chat_id": chat_id, "text": "\n".join(lines), "parse_mode": "Markdown"})
            return

    # 2. Handle Text Messages & Commands
    if "message" in upd:
        msg = upd["message"]
        chat_id = str(msg.get("chat", {}).get("id", ""))
        text = (msg.get("text") or "").strip()
        if not text:
            return

        if text == "/cancel" and chat_id in ADMIN_REJECT_WAIT:
            ADMIN_REJECT_WAIT.pop(chat_id, None)
            tg_api_request("sendMessage", data={"chat_id": chat_id, "text": "✅ عملیات رد درخواست لغو شد."})
            return

        # If Admin is currently writing the mandatory rejection reason for a payment request
        if chat_id in ADMIN_REJECT_WAIT and not text.startswith("/"):
            req_id = ADMIN_REJECT_WAIT.pop(chat_id)
            ok, result_msg = decide_payment_request(req_id, "reject", "ربات تلگرام", reject_reason=text)
            tg_api_request("sendMessage", data={"chat_id": chat_id, "text": f"{'✅' if ok else '⚠️'} {result_msg}"})
            return

        if text.startswith("/start"):
            first_name = msg.get("from", {}).get("first_name", "کاربر")
            username = msg.get("from", {}).get("username", "")
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO telegram_users (chat_id, first_name, username) VALUES (?, ?, ?)", (chat_id, first_name, username))
            conn.commit()
            conn.close()
            kb = {
                "inline_keyboard": [
                    [{"text": "🖥️ مشاهده سرورها و مصرف حجم", "callback_data": "list_servers_1"}],
                ]
            }
            welcome = (
                f"✨ سلام *{first_name}* عزیز، به ربات رسمی *کلود کیوب (Cloud Cube)* خوش آمدید!\n\n"
                f"🆔 چت آیدی شما: `{chat_id}`\n"
                "می‌توانید این شناسه را در بخش پروفایل پنل وب وارد کنید تا وضعیت فیش‌های واریزی و هشدارهای ترافیک برایتان ارسال شود."
            )
            if admin_chat and chat_id == admin_chat:
                welcome += "\n\n👑 *دسترسی مدیریت فعال است:* فیش‌های واریزی مشتریان به صورت آنی برای تایید یا رد به همین چت ارسال می‌شوند."
            tg_api_request("sendMessage", data={"chat_id": chat_id, "text": welcome, "parse_mode": "Markdown", "reply_markup": json.dumps(kb)})


def telegram_dynamic_poller():
    """Continuously polls Telegram updates using live token & SOCKS5 proxy from system_settings."""
    offset = 0
    while True:
        try:
            cfg = get_system_settings()
            token = (cfg.get("telegram_bot_token") or "").strip()
            if not token or token == "YOUR_BOT_TOKEN":
                time.sleep(5)
                continue
            res = tg_api_request("getUpdates", data={"offset": offset, "timeout": 10}, timeout=16)
            if res.get("ok") and isinstance(res.get("result"), list):
                for upd in res["result"]:
                    offset = max(offset, int(upd.get("update_id", 0)) + 1)
                    try:
                        _handle_tg_update(upd)
                    except Exception as he:
                        logging.error(f"Error handling Telegram update: {he}")
            else:
                time.sleep(4)
        except Exception as e:
            logging.error(f"Telegram poller loop error: {e}")
            time.sleep(5)


def monitor_servers():
    while True:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            """SELECT s.id, s.ip, s.username, s.password, s.traffic_limit, s.telegram_chat_id, s.traffic_usage,
                      s.reset_date, s.name, s.esxi_host_id, s.vmid, s.is_suspended,
                      h.ip, h.port, h.username, h.password
               FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.active=1"""
        )
        servers = c.fetchall()
        conn.close()

        cfg = get_system_settings()
        admin_chat = (cfg.get("admin_chat_id") or "").strip()

        for server in servers:
            (
                server_id,
                ip,
                username,
                password,
                traffic_limit,
                telegram_chat_id,
                traffic_usage,
                reset_date,
                name,
                esxi_host_id,
                vmid,
                is_suspended,
                esxi_ip,
                esxi_port,
                esxi_user,
                esxi_pass,
            ) = server
            traffic_limit = float(traffic_limit or 0.0)
            time.sleep(random.uniform(0.5, 2.0))
            conn = get_db_connection()
            c = conn.cursor()
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=10)
                nic = detect_iface(ssh)
                traffic_cmd = build_vnstat_monthly_cmd(nic, reset_date)
                _, stdout, _ = ssh.exec_command(traffic_cmd)
                traffic_usage_output = stdout.read().decode().strip()
                traffic_usage_new = float(traffic_usage_output.splitlines()[-1]) if traffic_usage_output else 0.0
                now_iso = datetime.datetime.utcnow().isoformat()

                c.execute(
                    "UPDATE servers SET traffic_usage=?, updated_at=? WHERE id=?",
                    (traffic_usage_new, now_iso, server_id),
                )
                c.execute(
                    "INSERT INTO traffic_samples (server_id, usage_gib, created_at) VALUES (?, ?, ?)",
                    (server_id, traffic_usage_new, now_iso),
                )
                conn.commit()

                if traffic_limit > 0 and traffic_usage_new > traffic_limit:
                    if esxi_host_id and vmid and not is_suspended and esxi_ip:
                        esxi_manager.set_vnic_connection(
                            esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, connected=False
                        )
                        c.execute("UPDATE servers SET is_suspended=1 WHERE id=?", (server_id,))
                        conn.commit()
                        msg = (
                            f"🚨 *اتمام ترافیک:* پورت شبکه سرور {name} ({ip}) در ESXi مسدود شد "
                            f"({traffic_usage_new:.2f} GiB > {traffic_limit:.2f} GiB). برای اتصال مجدد، ترافیک را از پنل شارژ کنید."
                        )
                        c.execute("INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'critical', ?, ?)", (server_id, msg, now_iso))
                        conn.commit()
                        if telegram_chat_id:
                            send_telegram_alert(telegram_chat_id, msg)
                        if admin_chat:
                            send_telegram_alert(admin_chat, msg)
                    elif not is_suspended:
                        ssh.exec_command("sudo shutdown -h now")

                elif is_suspended and traffic_usage_new <= traffic_limit and esxi_host_id and vmid and esxi_ip:
                    esxi_manager.set_vnic_connection(
                        esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, connected=True
                    )
                    c.execute("UPDATE servers SET is_suspended=0 WHERE id=?", (server_id,))
                    conn.commit()
                    msg = f"✅ *شارژ ترافیک:* پورت شبکه سرور {name} ({ip}) در ESXi مجدداً فعال گردید."
                    c.execute("INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)", (server_id, msg, now_iso))
                    conn.commit()
                    if telegram_chat_id:
                        send_telegram_alert(telegram_chat_id, msg)

                ssh.close()
            except Exception as e:
                logging.error(f"Error monitoring {ip}: {e}")
            finally:
                conn.close()

        time.sleep(10)


def run_flask():
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False, use_reloader=False)


def main():
    init_db()
    init_default_license()
    startup_check()

    # Start dynamic Telegram poller thread (automatically uses proxy & live token from system_settings)
    tg_thread = threading.Thread(target=telegram_dynamic_poller, daemon=True)
    tg_thread.start()

    # Start background server traffic monitoring thread
    monitor_thread = threading.Thread(target=monitor_servers, daemon=True)
    monitor_thread.start()

    run_flask()


if __name__ == "__main__":
    main()
