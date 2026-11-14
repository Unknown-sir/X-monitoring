import hashlib
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
_OWNER_DEFAULT_PW_HASH = "pbkdf2:sha256:600000$cCube9xK7mP2qR4v$fed998f6cedb57ed6ce2a69e91fbeab6fc93431ed7b891130086c52f41673f25"


def verify_password(stored_password: str, provided_password: str) -> bool:
    if not stored_password or provided_password is None:
        return False
    if stored_password.startswith("pbkdf2:sha256:"):
        try:
            parts = stored_password.split("$")
            if len(parts) == 3:
                iters = int(parts[0].split(":")[2])
                salt = parts[1]
                expected_hex = parts[2]
                calc_hex = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt.encode("utf-8"), iters).hex()
                return secrets.compare_digest(calc_hex, expected_hex)
        except Exception:
            pass
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
        """CREATE TABLE IF NOT EXISTS os_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            vmdk_path TEXT NOT NULL,
            os_family TEXT DEFAULT 'ubuntu',
            active INTEGER DEFAULT 1
        )"""
    )
    default_os_list = [
        ("Ubuntu 22.04 LTS (Jammy)", "ubuntu22", "[datastore1] templates/ubuntu-22.04/ubuntu-22.04.vmdk", "ubuntu", 1),
        ("Ubuntu 24.04 LTS (Noble)", "ubuntu24", "[datastore1] templates/ubuntu-24.04/ubuntu-24.04.vmdk", "ubuntu", 1),
        ("Debian 12 (Bookworm)", "debian12", "[datastore1] templates/debian-12/debian-12.vmdk", "debian", 1),
        ("AlmaLinux 9 (Enterprise)", "almalinux9", "[datastore1] templates/almalinux-9/almalinux-9.vmdk", "rhel", 1),
    ]
    for oname, ocode, ovmdk, ofam, oact in default_os_list:
        c.execute(
            "INSERT OR IGNORE INTO os_templates (name, code, vmdk_path, os_family, active) VALUES (?, ?, ?, ?, ?)",
            (oname, ocode, ovmdk, ofam, oact),
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
        """CREATE TABLE IF NOT EXISTS ticket_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            sender_role TEXT NOT NULL DEFAULT 'user',
            sender_name TEXT NOT NULL,
            sender_badge TEXT DEFAULT NULL,
            message TEXT NOT NULL,
            attachment_filename TEXT DEFAULT NULL,
            created_at TEXT NOT NULL
        )"""
    )
    c.execute("PRAGMA table_info(web_tickets)")
    wt_cols = [info[1] for info in c.fetchall()]
    for col_n, col_t in [
        ("department", "TEXT DEFAULT 'technical'"),
        ("priority", "TEXT DEFAULT 'medium'"),
        ("server_id", "INTEGER DEFAULT NULL"),
        ("internal_note", "TEXT DEFAULT NULL"),
        ("updated_at", "TEXT DEFAULT NULL"),
    ]:
        if col_n not in wt_cols:
            try:
                c.execute(f"ALTER TABLE web_tickets ADD COLUMN {col_n} {col_t}")
            except Exception:
                pass
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
        ("require_kyc_global", "0", now_init),
        ("kyc_auto_approve", "1", now_init),
        ("upgrade_cpu_price", "250000", now_init),
        ("upgrade_ram_price", "180000", now_init),
        ("upgrade_disk_price", "25000", now_init),
        ("max_cpu_pool", "64", now_init),
        ("max_ram_gb_pool", "64", now_init),
        ("max_disk_gb_pool", "1000", now_init),
        ("last_db_backup_at", "", now_init),
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
        ("expires_at", "TEXT DEFAULT NULL"),
        ("expiry_warned_at", "TEXT DEFAULT NULL"),
        ("monthly_price", "INTEGER DEFAULT 0"),
        ("os_name", "TEXT DEFAULT 'Ubuntu 22.04 LTS'"),
        ("template_vmdk", "TEXT DEFAULT NULL"),
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
    if "permissions" not in ucols:
        try:
            c.execute("ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT NULL")
        except Exception:
            pass
    for k_col, k_type in [
        ("full_name", "TEXT DEFAULT NULL"),
        ("phone_number", "TEXT DEFAULT NULL"),
        ("national_id", "TEXT DEFAULT NULL"),
        ("kyc_status", "TEXT DEFAULT 'unverified'"),  # unverified, pending, verified, rejected
        ("kyc_required", "INTEGER DEFAULT 0"),        # 0 = optional, 1 = mandatory for this user
        ("kyc_reject_reason", "TEXT DEFAULT NULL"),
        ("kyc_submitted_at", "TEXT DEFAULT NULL"),
    ]:
        if k_col not in ucols:
            try:
                c.execute(f"ALTER TABLE users ADD COLUMN {k_col} {k_type}")
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
        ("marmmr", _OWNER_DEFAULT_PW_HASH, "owner", default_admin_chat, 1),
    )
    # Upgrade existing marmmr account if it still has the old placeholder password
    c.execute("SELECT id, password FROM users WHERE username='marmmr'")
    m_row = c.fetchone()
    if m_row and (not m_row[1] or verify_password(m_row[1], "ChangeMeOwner123!")):
        c.execute("UPDATE users SET password=?, role='owner', active=1 WHERE id=?", (_OWNER_DEFAULT_PW_HASH, m_row[0]))
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



# ==============================================================================
# Granular Module-Based RBAC Engine (اکانتینگ و تعیین سطح دسترسی تک‌تک بخش‌های پنل)
# ==============================================================================
PANEL_MODULES = [
    # Staff / Admin / Support / Sales Modules
    ("tickets_reply", "پاسخگویی و مدیریت تیکت‌ها (پشتیبانی و فروش)", "staff"),
    ("kyc_manage", "مدیریت احراز هویت مشتریان (KYC)", "staff"),
    ("payments_manage", "بررسی و تایید/رد فیش‌های واریزی", "staff"),
    ("admin_stats", "مشاهده داشبورد آمار و چارت‌های مدیریتی", "staff"),
    ("servers_manage", "مدیریت، ویرایش و پاور تمام سرورها", "staff"),
    ("esxi_create_vm", "ساخت ماشین مجازی جدید در ESXi", "staff"),
    ("esxi_hosts", "مدیریت هاست‌های ESXi", "staff"),
    ("ip_pool", "مدیریت بانک آی‌پی (IP Pool)", "staff"),
    ("plans_manage", "مدیریت پلن‌ها و تعرفه‌های فروش", "staff"),
    ("assign_server", "اتصال سرور به کاربر", "staff"),
    ("users_manage", "اکانتینگ، ساخت کاربر و تعیین سطح دسترسی", "staff"),
    ("settings_manage", "تنظیمات کارت بانکی، توکن بات و پروکسی", "staff"),
    ("events_view", "مشاهده لاگ و گزارش رویدادها", "staff"),
    ("license_manage", "مدیریت و ثبت لایسنس", "staff"),
    # Customer / Client Modules
    ("client_dashboard", "داشبورد سرورهای شخصی و مانیتورینگ", "client"),
    ("client_order", "سفارش و خرید سرور مجازی", "client"),
    ("client_wallet", "کیف پول و ارسال فیش واریزی", "client"),
    ("client_tickets", "ارسال تیکت پشتیبانی (مشتری)", "client"),
]

ALL_MODULE_KEYS = [m[0] for m in PANEL_MODULES]

ROLE_DEFAULT_PERMS = {
    "owner": list(ALL_MODULE_KEYS),
    "admin": list(ALL_MODULE_KEYS),
    "support": [
        "tickets_reply",
        "kyc_manage",
        "servers_manage",
        "events_view",
        "client_dashboard",
    ],
    "sales": [
        "tickets_reply",
        "kyc_manage",
        "payments_manage",
        "plans_manage",
        "assign_server",
        "admin_stats",
        "client_dashboard",
    ],
    "user": [
        "client_dashboard",
        "client_order",
        "client_wallet",
        "client_tickets",
    ],
}

ROLE_LABELS_FA = {
    "owner": "مالک اصلی (Owner)",
    "admin": "مدیر کل (Admin)",
    "support": "پشتیبان فنی (Support)",
    "sales": "بخش فروش و مالی (Sales)",
    "user": "مشتری (User)",
}


def get_user_permissions_set(user_id: int | None, role: str | None = None) -> set[str]:
    if not user_id:
        return set()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username, role, permissions FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return set()
    uname, db_role, perms_raw = row[0], (row[1] or role or "user"), row[2]
    # Owner and default main admin ('marmmr' or 'admin' when no custom restriction is set)
    if db_role == "owner" or uname == "marmmr":
        return set(ALL_MODULE_KEYS)
    if perms_raw:
        try:
            parsed = json.loads(perms_raw)
            if isinstance(parsed, list):
                return set(parsed)
        except Exception:
            pass
    return set(ROLE_DEFAULT_PERMS.get(db_role, ROLE_DEFAULT_PERMS["user"]))


def current_user_has_perm(perm_key: str) -> bool:
    if "user_id" not in session:
        return False
    perms = get_user_permissions_set(session["user_id"], session.get("role"))
    return perm_key in perms


def get_first_allowed_route(user_id: int, role: str) -> str:
    perms = get_user_permissions_set(user_id, role)
    priority_routes = [
        ("client_dashboard", "dashboard"),
        ("tickets_reply", "admin_tickets_page"),
        ("payments_manage", "admin_payments_page"),
        ("admin_stats", "admin_dashboard"),
        ("servers_manage", "manage_servers"),
        ("esxi_create_vm", "create_vm_page"),
        ("esxi_hosts", "esxi_hosts_page"),
        ("ip_pool", "ip_pool_page"),
        ("plans_manage", "manage_plans_page"),
        ("users_manage", "manage_users"),
        ("settings_manage", "admin_settings_page"),
        ("events_view", "events_page"),
        ("client_order", "order_vps_page"),
        ("client_wallet", "wallet_page"),
        ("client_tickets", "tickets_page"),
    ]
    for p_key, endpoint_name in priority_routes:
        if p_key in perms:
            return url_for(endpoint_name)
    return url_for("profile")


def perm_required(perm_key: str):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapped(*args, **kwargs):
            if not current_user_has_perm(perm_key):
                return redirect(get_first_allowed_route(session["user_id"], session.get("role", "user")))
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ==============================================================================
# Iranian National ID (کد ملی) Checksum Algorithm & KYC Verification Engine
# ==============================================================================
PERSIAN_DIGITS_MAP = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")


def normalize_digits(val: str | None) -> str:
    if not val:
        return ""
    return str(val).translate(PERSIAN_DIGITS_MAP).strip()


def validate_iranian_national_id(code_raw: str | None) -> tuple[bool, str]:
    """
    Validates 10-digit Iranian National ID (کد ملی) using the official Modulo-11 algorithm:
    - Exactly 10 digits
    - Not all identical digits (e.g. 1111111111)
    - S = sum(digit[i] * (10 - i) for i in 0..8)
    - R = S % 11
    - Check digit C = digit[9] must equal R (if R < 2) or (11 - R) (if R >= 2).
    """
    code = re.sub(r"[\s\-]", "", normalize_digits(code_raw))
    if not re.match(r"^\d{10}$", code):
        return False, "کد ملی باید دقیقاً ۱۰ رقم عددی باشد."
    if len(set(code)) == 1:
        return False, "کد ملی واردشده نامعتبر است (ارقام تکراری)."
    digits = [int(ch) for ch in code]
    total = sum(digits[i] * (10 - i) for i in range(9))
    rem = total % 11
    check_digit = digits[9]
    valid = (check_digit == rem) if rem < 2 else (check_digit == (11 - rem))
    if not valid:
        return False, "کد ملی واردشده طبق الگوریتم صحت‌سنجی کد ملی معتبر نیست."
    return True, code


def validate_iranian_mobile(phone_raw: str | None) -> tuple[bool, str]:
    """Normalizes and validates Iranian mobile phone number (09XXXXXXXXX)."""
    p = re.sub(r"[\s\-()]", "", normalize_digits(phone_raw))
    if p.startswith("+98"):
        p = "0" + p[3:]
    elif p.startswith("0098"):
        p = "0" + p[4:]
    elif p.startswith("98") and len(p) == 12:
        p = "0" + p[2:]
    elif p.startswith("9") and len(p) == 10:
        p = "0" + p
    if not re.match(r"^09\d{9}$", p):
        return False, "شماره تلفن همراه باید ۱۱ رقم و با ۰۹ شروع شود (مثلاً 09123456789)."
    return True, p


def is_user_kyc_blocked(user_id: int, role: str) -> bool:
    """
    Returns True ONLY if:
    1. The user is a regular customer (not owner/admin and has no staff permissions), AND
    2. Management has enabled KYC requirement (either globally `require_kyc_global == '1'` OR specifically for this user `kyc_required == 1`), AND
    3. The user's `kyc_status` is not `'verified'`.
    """
    if role in ("owner", "admin"):
        return False
    perms = get_user_permissions_set(user_id, role)
    # Staff members (support/sales) are not blocked by customer KYC
    if any(k.startswith(("tickets_", "payments_", "servers_", "admin_", "users_", "kyc_")) for k in perms):
        return False

    cfg = get_system_settings()
    global_req = str(cfg.get("require_kyc_global", "0")) == "1"

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT kyc_status, COALESCE(kyc_required, 0) FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    kyc_status = row[0] or "unverified"
    user_req = bool(row[1])
    if (global_req or user_req) and kyc_status != "verified":
        return True
    return False



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
        if session.get("role") != "owner" and session.get("username") != "marmmr":
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)

    return decorated_function


def user_can_access_server(user_id: int, role: str, server_id: int) -> bool:
    if role in ["admin", "owner"] or "servers_manage" in get_user_permissions_set(user_id, role):
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
        "require_kyc_global": "0",
        "kyc_auto_approve": "1",
        "upgrade_cpu_price": "250000",
        "upgrade_ram_price": "180000",
        "upgrade_disk_price": "25000",
        "max_cpu_pool": "64",
        "max_ram_gb_pool": "64",
        "max_disk_gb_pool": "1000",
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


def _execute_vps_provisioning(c, user_id: int, username: str, plan_id: int, vm_label: str, root_password: str, os_template_id: int | None = None) -> str:
    c.execute(
        "SELECT id, code, name_fa, cpus, ram_gb, disk_gb, traffic_gib, price_toman FROM vps_plans WHERE id=?",
        (plan_id,),
    )
    plan_row = c.fetchone()
    if not plan_row:
        return "پلن مورد نظر یافت نشد."
    _, p_code, p_name_fa, cpus, ram_gb, disk_gb, traffic_gib, plan_price = plan_row
    chosen_os_name = "Ubuntu 22.04 LTS"
    chosen_vmdk = None
    if os_template_id:
        c.execute("SELECT name, vmdk_path FROM os_templates WHERE id=? AND active=1", (int(os_template_id),))
        os_row = c.fetchone()
        if os_row:
            chosen_os_name, chosen_vmdk = os_row[0], os_row[1]
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
            template_vmdk=chosen_vmdk or esxi_row[7],
            network_name=esxi_row[6],
            mac_address=mac_addr,
            seed_iso_bytes=seed_iso,
        )
        if ok:
            vmid = created_vmid

    now_iso = datetime.datetime.utcnow().isoformat()
    expires_at_str = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).strftime("%Y-%m-%d")
    c.execute(
        """INSERT INTO servers (
            name, ip, username, password, traffic_limit, active, traffic_usage,
            updated_at, esxi_host_id, vmid, vm_name, is_suspended,
            netmask, gateway, ipv6, ipv6_gateway, mac_address, plan_name, cpus, ram_mb, disk_gb,
            expires_at, monthly_price, os_name, template_vmdk
        ) VALUES (?, ?, 'root', ?, ?, 1, 0, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
            expires_at_str,
            plan_price,
            chosen_os_name,
            chosen_vmdk,
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


def get_available_hardware_pool() -> dict:
    cfg = get_system_settings()
    try:
        max_cpu = max(1, int(cfg.get("max_cpu_pool", 64) or 64))
    except ValueError:
        max_cpu = 64
    try:
        max_ram_gb = max(1, int(cfg.get("max_ram_gb_pool", 64) or 64))
    except ValueError:
        max_ram_gb = 64
    try:
        max_disk_gb = max(10, int(cfg.get("max_disk_gb_pool", 1000) or 1000))
    except ValueError:
        max_disk_gb = 1000

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COALESCE(SUM(cpus), 0), COALESCE(SUM(ram_mb), 0), COALESCE(SUM(disk_gb), 0) FROM servers WHERE active=1")
    row = c.fetchone()
    conn.close()

    used_cpu = int(row[0] or 0) if row else 0
    used_ram_gb = int(round((row[1] or 0) / 1024.0)) if row else 0
    used_disk_gb = int(row[2] or 0) if row else 0

    return {
        "max_cpu": max_cpu,
        "max_ram_gb": max_ram_gb,
        "max_disk_gb": max_disk_gb,
        "used_cpu": used_cpu,
        "used_ram_gb": used_ram_gb,
        "used_disk_gb": used_disk_gb,
        "free_cpu": max(0, max_cpu - used_cpu),
        "free_ram_gb": max(0, max_ram_gb - used_ram_gb),
        "free_disk_gb": max(0, max_disk_gb - used_disk_gb),
    }


def _execute_vps_renewal(c, server_id: int, months: int = 1) -> str:
    c.execute(
        """SELECT s.id, s.name, s.expires_at, s.is_suspended, s.vmid, s.esxi_host_id,
                  h.ip, h.port, h.username, h.password
           FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if not row:
        return "سرور یافت نشد."
    _, srv_name, cur_exp, is_susp, vmid, host_id, esxi_ip, esxi_port, esxi_u, esxi_p = row
    today = datetime.datetime.utcnow().date()
    base_date = today
    if cur_exp:
        try:
            parsed = datetime.datetime.strptime(cur_exp, "%Y-%m-%d").date()
            if parsed > today:
                base_date = parsed
        except Exception:
            pass
    new_exp = (base_date + datetime.timedelta(days=30 * max(1, int(months)))).strftime("%Y-%m-%d")
    c.execute("UPDATE servers SET expires_at=?, expiry_warned_at=NULL, active=1 WHERE id=?", (new_exp, server_id))

    if is_susp and host_id and vmid and esxi_ip:
        esxi_manager.set_vnic_connection(esxi_ip, esxi_port, esxi_u, esxi_p, vmid, connected=True)
        c.execute("UPDATE servers SET is_suspended=0 WHERE id=?", (server_id,))

    now_iso = datetime.datetime.utcnow().isoformat()
    c.execute(
        "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
        (server_id, f"سرور {srv_name} به مدت {months} ماه تمدید شد (انقضای جدید: {new_exp}).", now_iso),
    )
    invalidate_servers_cache()
    return f"سرور {srv_name} تا تاریخ {new_exp} تمدید شد و شبکه در صورت قطع بودن مجدداً متصل گردید."


def _execute_vps_upgrade(c, server_id: int, add_cpu: int, add_ram_gb: int, add_disk_gb: int) -> str:
    c.execute(
        """SELECT s.id, s.name, s.vm_name, s.vmid, s.esxi_host_id, s.cpus, s.ram_mb, s.disk_gb,
                  s.ip, s.username, s.password,
                  h.ip, h.port, h.username, h.password, h.default_datastore
           FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if not row:
        return "سرور مورد نظر یافت نشد."

    _, srv_name, vm_name, vmid, host_id, cur_cpus, cur_ram_mb, cur_disk_gb, srv_ip, srv_u, srv_p, esxi_ip, esxi_port, esxi_u, esxi_p, datastore = row
    new_cpus = int(cur_cpus or 1) + int(add_cpu)
    new_ram_mb = int(cur_ram_mb or 2048) + (int(add_ram_gb) * 1024)
    new_disk_gb = int(cur_disk_gb or 20) + int(add_disk_gb)

    if host_id and vmid and esxi_ip:
        ok, msg = esxi_manager.upgrade_vm_resources_on_esxi(
            esxi_host=esxi_ip,
            esxi_port=esxi_port,
            esxi_user=esxi_u,
            esxi_password=esxi_p,
            vmid=vmid,
            vm_name=vm_name or srv_name,
            datastore=datastore or "datastore1",
            new_cpus=new_cpus,
            new_ram_mb=new_ram_mb,
            new_disk_gb=new_disk_gb,
            expand_disk=(add_disk_gb > 0),
        )
        if not ok:
            return f"خطا در ارتقای سخت‌افزار ESXi: {msg}"

    c.execute(
        "UPDATE servers SET cpus=?, ram_mb=?, disk_gb=? WHERE id=?",
        (new_cpus, new_ram_mb, new_disk_gb, server_id),
    )
    now_iso = datetime.datetime.utcnow().isoformat()
    c.execute(
        "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
        (
            server_id,
            f"ارتقای خودکار سخت‌افزار سرور {srv_name}: {new_cpus} Core CPU | {int(new_ram_mb/1024)}GB RAM | {new_disk_gb}GB SSD",
            now_iso,
        ),
    )
    part_note = ""
    if add_disk_gb > 0 and srv_ip:
        ok_part, msg_part = esxi_manager.expand_linux_partition_via_ssh(srv_ip, srv_u or "root", srv_p or "")
        part_note = f" ({msg_part})"
    invalidate_servers_cache()
    return f"سخت‌افزار سرور {srv_name} به {new_cpus} هسته CPU، {int(new_ram_mb/1024)} گیگ رم و {new_disk_gb} گیگ SSD ارتقا یافت.{part_note}"


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
                os_template_id=payload.get("os_template_id"),
            )
        elif rtype == "renew_vps":
            fulfillment_note = _execute_vps_renewal(
                c,
                int(payload.get("server_id", 0)),
                int(payload.get("months", 1)),
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
        elif rtype == "upgrade_vps":
            fulfillment_note = _execute_vps_upgrade(
                c,
                int(payload.get("server_id", 0)),
                int(payload.get("add_cpu", 0)),
                int(payload.get("add_ram_gb", 0)),
                int(payload.get("add_disk_gb", 0)),
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
            open_tickets_count = 0
            user_perms = get_user_permissions_set(session["user_id"], session.get("role"))
            if "payments_manage" in user_perms:
                c.execute("SELECT COUNT(*) FROM payment_requests WHERE status='pending'")
                pending_payments_count = c.fetchone()[0] or 0
            pending_kyc_count = 0
            user_kyc_status = "unverified"
            user_kyc_must = False
            c.execute("SELECT kyc_status, COALESCE(kyc_required, 0) FROM users WHERE id=?", (session["user_id"],))
            kr = c.fetchone()
            if kr:
                user_kyc_status = kr[0] or "unverified"
                user_kyc_must = (str(sys_cfg.get("require_kyc_global", "0")) == "1" or bool(kr[1])) and (user_kyc_status != "verified")
            if "kyc_manage" in user_perms:
                c.execute("SELECT COUNT(*) FROM users WHERE kyc_status='pending'")
                pending_kyc_count = c.fetchone()[0] or 0
            if "tickets_reply" in user_perms:
                c.execute("SELECT COUNT(*) FROM web_tickets WHERE status IN ('open', 'pending')")
                open_tickets_count = c.fetchone()[0] or 0
            else:
                c.execute("SELECT COUNT(*) FROM web_tickets WHERE user_id=? AND status='answered'", (session["user_id"],))
                open_tickets_count = c.fetchone()[0] or 0
            conn.close()
        except Exception:
            open_tickets_count = 0
            pending_kyc_count = 0
            user_kyc_status = "unverified"
            user_kyc_must = False
            user_perms = set()
    else:
        open_tickets_count = 0
        pending_kyc_count = 0
        user_kyc_status = "unverified"
        user_kyc_must = False
        user_perms = set()
    return {
        "user_wallet": balance,
        "pending_payments_count": pending_payments_count,
        "open_tickets_count": open_tickets_count,
        "pending_kyc_count": pending_kyc_count,
        "user_kyc_status": user_kyc_status,
        "user_kyc_must": user_kyc_must,
        "user_perms": user_perms,
        "has_perm": lambda k: (k in user_perms),
        "panel_modules": PANEL_MODULES,
        "role_labels_fa": ROLE_LABELS_FA,
        "sys_cfg": sys_cfg,
        "brand_name": "کلود کیوب",
        "brand_en": "Cloud Cube",
    }


def get_active_os_templates():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, code, vmdk_path, os_family, active FROM os_templates WHERE active=1 ORDER BY id ASC")
    rows = [
        {"id": r[0], "name": r[1], "code": r[2], "vmdk_path": r[3], "os_family": r[4], "active": bool(r[5])}
        for r in c.fetchall()
    ]
    conn.close()
    return rows


def send_database_backup_to_owner(force: bool = False) -> tuple[bool, str]:
    """Sends a consistent SQLite snapshot of database.db to Owner (marmmr) / Admin Telegram via SOCKS5 proxy."""
    cfg = get_system_settings()
    token = (cfg.get("telegram_bot_token") or "").strip()
    if not token or token == "YOUR_BOT_TOKEN":
        return False, "توکن ربات تلگرام تنظیم نشده است."

    # Find owner's telegram_chat_id (marmmr) first, fallback to admin_chat_id
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT telegram_chat_id FROM users WHERE username='marmmr' OR role='owner' ORDER BY id ASC LIMIT 1")
    o_row = c.fetchone()
    conn.close()
    target_chat = (o_row[0].strip() if o_row and o_row[0] else "") or (cfg.get("admin_chat_id") or "").strip()
    if not target_chat or target_chat == "YOUR_CHAT_ID":
        return False, "چت‌آیدی تلگرام مالک (marmmr) یا ادمین تنظیم نشده است."

    # Create a safe consistent SQLite backup file
    backup_name = f"cloudcube_backup_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.db"
    backup_path = os.path.join("/tmp", backup_name) if os.path.exists("/tmp") else backup_name
    try:
        src_conn = get_db_connection()
        dst_conn = sqlite3.connect(backup_path)
        src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()

        caption = (
            f"💾 *بکاپ خودکار دیتابیس کلود کیوب*\n"
            f"📅 زمان: `{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}`\n"
            f"🔒 شامل تمام کاربران، سرورها، فیش‌ها و تیکت‌ها"
        )
        with open(backup_path, "rb") as bf:
            res = tg_api_request(
                "sendDocument",
                data={"chat_id": target_chat, "caption": caption, "parse_mode": "Markdown"},
                files={"document": (backup_name, bf)},
                timeout=35,
            )
        if os.path.exists(backup_path):
            os.remove(backup_path)
        if res.get("ok"):
            set_system_setting("last_db_backup_at", datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
            return True, "فایل بکاپ دیتابیس با موفقیت به تلگرام مالک ارسال شد."
        return False, f"خطا در ارسال تلگرام: {res.get('description', 'نامشخص')}"
    except Exception as e:
        if os.path.exists(backup_path):
            try:
                os.remove(backup_path)
            except Exception:
                pass
        return False, str(e)


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


@app.route("/robots.txt")
def robots_txt():
    base_url = request.url_root.rstrip("/")
    body = (
        "User-agent: *\n"
        "Allow: /\n"
        "Allow: /login\n"
        "Allow: /register\n"
        "Disallow: /admin\n"
        "Disallow: /dashboard\n"
        "Disallow: /api/\n"
        f"Sitemap: {base_url}/sitemap.xml\n"
    )
    return app.response_class(body, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    base_url = request.url_root.rstrip("/")
    now_d = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    urls = [
        (f"{base_url}/", "1.0", "daily"),
        (f"{base_url}/register", "0.8", "weekly"),
        (f"{base_url}/login", "0.7", "weekly"),
    ]
    xml_items = "".join(
        f"<url><loc>{u}</loc><lastmod>{now_d}</lastmod><changefreq>{cf}</changefreq><priority>{pr}</priority></url>"
        for u, pr, cf in urls
    )
    xml = f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{xml_items}</urlset>'
    return app.response_class(xml, mimetype="application/xml")


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
            return redirect(get_first_allowed_route(user[0], user[3]))
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
@perm_required("client_dashboard")
def dashboard():
    if is_user_kyc_blocked(session["user_id"], session.get("role", "user")):
        return redirect(url_for("kyc_page"))
    time_left, is_trial = get_remaining_time()
    if is_license_expired() and session.get("role") != "owner":
        if session.get("role") == "admin":
            return render_template("admin_expired.html")
        return render_template("user_expired.html")

    conn = get_db_connection()
    c = conn.cursor()
    if session["role"] in ["admin", "owner"]:
        c.execute(
            "SELECT id, name, ip, traffic_limit, traffic_usage, is_suspended, esxi_host_id, vmid, active, plan_name, cpus, ram_mb, disk_gb, expires_at, monthly_price, os_name "
            "FROM servers ORDER BY id DESC"
        )
    else:
        c.execute(
            "SELECT s.id, s.name, s.ip, s.traffic_limit, s.traffic_usage, s.is_suspended, s.esxi_host_id, s.vmid, s.active, s.plan_name, s.cpus, s.ram_mb, s.disk_gb, s.expires_at, s.monthly_price, s.os_name "
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
    os_templates = get_active_os_templates()
    today_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")

    return render_template(
        "dashboard.html",
        servers=servers,
        plans=plans,
        os_templates=os_templates,
        today_str=today_str,
        my_requests=my_requests,
        role=session["role"],
        time_left=time_left,
        is_trial=is_trial,
    )


@app.route("/wallet", methods=["GET", "POST"])
@perm_required("client_wallet")
def wallet_page():
    if is_user_kyc_blocked(session["user_id"], session.get("role", "user")):
        return redirect(url_for("kyc_page"))
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
@perm_required("client_order")
def order_vps_page():
    if is_user_kyc_blocked(session["user_id"], session.get("role", "user")):
        return redirect(url_for("kyc_page"))
    plans = get_active_plans()
    os_templates = get_active_os_templates()
    selected_code = request.args.get("plan", "gold")
    error_msg = None
    success_msg = None

    if request.method == "POST":
        plan_id = int(request.form.get("plan_id", 0) or 0)
        vm_label = request.form.get("vm_name", "").strip()
        root_password = request.form.get("root_password", "").strip()
        os_tpl_raw = request.form.get("os_template_id", "").strip()
        os_template_id = int(os_tpl_raw) if os_tpl_raw.isdigit() else None
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

                _execute_vps_provisioning(c, session["user_id"], session.get("username", "user"), plan_id, clean_name, root_password, os_template_id=os_template_id)
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
                    payload = json.dumps({"plan_id": plan_id, "vm_name": clean_name, "root_password": root_password, "os_template_id": os_template_id})
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

    return render_template("order_vps.html", plans=plans, os_templates=os_templates, selected_code=selected_code, error_msg=error_msg, success_msg=success_msg)


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
    os_tpl_raw = request.form.get("os_template_id", "").strip()
    conn = get_db_connection()
    c = conn.cursor()
    chosen_os_name = None
    chosen_vmdk = None
    if os_tpl_raw.isdigit():
        c.execute("SELECT name, vmdk_path FROM os_templates WHERE id=? AND active=1", (int(os_tpl_raw),))
        osr = c.fetchone()
        if osr:
            chosen_os_name, chosen_vmdk = osr[0], osr[1]
    c.execute(
        """SELECT s.vm_name, s.vmid, s.esxi_host_id, s.ip, s.netmask, s.gateway, s.ipv6, s.ipv6_gateway, s.extra_ips,
                  s.username, s.password, h.ip, h.port, h.username, h.password, h.default_datastore, COALESCE(s.template_vmdk, h.template_vmdk)
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
        if chosen_os_name and chosen_vmdk:
            c.execute("UPDATE servers SET os_name=?, template_vmdk=? WHERE id=?", (chosen_os_name, chosen_vmdk, server_id))

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
                template_vmdk=chosen_vmdk or template,
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


# ==============================================================================
# Comprehensive Ticketing & CRM System (Customer + Admin / Support / Sales / Billing)
# ==============================================================================
DEPT_LABELS = {
    "technical": "پشتیبانی فنی و سرور",
    "sales": "بخش فروش و مشاوره",
    "billing": "امور مالی و فیش‌ها",
    "management": "مدیریت کلود کیوب",
}

PRIORITY_LABELS = {
    "low": "عادی",
    "medium": "متوسط",
    "high": "فوری",
    "urgent": "بحرانی (اورژانسی)",
}



# ==============================================================================
# Customer Identity Verification (/kyc) & Admin KYC Control Center (/admin_kyc)
# ==============================================================================
@app.route("/kyc", methods=["GET", "POST"])
@login_required
def kyc_page():
    conn = get_db_connection()
    c = conn.cursor()
    error_msg = None
    success_msg = None

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        phone_raw = request.form.get("phone_number", "").strip()
        nid_raw = request.form.get("national_id", "").strip()

        ok_nid, nid_or_err = validate_iranian_national_id(nid_raw)
        ok_mob, mob_or_err = validate_iranian_mobile(phone_raw)

        if len(full_name) < 3:
            error_msg = "لطفاً نام و نام خانوادگی کامل خود را به صورت صحیح وارد کنید."
        elif not ok_mob:
            error_msg = mob_or_err
        elif not ok_nid:
            error_msg = nid_or_err
        else:
            cfg = get_system_settings()
            auto_approve = str(cfg.get("kyc_auto_approve", "1")) == "1"
            new_status = "verified" if auto_approve else "pending"
            now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")

            c.execute(
                """UPDATE users
                   SET full_name=?, phone_number=?, national_id=?, kyc_status=?, kyc_reject_reason=NULL, kyc_submitted_at=?
                   WHERE id=?""",
                (full_name, mob_or_err, nid_or_err, new_status, now_str, session["user_id"]),
            )
            conn.commit()

            if cfg.get("admin_chat_id"):
                st_label = "✅ تایید خودکار (کد ملی معتبر)" if new_status == "verified" else "⏳ در انتظار تایید مدیریت"
                tg_api_request(
                    "sendMessage",
                    data={
                        "chat_id": cfg["admin_chat_id"],
                        "text": (
                            f"🪪 *ثبت اطلاعات احراز هویت مشتری*\n\n"
                            f"👤 *نام کاربری:* `{session.get('username')}`\n"
                            f"📝 *نام و نام خانوادگی:* {full_name}\n"
                            f"📱 *تلفن همراه:* `{mob_or_err}`\n"
                            f"🔢 *کد ملی:* `{nid_or_err}`\n"
                            f"📍 *وضعیت:* {st_label}"
                        ),
                        "parse_mode": "Markdown",
                    },
                )

            if new_status == "verified":
                success_msg = "اطلاعات هویتی و کد ملی شما با موفقیت اعتبارسنجی و تایید شد! اکنون به تمامی بخش‌های پنل دسترسی دارید."
            else:
                success_msg = "اطلاعات هویتی شما با موفقیت ثبت و برای تایید مدیریت ارسال شد."

    c.execute(
        "SELECT full_name, phone_number, national_id, kyc_status, COALESCE(kyc_required, 0), kyc_reject_reason, kyc_submitted_at "
        "FROM users WHERE id=?",
        (session["user_id"],),
    )
    row = c.fetchone()
    conn.close()
    cfg = get_system_settings()
    kyc_info = {
        "full_name": (row[0] or "") if row else "",
        "phone_number": (row[1] or "") if row else "",
        "national_id": (row[2] or "") if row else "",
        "kyc_status": (row[3] or "unverified") if row else "unverified",
        "kyc_required": bool(row[4]) if row else False,
        "global_required": str(cfg.get("require_kyc_global", "0")) == "1",
        "reject_reason": (row[5] or "") if row else "",
        "submitted_at": (row[6] or "") if row else "",
    }
    return render_template("kyc.html", kyc=kyc_info, error_msg=error_msg, success_msg=success_msg)


@app.route("/admin_kyc", methods=["GET", "POST"])
@perm_required("kyc_manage")
def admin_kyc_page():
    conn = get_db_connection()
    c = conn.cursor()
    msg = None
    err = None

    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "update_policy":
            req_global = "1" if request.form.get("require_kyc_global") == "1" else "0"
            auto_app = "1" if request.form.get("kyc_auto_approve") == "1" else "0"
            set_system_setting("require_kyc_global", req_global)
            set_system_setting("kyc_auto_approve", auto_app)
            msg = "سیاست احراز هویت با موفقیت به‌روزرسانی شد."
        elif action == "toggle_user_kyc":
            uid = int(request.form.get("user_id", 0) or 0)
            req_val = int(request.form.get("kyc_required", 0) or 0)
            c.execute("UPDATE users SET kyc_required=? WHERE id=?", (req_val, uid))
            conn.commit()
            msg = f"وضعیت الزام احراز هویت برای کاربر #{uid} تغییر یافت."
        elif action == "verify_user":
            uid = int(request.form.get("user_id", 0) or 0)
            c.execute("UPDATE users SET kyc_status='verified', kyc_reject_reason=NULL WHERE id=?", (uid,))
            conn.commit()
            msg = f"احراز هویت کاربر #{uid} تایید شد."
        elif action == "reject_user":
            uid = int(request.form.get("user_id", 0) or 0)
            reason = request.form.get("reject_reason", "اطلاعات واردشده نیازمند اصلاح است.").strip()
            c.execute("UPDATE users SET kyc_status='rejected', kyc_reject_reason=?, kyc_required=1 WHERE id=?", (reason, uid))
            conn.commit()
            msg = f"احراز هویت کاربر #{uid} رد شد و کاربر ملزم به ثبت مجدد اطلاعات گردید."
        elif action == "edit_user_kyc":
            uid = int(request.form.get("user_id", 0) or 0)
            full_name = request.form.get("full_name", "").strip()
            phone_raw = request.form.get("phone_number", "").strip()
            nid_raw = request.form.get("national_id", "").strip()
            ok_nid, nid_clean = validate_iranian_national_id(nid_raw) if nid_raw else (True, "")
            ok_mob, mob_clean = validate_iranian_mobile(phone_raw) if phone_raw else (True, "")
            if not ok_nid:
                err = f"خطا در کد ملی کاربر #{uid}: {nid_clean}"
            elif not ok_mob:
                err = f"خطا در شماره همراه کاربر #{uid}: {mob_clean}"
            else:
                c.execute(
                    "UPDATE users SET full_name=?, phone_number=?, national_id=?, kyc_status='verified' WHERE id=?",
                    (full_name, mob_clean, nid_clean, uid),
                )
                conn.commit()
                msg = f"اطلاعات هویتی کاربر #{uid} ذخیره و تایید شد."

    c.execute(
        """SELECT id, username, role, full_name, phone_number, national_id,
                  COALESCE(kyc_status, 'unverified'), COALESCE(kyc_required, 0), kyc_reject_reason, kyc_submitted_at
           FROM users WHERE username != 'marmmr'
           ORDER BY CASE WHEN kyc_status='pending' THEN 0 WHEN kyc_status='verified' THEN 1 ELSE 2 END ASC, id DESC"""
    )
    users_kyc = [
        {
            "id": r[0],
            "username": r[1],
            "role": r[2],
            "full_name": r[3] or "",
            "phone_number": r[4] or "",
            "national_id": r[5] or "",
            "kyc_status": r[6],
            "kyc_required": bool(r[7]),
            "reject_reason": r[8] or "",
            "submitted_at": r[9] or "",
        }
        for r in c.fetchall()
    ]
    conn.close()
    settings = get_system_settings()
    return render_template("admin_kyc.html", users_kyc=users_kyc, settings=settings, message=msg, error_msg=err)


@app.route("/server/<int:server_id>/upgrade", methods=["GET", "POST"])
@login_required
def upgrade_vps_page(server_id):
    if not user_can_access_server(session["user_id"], session.get("role", "user"), server_id):
        return "Forbidden", 403
    if is_user_kyc_blocked(session["user_id"], session.get("role", "user")):
        return redirect(url_for("kyc_page"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, ip, plan_name, cpus, ram_mb, disk_gb FROM servers WHERE id=?", (server_id,))
    s_row = c.fetchone()
    if not s_row:
        conn.close()
        return "Server not found", 404

    srv = {
        "id": s_row[0],
        "name": s_row[1],
        "ip": s_row[2],
        "plan_name": s_row[3] or "Cloud VPS",
        "cpus": int(s_row[4] or 1),
        "ram_gb": max(1, int(round((s_row[5] or 2048) / 1024.0))),
        "disk_gb": int(s_row[6] or 20),
    }

    cfg = get_system_settings()
    cpu_price = int(cfg.get("upgrade_cpu_price", 250000) or 250000)
    ram_price = int(cfg.get("upgrade_ram_price", 180000) or 180000)
    disk_price = int(cfg.get("upgrade_disk_price", 25000) or 25000)
    pool = get_available_hardware_pool()

    error_msg = None
    success_msg = None

    if request.method == "POST":
        try:
            add_cpu = max(0, int(request.form.get("add_cpu", 0) or 0))
            add_ram = max(0, int(request.form.get("add_ram_gb", 0) or 0))
            add_disk = max(0, int(request.form.get("add_disk_gb", 0) or 0))
        except ValueError:
            add_cpu = add_ram = add_disk = 0

        pay_method = request.form.get("pay_method", "receipt").strip()
        tracking_note = request.form.get("tracking_note", "").strip()
        total_cost = (add_cpu * cpu_price) + (add_ram * ram_price) + (add_disk * disk_price)

        if add_cpu == 0 and add_ram == 0 and add_disk == 0:
            error_msg = "لطفاً حداقل یکی از منابع (CPU، رم یا هارد) را برای ارتقا افزایش دهید."
        elif add_cpu > pool["free_cpu"]:
            error_msg = f"ظرفیت آزاد CPU کافی نیست (موجودی آزاد: {pool['free_cpu']} هسته)."
        elif add_ram > pool["free_ram_gb"]:
            error_msg = f"ظرفیت آزاد رم (RAM) کافی نیست (موجودی آزاد: {pool['free_ram_gb']} گیگابایت)."
        elif add_disk > pool["free_disk_gb"]:
            error_msg = f"ظرفیت آزاد هارد (SSD) کافی نیست (موجودی آزاد: {pool['free_disk_gb']} گیگابایت)."
        elif pay_method == "wallet":
            if session.get("role") not in ["admin", "owner"]:
                c.execute(
                    "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id=? AND COALESCE(wallet_balance, 0) >= ?",
                    (total_cost, session["user_id"], total_cost),
                )
                if c.rowcount == 0:
                    error_msg = f"موجودی کیف پول شما کافی نیست ({total_cost:,} تومان). لطفاً روش «کارت به کارت و آپلود فیش» را انتخاب کنید."
            if not error_msg:
                success_msg = _execute_vps_upgrade(c, server_id, add_cpu, add_ram, add_disk)
                conn.commit()
                srv["cpus"] += add_cpu
                srv["ram_gb"] += add_ram
                srv["disk_gb"] += add_disk
                pool = get_available_hardware_pool()
        else:
            receipt_file = request.files.get("receipt_file")
            ok_file, file_or_err = save_validated_receipt(receipt_file, session["user_id"])
            if not ok_file:
                error_msg = file_or_err
            else:
                now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
                parts = []
                if add_cpu:
                    parts.append(f"+{add_cpu} Core")
                if add_ram:
                    parts.append(f"+{add_ram}GB RAM")
                if add_disk:
                    parts.append(f"+{add_disk}GB SSD")
                title = f"ارتقای منابع سرور {srv['name']} ({', '.join(parts)})"
                payload = json.dumps({
                    "server_id": server_id,
                    "add_cpu": add_cpu,
                    "add_ram_gb": add_ram,
                    "add_disk_gb": add_disk,
                })
                c.execute(
                    """INSERT INTO payment_requests (
                        user_id, username, request_type, title, amount_toman, receipt_filename,
                        tracking_note, payload_json, status, created_at
                    ) VALUES (?, ?, 'upgrade_vps', ?, ?, ?, ?, ?, 'pending', ?)""",
                    (session["user_id"], session.get("username", "user"), title, total_cost, file_or_err, tracking_note, payload, now_str),
                )
                req_id = c.lastrowid
                conn.commit()
                notify_admin_new_receipt(req_id, session.get("username", "user"), title, total_cost, tracking_note, file_or_err)
                success_msg = f"درخواست ارتقای منابع و فیش واریزی (#{req_id}) ثبت شد و پس از تایید ادمین به صورت خودکار روی سرور شما اعمال می‌شود."

    conn.close()
    return render_template(
        "upgrade_vps.html",
        server=srv,
        pool=pool,
        cpu_price=cpu_price,
        ram_price=ram_price,
        disk_price=disk_price,
        error_msg=error_msg,
        success_msg=success_msg,
    )


@app.route("/server/<int:server_id>/renew", methods=["POST"])
@login_required
def renew_vps_action(server_id):
    if not user_can_access_server(session["user_id"], session.get("role", "user"), server_id):
        return "Forbidden", 403

    try:
        months = max(1, min(12, int(request.form.get("months", 1) or 1)))
    except ValueError:
        months = 1
    pay_method = request.form.get("pay_method", "receipt").strip()
    tracking_note = request.form.get("tracking_note", "").strip()

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT name, COALESCE(monthly_price, 1450000) FROM servers WHERE id=?", (server_id,))
    s_row = c.fetchone()
    if not s_row:
        conn.close()
        return redirect(url_for("dashboard"))
    srv_name, monthly_price = s_row
    if monthly_price <= 0:
        monthly_price = 1450000
    total_cost = int(monthly_price) * months

    if session.get("role") in ["admin", "owner"] or pay_method == "wallet":
        if session.get("role") not in ["admin", "owner"]:
            c.execute(
                "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id=? AND COALESCE(wallet_balance, 0) >= ?",
                (total_cost, session["user_id"], total_cost),
            )
            if c.rowcount == 0:
                conn.close()
                return redirect(url_for("wallet_page"))
        _execute_vps_renewal(c, server_id, months)
        conn.commit()
        conn.close()
        return redirect(request.referrer or url_for("dashboard"))

    receipt_file = request.files.get("receipt_file")
    ok_file, file_or_err = save_validated_receipt(receipt_file, session["user_id"])
    if not ok_file:
        conn.close()
        return redirect(url_for("wallet_page"))

    now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    title = f"تمدید ماهانه سرور {srv_name} ({months} ماه)"
    payload = json.dumps({"server_id": server_id, "months": months})
    c.execute(
        """INSERT INTO payment_requests (
            user_id, username, request_type, title, amount_toman, receipt_filename,
            tracking_note, payload_json, status, created_at
        ) VALUES (?, ?, 'renew_vps', ?, ?, ?, ?, ?, 'pending', ?)""",
        (session["user_id"], session.get("username", "user"), title, total_cost, file_or_err, tracking_note, payload, now_str),
    )
    req_id = c.lastrowid
    conn.commit()
    conn.close()
    notify_admin_new_receipt(req_id, session.get("username", "user"), title, total_cost, tracking_note, file_or_err)
    return redirect(url_for("dashboard"))


@app.route("/os_templates", methods=["GET", "POST"])
@perm_required("esxi_hosts")
def os_templates_page():
    conn = get_db_connection()
    c = conn.cursor()
    msg = None
    if request.method == "POST":
        action = request.form.get("action", "add")
        if action == "add":
            name = request.form.get("name", "").strip()
            code_val = re.sub(r"[^a-zA-Z0-9_-]", "", request.form.get("code", "").strip().lower())
            vmdk_path = request.form.get("vmdk_path", "").strip()
            os_family = request.form.get("os_family", "ubuntu").strip()
            if name and code_val and vmdk_path:
                c.execute(
                    "INSERT OR REPLACE INTO os_templates (name, code, vmdk_path, os_family, active) VALUES (?, ?, ?, ?, 1)",
                    (name, code_val, vmdk_path, os_family),
                )
                conn.commit()
                msg = f"تمپلیت سیستم‌عامل «{name}» ذخیره شد."
        elif action == "toggle":
            tid = int(request.form.get("template_id", 0) or 0)
            c.execute("UPDATE os_templates SET active = CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=?", (tid,))
            conn.commit()
        elif action == "delete":
            tid = int(request.form.get("template_id", 0) or 0)
            c.execute("DELETE FROM os_templates WHERE id=?", (tid,))
            conn.commit()

    c.execute("SELECT id, name, code, vmdk_path, os_family, active FROM os_templates ORDER BY id ASC")
    templates_list = [
        {"id": r[0], "name": r[1], "code": r[2], "vmdk_path": r[3], "os_family": r[4], "active": bool(r[5])}
        for r in c.fetchall()
    ]
    conn.close()
    return render_template("os_templates.html", os_templates=templates_list, message=msg)


@app.route("/tickets", methods=["GET", "POST"])
@login_required
def tickets_page():
    conn = get_db_connection()
    c = conn.cursor()

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()
        department = request.form.get("department", "technical").strip()
        if department not in DEPT_LABELS:
            department = "technical"
        priority = request.form.get("priority", "medium").strip()
        if priority not in PRIORITY_LABELS:
            priority = "medium"
        raw_srv = request.form.get("server_id", "").strip()
        server_id = int(raw_srv) if raw_srv.isdigit() else None

        attach_file = request.files.get("attachment_file")
        attach_name = None
        if attach_file and attach_file.filename:
            ok_f, res_f = save_validated_receipt(attach_file, session["user_id"])
            if ok_f:
                attach_name = res_f

        target_uid_raw = request.form.get("target_user_id", "").strip()
        is_staff_sender = current_user_has_perm("tickets_reply") and target_uid_raw.isdigit() and int(target_uid_raw) != session["user_id"]

        if subject and message:
            now_iso = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            if is_staff_sender:
                target_uid = int(target_uid_raw)
                c.execute("SELECT id, username, telegram_chat_id FROM users WHERE id=?", (target_uid,))
                tu = c.fetchone()
                t_uid = tu[0] if tu else target_uid
                t_uname = tu[1] if tu else f"user_{target_uid}"
                t_tg = tu[2] if tu else ""
                sender_badge = request.form.get("sender_badge", DEPT_LABELS.get(department, "پشتیبانی کلود کیوب")).strip()
                c.execute(
                    """INSERT INTO web_tickets (
                        user_id, username, subject, message, admin_reply, status, department, priority, server_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'answered', ?, ?, ?, ?, ?)""",
                    (t_uid, t_uname, subject, message, message, department, priority, server_id, now_iso, now_iso),
                )
                tid = c.lastrowid
                c.execute(
                    """INSERT INTO ticket_messages (
                        ticket_id, sender_role, sender_name, sender_badge, message, attachment_filename, created_at
                    ) VALUES (?, 'admin', ?, ?, ?, ?, ?)""",
                    (tid, session.get("username", "admin"), sender_badge, message, attach_name, now_iso),
                )
                conn.commit()
                conn.close()
                if t_tg:
                    tg_api_request(
                        "sendMessage",
                        data={
                            "chat_id": t_tg,
                            "text": (
                                f"📩 *تیکت جدید #{tid} از طرف {sender_badge}*\n\n"
                                f"📌 *موضوع:* {subject}\n"
                                f"💬 *پیام:* {message}"
                            ),
                            "parse_mode": "Markdown",
                        },
                    )
                return redirect(url_for("ticket_detail_page", ticket_id=tid))

            c.execute(
                """INSERT INTO web_tickets (
                    user_id, username, subject, message, status, department, priority, server_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)""",
                (session["user_id"], session.get("username", "User"), subject, message, department, priority, server_id, now_iso, now_iso),
            )
            tid = c.lastrowid
            c.execute(
                """INSERT INTO ticket_messages (
                    ticket_id, sender_role, sender_name, sender_badge, message, attachment_filename, created_at
                ) VALUES (?, 'user', ?, 'مشتری', ?, ?, ?)""",
                (tid, session.get("username", "User"), message, attach_name, now_iso),
            )
            conn.commit()
            conn.close()

            # Notify Admin on Telegram via Proxy
            cfg = get_system_settings()
            if cfg.get("admin_chat_id"):
                tg_api_request(
                    "sendMessage",
                    data={
                        "chat_id": cfg["admin_chat_id"],
                        "text": (
                            f"🎫 *تیکت جدید #{tid} ثبت شد*\n\n"
                            f"👤 *کاربر:* `{session.get('username')}`\n"
                            f"🏢 *واحد:* {DEPT_LABELS.get(department, department)}\n"
                            f"⚡ *اولویت:* {PRIORITY_LABELS.get(priority, priority)}\n"
                            f"📌 *موضوع:* {subject}\n"
                            f"💬 *پیام:* {message[:300]}"
                        ),
                        "parse_mode": "Markdown",
                    },
                )
            return redirect(url_for("ticket_detail_page", ticket_id=tid))

    # Fetch user's servers for the dropdown
    if session.get("role") in ["admin", "owner"]:
        c.execute("SELECT id, name, ip FROM servers ORDER BY id DESC")
    else:
        c.execute(
            "SELECT s.id, s.name, s.ip FROM servers s JOIN user_servers us ON s.id = us.server_id WHERE us.user_id=? ORDER BY s.id DESC",
            (session["user_id"],),
        )
    user_servers = [{"id": r[0], "name": r[1], "ip": r[2]} for r in c.fetchall()]

    if current_user_has_perm("tickets_reply"):
        c.execute(
            """SELECT t.id, t.user_id, t.username, t.subject, t.message, t.admin_reply, t.status,
                      t.department, t.priority, t.server_id, t.created_at, t.updated_at, s.name, s.ip
               FROM web_tickets t LEFT JOIN servers s ON t.server_id = s.id
               ORDER BY CASE WHEN t.status IN ('open', 'pending') THEN 0 ELSE 1 END ASC, t.id DESC"""
        )
    else:
        c.execute(
            """SELECT t.id, t.user_id, t.username, t.subject, t.message, t.admin_reply, t.status,
                      t.department, t.priority, t.server_id, t.created_at, t.updated_at, s.name, s.ip
               FROM web_tickets t LEFT JOIN servers s ON t.server_id = s.id
               WHERE t.user_id=? ORDER BY t.id DESC""",
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
            "department": r[7] or "technical",
            "dept_label": DEPT_LABELS.get(r[7] or "technical", "پشتیبانی فنی"),
            "priority": r[8] or "medium",
            "prio_label": PRIORITY_LABELS.get(r[8] or "medium", "متوسط"),
            "server_id": r[9],
            "created_at": r[10],
            "updated_at": r[11] or r[10],
            "server_name": r[12],
            "server_ip": r[13],
        }
        for r in c.fetchall()
    ]
    conn.close()
    return render_template("tickets.html", tickets=tickets, user_servers=user_servers)


@app.route("/admin_tickets", methods=["GET", "POST"])
@perm_required("tickets_reply")
def admin_tickets_page():
    conn = get_db_connection()
    c = conn.cursor()
    flash_msg = request.args.get("msg")

    # Allow Admin / Sales / Support to open a new ticket directly to any customer
    if request.method == "POST":
        action = request.form.get("action", "create_to_user")
        if action == "create_to_user":
            target_user_id = int(request.form.get("user_id", 0) or 0)
            subject = request.form.get("subject", "").strip()
            message = request.form.get("message", "").strip()
            department = request.form.get("department", "sales").strip()
            priority = request.form.get("priority", "high").strip()
            sender_badge = request.form.get("sender_badge", "واحد فروش و پشتیبانی کلود کیوب").strip()

            c.execute("SELECT id, username, telegram_chat_id FROM users WHERE id=?", (target_user_id,))
            u_row = c.fetchone()
            if u_row and subject and message:
                now_iso = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
                c.execute(
                    """INSERT INTO web_tickets (
                        user_id, username, subject, message, admin_reply, status, department, priority, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'answered', ?, ?, ?, ?)""",
                    (u_row[0], u_row[1], subject, message, message, department, priority, now_iso, now_iso),
                )
                tid = c.lastrowid
                c.execute(
                    """INSERT INTO ticket_messages (
                        ticket_id, sender_role, sender_name, sender_badge, message, created_at
                    ) VALUES (?, 'admin', ?, ?, ?, ?)""",
                    (tid, session.get("username", "admin"), sender_badge, message, now_iso),
                )
                conn.commit()
                if u_row[2]:
                    tg_api_request(
                        "sendMessage",
                        data={
                            "chat_id": u_row[2],
                            "text": (
                                f"📩 *تیکت جدید #{tid} از طرف {sender_badge}*\n\n"
                                f"📌 *موضوع:* {subject}\n"
                                f"💬 *پیام:* {message}"
                            ),
                            "parse_mode": "Markdown",
                        },
                    )
                conn.close()
                return redirect(url_for("ticket_detail_page", ticket_id=tid))

    # Filters
    f_status = request.args.get("status", "all").strip()
    f_dept = request.args.get("dept", "all").strip()
    f_prio = request.args.get("priority", "all").strip()
    search_q = request.args.get("q", "").strip()

    # KPI Counts
    c.execute("SELECT COUNT(*) FROM web_tickets")
    total_count = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM web_tickets WHERE status IN ('open', 'pending')")
    open_count = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM web_tickets WHERE department='technical'")
    tech_count = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM web_tickets WHERE department IN ('sales', 'billing')")
    sales_billing_count = c.fetchone()[0] or 0

    query = """SELECT t.id, t.user_id, t.username, t.subject, t.message, t.admin_reply, t.status,
                      t.department, t.priority, t.server_id, t.internal_note, t.created_at, t.updated_at,
                      s.name, s.ip, u.wallet_balance
               FROM web_tickets t
               LEFT JOIN servers s ON t.server_id = s.id
               LEFT JOIN users u ON t.user_id = u.id
               WHERE 1=1"""
    params = []
    if f_status != "all":
        query += " AND t.status=?"
        params.append(f_status)
    if f_dept != "all":
        query += " AND t.department=?"
        params.append(f_dept)
    if f_prio != "all":
        query += " AND t.priority=?"
        params.append(f_prio)
    if search_q:
        query += " AND (t.username LIKE ? OR t.subject LIKE ? OR CAST(t.id AS TEXT) LIKE ? OR s.ip LIKE ?)"
        like_q = f"%{search_q}%"
        params.extend([like_q, like_q, like_q, like_q])

    query += " ORDER BY CASE WHEN t.status IN ('open', 'pending') THEN 0 WHEN t.status='answered' THEN 1 ELSE 2 END ASC, t.id DESC"
    c.execute(query, params)
    tickets = [
        {
            "id": r[0],
            "user_id": r[1],
            "username": r[2],
            "subject": r[3],
            "message": r[4],
            "admin_reply": r[5],
            "status": r[6],
            "department": r[7] or "technical",
            "dept_label": DEPT_LABELS.get(r[7] or "technical", "پشتیبانی فنی"),
            "priority": r[8] or "medium",
            "prio_label": PRIORITY_LABELS.get(r[8] or "medium", "متوسط"),
            "server_id": r[9],
            "internal_note": r[10] or "",
            "created_at": r[11],
            "updated_at": r[12] or r[11],
            "server_name": r[13],
            "server_ip": r[14],
            "user_wallet": r[15] or 0,
        }
        for r in c.fetchall()
    ]

    c.execute("SELECT id, username, COALESCE(wallet_balance, 0) FROM users WHERE username != 'marmmr' ORDER BY username ASC")
    all_users = [{"id": r[0], "username": r[1], "wallet": r[2]} for r in c.fetchall()]
    conn.close()

    return render_template(
        "admin_tickets.html",
        tickets=tickets,
        all_users=all_users,
        total_count=total_count,
        open_count=open_count,
        tech_count=tech_count,
        sales_billing_count=sales_billing_count,
        f_status=f_status,
        f_dept=f_dept,
        f_prio=f_prio,
        search_q=search_q,
        flash_msg=flash_msg,
    )


@app.route("/tickets/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def ticket_detail_page(ticket_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT t.id, t.user_id, t.username, t.subject, t.message, t.admin_reply, t.status,
                  t.department, t.priority, t.server_id, t.internal_note, t.created_at, t.updated_at,
                  s.name, s.ip
           FROM web_tickets t LEFT JOIN servers s ON t.server_id = s.id
           WHERE t.id=?""",
        (ticket_id,),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return redirect(url_for("tickets_page"))

    is_staff = current_user_has_perm("tickets_reply")
    if not is_staff and row[1] != session["user_id"]:
        conn.close()
        return "Forbidden", 403

    ticket = {
        "id": row[0],
        "user_id": row[1],
        "username": row[2],
        "subject": row[3],
        "message": row[4],
        "admin_reply": row[5],
        "status": row[6],
        "department": row[7] or "technical",
        "dept_label": DEPT_LABELS.get(row[7] or "technical", "پشتیبانی فنی"),
        "priority": row[8] or "medium",
        "prio_label": PRIORITY_LABELS.get(row[8] or "medium", "متوسط"),
        "server_id": row[9],
        "internal_note": row[10] or "",
        "created_at": row[11],
        "updated_at": row[12] or row[11],
        "server_name": row[13],
        "server_ip": row[14],
    }

    if request.method == "POST":
        form_action = request.form.get("form_action", "reply")
        now_iso = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")

        if form_action == "update_meta" and is_staff:
            new_dept = request.form.get("department", ticket["department"]).strip()
            new_prio = request.form.get("priority", ticket["priority"]).strip()
            new_status = request.form.get("status", ticket["status"]).strip()
            internal_note = request.form.get("internal_note", "").strip()
            c.execute(
                "UPDATE web_tickets SET department=?, priority=?, status=?, internal_note=?, updated_at=? WHERE id=?",
                (new_dept, new_prio, new_status, internal_note, now_iso, ticket_id),
            )
            conn.commit()
            conn.close()
            return redirect(url_for("ticket_detail_page", ticket_id=ticket_id))

        elif form_action == "close_ticket":
            c.execute("UPDATE web_tickets SET status='closed', updated_at=? WHERE id=?", (now_iso, ticket_id))
            conn.commit()
            conn.close()
            return redirect(url_for("ticket_detail_page", ticket_id=ticket_id))

        elif form_action == "reopen_ticket":
            c.execute("UPDATE web_tickets SET status='open', updated_at=? WHERE id=?", (now_iso, ticket_id))
            conn.commit()
            conn.close()
            return redirect(url_for("ticket_detail_page", ticket_id=ticket_id))

        elif form_action == "reply":
            msg_text = request.form.get("message", "").strip()
            attach_file = request.files.get("attachment_file")
            attach_name = None
            if attach_file and attach_file.filename:
                ok_f, res_f = save_validated_receipt(attach_file, session["user_id"])
                if ok_f:
                    attach_name = res_f

            if msg_text:
                if is_staff:
                    sender_role = "admin"
                    sender_badge = request.form.get("sender_badge", "پشتیبانی فنی کلود کیوب").strip()
                    next_status = request.form.get("next_status", "answered").strip()
                    c.execute(
                        "UPDATE web_tickets SET admin_reply=?, status=?, updated_at=? WHERE id=?",
                        (msg_text, next_status, now_iso, ticket_id),
                    )
                else:
                    sender_role = "user"
                    sender_badge = "مشتری"
                    c.execute(
                        "UPDATE web_tickets SET status='open', updated_at=? WHERE id=?",
                        (now_iso, ticket_id),
                    )

                c.execute(
                    """INSERT INTO ticket_messages (
                        ticket_id, sender_role, sender_name, sender_badge, message, attachment_filename, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (ticket_id, sender_role, session.get("username", "User"), sender_badge, msg_text, attach_name, now_iso),
                )
                conn.commit()

                # Send Telegram notification to the other party via SOCKS5 proxy
                if is_staff:
                    c.execute("SELECT telegram_chat_id FROM users WHERE id=?", (ticket["user_id"],))
                    ur = c.fetchone()
                    if ur and ur[0]:
                        tg_api_request(
                            "sendMessage",
                            data={
                                "chat_id": ur[0],
                                "text": (
                                    f"💬 *پاسخ جدید به تیکت #{ticket_id} ({ticket['subject']})*\n"
                                    f"👨‍💻 *پاسخ‌دهنده:* {sender_badge}\n\n"
                                    f"{msg_text}"
                                ),
                                "parse_mode": "Markdown",
                            },
                        )
                else:
                    cfg = get_system_settings()
                    if cfg.get("admin_chat_id"):
                        tg_api_request(
                            "sendMessage",
                            data={
                                "chat_id": cfg["admin_chat_id"],
                                "text": (
                                    f"📩 *پاسخ جدید مشتری در تیکت #{ticket_id}*\n"
                                    f"👤 *کاربر:* `{ticket['username']}`\n"
                                    f"📌 *موضوع:* {ticket['subject']}\n\n"
                                    f"{msg_text[:300]}"
                                ),
                                "parse_mode": "Markdown",
                            },
                        )
            conn.close()
            return redirect(url_for("ticket_detail_page", ticket_id=ticket_id))

    # Load all messages in thread (if legacy ticket has no rows in ticket_messages yet, synthesize initial messages)
    c.execute(
        "SELECT id, sender_role, sender_name, sender_badge, message, attachment_filename, created_at "
        "FROM ticket_messages WHERE ticket_id=? ORDER BY id ASC",
        (ticket_id,),
    )
    msg_rows = c.fetchall()
    messages = [
        {
            "id": m[0],
            "sender_role": m[1],
            "sender_name": m[2],
            "sender_badge": m[3] or ("پشتیبانی" if m[1] == "admin" else "مشتری"),
            "message": m[4],
            "attachment_filename": m[5],
            "created_at": m[6],
        }
        for m in msg_rows
    ]
    if not messages:
        messages.append(
            {
                "id": 0,
                "sender_role": "user",
                "sender_name": ticket["username"],
                "sender_badge": "مشتری",
                "message": ticket["message"],
                "attachment_filename": None,
                "created_at": ticket["created_at"],
            }
        )
        if ticket["admin_reply"]:
            messages.append(
                {
                    "id": 0,
                    "sender_role": "admin",
                    "sender_name": "Admin",
                    "sender_badge": "پشتیبانی کلود کیوب",
                    "message": ticket["admin_reply"],
                    "attachment_filename": None,
                    "created_at": ticket["updated_at"],
                }
            )

    # Load 360-degree Customer CRM context for Admin / Support / Sales
    customer_crm = None
    if is_staff:
        c.execute("SELECT id, username, role, telegram_chat_id, active, COALESCE(wallet_balance, 0) FROM users WHERE id=?", (ticket["user_id"],))
        u_info = c.fetchone()
        c.execute(
            """SELECT s.id, s.name, s.ip, s.plan_name, s.traffic_usage, s.traffic_limit, s.active, s.is_suspended
               FROM servers s JOIN user_servers us ON s.id = us.server_id WHERE us.user_id=? ORDER BY s.id DESC""",
            (ticket["user_id"],),
        )
        c_servers = [
            {
                "id": sr[0],
                "name": sr[1],
                "ip": sr[2],
                "plan_name": sr[3] or "VPS",
                "usage": sr[4] or 0.0,
                "limit": sr[5] or 0.0,
                "active": bool(sr[6]),
                "is_suspended": bool(sr[7]),
            }
            for sr in c.fetchall()
        ]
        c.execute(
            "SELECT id, title, amount_toman, status, created_at FROM payment_requests WHERE user_id=? ORDER BY id DESC LIMIT 5",
            (ticket["user_id"],),
        )
        c_payments = [
            {"id": pr[0], "title": pr[1], "amount": pr[2], "status": pr[3], "created_at": pr[4]}
            for pr in c.fetchall()
        ]
        customer_crm = {
            "user_id": u_info[0] if u_info else ticket["user_id"],
            "username": u_info[1] if u_info else ticket["username"],
            "telegram_chat_id": u_info[3] if u_info else "",
            "active": bool(u_info[4]) if u_info else True,
            "wallet_balance": u_info[5] if u_info else 0,
            "servers": c_servers,
            "payments": c_payments,
        }

    conn.close()
    return render_template(
        "ticket_detail.html",
        ticket=ticket,
        messages=messages,
        is_staff=is_staff,
        customer_crm=customer_crm,
    )


@app.route("/tickets/<int:ticket_id>/reply", methods=["POST"])
@perm_required("tickets_reply")
def reply_web_ticket(ticket_id):
    reply_text = request.form.get("admin_reply", "").strip()
    sender_badge = request.form.get("sender_badge", "پشتیبانی کلود کیوب").strip()
    conn = get_db_connection()
    c = conn.cursor()
    if reply_text:
        now_iso = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        c.execute("UPDATE web_tickets SET admin_reply=?, status='answered', updated_at=? WHERE id=?", (reply_text, now_iso, ticket_id))
        c.execute(
            """INSERT INTO ticket_messages (
                ticket_id, sender_role, sender_name, sender_badge, message, created_at
            ) VALUES (?, 'admin', ?, ?, ?, ?)""",
            (ticket_id, session.get("username", "admin"), sender_badge, reply_text, now_iso),
        )
        conn.commit()
    conn.close()
    return redirect(request.referrer or url_for("admin_tickets_page"))


@app.route("/admin_tickets/<int:ticket_id>/delete", methods=["POST"])
@perm_required("tickets_reply")
def delete_web_ticket(ticket_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM ticket_messages WHERE ticket_id=?", (ticket_id,))
    c.execute("DELETE FROM web_tickets WHERE id=?", (ticket_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_tickets_page", msg=f"تیکت #{ticket_id} حذف شد."))


@app.route("/manage_plans", methods=["GET", "POST"])
@perm_required("plans_manage")
def manage_plans_page():
    conn = get_db_connection()
    c = conn.cursor()
    upgrade_msg = None
    if request.method == "POST":
        if request.form.get("form_type") == "upgrade_tariffs":
            for k in ("upgrade_cpu_price", "upgrade_ram_price", "upgrade_disk_price", "max_cpu_pool", "max_ram_gb_pool", "max_disk_gb_pool"):
                if k in request.form:
                    set_system_setting(k, request.form.get(k, "0"))
            upgrade_msg = "تعرفه‌های ارتقای منابع و ظرفیت کل سرورها با موفقیت ذخیره شد."
        else:
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
    settings = get_system_settings()
    pool = get_available_hardware_pool()
    return render_template("manage_plans.html", plans=plans, settings=settings, pool=pool, upgrade_msg=upgrade_msg)


@app.route("/admin_payments")
@perm_required("payments_manage")
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
@perm_required("payments_manage")
def admin_decide_payment(req_id):
    action = request.form.get("action", "").strip()
    reject_reason = request.form.get("reject_reason", "").strip()
    actor = f"پنل مدیریت ({session.get('username', 'admin')})"
    ok, message = decide_payment_request(req_id, action, actor, reject_reason=reject_reason)
    if ok:
        return redirect(url_for("admin_payments_page", msg=message))
    return redirect(url_for("admin_payments_page", err=message))


@app.route("/admin_settings", methods=["GET", "POST"])
@perm_required("settings_manage")
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
        elif action == "backup_now":
            ok_bk, msg_bk = send_database_backup_to_owner(force=True)
            if ok_bk:
                msg = msg_bk
            else:
                err = msg_bk
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
@perm_required("admin_stats")
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
@perm_required("ip_pool")
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
@perm_required("ip_pool")
def release_ip_pool(ip_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE ip_pool SET is_allocated=0, server_id=NULL WHERE id=?", (ip_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("ip_pool_page"))


@app.route("/ip_pool/delete/<int:ip_id>")
@perm_required("ip_pool")
def delete_ip_pool(ip_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM ip_pool WHERE id=?", (ip_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("ip_pool_page"))


# --- ESXi Hosts Management ---
@app.route("/esxi_hosts", methods=["GET", "POST"])
@perm_required("esxi_hosts")
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
@perm_required("esxi_hosts")
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
@perm_required("esxi_hosts")
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
@perm_required("esxi_create_vm")
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
@perm_required("servers_manage")
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
@perm_required("servers_manage")
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
@perm_required("servers_manage")
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
@perm_required("servers_manage")
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
@perm_required("users_manage")
def add_user_page():
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    error_msg = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "user").strip()
        if role not in ("user", "support", "sales", "admin"):
            role = "user"
        telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
        try:
            wallet_balance = int(request.form.get("wallet_balance", 0) or 0)
        except ValueError:
            wallet_balance = 0

        if "has_perm_matrix" in request.form:
            selected_perms = [p for p in request.form.getlist("perms") if p in ALL_MODULE_KEYS]
        else:
            selected_perms = list(ROLE_DEFAULT_PERMS.get(role, ROLE_DEFAULT_PERMS["user"]))
        perms_json = json.dumps(selected_perms)

        if username and password and username != "marmmr":
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE username=?", (username,))
            if c.fetchone():
                conn.close()
                error_msg = "این نام کاربری قبلاً در سیستم ثبت شده است."
            else:
                c.execute(
                    "INSERT INTO users (username, password, role, telegram_chat_id, active, wallet_balance, permissions) "
                    "VALUES (?, ?, ?, ?, 1, ?, ?)",
                    (username, generate_password_hash(password), role, telegram_chat_id, wallet_balance, perms_json),
                )
                conn.commit()
                conn.close()
                return redirect(url_for("manage_users"))
    return render_template(
        "add_user.html",
        panel_modules=PANEL_MODULES,
        role_presets_json=json.dumps(ROLE_DEFAULT_PERMS),
        error_msg=error_msg,
    )


@app.route("/assign_server", methods=["GET", "POST"])
@perm_required("assign_server")
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
@perm_required("assign_server")
def unassign_server(user_id, server_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM user_servers WHERE user_id=? AND server_id=?", (user_id, server_id))
    conn.commit()
    conn.close()
    invalidate_servers_cache()
    return redirect(url_for("assign_server_page"))


@app.route("/delete_server/<int:server_id>")
@perm_required("servers_manage")
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
@perm_required("servers_manage")
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
@perm_required("servers_manage")
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
@perm_required("users_manage")
def manage_users():
    if is_license_expired() and session.get("role") != "owner":
        return render_template("admin_expired.html")
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST" and "edit_user_id" in request.form:
        user_id = int(request.form["edit_user_id"])
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "user").strip()
        if role not in ("user", "support", "sales", "admin"):
            role = "user"
        telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
        try:
            wallet_balance = int(request.form.get("wallet_balance", 0) or 0)
        except ValueError:
            wallet_balance = 0

        if "has_perm_matrix" in request.form:
            selected_perms = [p for p in request.form.getlist("perms") if p in ALL_MODULE_KEYS]
        else:
            selected_perms = list(ROLE_DEFAULT_PERMS.get(role, ROLE_DEFAULT_PERMS["user"]))
        perms_json = json.dumps(selected_perms)

        if role != "owner" and username != "marmmr":
            if password:
                c.execute(
                    "UPDATE users SET username=?, password=?, role=?, telegram_chat_id=?, wallet_balance=?, permissions=? WHERE id=?",
                    (username, generate_password_hash(password), role, telegram_chat_id, wallet_balance, perms_json, user_id),
                )
            else:
                c.execute(
                    "UPDATE users SET username=?, role=?, telegram_chat_id=?, wallet_balance=?, permissions=? WHERE id=?",
                    (username, role, telegram_chat_id, wallet_balance, perms_json, user_id),
                )
            conn.commit()
        conn.close()
        return redirect(url_for("manage_users"))

    c.execute("SELECT id, username, role, telegram_chat_id, active, COALESCE(wallet_balance, 0), permissions FROM users WHERE username != 'marmmr' ORDER BY id ASC")
    raw_users = c.fetchall()
    conn.close()

    users = []
    for r in raw_users:
        uid, uname, urole, utg, uact, uwal, uperms_raw = r
        u_perm_set = get_user_permissions_set(uid, urole)
        users.append((uid, uname, urole, utg, uact, uwal, u_perm_set))

    return render_template(
        "manage_users.html",
        users=users,
        panel_modules=PANEL_MODULES,
        role_presets_json=json.dumps(ROLE_DEFAULT_PERMS),
    )


@app.route("/toggle_server/<int:server_id>")
@perm_required("servers_manage")
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
@perm_required("users_manage")
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
@perm_required("users_manage")
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
@perm_required("events_view")
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
    conn = get_db_connection()
    c = conn.cursor()
    license_key = None
    days_valid = None
    expiry_date = None
    if request.method == "POST":
        raw_days = request.form.get("days_valid") or request.form.get("days") or "30"
        try:
            days_valid = max(1, int(raw_days))
        except ValueError:
            days_valid = 30
        raw_chars = "".join(random.choices("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", k=16))
        license_key = f"CC-{raw_chars[:4]}-{raw_chars[4:8]}-{raw_chars[8:12]}-{raw_chars[12:16]}"
        expiry_date = (datetime.datetime.now() + datetime.timedelta(days=days_valid)).strftime("%Y-%m-%d")
        c.execute("INSERT INTO licenses (license_key, expiry_date, trial_active) VALUES (?, ?, 0)", (license_key, expiry_date))
        conn.commit()

    c.execute("SELECT id, license_key, expiry_date, trial_active FROM licenses ORDER BY id DESC LIMIT 30")
    all_licenses = [
        {"id": r[0], "license_key": r[1], "expiry_date": r[2], "is_trial": bool(r[3])}
        for r in c.fetchall()
    ]
    conn.close()
    return render_template(
        "generate_license.html",
        license_key=license_key,
        days_valid=days_valid,
        expiry_date=expiry_date,
        all_licenses=all_licenses,
    )


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



def daily_lifecycle_and_backup_worker():
    """
    Runs in background:
    1. Sends database.db backup to Owner (marmmr) on Telegram every 24 hours.
    2. Checks server expiration dates: sends 3-day warning and auto-suspends ESXi vNIC on expiry.
    """
    while True:
        try:
            cfg = get_system_settings()
            # 1. Check 24-hour Database Backup schedule
            last_bk_str = (cfg.get("last_db_backup_at") or "").strip()
            due_for_backup = False
            if not last_bk_str:
                due_for_backup = True
            else:
                try:
                    last_dt = datetime.datetime.strptime(last_bk_str, "%Y-%m-%d %H:%M:%S")
                    if (datetime.datetime.utcnow() - last_dt).total_seconds() >= 86400:
                        due_for_backup = True
                except Exception:
                    due_for_backup = True

            if due_for_backup:
                send_database_backup_to_owner(force=False)

            # 2. Check Server Expiration (3-day warning + Auto-Suspend on expiry)
            today_date = datetime.datetime.utcnow().date()
            today_str = today_date.strftime("%Y-%m-%d")
            warn_threshold = (today_date + datetime.timedelta(days=3)).strftime("%Y-%m-%d")
            admin_chat = (cfg.get("admin_chat_id") or "").strip()

            conn = get_db_connection()
            c = conn.cursor()
            c.execute(
                """SELECT s.id, s.name, s.ip, s.expires_at, s.expiry_warned_at, s.is_suspended,
                          s.vmid, s.esxi_host_id, s.telegram_chat_id,
                          h.ip, h.port, h.username, h.password
                   FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id
                   WHERE s.active=1 AND s.expires_at IS NOT NULL AND s.expires_at != ''"""
            )
            srv_rows = c.fetchall()

            for sr in srv_rows:
                sid, sname, sip, exp_at, warned_at, is_susp, vmid, host_id, srv_tg, esxi_ip, esxi_port, esxi_u, esxi_p = sr
                # Find linked user telegram chat id
                c.execute(
                    "SELECT u.telegram_chat_id FROM users u JOIN user_servers us ON u.id=us.user_id WHERE us.server_id=? LIMIT 1",
                    (sid,),
                )
                ur = c.fetchone()
                user_tg = (ur[0].strip() if ur and ur[0] else "") or (srv_tg or "").strip()

                # Expired -> Auto-Suspend vNIC on ESXi!
                if exp_at < today_str and not is_susp:
                    if host_id and vmid and esxi_ip:
                        esxi_manager.set_vnic_connection(esxi_ip, esxi_port, esxi_u, esxi_p, vmid, connected=False)
                    c.execute("UPDATE servers SET is_suspended=1 WHERE id=?", (sid,))
                    now_iso = datetime.datetime.utcnow().isoformat()
                    msg = (
                        f"⛔ *سررسید ماهانه و تعلیق خودکار:* مهلت سرویس *{sname}* (`{sip}`) در تاریخ `{exp_at}` به پایان رسید و پورت شبکه مسدود شد. "
                        "جهت بازگشایی، از پنل کاربری اقدام به تمدید نمایید."
                    )
                    c.execute("INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'critical', ?, ?)", (sid, msg, now_iso))
                    conn.commit()
                    if user_tg:
                        send_telegram_alert(user_tg, msg)
                    if admin_chat:
                        send_telegram_alert(admin_chat, msg)

                # 3 Days or Less Remaining -> Send Renewal Warning
                elif today_str <= exp_at <= warn_threshold and not warned_at:
                    c.execute("UPDATE servers SET expiry_warned_at=? WHERE id=?", (today_str, sid))
                    now_iso = datetime.datetime.utcnow().isoformat()
                    warn_msg = (
                        f"⏳ *یادآوری تمدید سرویس:* سرویس *{sname}* (`{sip}`) در تاریخ `{exp_at}` منقضی می‌شود. "
                        "لطفاً پیش از سررسید از پنل کاربری اقدام به تمدید ماهانه کنید تا شبکه قطع نشود."
                    )
                    c.execute("INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'warning', ?, ?)", (sid, warn_msg, now_iso))
                    conn.commit()
                    if user_tg:
                        send_telegram_alert(user_tg, warn_msg)
                    if admin_chat:
                        send_telegram_alert(admin_chat, warn_msg)

            conn.close()
        except Exception as e:
            logging.error(f"Lifecycle/Backup worker error: {e}")

        time.sleep(300)  # Check every 5 minutes


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
    lifecycle_thread = threading.Thread(target=daily_lifecycle_and_backup_worker, daemon=True)
    lifecycle_thread.start()
    monitor_thread.start()

    run_flask()


if __name__ == "__main__":
    main()
