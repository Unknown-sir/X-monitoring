import asyncio
import datetime
import json
import logging
import os
import platform
import random
import re
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

    # Ensure dynamic columns exist for existing databases
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
    ]
    for col_name, col_type in needed_cols:
        if col_name not in cols:
            try:
                c.execute(f"ALTER TABLE servers ADD COLUMN {col_name} {col_type}")
                logging.info(f"Added column {col_name} to servers table.")
            except Exception as e:
                logging.error(f"Error adding column {col_name}: {e}")

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


@app.route("/", methods=["GET", "POST"])
def login():
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
        return "نام کاربری یا رمز عبور اشتباه است!", 401
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


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
            "SELECT id, name, ip, traffic_limit, traffic_usage, is_suspended FROM servers WHERE active=1 ORDER BY name ASC"
        )
    else:
        c.execute(
            "SELECT s.id, s.name, s.ip, s.traffic_limit, s.traffic_usage, s.is_suspended FROM servers s "
            "JOIN user_servers us ON s.id = us.server_id "
            "WHERE us.user_id=? AND s.active=1 ORDER BY s.name ASC",
            (session["user_id"],),
        )
    servers = c.fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        servers=servers,
        role=session["role"],
        time_left=time_left,
        is_trial=is_trial,
    )


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
    conn.close()

    return render_template(
        "admin_dashboard.html",
        time_left=time_left,
        is_trial=is_trial,
        total_servers=total_servers,
        active_servers=active_servers,
        total_users=total_users,
        active_users=active_users,
    )


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


# --- Automatic VM Creation on ESXi ---
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
        mac_address = request.form.get("mac_address", "").strip()

        # Network parameters
        primary_ip = request.form.get("primary_ip", "").strip()
        netmask = request.form.get("netmask", "25").strip()
        gateway = request.form.get("gateway", "").strip()
        ipv6 = request.form.get("ipv6", "").strip()
        ipv6_gateway = request.form.get("ipv6_gateway", "").strip()
        extra_ips = request.form.get("extra_ips", "").strip()

        # Credentials & traffic
        ssh_user = request.form.get("username", "root").strip()
        ssh_password = request.form.get("password", "").strip()
        traffic_limit = float(request.form.get("traffic_limit", 1000) or 1000)
        user_id = request.form.get("user_id")

        # 1. Fetch ESXi host credentials
        c.execute("SELECT ip, port, username, password FROM esxi_hosts WHERE id=?", (esxi_host_id,))
        esxi_row = c.fetchone()
        if not esxi_row:
            conn.close()
            return "ESXi Host not found", 404

        # 2. Deploy VM on ESXi via SSH
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
        )

        if not success:
            conn.close()
            return f"خطا در ساخت ماشین در ESXi: {message}", 500

        now_iso = datetime.datetime.utcnow().isoformat()

        # 3. Save server record
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

        # 4. Assign server to user if selected
        if user_id:
            c.execute("INSERT OR IGNORE INTO user_servers (user_id, server_id) VALUES (?, ?)", (user_id, server_id))

        c.execute(
            "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
            (server_id, f"سرور مجازی {vm_name} با موفقیت در ESXi ایجاد و روشن شد.", now_iso),
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
    conn.close()
    return render_template("create_vm.html", esxi_hosts=hosts, users=users)


# --- Rebuild Server on ESXi ---
@app.route("/server/<int:server_id>/rebuild", methods=["GET", "POST"])
@admin_required
def rebuild_vm_action(server_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT s.vm_name, s.vmid, s.esxi_host_id, h.ip, h.port, h.username, h.password, h.default_datastore, h.template_vmdk
           FROM servers s JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if not row or not row[1]:
        conn.close()
        return "سرور مربوطه در ESXi پیکربندی نشده است.", 400

    vm_name, vmid, _, esxi_ip, esxi_port, esxi_user, esxi_pass, datastore, template = row
    success, msg = esxi_manager.rebuild_vm_on_esxi(
        esxi_host=esxi_ip,
        esxi_port=esxi_port,
        esxi_user=esxi_user,
        esxi_password=esxi_pass,
        vmid=vmid,
        vm_name=vm_name,
        datastore=datastore,
        template_vmdk=template,
    )

    now_iso = datetime.datetime.utcnow().isoformat()
    if success:
        c.execute(
            "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
            (server_id, f"ماشین مجازی {vm_name} با موفقیت از تمپلیت ریبیلد شد.", now_iso),
        )
        c.execute("UPDATE servers SET is_suspended=0 WHERE id=?", (server_id,))
        conn.commit()
    conn.close()
    return redirect(request.referrer or url_for("manage_servers"))


# --- Change IP & Add Secondary IP ---
@app.route("/server/<int:server_id>/change_ip", methods=["GET", "POST"])
@admin_required
def change_ip_page(server_id):
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == "POST":
        primary_ip = request.form.get("primary_ip", "").strip()
        netmask = request.form.get("netmask", "25").strip()
        gateway = request.form.get("gateway", "").strip()
        ipv6 = request.form.get("ipv6", "").strip()
        ipv6_gateway = request.form.get("ipv6_gateway", "").strip()
        extra_ips = request.form.get("extra_ips", "").strip()
        apply_remote = request.form.get("apply_remote") == "1"

        c.execute("SELECT username, password FROM servers WHERE id=?", (server_id,))
        srv_cred = c.fetchone()

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
            # Try to connect to VM and apply netplan
            esxi_manager.apply_netplan_to_vm(primary_ip, srv_cred[0], srv_cred[1], netplan_yaml)

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
    conn.close()
    if not row:
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
    return render_template("change_ip.html", server=srv)


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
        # connect=True when unsuspend (was suspended)
        connect = bool(is_suspended)
        esxi_manager.set_vnic_connection(host_ip, host_port, host_user, host_pass, vmid, connected=connect)
        c.execute("UPDATE servers SET is_suspended=? WHERE id=?", (1 if new_state else 0, server_id))
        conn.commit()
    conn.close()
    return redirect(request.referrer or url_for("manage_servers"))


# --- Traffic Recharge (Customer & Admin) ---
@app.route("/server/<int:server_id>/recharge_traffic", methods=["POST"])
@login_required
def recharge_traffic_action(server_id):
    if not user_can_access_server(session["user_id"], session.get("role", "user"), server_id):
        return "Forbidden", 403

    add_amount = float(request.form.get("add_amount", 100) or 100)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """SELECT s.traffic_limit, s.traffic_usage, s.is_suspended, s.vmid, s.name, h.ip, h.port, h.username, h.password
           FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
        (server_id,),
    )
    row = c.fetchone()
    if row:
        curr_limit, curr_usage, is_suspended, vmid, srv_name, esxi_ip, esxi_port, esxi_user, esxi_pass = row
        new_limit = (curr_limit or 0.0) + add_amount
        c.execute("UPDATE servers SET traffic_limit=? WHERE id=?", (new_limit, server_id))

        # If network was suspended, automatically restore it on ESXi
        if is_suspended and vmid and esxi_ip:
            esxi_manager.set_vnic_connection(esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, connected=True)
            c.execute("UPDATE servers SET is_suspended=0 WHERE id=?", (server_id,))

        now_iso = datetime.datetime.utcnow().isoformat()
        c.execute(
            "INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'info', ?, ?)",
            (server_id, f"ترافیک سرور {srv_name} به میزان {add_amount} GiB شارژ شد و شبکه فعال گردید.", now_iso),
        )
        conn.commit()
        invalidate_servers_cache()

    conn.close()
    return redirect(request.referrer or url_for("dashboard"))


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
    c.execute("SELECT id, username FROM users WHERE active=1 AND username != 'marmmr'")
    users = c.fetchall()
    c.execute("SELECT id, name, ip FROM servers WHERE active=1 ORDER BY name ASC")
    servers = c.fetchall()
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
        return redirect(url_for("admin_dashboard"))
    conn.close()
    return render_template("assign_server.html", users=users, servers=servers)


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

    # If limit is increased above usage and server was suspended, automatically unsuspend!
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

        # Unsuspend network on ESXi if suspended
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

        if role != "owner" and username != "marmmr":
            if password:
                c.execute(
                    "UPDATE users SET username=?, password=?, role=?, telegram_chat_id=? WHERE id=?",
                    (username, generate_password_hash(password), role, telegram_chat_id, user_id),
                )
            else:
                c.execute(
                    "UPDATE users SET username=?, role=?, telegram_chat_id=? WHERE id=?",
                    (username, role, telegram_chat_id, user_id),
                )
            conn.commit()
        conn.close()
        return redirect(url_for("manage_users"))

    c.execute("SELECT id, username, role, telegram_chat_id, active FROM users WHERE username != 'marmmr'")
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

        # If on ESXi, also send power command
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


async def show_main_menu(update, context, chat_id, message_id=None):
    welcome_message = (
        "🚀 *سلام! به ربات مدیریت سرورهای مجازی و هاستینگ خوش اومدی!* 🚀\n\n"
        "یکی از گزینه‌های زیر رو انتخاب کن 👇"
    )
    keyboard = [
        [
            InlineKeyboardButton("🖥️ لیست سرورها", callback_data="list_servers_1"),
            InlineKeyboardButton("ℹ️ قوانین ریفاند", callback_data="about"),
        ],
        [
            InlineKeyboardButton("🛠️ پشتیبانی", callback_data="support"),
            InlineKeyboardButton("🎫 ارسال تیکت", callback_data="ticket"),
        ],
    ]
    if str(chat_id) == ADMIN_CHAT_ID:
        keyboard.extend(
            [
                [
                    InlineKeyboardButton("📬 فوروارد پیام همگانی", callback_data="forward_broadcast"),
                    InlineKeyboardButton("✉️ ارسال پیام همگانی", callback_data="text_broadcast"),
                ],
                [
                    InlineKeyboardButton("📊 آمار", callback_data="admin_stats"),
                    InlineKeyboardButton("🎫 تیکت‌های باز", callback_data="open_tickets"),
                ],
            ]
        )
    keyboard.append([InlineKeyboardButton("© کپی رایت", callback_data="copyright")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    if message_id:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=welcome_message,
            parse_mode="Markdown",
            reply_markup=reply_markup,
        )
    else:
        await update.message.reply_text(welcome_message, parse_mode="Markdown", reply_markup=reply_markup)


async def start(update, context):
    chat_id = str(update.message.chat_id)
    first_name = update.message.from_user.first_name
    username = update.message.from_user.username or "نام کاربری ندارد"
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM telegram_users WHERE chat_id=?", (chat_id,))
    if not c.fetchone():
        c.execute("INSERT INTO telegram_users (chat_id, first_name, username) VALUES (?, ?, ?)", (chat_id, first_name, username))
        conn.commit()
    conn.close()
    await show_main_menu(update, context, chat_id)


async def button(update, context):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id
    message_id = query.message.message_id
    data = query.data

    if data.startswith("list_servers"):
        page = int(data.split("_")[-1]) if "_" in data and data.split("_")[-1].isdigit() else 1
        servers_per_page = 10
        conn = get_db_connection()
        c = conn.cursor()
        if str(chat_id) == ADMIN_CHAT_ID:
            c.execute("SELECT id, ip, name, is_suspended FROM servers WHERE active=1 ORDER BY name ASC")
            servers = c.fetchall()
        else:
            c.execute(
                "SELECT s.id, s.ip, s.name, s.is_suspended FROM servers s "
                "JOIN user_servers us ON s.id = us.server_id "
                "JOIN users u ON us.user_id = u.id "
                "WHERE u.telegram_chat_id=? AND s.active=1 AND u.active=1 ORDER BY s.name ASC",
                (str(chat_id),),
            )
            servers = c.fetchall()
        conn.close()

        if not servers:
            await query.edit_message_text("⚠️ هیچ سروری برای شما ثبت نشده است.", parse_mode="Markdown")
            return

        total_pages = (len(servers) + servers_per_page - 1) // servers_per_page
        start_idx = (page - 1) * servers_per_page
        page_servers = servers[start_idx : start_idx + servers_per_page]

        message = f"🖥️ *لیست سرورها (صفحه {page} از {total_pages}):*\n\n"
        for idx, (_, ip, name, is_susp) in enumerate(page_servers, start_idx + 1):
            st = "🔴 [مسدود]" if is_susp else "🟢 [متصل]"
            message += f"{idx}. {name} ({ip}) — {st}\n"

        keyboard = []
        row = []
        for srv_id, _, name, _ in page_servers:
            row.append(InlineKeyboardButton(f"🔍 {name}", callback_data=f"server_{srv_id}"))
            if len(row) == 2:
                keyboard.append(row)
                row = []
        if row:
            keyboard.append(row)

        nav_buttons = []
        if page > 1:
            nav_buttons.append(InlineKeyboardButton("⬅️ قبلی", callback_data=f"list_servers_{page-1}"))
        if page < total_pages:
            nav_buttons.append(InlineKeyboardButton("بعدی ➡️", callback_data=f"list_servers_{page+1}"))
        if nav_buttons:
            keyboard.append(nav_buttons)
        keyboard.append([InlineKeyboardButton("🏠 منوی اصلی", callback_data="main_menu")])
        await query.edit_message_text(message, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

    elif data == "main_menu":
        await show_main_menu(query, context, chat_id, message_id)

    elif data.startswith("server_"):
        server_id = int(data.split("_")[1])
        if not telegram_user_can_access_server(chat_id, server_id):
            await query.edit_message_text("⛔️ دسترسی به این سرور مجاز نیست.")
            return
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip, name, is_suspended FROM servers WHERE id=?", (server_id,))
        server = c.fetchone()
        conn.close()
        if server:
            ip, name, is_susp = server
            st_text = "🔴 مسدود به دلیل اتمام ترافیک" if is_susp else "🟢 شبکه متصل است"
            message = f"🖥️ *سرور: {name} ({ip})*\nوضعیت پورت: {st_text}\n\nگزینه مورد نظر را انتخاب کنید:"
            keyboard = [
                [
                    InlineKeyboardButton("📊 وضعیت", callback_data=f"status_{server_id}"),
                    InlineKeyboardButton("📈 مصرف ترافیک", callback_data=f"traffic_{server_id}"),
                ],
                [
                    InlineKeyboardButton("⚡ شارژ ترافیک (+100GB)", callback_data=f"rech_{server_id}"),
                    InlineKeyboardButton("🔁 ریبوت", callback_data=f"reboot_{server_id}"),
                ],
                [InlineKeyboardButton("🔙 بازگشت به لیست", callback_data="list_servers_1")],
            ]
            await query.edit_message_text(message, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

    elif data.startswith("rech_"):
        server_id = int(data.split("_")[1])
        if not telegram_user_can_access_server(chat_id, server_id):
            await query.edit_message_text("⛔️ دسترسی ندارید.")
            return
        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            """SELECT s.traffic_limit, s.is_suspended, s.vmid, s.name, h.ip, h.port, h.username, h.password
               FROM servers s LEFT JOIN esxi_hosts h ON s.esxi_host_id = h.id WHERE s.id=?""",
            (server_id,),
        )
        row = c.fetchone()
        if row:
            curr_limit, is_suspended, vmid, name, esxi_ip, esxi_port, esxi_user, esxi_pass = row
            new_limit = (curr_limit or 0.0) + 100.0
            c.execute("UPDATE servers SET traffic_limit=? WHERE id=?", (new_limit, server_id))
            if is_suspended and vmid and esxi_ip:
                esxi_manager.set_vnic_connection(esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, connected=True)
                c.execute("UPDATE servers SET is_suspended=0 WHERE id=?", (server_id,))
            conn.commit()
            await query.edit_message_text(f"✅ ترافیک سرور {name} به میزان ۱۰۰ گیگابایت شارژ شد و پورت شبکه فعال گردید! 🚀")
        conn.close()

    elif data.startswith("status_"):
        server_id = int(data.split("_")[1])
        status = get_server_status(server_id)
        keyboard = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"server_{server_id}")]]
        await query.edit_message_text(status, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

    elif data.startswith("traffic_"):
        server_id = int(data.split("_")[1])
        traffic = get_server_traffic(server_id)
        keyboard = [[InlineKeyboardButton("🔙 بازگشت", callback_data=f"server_{server_id}")]]
        await query.edit_message_text(traffic, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))


async def handle_message(update, context):
    pass


def get_server_status(server_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, username, password, name FROM servers WHERE id=?", (server_id,))
    server = c.fetchone()
    conn.close()
    if server:
        ip, username, password, name = server
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=10)
            _, stdout, _ = ssh.exec_command("uptime")
            uptime = stdout.read().decode().strip()
            ssh.close()
            return f"🖥️ *وضعیت سرور: {name} ({ip})*\n\n✅ سرور فعال و آنلاین است!\n⏳ *آپتایم:* `{uptime}`"
        except Exception as e:
            return f"🖥️ *وضعیت سرور: {name} ({ip})*\n\n⚠️ سرور غیرقابل دسترسی است: {str(e)}"
    return "⚠️ سرور پیدا نشد."


def get_server_traffic(server_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, username, password, traffic_limit, traffic_usage, reset_date, name FROM servers WHERE id=?", (server_id,))
    server = c.fetchone()
    conn.close()
    if server:
        ip, username, password, traffic_limit, traffic_usage, reset_date, name = server
        traffic_limit = float(traffic_limit or 0.0)
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=10)
            nic = detect_iface(ssh)
            traffic_cmd = build_vnstat_monthly_cmd(nic, reset_date)
            _, stdout, _ = ssh.exec_command(traffic_cmd)
            traffic_usage_output = stdout.read().decode().strip()
            traffic_usage_new = float(traffic_usage_output.splitlines()[-1]) if traffic_usage_output else 0.0
            ssh.close()
            return (
                f"📈 *ترافیک سرور: {name} ({ip})*\n\n"
                f"📊 *مصرف فعلی:* `{traffic_usage_new:.2f} GiB`\n"
                f"🚧 *محدودیت:* `{traffic_limit if traffic_limit > 0 else 'نامحدود'} GiB`"
            )
        except Exception as e:
            return f"📈 *ترافیک سرور: {name} ({ip})*\n\n⚠️ خطا در خواندن vnstat: {str(e)}"
    return "⚠️ سرور پیدا نشد."


async def send_telegram_message(bot, chat_id, message):
    if not chat_id or str(chat_id) == "YOUR_CHAT_ID":
        return
    try:
        await bot.send_message(chat_id=chat_id, text=message)
    except Exception as e:
        logging.error(f"Failed to send Telegram message to {chat_id}: {str(e)}")


def monitor_servers(application):
    alerted_servers = set()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
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

                # بررسی اتمام ترافیک و ساسپند سخت‌افزاری شبکه در ESXi
                if traffic_limit > 0 and traffic_usage_new > traffic_limit:
                    if esxi_host_id and vmid and not is_suspended and esxi_ip:
                        esxi_manager.set_vnic_connection(
                            esxi_ip, esxi_port, esxi_user, esxi_pass, vmid, connected=False
                        )
                        c.execute("UPDATE servers SET is_suspended=1 WHERE id=?", (server_id,))
                        conn.commit()
                        msg = (
                            f"🚨 *اتمام ترافیک:* پورت شبکه سرور {name} ({ip}) در ESXi مسدود شد "
                            f"({traffic_usage_new:.2f} GiB > {traffic_limit:.2f} GiB). برای اتصال، ترافیک را شارژ کنید."
                        )
                        c.execute("INSERT INTO events (server_id, level, message, created_at) VALUES (?, 'critical', ?, ?)", (server_id, msg, now_iso))
                        conn.commit()
                        if telegram_chat_id:
                            loop.run_until_complete(send_telegram_message(application.bot, telegram_chat_id, msg))
                        loop.run_until_complete(send_telegram_message(application.bot, ADMIN_CHAT_ID, msg))
                    elif not is_suspended:
                        # Fallback to guest shutdown if not an ESXi VM
                        ssh.exec_command("sudo shutdown -h now")

                # بازگردانی خودکار شبکه در صورت شارژ شدن ترافیک
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
                        loop.run_until_complete(send_telegram_message(application.bot, telegram_chat_id, msg))

                ssh.close()
            except Exception as e:
                logging.error(f"Error monitoring {ip}: {e}")
            finally:
                conn.close()

        time.sleep(5)


def run_flask():
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False, use_reloader=False)


def main():
    init_db()
    init_default_license()
    startup_check()

    if not TELEGRAM_TOKEN or TELEGRAM_TOKEN == "YOUR_BOT_TOKEN":
        logging.warning("TELEGRAM_TOKEN تنظیم نشده است؛ فقط وب‌پنل Flask اجرا می‌شود.")
        run_flask()
        return

    application = Application.builder().token(TELEGRAM_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    monitor_thread = threading.Thread(target=monitor_servers, args=(application,), daemon=True)
    monitor_thread.start()

    if platform.system() == "Emscripten":
        asyncio.ensure_future(application.run_polling())
    else:
        application.run_polling()


if __name__ == "__main__":
    main()
