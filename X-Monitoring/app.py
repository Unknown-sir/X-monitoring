import asyncio
import platform
import sqlite3
import paramiko
import logging
import threading
import time
import subprocess
import smtplib
from email.mime.text import MIMEText
import redis
import pickle
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters
import datetime
import os
import json
import random
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from functools import wraps

# بارگذاری متغیرهای محیطی
load_dotenv()

app = Flask(__name__)

# تنظیمات لاگ
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

# Redis cache
cache = redis.Redis(host='localhost', port=6379, db=0)
def invalidate_servers_cache():
    """Remove all cached server lists for all users/roles."""
    try:
        for key in cache.scan_iter("servers:*"):
            cache.delete(key)
    except Exception:
        # Redis might be unavailable; ignore cache errors
        pass


# تنظیمات پیش‌فرض
DEFAULT_ENV = {
    "SECRET_KEY": "mysecretkey123",
    "TELEGRAM_TOKEN": "7922676385:AAGwL5xR93QpBUkK8l6uoDOjJSXIqlo2cuY",
    "ADMIN_CHAT_ID": "5961740775",
    "EMAIL_FROM": "YOUR_E-MAIL",
    "EMAIL_PASSWORD": "Email_password",
    "SMTP_SERVER": "smtp.mailersend.net",
    "SMTP_PORT": "587",
    "DB_PASSWORD": "mypassword",
    "OWNER_PASSWORD": "M801009m780526#"
}

if not os.path.exists('.env'):
    with open('.env', 'w') as f:
        for key, value in DEFAULT_ENV.items():
            f.write(f"{key}={value}\n")
    logging.info("فایل .env با مقادیر پیش‌فرض ساخته شد.")

load_dotenv()

app.secret_key = os.getenv('SECRET_KEY')
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
ADMIN_CHAT_ID = os.getenv('ADMIN_CHAT_ID')
EMAIL_FROM = os.getenv('EMAIL_FROM')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT'))
CONFIG_FILE = "config.json"
DB_PASSWORD = os.getenv('DB_PASSWORD')
OWNER_PASSWORD = os.getenv('OWNER_PASSWORD')

def get_db_connection():
    conn = sqlite3.connect('database.db', check_same_thread=False)
    conn.execute(f"PRAGMA key='{DB_PASSWORD}'")
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, telegram_chat_id TEXT, active INTEGER DEFAULT 1)''')
    c.execute('''CREATE TABLE IF NOT EXISTS servers (id INTEGER PRIMARY KEY, name TEXT, ip TEXT, username TEXT, password TEXT, traffic_limit INTEGER DEFAULT 0, telegram_chat_id TEXT, active INTEGER DEFAULT 1, traffic_usage REAL DEFAULT 0, reset_date TEXT DEFAULT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS user_servers (user_id INTEGER, server_id INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS licenses (id INTEGER PRIMARY KEY, license_key TEXT UNIQUE, expiry_date TEXT, trial_active INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS telegram_users (chat_id TEXT PRIMARY KEY, first_name TEXT, username TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY, chat_id TEXT, message_id INTEGER, message_text TEXT, status TEXT DEFAULT 'open')''')
    c.execute("PRAGMA table_info(servers)")
    columns = [info[1] for info in c.fetchall()]
    if 'reset_date' not in columns:
        c.execute("ALTER TABLE servers ADD COLUMN reset_date TEXT DEFAULT NULL")
        logging.info("ستون reset_date به جدول servers اضافه شد.")
    c.execute("INSERT OR IGNORE INTO users (username, password, role, telegram_chat_id, active) VALUES (?, ?, ?, ?, ?)",
              ('marmmr', OWNER_PASSWORD, 'owner', '5961740775', 1))
    c.execute("INSERT OR IGNORE INTO users (username, password, role, telegram_chat_id, active) VALUES (?, ?, ?, ?, ?)",
              ('admin', 'admin123', 'admin', '5961740775', 1))
    conn.commit()
    conn.close()

def init_default_license():
    if not os.path.exists(CONFIG_FILE):
        default_license_key = "DEFAULT_5_DAY_LICENSE"
        expiry_date = (datetime.datetime.now() + datetime.timedelta(days=5)).strftime("%Y-%m-%d")
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO licenses (license_key, expiry_date, trial_active) VALUES (?, ?, 1)", (default_license_key, expiry_date))
        conn.commit()
        conn.close()
        with open(CONFIG_FILE, 'w') as f:
            json.dump({"license_key": default_license_key, "register_date": datetime.datetime.now().strftime("%Y-%m-%d"), "is_trial": True}, f)
        logging.info("لایسنس 5 روزه پیش‌فرض ثبت شد.")

def send_email(subject, body, to_email='admin@example.com'):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = to_email
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
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session['role'] not in ['admin', 'owner']:
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def owner_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session['role'] != 'owner':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_remaining_time():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        license_key = config.get("license_key")
        register_date = datetime.datetime.strptime(config['register_date'], "%Y-%m-%d")
        is_trial = config.get("is_trial", False)
        if is_trial:
            days_total = 5
        else:
            days_total = 30
        expiry_date = register_date + datetime.timedelta(days=days_total)
        time_left = expiry_date - datetime.datetime.now()
        if time_left.total_seconds() <= 0:
            return {'days': 0, 'hours': 0, 'minutes': 0, 'seconds': 0}, is_trial
        days = time_left.days
        hours, remainder = divmod(time_left.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return {'days': days, 'hours': hours, 'minutes': minutes, 'seconds': seconds}, is_trial
    else:
        init_default_license()
        return {'days': 5, 'hours': 0, 'minutes': 0, 'seconds': 0}, True

def startup_check():
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds > 0 or session.get('role') == 'owner':
        mode = "trial" if is_trial else "license"
        logging.info(f"زمان باقی‌مونده: {time_left['days']} روز، {time_left['hours']} ساعت، {time_left['minutes']} دقیقه، {time_left['seconds']} ثانیه ({mode})")
        return True
    else:
        logging.error("لایسنس منقضی شده یا دوره آزمایشی تمام شده است.")
        return False

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=? AND active=1", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['role'] = user[3]
            session['username'] = user[1]
            logging.info(f"کاربر {username} با موفقیت وارد شد.")
            return redirect(url_for('dashboard'))
        else:
            logging.error(f"ورود ناموفق برای {username}")
            return "نام کاربری یا رمز عبور اشتباه است!", 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        telegram_chat_id = request.form['telegram_chat_id']
        password = request.form['password']
        conn = get_db_connection()
        c = conn.cursor()
        if session['role'] != 'owner' or session['username'] != 'marmmr':
            c.execute("UPDATE users SET telegram_chat_id=?, password=? WHERE id=?", (telegram_chat_id, password, session['user_id']))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))
    return render_template('profile.html')

@app.route('/dashboard')
@login_required
def dashboard():
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        if session['role'] == 'admin':
            return render_template('admin_expired.html')
        else:
            return render_template('user_expired.html')
    cache_key = f"servers:{session['user_id']}:{session['role']}"
    cached_servers = cache.get(cache_key)
    if cached_servers:
        servers = pickle.loads(cached_servers)
    else:
        conn = get_db_connection()
        c = conn.cursor()
        if session['role'] in ['admin', 'owner']:
            c.execute("SELECT id, name, ip, traffic_limit FROM servers WHERE active=1 ORDER BY name ASC")
            servers = [(row[0], row[1], row[2], row[3]) for row in c.fetchall()]
        else:
            c.execute("SELECT s.id, s.name, s.ip, s.traffic_limit FROM servers s JOIN user_servers us ON s.id = us.server_id WHERE us.user_id=? AND s.active=1 ORDER BY s.name ASC",
                      (session['user_id'],))
            servers = [(row[0], row[1], row[2], row[3]) for row in c.fetchall()]
        conn.commit()
        conn.close()
        cache.setex(cache_key, 300, pickle.dumps(servers))
    return render_template('dashboard.html', servers=servers, role=session['role'], time_left=time_left, is_trial=is_trial)

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        return render_template('admin_expired.html')

    # Basic stats for admin dashboard
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
        'admin_dashboard.html',
        time_left=time_left,
        is_trial=is_trial,
        total_servers=total_servers,
        active_servers=active_servers,
        total_users=total_users,
        active_users=active_users
    )


@app.route('/add_server', methods=['GET', 'POST'])
@admin_required
def add_server_page():
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        return render_template('admin_expired.html')
    if request.method == 'POST':
        name = request.form['name']
        ip = request.form['ip']
        username = request.form['username']
        password = request.form['password']
        traffic_limit = request.form.get('traffic_limit', 0)
        telegram_chat_id = request.form.get('telegram_chat_id', '')
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO servers (name, ip, username, password, traffic_limit, telegram_chat_id, active, traffic_usage, reset_date) VALUES (?, ?, ?, ?, ?, ?, 1, 0, NULL)", 
                  (name, ip, username, password, traffic_limit, telegram_chat_id))
        conn.commit()
        conn.close()
        invalidate_servers_cache()
        return redirect(url_for('admin_dashboard'))
    return render_template('add_server.html')

@app.route('/add_user', methods=['GET', 'POST'])
@admin_required
def add_user_page():
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        return render_template('admin_expired.html')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        telegram_chat_id = request.form.get('telegram_chat_id', '')
        if role != 'owner':
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, role, telegram_chat_id, active) VALUES (?, ?, ?, ?, 1)", 
                      (username, password, role, telegram_chat_id))
            conn.commit()
            conn.close()
        return redirect(url_for('admin_dashboard'))
    return render_template('add_user.html')

@app.route('/assign_server', methods=['GET', 'POST'])
@admin_required
def assign_server_page():
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        return render_template('admin_expired.html')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE active=1 AND username != 'marmmr'")
    users = c.fetchall()
    c.execute("SELECT id, name FROM servers WHERE active=1 ORDER BY name ASC")
    servers = c.fetchall()
    if request.method == 'POST':
        user_id = request.form['user_id']
        server_id = request.form['server_id']
        c.execute("INSERT OR IGNORE INTO user_servers (user_id, server_id) VALUES (?, ?)", (user_id, server_id))
        conn.commit()
        conn.close()
        invalidate_servers_cache()
        return redirect(url_for('admin_dashboard'))
    conn.close()
    return render_template('assign_server.html', users=users, servers=servers)

@app.route('/manage_servers', methods=['GET', 'POST'])
@admin_required
def manage_servers():
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        return render_template('admin_expired.html')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM servers ORDER BY name ASC")
    servers = c.fetchall()
    if request.method == 'POST' and 'edit_server_id' in request.form:
        server_id = request.form['edit_server_id']
        name = request.form['name']
        ip = request.form['ip']
        username = request.form['username']
        password = request.form['password']
        traffic_limit = request.form.get('traffic_limit', 0)
        telegram_chat_id = request.form.get('telegram_chat_id', '')
        c.execute("UPDATE servers SET name=?, ip=?, username=?, password=?, traffic_limit=?, telegram_chat_id=? WHERE id=?", 
                  (name, ip, username, password, traffic_limit, telegram_chat_id, server_id))
        conn.commit()
        conn.close()
        invalidate_servers_cache()
        return redirect(url_for('manage_servers'))
    conn.close()
    return render_template('manage_servers.html', servers=servers)

@app.route('/servers/<int:server_id>/limit', methods=['POST'])
@owner_required
def update_server_limit(server_id):
    """Update only the traffic_limit of a server.
    Only the owner of the panel can access this endpoint.
    """
    traffic_limit_raw = request.form.get('traffic_limit', '').strip()
    try:
        new_limit = float(traffic_limit_raw)
    except (TypeError, ValueError):
        # مقدار نامعتبر؛ فقط برگرد به صفحه قبلی
        return redirect(request.referrer or url_for('manage_servers'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE servers SET traffic_limit=? WHERE id=?", (new_limit, server_id))
    conn.commit()
    conn.close()
    try:
        invalidate_servers_cache()
    except Exception:
        pass
    return redirect(request.referrer or url_for('manage_servers'))


@app.route('/reset_traffic/<int:server_id>')
@admin_required
def reset_traffic(server_id):
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        return render_template('admin_expired.html')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, username, password FROM servers WHERE id=?", (server_id,))
    server = c.fetchone()
    if server:
        ip, username, password = server
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=10)
            ssh.exec_command("vnstat -i ens34 --reset")
            ssh.close()
            logging.info(f"Traffic reset for server {ip}")
        except Exception as e:
            logging.error(f"Failed to reset traffic for {ip}: {str(e)}")
        reset_date = datetime.datetime.now().strftime("%Y-%m")
        c.execute("UPDATE servers SET traffic_usage=0, reset_date=? WHERE id=?", (reset_date, server_id))
        conn.commit()
        conn.close()
        invalidate_servers_cache()
    return redirect(url_for('manage_servers'))

@app.route('/manage_users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        return render_template('admin_expired.html')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, role, telegram_chat_id, active FROM users WHERE username != 'marmmr'")
    users = c.fetchall()
    if request.method == 'POST' and 'edit_user_id' in request.form:
        user_id = request.form['edit_user_id']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        telegram_chat_id = request.form.get('telegram_chat_id', '')
        if role != 'owner' and username != 'marmmr':
            c.execute("UPDATE users SET username=?, password=?, role=?, telegram_chat_id=? WHERE id=?", 
                      (username, password, role, telegram_chat_id, user_id))
        conn.commit()
        conn.close()
        return redirect(url_for('manage_users'))
    conn.close()
    return render_template('manage_users.html', users=users)

@app.route('/toggle_server/<int:server_id>')
@admin_required
def toggle_server(server_id):
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        return render_template('admin_expired.html')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT active FROM servers WHERE id=?", (server_id,))
    current_status = c.fetchone()[0]
    new_status = 0 if current_status == 1 else 1
    c.execute("UPDATE servers SET active=? WHERE id=?", (new_status, server_id))
    conn.commit()
    conn.close()
    invalidate_servers_cache()
    return redirect(url_for('manage_servers'))

@app.route('/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        return render_template('admin_expired.html')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    if user and user[0] != 'marmmr':
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        c.execute("DELETE FROM user_servers WHERE user_id=?", (user_id,))
        conn.commit()
        conn.close()
    return redirect(url_for('manage_users'))

@app.route('/toggle_user/<int:user_id>')
@admin_required
def toggle_user(user_id):
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        return render_template('admin_expired.html')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT active, username FROM users WHERE id=?", (user_id,))
    result = c.fetchone()
    if result and result[1] != 'marmmr':
        current_status = result[0]
        new_status = 0 if current_status == 1 else 1
        c.execute("UPDATE users SET active=? WHERE id=?", (new_status, user_id))
        conn.commit()
        conn.close()
    return redirect(url_for('manage_users'))

@app.route('/live/<int:server_id>')
@login_required
def live_port(server_id):
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        if session['role'] == 'admin':
            return render_template('admin_expired.html')
        else:
            return render_template('user_expired.html')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, username, password, traffic_limit FROM servers WHERE id=?", (server_id,))
    server = c.fetchone()
    conn.close()
    if server:
        return render_template('live_port.html', server_id=server_id)
    return "Server not found", 404

@app.route('/monitor/<int:server_id>')
@login_required
def monitor_server(server_id):
    time_left, is_trial = get_remaining_time()
    total_seconds = time_left['days'] * 86400 + time_left['hours'] * 3600 + time_left['minutes'] * 60 + time_left['seconds']
    if total_seconds <= 0 and session['role'] != 'owner':
        if session['role'] == 'admin':
            return render_template('admin_expired.html')
        else:
            return render_template('user_expired.html')
    logging.info(f"Request received for monitoring server ID: {server_id}")
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, username, password, traffic_limit, telegram_chat_id, reset_date FROM servers WHERE id=?", (server_id,))
    server = c.fetchone()
    if server:
        ip, username, password, traffic_limit, telegram_chat_id, reset_date = server
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=10)
            if reset_date:
                command = (
                    "nproc && "
                    "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' && "
                    "free -m | awk '/Mem:/ {print $2}' && "
                    "free -m | awk '/Mem:/ {print $3/$2 *100}' && "
                    "vnstat -tr 2 -i ens34 | grep 'rx' | awk '{print $2}' && "
                    "vnstat -tr 2 -i ens34 | grep 'tx' | awk '{print $2}' && "
                    "df -h / | awk 'NR==2 {print $2}' && "
                    "iostat -d 1 2 | tail -n 1 | awk '{print $3}' && "
                    "iostat -d 1 2 | tail -n 1 | awk '{print $4}' && "
                    f"vnstat -m -i ens34 | awk '/[0-9]{{4}}-[0-9]{{2}}/ && $1 >= \"{reset_date}\" && !/estimated/ {{if ($9 == \"TiB\") sum += $8 *1024; else sum += $8}} END {{print sum ? sum : 0}}'"
                )
            else:
                command = (
                    "nproc && "
                    "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' && "
                    "free -m | awk '/Mem:/ {print $2}' && "
                    "free -m | awk '/Mem:/ {print $3/$2 *100}' && "
                    "vnstat -tr 2 -i ens34 | grep 'rx' | awk '{print $2}' && "
                    "vnstat -tr 2 -i ens34 | grep 'tx' | awk '{print $2}' && "
                    "df -h / | awk 'NR==2 {print $2}' && "
                    "iostat -d 1 2 | tail -n 1 | awk '{print $3}' && "
                    "iostat -d 1 2 | tail -n 1 | awk '{print $4}' && "
                    "vnstat -m -i ens34 | awk '/[0-9]{4}-[0-9]{2}/ && !/estimated/ {if ($9 == \"TiB\") sum += $8 * 1024; else sum += $8} END {print sum ? sum : 0}'"
                )
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode().strip().split('\n')
            total_cpu = int(output[0]) if output[0] else 0
            cpu_usage = float(output[1]) if output[1] else 0.0
            total_ram = int(output[2]) if output[2] else 0
            ram_usage = float(output[3]) if output[3] else 0.0
            download = float(output[4]) / 8 if output[4] else 0.0
            upload = float(output[5]) / 8 if output[5] else 0.0
            total_network = upload + download
            total_disk = float(output[6].rstrip('G')) if output[6] else 0.0
            disk_read = float(output[7]) / 1024 if output[7] else 0.0
            disk_write = float(output[8]) / 1024 if output[8] else 0.0
            traffic_usage = float(output[9]) if output[9] else 0.0

            logging.debug(f"Raw vnstat output for server {ip}: {stdout.read().decode().strip()}")
            logging.debug(f"Parsed traffic_usage for server {ip}: {traffic_usage}")

            server_shutdown = False
            if traffic_limit > 0 and traffic_usage > traffic_limit:
                ssh.exec_command("sudo shutdown -h now")
                message = f"Server {ip} exceeded traffic limit ({traffic_usage} GiB > {traffic_limit} GiB) and shut down."
                logging.info(message)
                send_email(f"Server Shutdown: {ip}", message)
                server_shutdown = True

            ping_result = subprocess.run(['ping', '-c', '4', ip], capture_output=True, text=True)
            ping_time = float(ping_result.stdout.split('time=')[1].split()[0]) if 'time=' in ping_result.stdout else 0.0
            ssh.close()

            c.execute("UPDATE servers SET traffic_usage=? WHERE id=?", (traffic_usage, server_id))
            conn.commit()
            conn.close()

            data = {
                'total_cpu': total_cpu,
                'cpu_usage': cpu_usage,
                'total_ram': total_ram,
                'ram_usage': ram_usage,
                'upload': upload,
                'download': download,
                'total_network': total_network,
                'total_disk': total_disk,
                'disk_read': disk_read,
                'disk_write': disk_write,
                'traffic_limit': traffic_limit,
                'traffic_usage': traffic_usage,
                'ping_time': ping_time,
                'ping_france_time': 0.0,
                'server_status': 'shutdown' if server_shutdown else 'active'
            }
            logging.debug(f"Monitoring data for server {server_id}: {data}")
            return jsonify(data)
        except Exception as e:
            conn.close()
            error_msg = str(e)
            logging.error(f"Error monitoring server {ip}: {error_msg}")
            return jsonify({
                'error': error_msg,
                'server_status': 'offline'
            }), 500
    conn.close()
    return jsonify({'error': 'Server not found'}), 404

@app.route('/generate_license', methods=['GET', 'POST'])
@owner_required
def generate_license():
    if request.method == 'POST':
        license_key = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))
        expiry_date = (datetime.datetime.now() + datetime.timedelta(days=int(request.form['days']))).strftime("%Y-%m-%d")
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO licenses (license_key, expiry_date, trial_active) VALUES (?, ?, 0)", (license_key, expiry_date))
        conn.commit()
        c.execute("SELECT license_key, expiry_date FROM licenses WHERE license_key=?", (license_key,))
        stored = c.fetchone()
        if stored:
            logging.info(f"لایسنس {license_key} با موفقیت در دیتابیس ذخیره شد با انقضای {stored[1]}")
        else:
            logging.error(f"خطا در ذخیره‌سازی لایسنس {license_key} در دیتابیس")
        conn.close()
        return render_template('generate_license.html', license_key=license_key)
    return render_template('generate_license.html')

@app.route('/register_license', methods=['GET', 'POST'])
@login_required
def register_license():
    if session['role'] not in ['admin', 'owner']:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        license_key = request.form['license_key']
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT license_key, expiry_date, trial_active FROM licenses WHERE license_key=?", (license_key,))
        result = c.fetchone()
        if result:
            db_license_key, expiry_date, trial_active = result
            current_date = time.strftime("%Y-%m-%d")
            logging.debug(f"لایسنس پیدا شده: {license_key}, انقضا: {expiry_date}, فعلی: {current_date}, trial: {trial_active}")
            if expiry_date > current_date:
                with open(CONFIG_FILE, 'w') as f:
                    json.dump({"license_key": license_key, "register_date": datetime.datetime.now().strftime("%Y-%m-%d"), "is_trial": trial_active == 1}, f)
                logging.info(f"لایسنس {license_key} ثبت شد. دوره: {'5 روزه' if trial_active else '30 روزه'}")
                conn.close()
                return redirect(url_for('license_result', license_key=license_key, valid=True))
            else:
                logging.warning(f"لایسنس {license_key} منقضی شده: {expiry_date} <= {current_date}")
        else:
            c.execute("SELECT license_key, expiry_date FROM licenses")
            all_licenses = c.fetchall()
            logging.debug(f"همه لایسنس‌های موجود: {[lic[0] for lic in all_licenses]}")
            logging.warning(f"لایسنس {license_key} در دیتابیس پیدا نشد.")
        conn.close()
        return redirect(url_for('license_result', license_key=license_key, valid=False))
    return render_template('register_license.html')

@app.route('/license_result/<license_key>/')
@login_required
def license_result(license_key, valid):
    valid = valid == 'True'
    time_left, is_trial = get_remaining_time()
    return render_template('license_result.html', license_key=license_key, valid=valid, time_left=time_left, is_trial=is_trial)

async def show_main_menu(update, context, chat_id, message_id=None):
    welcome_message = (
        "🚀 *سلام! به ربات هوشمند مدیریت سرور خوش اومدی!* 🚀\n\n"
        "من اینجام تا مدیریت سرورهات رو آسون‌تر کنم. 😎\n"
        "با ابزارهای پیشرفته، وضعیت سرورها رو چک کن، ترافیک رو مدیریت کن و کلی کار دیگه!\n\n"
        "یکی از گزینه‌های زیر رو انتخاب کن 👇"
    )
    keyboard = [
        [
            InlineKeyboardButton("🖥️ لیست سرورها", callback_data='list_servers_1'),
            InlineKeyboardButton("ℹ️ قوانین ریفاند", callback_data='about')
        ],
        [
            InlineKeyboardButton("🛠️ پشتیبانی", callback_data='support'),
            InlineKeyboardButton("🎫 ارسال تیکت", callback_data='ticket')
        ]
    ]
    if str(chat_id) == ADMIN_CHAT_ID:
        keyboard.extend([
            [
                InlineKeyboardButton("📬 فوروارد پیام همگانی", callback_data='forward_broadcast'),
                InlineKeyboardButton("✉️ ارسال پیام همگانی", callback_data='text_broadcast')
            ],
            [
                InlineKeyboardButton("📊 آمار", callback_data='admin_stats'),
                InlineKeyboardButton("🎫 تیکت‌های باز", callback_data='open_tickets')
            ]
        ])
    keyboard.append([InlineKeyboardButton("© کپی رایت", callback_data='copyright')])
    reply_markup = InlineKeyboardMarkup(keyboard)
    if message_id:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=welcome_message,
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
    else:
        await update.message.reply_text(welcome_message, parse_mode='Markdown', reply_markup=reply_markup)

async def start(update, context):
    """نمایش منوی اصلی با پیام خوش‌آمدگویی جذاب"""
    chat_id = str(update.message.chat_id)
    first_name = update.message.from_user.first_name
    username = update.message.from_user.username or "نام کاربری ندارد"
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM telegram_users WHERE chat_id=?", (chat_id,))
    user = c.fetchone()
    
    if not user:
        # کاربر جدید است، ذخیره و اطلاع به ادمین
        c.execute("INSERT INTO telegram_users (chat_id, first_name, username) VALUES (?, ?, ?)", (chat_id, first_name, username))
        conn.commit()
        message_to_admin = f"کاربر جدید به ربات وارد شد:\nنام: {first_name}\nنام کاربری: @{username}\nچت آیدی: {chat_id}"
        await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=message_to_admin)
    
    conn.close()
    
    await show_main_menu(update, context, chat_id)

async def button(update, context):
    """مدیریت دکمه‌های اینلاین با رابط کاربری بهبودیافته"""
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id
    message_id = query.message.message_id
    data = query.data

    if data.startswith('list_servers'):
        page = int(data.split('_')[-1]) if '_' in data else 1
        servers_per_page = 10  # تعداد سرورها در هر صفحه
        conn = get_db_connection()
        c = conn.cursor()
        if str(chat_id) == ADMIN_CHAT_ID:
            c.execute("SELECT id, ip, name FROM servers WHERE active=1 ORDER BY name ASC")
            servers = c.fetchall()
        else:
            c.execute(
                "SELECT s.id, s.ip, s.name FROM servers s JOIN user_servers us ON s.id = us.server_id "
                "JOIN users u ON us.user_id = u.id WHERE u.telegram_chat_id=? AND s.active=1 ORDER BY s.name ASC",
                (str(chat_id),)
            )
            servers = c.fetchall()
        conn.close()

        if not servers:
            await query.edit_message_text(
                "⚠️ *هیچ سروری برات ثبت نشده!* 😕\nبا پشتیبانی تماس بگیر: @CloudCubeVPS",
                parse_mode='Markdown'
            )
            return

        total_pages = (len(servers) + servers_per_page - 1) // servers_per_page
        start_idx = (page - 1) * servers_per_page
        end_idx = start_idx + servers_per_page
        page_servers = servers[start_idx:end_idx]

        message = f"🖥️ *لیست سرورهای فعال (صفحه {page} از {total_pages}):* 🖥️\n\n"
        for idx, (_, ip, name) in enumerate(page_servers, start_idx + 1):
            message += f"🔹 {idx}. {name} ({ip})\n"

        keyboard = []
        row = []
        for id, _, name in page_servers:
            row.append(InlineKeyboardButton(f"🔍 {name}", callback_data=f"server_{id}"))
            if len(row) == 2:
                keyboard.append(row)
                row = []
        if row:
            keyboard.append(row)

        # اضافه کردن دکمه‌های صفحه‌بندی
        nav_buttons = []
        if page > 1:
            nav_buttons.append(InlineKeyboardButton("⬅️ صفحه قبل", callback_data=f"list_servers_{page-1}"))
        if page < total_pages:
            nav_buttons.append(InlineKeyboardButton("➡️ صفحه بعد", callback_data=f"list_servers_{page+1}"))
        if nav_buttons:
            keyboard.append(nav_buttons)
        keyboard.append([InlineKeyboardButton("🏠 بازگشت به منو اصلی", callback_data='main_menu')])
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)

    elif data == 'about':
        about_message = (
            "📜 *قوانین عمومی ریفاند* 📜\n\n"
            "1. **دوره ضمانت بازگشت وجه:**\n"
            "   - سرور مجازی (VPS) یا اختصاصی: ۳ تا ۵ روز پس از فعال‌سازی.\n"
            "   - پس از پایان دوره ضمانت، بازگشت وجه امکان‌پذیر نیست.\n\n"
            "2. **شرایط بازگشت وجه:**\n"
            "   - فقط در صورت وجود مشکلات فنی مانند:\n"
            "     - قطعی سرور یا عدم دسترسی به سرویس.\n"
            "     - عدم تحویل سرویس مطابق با مشخصات اعلام‌شده.\n"
            "     - در صورت خرید آیپی نیم‌بها، سایت مرجع تشخیص نیم‌بها: https://eservices.ito.gov.ir/page/IPListSearch\n"
            "     - نقص در عملکرد پورت یا منابع وعده‌داده‌شده (مانند CPU، RAM یا پهنای باند).\n"
            "   - در صورت عدم استفاده از سرور (فعال‌سازی بدون ورود یا نصب نرم‌افزار).\n"
            "   - درخواست ریفاند باید از طریق تیکت پشتیبانی یا ایمیل رسمی ثبت شود.\n\n"
            "3. **محدودیت‌ها و استثناها:**\n"
            "   - **استفاده از سرور:** استفاده بالای ۱۰ گیگ، حق ریفاند را لغو می‌کند.\n"
            "   - **نقض قوانین:** موارد زیر منجر به مسدودی سرویس بدون امکان ریفاند می‌شود:\n"
            "     - استفاده غیرقانونی (مانند انتشار محتوای غیراخلاقی، قمار، پورن، تروریسم یا نقض کپی‌رایت).\n"
            "     - ارسال اسپم، انجام حملات DDoS یا ماینینگ غیرمجاز.\n"
            "     - فروش مجدد سرور بدون مجوز شرکت.\n"
            "     - توهین به عوامل فروش و پشتیبانی.\n"
            "   - **هزینه‌های جانبی:** هزینه‌های راه‌اندازی، ترافیک مصرف‌شده یا تنظیمات سفارشی قابل بازگشت نیستند.\n"
            "   - **بک‌آپ داده‌ها:** مسئولیت تهیه نسخه پشتیبان بر عهده کاربر است و شرکت در صورت از دست رفتن داده‌ها مسئولیتی ندارد.\n\n"
            "4. **فرآیند درخواست ریفاند:**\n"
            "   - درخواست باید از طریق ربات مانیتورینگ یا ایمیل رسمی شرکت تیکت ثبت شود.\n"
            "   - بررسی درخواست ممکن است ۵ تا ۱۰ روز کاری طول بکشد.\n"
            "   - در صورت تأیید، وجه پس از کسر کارمزد (مانند هزینه تراکنش بانکی یا جرائم تأخیر) بازگردانده می‌شود.\n\n"
            "5. **قوانین پرداخت و جرائم:**\n"
            "   - تأخیر در پرداخت ممکن است جریمه روزانه (معمولاً ۱%) داشته باشد."
        )
        keyboard = [[InlineKeyboardButton("🏠 بازگشت به منو اصلی", callback_data='main_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(about_message, parse_mode='Markdown', reply_markup=reply_markup)

    elif data == 'support':
        support_message = (
            "🛠️ *پشتیبانی حرفه‌ای* 🛠️\n\n"
            "هر مشکلی داشتی یا سوالی، تیم ما همیشه آماده کمک‌رسانیه!\n"
            "📩 تماس با پشتیبانی: @CloudCubeVPS\n"
            "🌐 وبسایت: https://www.cloudcube.ir/support/ticket\n\n"
            "ما ۲۴/۷ در خدمتتیم! 🚀"
        )
        keyboard = [[InlineKeyboardButton("🏠 بازگشت به منو اصلی", callback_data='main_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(support_message, parse_mode='Markdown', reply_markup=reply_markup)

    elif data == 'copyright':
        copyright_message = (
            "© *کپی رایت CloudCube* ©\n\n"
            "این ربات با افتخار توسط تیم CloudCube طراحی و توسعه یافته است.\n"
            "ما متعهد به ارائه بهترین تجربه مدیریت سرور هستیم! 🚀\n\n"
            "📩 *آیدی پشتیبانی:* @CloudCubeVPS\n"
            "🌐 *آدرس وبسایت:* https://www.cloudcube.ir\n"
            "👨‍💼 *آیدی مدیریت تیم:* @unknown_eng\n\n"
            "با ما در ارتباط باشید و از خدمات حرفه‌ای ما لذت ببرید! 😊"
        )
        keyboard = [[InlineKeyboardButton("🏠 بازگشت به منو اصلی", callback_data='main_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(copyright_message, parse_mode='Markdown', reply_markup=reply_markup)

    elif data == 'main_menu':
        await show_main_menu(query, context, chat_id, message_id)

    elif data.startswith('server_'):
        server_id = int(data.split('_')[1])
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip, name FROM servers WHERE id=?", (server_id,))
        server = c.fetchone()
        conn.close()
        if server:
            ip, name = server
            message = f"🖥️ *سرور انتخابی: {name} ({ip})* 🖥️\n\nگزینه مورد نظرت رو انتخاب کن:"
            keyboard = [
                [InlineKeyboardButton("📊 وضعیت سرور", callback_data=f"status_{server_id}"),
                 InlineKeyboardButton("📈 ترافیک مصرفی", callback_data=f"traffic_{server_id}")]
            ]
            # --- تغییر: دکمه ریست ترافیک فقط برای ادمین نمایش داده می‌شود ---
            if str(chat_id) == ADMIN_CHAT_ID:
                keyboard.append([
                    InlineKeyboardButton("🔄 ریست ترافیک", callback_data=f"reset_{server_id}"),
                    InlineKeyboardButton("🔁 ریبوت سرور", callback_data=f"reboot_{server_id}")
                ])
            else:
                keyboard.append([
                    InlineKeyboardButton("🔁 ریبوت سرور", callback_data=f"reboot_{server_id}")
                ])
            # --------------------------------------------------------------
            keyboard.append([InlineKeyboardButton("🛑 خاموش کردن سرور", callback_data=f"shutdown_{server_id}")])
            keyboard.append([InlineKeyboardButton("🔄 ریبیلد سرور", callback_data=f"rebuild_{server_id}")])
            keyboard.append([InlineKeyboardButton("🔙 بازگشت به لیست سرورها", callback_data='list_servers_1')])
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)

    elif data.startswith('status_'):
        server_id = int(data.split('_')[1])
        status = get_server_status(server_id)
        keyboard = [[InlineKeyboardButton("🔙 بازگشت به سرور", callback_data=f"server_{server_id}")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(status, parse_mode='Markdown', reply_markup=reply_markup)

    elif data.startswith('traffic_'):
        server_id = int(data.split('_')[1])
        traffic = get_server_traffic(server_id)
        keyboard = [[InlineKeyboardButton("🔙 بازگشت به سرور", callback_data=f"server_{server_id}")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(traffic, parse_mode='Markdown', reply_markup=reply_markup)

    elif data.startswith('reset_'):
        server_id = int(data.split('_')[1])
        # --- تغییر: جلوگیری از اجرای ریست توسط کاربران غیرادمین ---
        if str(chat_id) != ADMIN_CHAT_ID:
            message = "⛔️ *دسترسی غیرمجاز:* فقط ادمین می‌تواند ترافیک را ریست کند."
            keyboard = [[InlineKeyboardButton("🔙 بازگشت به سرور", callback_data=f"server_{server_id}")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)
            return
        # ---------------------------------------------------------------
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip, username, password, name FROM servers WHERE id=?", (server_id,))
        server = c.fetchone()
        if server:
            ip, username, password, name = server
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=10)
                ssh.exec_command("vnstat -i ens34 --reset")
                ssh.close()
                reset_date = datetime.datetime.now().strftime("%Y-%m")
                c.execute("UPDATE servers SET traffic_usage=0, reset_date=? WHERE id=?", (reset_date, server_id))
                conn.commit()
                message = f"✅ *ترافیک سرور {name} ({ip}) با موفقیت ریست شد!* 🎉"
                logging.info(f"Traffic reset for server {ip}")
            except Exception as e:
                message = f"❌ *خطا در ریست ترافیک سرور {name} ({ip}):* {str(e)} 😔"
                logging.error(f"Failed to reset traffic for {ip}: {str(e)}")
            conn.close()
            keyboard = [[InlineKeyboardButton("🔙 بازگشت به سرور", callback_data=f"server_{server_id}")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)

    elif data.startswith('reboot_'):
        server_id = int(data.split('_')[1])
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip, username, password, name FROM servers WHERE id=?", (server_id,))
        server = c.fetchone()
        conn.close()
        if server:
            ip, name, username, password = server
            message = f"⚠️ *توجه: با ریبوت سرور {name} ({ip})، ممکن است سرویس‌های شما موقتاً قطع شوند!*\nآیا مطمئن هستید؟"
            keyboard = [
                [InlineKeyboardButton("✅ بله", callback_data=f"confirm_reboot_{server_id}"),
                 InlineKeyboardButton("❌ خیر", callback_data=f"cancel_reboot_{server_id}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)

    elif data.startswith('confirm_reboot_'):
        server_id = int(data.split('_')[2])
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip, username, password, name FROM servers WHERE id=?", (server_id,))
        server = c.fetchone()
        if server:
            ip, username, password, name = server
            first_name = query.from_user.first_name
            telegram_username = query.from_user.username or "نام کاربری ندارد"
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=10)
                ssh.exec_command("sudo reboot")
                ssh.close()
                message_to_user = f"🔁 *سرور {name} ({ip}) با موفقیت ریبوت شد!* ⏳\nلطفاً چند دقیقه صبر کنید تا سرور دوباره آنلاین بشه."
                message_to_admin = (
                    f"درخواست ریبوت سرور:\n"
                    f"نام سرور: {name}\n"
                    f"آیپی: {ip}\n"
                    f"نام کاربر: {first_name}\n"
                    f"نام کاربری: @{telegram_username}\n"
                    f"چت آیدی: {chat_id}\n"
                    f"عمل درخواست شده: ریبوت سرور"
                )
                logging.info(f"Server rebooted: {ip}")
                keyboard = [[InlineKeyboardButton("🏠 بازگشت به منو اصلی", callback_data='main_menu')]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.message.reply_text(message_to_user, parse_mode='Markdown', reply_markup=reply_markup)
                await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=message_to_admin)
            except Exception as e:
                message = f"❌ *خطا در ریبوت سرور {name} ({ip}):* {str(e)} 😔"
                logging.error(f"Failed to reboot server {ip}: {str(e)}")
                keyboard = [[InlineKeyboardButton("🔙 بازگشت به سرور", callback_data=f"server_{server_id}")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)
            conn.close()

    elif data.startswith('cancel_reboot_'):
        server_id = int(data.split('_')[2])
        keyboard = [[InlineKeyboardButton("🔙 بازگشت به سرور", callback_data=f"server_{server_id}")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("❌ عملیات ریبوت لغو شد.", parse_mode='Markdown', reply_markup=reply_markup)

    elif data.startswith('shutdown_'):
        server_id = int(data.split('_')[1])
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip, username, password, name FROM servers WHERE id=?", (server_id,))
        server = c.fetchone()
        conn.close()
        if server:
            ip, name, username, password = server
            message = f"⚠️ *توجه: با خاموش کردن سرور {name} ({ip})، تمامی سرویس‌های شما متوقف خواهند شد!*\nآیا مطمئن هستید؟"
            keyboard = [
                [InlineKeyboardButton("✅ بله", callback_data=f"confirm_shutdown_{server_id}"),
                 InlineKeyboardButton("❌ خیر", callback_data=f"cancel_shutdown_{server_id}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)

    elif data.startswith('confirm_shutdown_'):
        server_id = int(data.split('_')[2])
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip, username, password, name FROM servers WHERE id=?", (server_id,))
        server = c.fetchone()
        if server:
            ip, username, password, name = server
            first_name = query.from_user.first_name
            telegram_username = query.from_user.username or "نام کاربری ندارد"
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=10)
                ssh.exec_command("sudo shutdown -h now")
                ssh.close()
                message_to_user = f"🛑 *سرور {name} ({ip}) با موفقیت خاموش شد!* 🔌\nبرای روشن کردن، از پنل هاستینگ استفاده کنید."
                message_to_admin = (
                    f"درخواست خاموش کردن سرور:\n"
                    f"نام سرور: {name}\n"
                    f"آیپی: {ip}\n"
                    f"نام کاربر: {first_name}\n"
                    f"نام کاربری: @{telegram_username}\n"
                    f"چت آیدی: {chat_id}\n"
                    f"عمل درخواست شده: خاموش کردن سرور"
                )
                logging.info(f"Server shutdown: {ip}")
                keyboard = [[InlineKeyboardButton("🏠 بازگشت به منو اصلی", callback_data='main_menu')]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.message.reply_text(message_to_user, parse_mode='Markdown', reply_markup=reply_markup)
                await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=message_to_admin)
            except Exception as e:
                message = f"❌ *خطا در خاموش کردن سرور {name} ({ip}):* {str(e)} 😔"
                logging.error(f"Failed to shutdown server {ip}: {str(e)}")
                keyboard = [[InlineKeyboardButton("🔙 بازگشت به سرور", callback_data=f"server_{server_id}")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)
            conn.close()

    elif data.startswith('cancel_shutdown_'):
        server_id = int(data.split('_')[2])
        keyboard = [[InlineKeyboardButton("🔙 بازگشت به سرور", callback_data=f"server_{server_id}")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("❌ عملیات خاموش کردن لغو شد.", parse_mode='Markdown', reply_markup=reply_markup)

    elif data.startswith('rebuild_'):
        server_id = int(data.split('_')[1])
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip, name FROM servers WHERE id=?", (server_id,))
        server = c.fetchone()
        conn.close()
        if server:
            ip, name = server
            message = f"⚠️ *توجه: با ریبیلد سرور {name} ({ip})، تمامی اطلاعات شما حذف خواهد شد!*\nآیا مطمئن هستید؟"
            keyboard = [
                [InlineKeyboardButton("✅ بله", callback_data=f"confirm_rebuild_{server_id}"),
                 InlineKeyboardButton("❌ خیر", callback_data=f"cancel_rebuild_{server_id}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)

    elif data.startswith('confirm_rebuild_'):
        server_id = int(data.split('_')[2])
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT ip, name FROM servers WHERE id=?", (server_id,))
        server = c.fetchone()
        conn.close()
        if server:
            ip, name = server
            first_name = query.from_user.first_name
            telegram_username = query.from_user.username or "نام کاربری ندارد"
            message_to_user = f"✅ سرور {name} ({ip}) تا ۱۵ دقیقه دیگر ریبیلد خواهد شد. لطفاً منتظر بمانید."
            message_to_admin = (
                f"درخواست ریبیلد سرور:\n"
                f"نام سرور: {name}\n"
                f"آیپی: {ip}\n"
                f"نام کاربر: {first_name}\n"
                f"نام کاربری: @{telegram_username}\n"
                f"چت آیدی: {chat_id}\n"
                f"عمل درخواست شده: ریبیلد سرور"
            )
            keyboard = [[InlineKeyboardButton("🏠 بازگشت به منو اصلی", callback_data='main_menu')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.message.reply_text(message_to_user, parse_mode='Markdown', reply_markup=reply_markup)
            await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=message_to_admin)

    elif data.startswith('cancel_rebuild_'):
        server_id = int(data.split('_')[2])
        keyboard = [[InlineKeyboardButton("🔙 بازگشت به سرور", callback_data=f"server_{server_id}")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("❌ عملیات ریبیلد لغو شد.", parse_mode='Markdown', reply_markup=reply_markup)

    elif data == 'ticket':
        await query.edit_message_text("🎫 لطفاً متن تیکت خود را ارسال کنید.", parse_mode='Markdown')
        context.user_data['ticket_mode'] = True

    elif data == 'forward_broadcast':
        if str(chat_id) != ADMIN_CHAT_ID:
            await query.edit_message_text("⚠️ فقط ادمین می‌تواند از این قابلیت استفاده کند!", parse_mode='Markdown')
            return
        await query.edit_message_text(
            "📬 لطفاً روی پیام مورد نظر ریپلای کنید تا به همه کاربران فوروارد شود.",
            parse_mode='Markdown'
        )
        context.user_data['forward_broadcast'] = True

    elif data == 'text_broadcast':
        if str(chat_id) != ADMIN_CHAT_ID:
            await query.edit_message_text("⚠️ فقط ادمین می‌تواند از این قابلیت استفاده کند!", parse_mode='Markdown')
            return
        await query.edit_message_text(
            "✉️ لطفاً متن پیام خود را برای ارسال به همه کاربران وارد کنید.",
            parse_mode='Markdown'
        )
        context.user_data['text_broadcast'] = True

    elif data == 'admin_stats':
        if str(chat_id) != ADMIN_CHAT_ID:
            await query.edit_message_text("⚠️ فقط ادمین می‌تواند از این قابلیت استفاده کند!", parse_mode='Markdown')
            return
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM telegram_users")
        num_users = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM servers WHERE active=1")
        num_servers = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM tickets")
        num_tickets = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM tickets WHERE status='open'")
        num_open_tickets = c.fetchone()[0]
        conn.close()
        message = (
            f"📊 *آمار سیستم:*\n\n"
            f"تعداد کاربران ربات: {num_users}\n"
            f"تعداد سرورهای فعال: {num_servers}\n"
            f"تعداد کل تیکت‌ها: {num_tickets}\n"
            f"تعداد تیکت‌های باز: {num_open_tickets}"
        )
        keyboard = [[InlineKeyboardButton("🏠 بازگشت به منو اصلی", callback_data='main_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)

    elif data == 'open_tickets':
        if str(chat_id) != ADMIN_CHAT_ID:
            await query.edit_message_text("⚠️ فقط ادمین می‌تواند از این قابلیت استفاده کند!", parse_mode='Markdown')
            return
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT chat_id, message_text FROM tickets WHERE status='open'")
        open_tickets = c.fetchall()
        conn.close()
        if not open_tickets:
            message = "🎫 *هیچ تیکت باز وجود ندارد!* 😊"
        else:
            message = "🎫 *لیست تیکت‌های باز:*\n\n"
            for idx, (user_chat_id, ticket_text) in enumerate(open_tickets, 1):
                message += f"{idx}. از کاربر {user_chat_id}:\n{ticket_text}\n\n"
        keyboard = [[InlineKeyboardButton("🏠 بازگشت به منو اصلی", callback_data='main_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(message, parse_mode='Markdown', reply_markup=reply_markup)

async def handle_message(update, context):
    chat_id = str(update.message.chat_id)
    
    # مدیریت تیکت
    if context.user_data.get('ticket_mode', False):
        message_text = update.message.text
        message_id = update.message.message_id
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO tickets (chat_id, message_id, message_text) VALUES (?, ?, ?)", (chat_id, message_id, message_text))
        conn.commit()
        conn.close()
        await update.message.reply_text("🎫 تیکت شما با موفقیت ارسال شد! منتظر پاسخ پشتیبانی باشید. 😊")
        await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=f"🎫 تیکت جدید از {chat_id}:\n{message_text}")
        context.user_data['ticket_mode'] = False
        await show_main_menu(update, context, chat_id)
        return

    # مدیریت پاسخ به تیکت توسط ادمین
    if str(chat_id) == ADMIN_CHAT_ID and update.message.reply_to_message:
        original_message = update.message.reply_to_message.text
        if "تیکت جدید از" in original_message:
            reply_text = update.message.text
            user_chat_id = original_message.split("تیکت جدید از ")[1].split(":")[0]
            await context.bot.send_message(chat_id=user_chat_id, text=f"📬 پاسخ به تیکت شما:\n{reply_text}")
            await update.message.reply_text("✅ پاسخ با موفقیت ارسال شد.")
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("UPDATE tickets SET status='closed' WHERE chat_id=? AND message_text=?", 
                      (user_chat_id, original_message.split("\n", 1)[1]))
            conn.commit()
            conn.close()
            await show_main_menu(update, context, chat_id)
            return

    # مدیریت فوروارد پیام همگانی
    if str(chat_id) == ADMIN_CHAT_ID and context.user_data.get('forward_broadcast', False):
        if not update.message.reply_to_message:
            await update.message.reply_text(
                "⚠️ لطفاً روی یک پیام ریپلای کنید تا فوروارد شود!",
                parse_mode='Markdown'
            )
            return
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT chat_id FROM telegram_users")
        users = c.fetchall()
        conn.close()
        for user in users:
            try:
                await context.bot.forward_message(
                    chat_id=user[0],
                    from_chat_id=chat_id,
                    message_id=update.message.reply_to_message.message_id
                )
                logging.info(f"پیام فوروارد شده برای {user[0]} از پیام {update.message.reply_to_message.message_id}")
            except Exception as e:
                logging.error(f"خطا در فوروارد پیام به {user[0]}: {str(e)}")
        await update.message.reply_text("📬 پیام به همه کاربران فوروارد شد.")
        context.user_data['forward_broadcast'] = False
        await show_main_menu(update, context, chat_id)
        return

    # مدیریت ارسال پیام همگانی
    if str(chat_id) == ADMIN_CHAT_ID and context.user_data.get('text_broadcast', False):
        message_text = update.message.text
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT chat_id FROM telegram_users")
        users = c.fetchall()
        conn.close()
        for user in users:
            try:
                await context.bot.send_message(chat_id=user[0], text=message_text)
                logging.info(f"پیام پخش شده برای {user[0]}: {message_text}")
            except Exception as e:
                logging.error(f"خطا در ارسال پیام پخش به {user[0]}: {str(e)}")
        await update.message.reply_text("✉️ پیام به همه کاربران ارسال شد.")
        context.user_data['text_broadcast'] = False
        await show_main_menu(update, context, chat_id)
        return

async def broadcast(update, context):
    chat_id = str(update.message.chat_id)
    if chat_id != ADMIN_CHAT_ID:
        await update.message.reply_text("⚠️ فقط ادمین می‌تواند از این دستور استفاده کند!")
        return
    if len(context.args) < 1:
        await update.message.reply_text("لطفاً متن پیام را وارد کنید. مثال: /broadcast سلام به همه")
        return
    message_text = ' '.join(context.args)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT chat_id FROM telegram_users")
    users = c.fetchall()
    conn.close()
    for user in users:
        try:
            await context.bot.send_message(chat_id=user[0], text=message_text)
            logging.info(f"پیام پخش شده برای {user[0]}: {message_text}")
        except Exception as e:
            logging.error(f"خطا در ارسال پیام پخش به {user[0]}: {str(e)}")
    await update.message.reply_text("📢 پیام به همه کاربران ارسال شد.")
    await show_main_menu(update, context, chat_id)

async def forward(update, context):
    chat_id = str(update.message.chat_id)
    if chat_id != ADMIN_CHAT_ID:
        await update.message.reply_text("⚠️ فقط ادمین می‌تواند از این دستور استفاده کند!")
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("لطفاً پیام مورد نظر را فوروارد کنید یا روی یک پیام ریپلای کنید و سپس دستور /forward را وارد کنید.")
        return
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT chat_id FROM telegram_users")
    users = c.fetchall()
    conn.close()
    for user in users:
        try:
            await context.bot.forward_message(chat_id=user[0], from_chat_id=chat_id, message_id=update.message.reply_to_message.message_id)
            logging.info(f"پیام فوروارد شده برای {user[0]} از پیام {update.message.reply_to_message.message_id}")
        except Exception as e:
            logging.error(f"خطا در فوروارد پیام به {user[0]}: {str(e)}")
    await update.message.reply_text("📬 پیام به همه کاربران فوروارد شد.")
    await show_main_menu(update, context, chat_id)

def get_server_status(server_id):
    """نمایش وضعیت سرور با قالب‌بندی جذاب"""
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
            stdin, stdout, stderr = ssh.exec_command("uptime")
            uptime = stdout.read().decode().strip()
            ssh.close()
            return (
                f"🖥️ *وضعیت سرور: {name} ({ip})* 🖥️\n\n"
                f"✅ *سرور فعال و آنلاین است!* 🌟\n"
                f"⏳ *آپتایم:* `{uptime}`\n\n"
                f"همه چیز عالی به نظر می‌رسه! 🚀"
            )
        except Exception as e:
            return (
                f"🖥️ *وضعیت سرور: {name} ({ip})* 🖥️\n\n"
                f"⚠️ *سرور خاموش یا غیرقابل دسترسی است:* {str(e)} 😔\n"
                f"لطفاً اتصال رو چک کنید یا با پشتیبانی تماس بگیرید."
            )
    return "⚠️ *سرور پیدا نشد!* 😕"

def get_server_traffic(server_id):
    """نمایش ترافیک سرور با قالب‌بندی جذاب"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, username, password, traffic_limit, traffic_usage, reset_date, name FROM servers WHERE id=?", (server_id,))
    server = c.fetchone()
    conn.close()
    if server:
        ip, username, password, traffic_limit, traffic_usage, reset_date, name = server
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=10)
            if reset_date:
                traffic_cmd = (
                    f"vnstat -m -i ens34 | awk '/[0-9]{{4}}-[0-9]{{2}}/ && $1 >= \"{reset_date}\" "
                    "&& !/estimated/ {if ($9 == \"TiB\") sum += $8 *1024; else sum += $8} END {print sum ? sum : 0}'"
                )
            else:
                traffic_cmd = (
                    "vnstat -m -i ens34 | awk '/[0-9]{4}-[0-9]{2}/ && !/estimated/ "
                    "{if ($9 == \"TiB\") sum += $8 * 1024; else sum += $8} END {print sum ? sum : 0}'"
                )
            stdin, stdout, stderr = ssh.exec_command(traffic_cmd)
            traffic_usage_output = stdout.read().decode().strip()
            traffic_usage_new = float(traffic_usage_output) if traffic_usage_output else 0.0
            ssh.close()
            logging.debug(f"Raw traffic output for server {ip}: {traffic_usage_output}")
            return (
                f"📈 *ترافیک سرور: {name} ({ip})* 📈\n\n"
                f"📊 *مصرف فعلی:* `{traffic_usage_new:.2f} GiB` 📉\n"
                f"🚧 *محدودیت ترافیک:* `{traffic_limit if traffic_limit > 0 else 'نامحدود'} GiB` ⚠️\n\n"
                f"اگه نزدیک به حد مجاز شدی، مراقب باش! 😊"
            )
        except Exception as e:
            return (
                f"📈 *ترافیک سرور: {name} ({ip})* 📈\n\n"
                f"⚠️ *خطا در دریافت اطلاعات ترافیک:* {str(e)} 😔\n"
                f"لطفاً اتصال رو چک کنید."
            )
    return "⚠️ *سرور پیدا نشد!* 😕"

async def send_telegram_message(bot, chat_id, message):
    try:
        await bot.send_message(chat_id=chat_id, text=message)
        logging.info(f"Telegram message sent to {chat_id}: {message}")
    except Exception as e:
        logging.error(f"Failed to send Telegram message to {chat_id}: {str(e)}")

def monitor_servers(application):
    traffic_alerts = {server_id: set() for server_id in range(1, 100)}
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    while True:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, ip, username, password, traffic_limit, telegram_chat_id, traffic_usage, reset_date FROM servers WHERE active=1")
        servers = c.fetchall()
        conn.close()
        for server in servers:
            server_id, ip, username, password, traffic_limit, telegram_chat_id, traffic_usage, reset_date = server
            time.sleep(random.uniform(0.5, 2.0))
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=10)
                if reset_date:
                    traffic_cmd = f"vnstat -m -i ens34 | awk '/[0-9]{{4}}-[0-9]{{2}}/ && $1 >= \"{reset_date}\" && !/estimated/ {{if ($9 == \"TiB\") sum += $8 *1024; else sum += $8}} END {{print sum ? sum : 0}}'"
                else:
                    traffic_cmd = "vnstat -m -i ens34 | awk '/[0-9]{4}-[0-9]{2}/ && !/estimated/ {if ($9 == \"TiB\") sum += $8 * 1024; else sum += $8} END {print sum ? sum : 0}'"
                stdin, stdout, stderr = ssh.exec_command(traffic_cmd)
                traffic_usage_output = stdout.read().decode().strip()
                traffic_usage_new = float(traffic_usage_output) if traffic_usage_output else 0.0
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("UPDATE servers SET traffic_usage=? WHERE id=?", (traffic_usage_new, server_id))
                conn.commit()

                # بررسی آستانه 200 گیگابایت باقی‌مانده
                if traffic_limit > 0:
                    remaining_traffic = traffic_limit - traffic_usage_new
                    if 0 < remaining_traffic <= 200 and server_id not in traffic_alerts:
                        # دریافت کاربران مرتبط با سرور
                        c.execute("SELECT u.telegram_chat_id FROM users u JOIN user_servers us ON u.id = us.user_id WHERE us.server_id=? AND u.telegram_chat_id IS NOT NULL", (server_id,))
                        user_chat_ids = [row[0] for row in c.fetchall()]
                        message = f"⚠️ *هشدار ترافیک:* حجم سرویس سرور {ip} رو به اتمامه ({remaining_traffic:.2f} گیگابایت باقی‌مانده). برای تمدید، با مدیریت تماس بگیرید! 📩"
                        
                        # ارسال پیام به کاربران مرتبط
                        for chat_id in user_chat_ids:
                            loop.run_until_complete(send_telegram_message(application.bot, chat_id, message))
                        
                        # ارسال پیام به مدیر
                        loop.run_until_complete(send_telegram_message(application.bot, ADMIN_CHAT_ID, message))
                        
                        # اضافه کردن سرور به لیست اعلان‌های ارسال‌شده
                        traffic_alerts[server_id].add(server_id)
                        logging.info(f"Traffic warning sent for server {ip}: {remaining_traffic:.2f} GiB remaining")

                # بررسی تخطی از حد مجاز
                if traffic_limit > 0 and traffic_usage_new > traffic_limit:
                    ssh.exec_command("sudo shutdown -h now")
                    message = f"🚨 *هشدار:* سرور {ip} از حد ترافیک مجاز عبور کرد ({traffic_usage_new} GiB > {traffic_limit} GiB) و خاموش شد! 🔌"
                    logging.info(message)
                    send_email(f"Server Shutdown: {ip}", message)
                    # ارسال پیام به کاربران مرتبط و مدیر
                    c.execute("SELECT u.telegram_chat_id FROM users u JOIN user_servers us ON u.id = us.user_id WHERE us.server_id=? AND u.telegram_chat_id IS NOT NULL", (server_id,))
                    user_chat_ids = [row[0] for row in c.fetchall()]
                    for chat_id in user_chat_ids:
                        loop.run_until_complete(send_telegram_message(application.bot, chat_id, message))
                    loop.run_until_complete(send_telegram_message(application.bot, ADMIN_CHAT_ID, message))
                    traffic_alerts[server_id].clear()  # ریست کردن اعلان‌ها پس از خاموش شدن سرور

                ssh.close()
                conn.close()
                logging.debug(f"Monitor servers - Raw traffic output for {ip}: {traffic_usage_output}")
            except Exception as e:
                logging.error(f"Error monitoring server {ip}: {str(e)}")
                conn.close()
time.sleep(5)

def run_flask():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

def main():
    init_db()
    init_default_license()
    if not startup_check():
        logging.error("برنامه به دلیل مشکل لایسنس متوقف شد.")
        return

    application = Application.builder().token(TELEGRAM_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button))
    application.add_handler(CommandHandler("broadcast", broadcast))
    application.add_handler(CommandHandler("forward", forward))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    monitor_thread = threading.Thread(target=monitor_servers, args=(application,))
    monitor_thread.daemon = True
    monitor_thread.start()

    if platform.system() == "Emscripten":
        asyncio.ensure_future(application.run_polling())
    else:
        application.run_polling()

if __name__ == "__main__":
    main()
