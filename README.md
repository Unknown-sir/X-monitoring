<div align="center"><img src="https://s34.picofile.com/file/8488298118/Screenshot_2.jpg" width="500"></div>
<div align="center"><img src="https://s34.picofile.com/file/8488298126/Screenshot_1.jpg" width="500"></div>
<div align="center"><br>

  برای توضیحات <a href="https://github.com/MrAminiDev/NebulaTunnel/blob/main/README-fa.md"> فارسی اینجا بزنید </a

# XMonitor

XMonitor is a lightweight server traffic monitoring panel built with Flask,
a background SSH worker and a Telegram bot.

It is designed for hosting providers and administrators who need a
simple way to monitor data usage on multiple Linux servers using `vnstat`.

> **Languages:** Code comments are in Persian.  
> This README is in English so it is easier to share publicly on GitHub.

---

## Features

- Web dashboard with owner / admin / user roles
- License-based access (trial / full)
- Per-server traffic limit and reset date
- Live traffic usage and historical samples
- Telegram bot:
  - List servers
  - Change traffic limits (owner only)
  - View recent events/alerts
- Email & Telegram notifications
- Worker process that:
  - Connects to each server via SSH (Paramiko)
  - Reads traffic usage using `vnstat`
  - Stores samples in MySQL using SQLAlchemy
- Redis cache for faster server list responses

---

## Project structure

```text
app.py                     # Flask web panel (SQLite + Redis + Telegram notifier)
worker.py                  # SSH + vnstat monitoring worker (MySQL via SQLAlchemy)
bot.py                     # Standalone Telegram bot (python-telegram-bot)
db.py                      # SQLAlchemy engine/session (uses DB_URL env)
models.py                  # ORM models: Server, TrafficSample, Event
migrate_sqlite_to_mysql.py # Helper script to migrate servers from SQLite to MySQL

templates/                 # Jinja2 templates (dashboard, login, admin, etc.)
static/                    # CSS & JS (including live dashboard refresh)
.env.example               # Sample environment variables (no secrets)
config.example.json        # Sample license config
requirements.txt           # Python dependencies
docs/
  INSTALL.md               # Local/dev installation
  DEPLOYMENT.md            # Production deployment guide
```

---

## Quick start (development)

### 1. Requirements

- Python 3.10+
- Redis server
- SQLite (built-in with Python)
- MySQL or MariaDB (recommended for the worker & bot)
- `vnstat` installed on each **monitored** Linux server

### 2. Clone & install

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/xmonitor.git
cd xmonitor

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### 3. Environment & config

Copy the sample files and edit them:

```bash
cp .env.example .env
cp config.example.json config.json
```

Then open `.env` and set at least:

- `SECRET_KEY`
- `DB_PASSWORD` (if you use encrypted SQLite)
- `DB_URL` (MySQL URL for the monitoring database)
- `TELEGRAM_TOKEN` & `ADMIN_CHAT_ID`
- `BOT_TOKEN`, `BOT_ADMINS`, `BOT_OWNER_ID`
- SMTP settings (`EMAIL_FROM`, `EMAIL_PASSWORD`, `SMTP_SERVER`, `SMTP_PORT`)

Configure `config.json` with your license information.

---

## Running the web panel

```bash
source .venv/bin/activate
python app.py
```

By default it will listen on:

- `http://0.0.0.0:5000`

On first run, the SQLite database (`database.db`) and tables are created automatically.
The owner password is read from `OWNER_PASSWORD` in `.env`.

---

## Running the monitoring worker

The worker uses **MySQL** (via SQLAlchemy and `DB_URL`) and reads traffic from your
servers using `vnstat`.

```bash
source .venv/bin/activate
MONITOR_INTERVAL=10 python worker.py
```

Notes:

- `MONITOR_INTERVAL` is in **seconds** (default: `1.0` but 10–60 is usually better in production).
- Each server gets its own monitoring thread.
- Each monitored server must have:
  - `vnstat` installed and configured
  - SSH access with the username/password stored in the `servers` table

---

## Running the Telegram bot

```bash
source .venv/bin/activate
BOT_TOKEN=your_bot_token BOT_ADMINS=123456789 python bot.py
```

Features:

- `/start` – basic info
- `/list` – list servers
- `/events` – last events
- `/setlimit` – change traffic limit (owner only)
- `/edit` – edit server settings

You must set:

- `BOT_TOKEN`
- `BOT_ADMINS` (comma-separated chat IDs)
- `BOT_OWNER_ID` (ID of the main owner)

---

## Migrating from SQLite to MySQL

If you have an existing `database.db` with servers defined in SQLite,
you can migrate the `servers` table to MySQL:

```bash
source .venv/bin/activate
export DB_URL='mysql+pymysql://user:pass@127.0.0.1/xmonitor?charset=utf8mb4'
python migrate_sqlite_to_mysql.py /path/to/database.db
```

This will:

- Create the `servers` table in the MySQL database (if needed)
- Copy all servers from SQLite into MySQL

---

## Production deployment

For production you typically want:

- A dedicated Linux VPS (Ubuntu 22.04+)
- MySQL/MariaDB and Redis running as services
- `gunicorn` (or another WSGI server) in front of `app.py`
- `nginx` as reverse proxy for HTTPS
- `systemd` services for:
  - Web app (gunicorn)
  - Worker (`worker.py`)
  - Telegram bot (`bot.py`)

See `docs/DEPLOYMENT.md` for a step-by-step guide.

---

## Hardware recommendations

Very roughly (for typical usage):

- Up to **20 monitored servers**  
  → 1 vCPU, 1–2 GB RAM, 20 GB disk

- Around **20–100 servers**  
  → 2 vCPU, 4 GB RAM, faster disk (SSD, which is standard on most VPSes)

- Above **100 servers**  
  → 4+ vCPU, 8+ GB RAM, and proper MySQL tuning

Factors that increase resource usage:

- Very small `MONITOR_INTERVAL` (e.g. 1 second)
- Many servers with slow SSH connections
- Long retention for `traffic_samples` and large MySQL dataset

You can always start small (e.g. 2 GB RAM) and monitor CPU/RAM usage
from the hypervisor or your hosting provider.

---

## License

You can choose your own license (MIT, proprietary, etc).
Add a `LICENSE` file if you want the project to be clearly open-source.
