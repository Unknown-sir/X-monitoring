# XMonitor – Installation (Development / Local)

This document explains how to run XMonitor on a local machine for development
or testing.

## 1. Prerequisites

- Linux, macOS, or Windows (WSL recommended on Windows)
- Python 3.10 or newer
- Git
- Redis server
- MySQL or MariaDB (for the monitoring database)
- `vnstat` installed on each monitored server

---

## 2. Clone the repository

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/xmonitor.git
cd xmonitor
```

---

## 3. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
```

---

## 4. Install Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 5. Environment and config

Create your `.env` and `config.json` from the examples:

```bash
cp .env.example .env
cp config.example.json config.json
```

**Edit `.env`** and fill in:

- `SECRET_KEY`
- `DB_PASSWORD` (if you use encrypted SQLite)
- `DB_URL` (MySQL URL)
- Telegram tokens and admin IDs
- SMTP settings

**Edit `config.json`** and set:

- `license_key`
- `register_date`
- `is_trial` (`true` or `false`)

---

## 6. Initialize database

The SQLite database used by `app.py` is created automatically on first run.
The MySQL database for the worker is created by SQLAlchemy when `worker.py`
starts, as long as `DB_URL` points to an existing database.

Create a database in MySQL first, for example:

```sql
CREATE DATABASE xmonitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL ON xmonitor.* TO 'xmonitor_user'@'127.0.0.1' IDENTIFIED BY 'STRONG_PASSWORD';
FLUSH PRIVILEGES;
```

Then set in `.env`:

```dotenv
DB_URL=mysql+pymysql://xmonitor_user:STRONG_PASSWORD@127.0.0.1/xmonitor?charset=utf8mb4
```

---

## 7. Run the web app

```bash
python app.py
```

Open:

- `http://localhost:5000` (or the server IP on port 5000)

---

## 8. Run the worker

```bash
MONITOR_INTERVAL=10 python worker.py
```

Make sure:

- Remote servers have `vnstat` installed.
- SSH username/password in the `servers` table is correct.

---

## 9. Run the Telegram bot

```bash
BOT_TOKEN=your_bot_token BOT_ADMINS=123456789 python bot.py
```

Keep the bot process running in a separate terminal during development.
In production you will use `systemd` instead.

---

## 10. Useful tips

- Use `git status` frequently to ensure `.env`, `config.json` and `database.db`
  are not committed to Git.
- In development you can set `MONITOR_INTERVAL=3` for quick feedback, and use
  a higher value (10–60) in production.
