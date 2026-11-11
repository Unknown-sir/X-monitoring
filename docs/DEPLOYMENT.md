# XMonitor – Production Deployment (Ubuntu example)

This document describes a simple way to deploy XMonitor on an Ubuntu server
using:

- `systemd` services
- `gunicorn` as WSGI server
- `nginx` as reverse proxy

> Adjust paths and usernames according to your environment.

---

## 1. Server requirements

For a small setup (up to ~20 monitored servers):

- Ubuntu 22.04+
- 1 vCPU
- 2 GB RAM
- 20 GB SSD

---

## 2. Install system packages

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip                         redis-server mysql-server nginx git
```

Secure MySQL (optional but recommended):

```bash
sudo mysql_secure_installation
```

---

## 3. Create MySQL database and user

```bash
sudo mysql
```

Inside the MySQL shell:

```sql
CREATE DATABASE xmonitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'xmonitor_user'@'127.0.0.1' IDENTIFIED BY 'STRONG_PASSWORD';
GRANT ALL ON xmonitor.* TO 'xmonitor_user'@'127.0.0.1';
FLUSH PRIVILEGES;
EXIT;
```

---

## 4. Create a dedicated Linux user

```bash
sudo adduser --system --group --home /opt/xmonitor xmonitor
sudo chown -R xmonitor:xmonitor /opt/xmonitor
```

---

## 5. Clone the project and create venv

```bash
sudo -u xmonitor -H bash

cd /opt/xmonitor
git clone https://github.com/YOUR_GITHUB_USERNAME/xmonitor.git .
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn
```

---

## 6. Environment and config

```bash
cp .env.example .env
cp config.example.json config.json
nano .env
nano config.json
```

Set at least:

- `DB_URL=mysql+pymysql://xmonitor_user:STRONG_PASSWORD@127.0.0.1/xmonitor?charset=utf8mb4`
- `SECRET_KEY`, `DB_PASSWORD`, Telegram tokens, SMTP settings, etc.

Exit the `xmonitor` shell when done:

```bash
exit
```

---

## 7. systemd service units

Create a service for **gunicorn (web app)**:

`/etc/systemd/system/xmonitor-web.service`

```ini
[Unit]
Description=XMonitor Web (gunicorn)
After=network.target

[Service]
User=xmonitor
Group=xmonitor
WorkingDirectory=/opt/xmonitor
Environment="PATH=/opt/xmonitor/.venv/bin"
EnvironmentFile=/opt/xmonitor/.env
ExecStart=/opt/xmonitor/.venv/bin/gunicorn -w 3 -b 0.0.0.0:5000 app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Service for **worker**:

`/etc/systemd/system/xmonitor-worker.service`

```ini
[Unit]
Description=XMonitor Worker
After=network.target mysql.service

[Service]
User=xmonitor
Group=xmonitor
WorkingDirectory=/opt/xmonitor
Environment="PATH=/opt/xmonitor/.venv/bin"
EnvironmentFile=/opt/xmonitor/.env
ExecStart=/opt/xmonitor/.venv/bin/python worker.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Service for **Telegram bot**:

`/etc/systemd/system/xmonitor-bot.service`

```ini
[Unit]
Description=XMonitor Telegram Bot
After=network.target

[Service]
User=xmonitor
Group=xmonitor
WorkingDirectory=/opt/xmonitor
Environment="PATH=/opt/xmonitor/.venv/bin"
EnvironmentFile=/opt/xmonitor/.env
ExecStart=/opt/xmonitor/.venv/bin/python bot.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Reload systemd and enable services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable xmonitor-web xmonitor-worker xmonitor-bot
sudo systemctl start  xmonitor-web xmonitor-worker xmonitor-bot
```

Check status:

```bash
sudo systemctl status xmonitor-web
sudo systemctl status xmonitor-worker
sudo systemctl status xmonitor-bot
```

---

## 8. nginx reverse proxy

Create a new nginx site:

`/etc/nginx/sites-available/xmonitor.conf`

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

Enable and reload nginx:

```bash
sudo ln -s /etc/nginx/sites-available/xmonitor.conf /etc/nginx/sites-enabled/xmonitor.conf
sudo nginx -t
sudo systemctl reload nginx
```

Optional: use `certbot` to obtain free HTTPS certificates.

---

## 9. Monitoring and tuning

- Watch CPU/RAM usage with `top`, `htop` or your hosting panel.
- Increase `MONITOR_INTERVAL` in production if load is high.
- Tune MySQL (buffer sizes, caches) if you have many servers (100+).
