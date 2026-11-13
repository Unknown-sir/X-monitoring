#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Cloud Cube (کلود کیوب) — One-Command Permanent Production Installer (Ubuntu/Debian)
# Installs to /opt/cloudcube, sets up systemd service, and registers `cloudcube-update`
# ==============================================================================

APP_DIR="/opt/cloudcube"
REPO_URL="${CLOUDCUBE_REPO:-https://github.com/Unknown-sir/X-monitoring.git}"
SERVICE_NAME="cloudcube"
PORT="${PORT:-5000}"

GREEN='\033[0;32m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${PURPLE}"
echo "=============================================================="
echo "   Cloud Cube (کلود کیوب) — Permanent Server Installer"
echo "=============================================================="
echo -e "${NC}"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}لطفاً این اسکریپت را با دسترسی root اجرا کنید: sudo bash install.sh${NC}"
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
echo -e "${YELLOW}[1/6] در حال نصب پیش‌نیازهای سیستم (Python3, Git, Redis)...${NC}"
apt-get update -y
apt-get install -y python3 python3-venv python3-pip git redis-server curl iputils-ping

systemctl enable redis-server >/dev/null 2>&1 || true
systemctl restart redis-server >/dev/null 2>&1 || true

echo -e "${YELLOW}[2/6] در حال آماده‌سازی پوشه پروژه در ${APP_DIR}...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$SCRIPT_DIR" != "$APP_DIR" ]]; then
    if [[ -d "$APP_DIR/.git" ]]; then
        echo "مخزن قبلی در $APP_DIR یافت شد؛ در حال به‌روزرسانی کدها..."
        cd "$APP_DIR"
        git fetch --all || true
        git reset --hard origin/main || git reset --hard origin/master || true
    elif [[ -f "$SCRIPT_DIR/app.py" ]]; then
        mkdir -p "$APP_DIR"
        cp -a "$SCRIPT_DIR/." "$APP_DIR/"
    else
        git clone "$REPO_URL" "$APP_DIR"
    fi
fi

cd "$APP_DIR"
if [[ ! -d "$APP_DIR/.git" ]]; then
    git init
    git branch -M main
    git remote add origin "$REPO_URL" || true
fi

echo -e "${YELLOW}[3/6] در حال ساخت محیط مجازی Python و نصب پکیج‌ها...${NC}"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

echo -e "${YELLOW}[4/6] در حال پیکربندی فایل تنظیمات (.env)...${NC}"
if [[ ! -f "$APP_DIR/.env" ]]; then
    RAND_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    cat > "$APP_DIR/.env" <<EOF
SECRET_KEY=${RAND_SECRET}
PORT=${PORT}
TELEGRAM_TOKEN=YOUR_BOT_TOKEN
ADMIN_CHAT_ID=YOUR_CHAT_ID
TELEGRAM_PROXY=socks5://CBZBWfWxTa:YZSIy26WQC@sub.rskhi.ir:12012
REDIS_HOST=localhost
REDIS_PORT=6379
EOF
    echo -e "${GREEN}فایل .env با کلید امنیتی تصادفی ساخته شد.${NC}"
else
    echo "فایل .env قبلی حفظ شد."
fi

mkdir -p "$APP_DIR/static/uploads/receipts"

echo -e "${YELLOW}[5/6] در حال ساخت سرویس دائمی systemd (${SERVICE_NAME})...${NC}"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Cloud Cube (X-monitoring) Permanent SaaS Panel & ESXi Automation
After=network-online.target redis-server.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/venv/bin/python ${APP_DIR}/app.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/cloudcube.log
StandardError=append:/var/log/cloudcube.log

[Install]
WantedBy=multi-user.target
EOF

chmod +x "$APP_DIR/install.sh" "$APP_DIR/update.sh"

# Install global single-command updater & helper CLI
ln -sf "$APP_DIR/update.sh" /usr/local/bin/cloudcube-update

cat > /usr/local/bin/cloudcube <<'EOF'
#!/usr/bin/env bash
case "${1:-status}" in
    update)  exec /usr/local/bin/cloudcube-update ;;
    restart) systemctl restart cloudcube && systemctl status cloudcube --no-pager -l ;;
    stop)    systemctl stop cloudcube ;;
    start)   systemctl start cloudcube ;;
    logs)    tail -n 80 -f /var/log/cloudcube.log ;;
    *)       systemctl status cloudcube --no-pager -l ;;
esac
EOF
chmod +x /usr/local/bin/cloudcube

echo -e "${YELLOW}[6/6] در حال فعال‌سازی و اجرای دائمی سرویس...${NC}"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

if command -v ufw >/dev/null 2>&1; then
    ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
fi

SERVER_IP="$(curl -s4 --max-time 4 https://api.ipify.org || hostname -I | awk '{print $1}')"

echo -e "${GREEN}"
echo "=============================================================="
echo "  ✅ نصب و راه‌اندازی دائمی کلود کیوب با موفقیت انجام شد!"
echo "=============================================================="
echo -e "${NC}"
echo -e "🌐 آدرس پنل وب:   ${GREEN}http://${SERVER_IP}:${PORT}${NC}"
echo -e "🔄 دستور آپدیت:   ${YELLOW}cloudcube-update${NC}  (آپدیت خودکار از گیت‌هاب)"
echo -e "📊 وضعیت سرویس:   ${YELLOW}cloudcube status${NC}"
echo -e "📜 مشاهده لاگ:    ${YELLOW}cloudcube logs${NC}"
echo ""
