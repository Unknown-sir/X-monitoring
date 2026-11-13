#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Cloud Cube (کلود کیوب) — One-Command GitHub Updater
# Safely updates code from GitHub while preserving .env, database.db & receipts
# ==============================================================================

APP_DIR="/opt/cloudcube"
if [[ ! -d "$APP_DIR" ]]; then
    APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

cd "$APP_DIR"

echo "🔄 در حال دریافت آخرین نسخه کلود کیوب از گیت‌هاب..."
git fetch --all

if git show-ref --verify --quiet refs/remotes/origin/main; then
    git reset --hard origin/main
elif git show-ref --verify --quiet refs/remotes/origin/master; then
    git reset --hard origin/master
else
    git pull --rebase || true
fi

if [[ -x "$APP_DIR/venv/bin/pip" ]]; then
    echo "📦 در حال بررسی و نصب پکیج‌های جدید Python..."
    "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt" --quiet
else
    pip3 install -r "$APP_DIR/requirements.txt" --quiet
fi

chmod +x "$APP_DIR/install.sh" "$APP_DIR/update.sh" || true

if systemctl list-unit-files | grep -q "^cloudcube.service"; then
    echo "🚀 در حال ری‌استارت سرویس دائمی cloudcube..."
    systemctl restart cloudcube
    sleep 2
    systemctl status cloudcube --no-pager -l | head -n 15
fi

echo "✅ پروژه کلود کیوب با موفقیت به آخرین نسخه گیت‌هاب آپدیت و اجرا شد!"
