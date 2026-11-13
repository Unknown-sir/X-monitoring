# 🧊 Cloud Cube (X-monitoring) — SaaS VPS Store, ESXi Automation & Monitoring Panel

**Cloud Cube** is a full-stack SaaS VPS hosting platform featuring a customer dashboard, multi-department ticketing & CRM (Support, Sales, Billing), Iranian National ID KYC verification, two-way card-to-card receipt approval (Web Panel + Telegram Bot over SOCKS5 proxy), granular module-based RBAC accounting, and full **VMware ESXi** automation (Cloud-Init provisioning, live CPU/RAM/SSD upgrades, snapshots, IP pool management, and automated vNIC suspension).

---

## 🚀 One-Command Permanent Production Installation (Ubuntu / Debian)

Run this command as `root` on your server to install Cloud Cube to `/opt/cloudcube`, configure a permanent **`systemd` service (`cloudcube`)** that runs 24/7 and auto-starts on boot, and register the global `cloudcube-update` command:

```bash
git clone https://github.com/Unknown-sir/X-monitoring.git /opt/cloudcube && cd /opt/cloudcube && sudo bash install.sh
```

Or if you already extracted the project directory on your server:
```bash
sudo bash install.sh
```

Once finished, the panel runs permanently on port **5000** (`http://YOUR_SERVER_IP:5000`).

---

## 🔄 One-Command GitHub Update

To pull the latest updates from GitHub without overwriting your `.env`, `database.db`, or uploaded receipts, run:

```bash
cloudcube-update
```

---

## 🛠️ Service Management Commands

| Command | Description |
| :--- | :--- |
| `cloudcube status` | Check live `systemd` service status |
| `cloudcube logs` | Stream live application & Telegram bot logs |
| `cloudcube restart` | Restart the permanent service |
| `cloudcube-update` | Pull latest code from GitHub, install deps & restart |
