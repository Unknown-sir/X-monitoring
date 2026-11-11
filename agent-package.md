1- First run the following command on the monitored agent servers:
```bash
sudo apt update && sudo apt install -y vnstat sysstat && sudo useradd -m -s /bin/bash monitoring && sudo passwd monitoring && echo "monitoring ALL=(ALL) NOPASSWD: /sbin/shutdown, /sbin/reboot, /usr/bin/vnstat" | sudo tee /etc/sudoers.d/monitoring
```
2- Enter the monitoring user password.
