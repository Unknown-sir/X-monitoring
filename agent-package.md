1- First install the following command on the agent servers
```
sudo apt update && sudo apt install -y vnstat sysstat && sudo useradd -m -s /bin/bash monitoring && sudo passwd monitoring && echo "monitoring ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/monitoring
```
2- Enter the monitoring user password
