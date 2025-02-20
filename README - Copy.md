Installation Guide in English
Installation Guide for X-monitoring Project with nohup
This guide will help you install and run the X-monitoring project on a Linux server using nohup. The project is assumed to be uploaded as a ZIP file on GitHub.
Prerequisites
Operating System: Linux (e.g., Ubuntu 20.04 or higher)
Root or sudo access
Internet connection
Tools: unzip, python3, pip
Installation Steps
Update System
Log into your server:
ssh user@your_server_ip
Update the system:
sudo apt update && sudo apt upgrade -y
Install Required Tools
Install Python and necessary tools:
sudo apt install python3 python3-pip unzip -y
Download Project from GitHub
Copy the ZIP file download link from GitHub (e.g., from Releases or "Download ZIP").
Download the file (replace URL with the actual link):
wget https://github.com/username/repository/releases/download/v1.0/X-monitoring.zip -O /tmp/X-monitoring.zip
Extract the ZIP File
Extract the file to a directory (e.g., /opt):
sudo unzip /tmp/X-monitoring.zip -d /opt/X-monitoring
cd /opt/X-monitoring
Install Dependencies
Navigate to the project directory and install dependencies:
sudo pip3 install -r requirements.txt
Run Project with nohup
Run the project in the background with nohup:
nohup python3 app.py > app.log 2>&1 &
Note the process ID or check it with:
ps aux | grep python3
Firewall Configuration (Optional)
If a firewall is active, allow port 5000:
sudo ufw allow 5000/tcp
Access the Project
Open a browser and go to:
http://your_server_ip:5000
Login with default credentials:
Username: admin
Password: admin123
Notes
Logs: Check the output in app.log:
cat app.log
Stop the Project: Find and kill the process:
kill -9 <process_id>
Troubleshooting
If port 5000 is in use, change the port in app.py (e.g., to 5001)