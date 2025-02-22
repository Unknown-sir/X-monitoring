# Server Monitoring Tool
<div align="center"><img src="https://uploadkon.ir/uploads/dd5320_25Screenshot-15.jpg" width="300"></div>
<div align="center"><img src="https://uploadkon.ir/uploads/fc8c20_25Screenshot-16.jpg" width="300"></div>
<div align="center"><img src="https://uploadkon.ir/uploads/493020_25Screenshot-17.jpg" width="300"></div>
<div align="center"><br>

برای توضیحات <a href="https://github.com/Unknown-sir/X-monitoring/blob/main/README-fa.md"> فارسی اینجا بزنید </a>
</div>

Installation Guide in English
Installation Guide for X-monitoring Project with nohup
This guide will help you install and run the X-monitoring project on a Linux server using nohup. The project is assumed to be uploaded as a ZIP file on GitHub.
Prerequisites
Operating System: Linux (e.g., Ubuntu 20.04 or higher)
Root or sudo access
Internet connection
Tools: unzip, python3, pip
Installation Steps

1.Update System

-Update the system:
```
sudo apt update && sudo apt upgrade -y
```
2.Install Required Tools
-Install Python and necessary tools:
```
sudo apt install python3 python3-pip unzip -y
```
3.Download Project from GitHub
-Copy the ZIP file download link from GitHub (e.g., from Releases or "Download ZIP").

-Download the file:
```
wget https://github.com/unknown-sir/X-monitoring/X-monitoring.zip -O /tmp/X-monitoring.zip
```
4.Extract the ZIP File
-Extract the file to a directory (e.g., /opt):
```
sudo unzip /tmp/X-monitoring.zip -d /opt/X-monitoring
cd /opt/X-monitoring
```
5.Install Dependencies
-Navigate to the project directory and install dependencies:
```
sudo pip3 install -r requirements.txt
```
6.Run Project with nohup
-Run the project in the background with nohup:
```
nohup python3 app.py > app.log 2>&1 &
```
7.Access the Project

Open a browser and go to:

<b>http://your_server_ip:5000</b>

Login with default credentials:

Username: <b>admin</b>
Password: <b>admin123</b>

 توضیحات <a href="https://github.com/Unknown-sir/X-monitoring/blob/main/agent-package.md"> نصب پکیج های سرورهای ایجنت </a>
