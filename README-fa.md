# Server Monitoring Tool
<div align="center"><img src="https://uploadkon.ir/uploads/dacc26_25Screenshot-1.jpg" width="300"></div>
<div align="center"><img src="https://uploadkon.ir/uploads/456f26_25Screenshot-2.jpg" width="300"></div>
<div align="center"><img src="https://uploadkon.ir/uploads/fe9f26_25Screenshot-3.jpg" width="300"></div>


راهنمای نصب به زبان فارسی
راهنمای نصب پروژه X-monitoring با nohup
این راهنما شما را برای نصب و اجرای پروژه X-monitoring روی سرور لینوکس با استفاده از nohup راهنمایی می‌کند. فرض بر این است که پروژه به صورت فایل زیپ در GitHub آپلود شده است.
پیش‌نیازها
سیستم‌عامل: لینوکس (مانند Ubuntu 20.04 یا بالاتر)
دسترسی root یا sudo
اتصال به اینترنت
ابزارها: unzip, python3, pip
مراحل نصب

1.به‌روزرسانی سیستم

-سیستم را به‌روزرسانی کنید:
```
sudo apt update && sudo apt upgrade -y
```
2.نصب ابزارهای لازم
-پایتون و ابزارهای مورد نیاز را نصب کنید:
```
sudo apt install python3 python3-pip unzip -y
```
3.دانلود پروژه از GitHub
-لینک دانلود فایل زیپ را از GitHub کپی کنید (مثلاً از بخش Releases یا با کلیک روی "Download ZIP").
-فایل را دانلود کنید:
```
wget https://github.com/unknown-sir/X-monitoring/X-monitoring.zip -O /tmp/X-monitoring.zip
```
4.باز کردن فایل زیپ
-فایل را در دایرکتوری دلخواه (مثلاً /opt) باز کنید:
```
sudo unzip /tmp/X-monitoring.zip -d /opt/X-monitoring
cd /opt/X-monitoring
```
**با دستور زیر در کد
توکن ربات تلگرام ، آیدی عددی ادمین در تلگرام ، اطلاعات smtp خود را وارد کنید**
```
nano app.py
```
5.نصب وابستگی‌ها
-به دایرکتوری پروژه بروید و وابستگی‌ها را نصب کنید:
```
sudo pip3 install -r requirements.txt
```
6.اجرای پروژه با nohup
-پروژه را با nohup اجرا کنید تا در پس‌زمینه کار کند:
```
nohup python3 app.py > app.log 2>&1 &
```
7.دسترسی به پروژه

در مرورگر به آدرس زیر بروید:

<b>http://your_server_ip:5000</b>

ورود با اطلاعات پیش‌فرض:

نام کاربری: <b>admin</b>
رمز عبور: <b>admin123</b>


 توضیحات <a href="https://github.com/Unknown-sir/X-monitoring/blob/main/agent-package.md"> نصب پکیج های سرورهای ایجنت </a>
