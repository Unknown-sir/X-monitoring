راهنمای نصب به زبان فارسی
راهنمای نصب پروژه X-monitoring با nohup
این راهنما شما را برای نصب و اجرای پروژه X-monitoring روی سرور لینوکس با استفاده از nohup راهنمایی می‌کند. فرض بر این است که پروژه به صورت فایل زیپ در GitHub آپلود شده است.
پیش‌نیازها
سیستم‌عامل: لینوکس (مانند Ubuntu 20.04 یا بالاتر)
دسترسی root یا sudo
اتصال به اینترنت
ابزارها: unzip, python3, pip
مراحل نصب
به‌روزرسانی سیستم
وارد سرور شوید:
ssh user@your_server_ip
سیستم را به‌روزرسانی کنید:
sudo apt update && sudo apt upgrade -y
نصب ابزارهای لازم
پایتون و ابزارهای مورد نیاز را نصب کنید:
sudo apt install python3 python3-pip unzip -y
دانلود پروژه از GitHub
لینک دانلود فایل زیپ را از GitHub کپی کنید (مثلاً از بخش Releases یا با کلیک روی "Download ZIP").
فایل را دانلود کنید:
'''
wget https://github.com/username/repository/releases/download/v1.0/X-monitoring.zip -O /tmp/X-monitoring.zip
'''
باز کردن فایل زیپ
فایل را در دایرکتوری دلخواه (مثلاً /opt) باز کنید:
sudo unzip /tmp/X-monitoring.zip -d /opt/X-monitoring
cd /opt/X-monitoring
نصب وابستگی‌ها
به دایرکتوری پروژه بروید و وابستگی‌ها را نصب کنید:
sudo pip3 install -r requirements.txt
اجرای پروژه با nohup
پروژه را با nohup اجرا کنید تا در پس‌زمینه کار کند:
nohup python3 app.py > app.log 2>&1 &
شماره پروسه را یادداشت کنید یا با این دستور بررسی کنید:
ps aux | grep python3
تنظیم فایروال (اختیاری)
اگر فایروال دارید، پورت 5000 را باز کنید:
sudo ufw allow 5000/tcp
دسترسی به پروژه
در مرورگر به آدرس زیر بروید:
http://your_server_ip:5000
ورود با اطلاعات پیش‌فرض:
نام کاربری: admin
رمز عبور: admin123
نکات
لاگ‌ها: برای بررسی خروجی، فایل app.log را ببینید:
cat app.log
توقف پروژه: پروسه را پیدا کنید و ببندید:
kill -9 <process_id>
عیب‌یابی
اگر پورت 5000 اشغال بود، در app.py پورت را تغییر دهید (مثلاً به 5001).