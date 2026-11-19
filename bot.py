# -*- coding: utf-8 -*-
"""
ربات تلگرام آیرون کور کلود (IronCore Cloud) با پشتیبانی پیش‌فرض از پروکسی SOCKS5 ایران
و سیستم تایید/رد یک‌بارمصرف فیش‌های واریزی مشترک با پنل وب
"""
import app as cc_app

if __name__ == "__main__":
    cc_app.init_db()
    print("🤖 ربات تلگرام آیرون کور کلود با پروکسی SOCKS5 فعال شد...")
    cc_app.telegram_dynamic_poller()
