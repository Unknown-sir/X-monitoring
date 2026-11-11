import os
import re
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    ConversationHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from sqlalchemy import select, update
from db import SessionLocal
from models import Server, EsxiHost, Event
import esxi_manager

ADMINS = {int(x.strip()) for x in os.getenv("BOT_ADMINS", "").split(",") if x.strip().isdigit()}
BOT_OWNER_ID = int(os.getenv("BOT_OWNER_ID", "0") or 0)
RESET_DATE_RE = re.compile(r"^\d{4}-\d{2}$")


def is_admin(user_id: int) -> bool:
    return user_id in ADMINS or (BOT_OWNER_ID != 0 and user_id == BOT_OWNER_ID)


def is_owner(user_id: int) -> bool:
    if BOT_OWNER_ID == 0:
        return is_admin(user_id)
    return user_id == BOT_OWNER_ID


async def require_owner(update: Update):
    await update.message.reply_text("فقط مدیر اصلی ربات می‌تواند این عملیات را انجام دهد.")


async def require_admin(update: Update):
    await update.message.reply_text("دسترسی ندارید.")


SELECT_SERVER, SET_VALUE, FIELD_SELECT, INPUT_VALUE, RECHARGE_VAL = range(5)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 *ربات مدیریت و مانیتورینگ سرورهای مجازی XMonitor*\n\n"
        "/list — لیست سرورها و وضعیت پورت شبکه\n"
        "/recharge — شارژ ترافیک سرور و فعال‌سازی مجدد شبکه\n"
        "/setlimit — تغییر سقف ترافیک (مخصوص Owner)\n"
        "/edit — ویرایش مشخصات سرور\n"
        "/events — لاگ رویدادها و هشدارهای اخیر",
        parse_mode="Markdown",
    )


async def list_servers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await require_admin(update)
    db = SessionLocal()
    try:
        rows = db.execute(
            select(
                Server.id,
                Server.name,
                Server.ip,
                Server.traffic_usage,
                Server.traffic_limit,
                Server.active,
                Server.is_suspended,
            )
        ).all()
    finally:
        db.close()
    lines = []
    for r in rows:
        st = "🔴 مسدود (اتمام ترافیک)" if r[6] else ("🟢 فعال" if r[5] else "⚪ غیرفعال")
        lines.append(f"{r[0]} • {r[1]} ({r[2]})\n   📊 {(r[3] or 0.0):.2f}/{r[4] or 0} GiB | {st}")
    txt = "\n\n".join(lines) or "هیچ سروری نیست."
    await update.message.reply_text(txt)


async def recharge(update: Update, context: ContextTypes.DEFAULT_TYPE):
    db = SessionLocal()
    try:
        servers = db.execute(select(Server.id, Server.name)).all()
    finally:
        db.close()
    if not servers:
        await update.message.reply_text("هیچ سروری ثبت نشده است.")
        return ConversationHandler.END
    kb = [[InlineKeyboardButton(f"{sid} • {name}", callback_data=f"rc:{sid}")] for sid, name in servers]
    await update.message.reply_text("سرور مورد نظر برای شارژ ترافیک را انتخاب کنید:", reply_markup=InlineKeyboardMarkup(kb))
    return SELECT_SERVER


async def on_select_server_recharge(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    sid = int(q.data.split(":")[1])
    context.user_data["recharge_sid"] = sid
    await q.edit_message_text("میزان حجم اضافه برای شارژ سرور را به GiB وارد کنید (مثلاً: 100):")
    return RECHARGE_VAL


async def on_recharge_val(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        amount = float(update.message.text.strip())
        if amount <= 0:
            raise ValueError()
    except ValueError:
        await update.message.reply_text("لطفاً یک عدد مثبت و معتبر ارسال کنید.")
        return RECHARGE_VAL

    sid = context.user_data["recharge_sid"]
    db = SessionLocal()
    try:
        s = db.execute(select(Server).where(Server.id == sid)).scalar_one_or_none()
        if not s:
            await update.message.reply_text("سرور پیدا نشد.")
            return ConversationHandler.END

        new_limit = (s.traffic_limit or 0.0) + amount
        s.traffic_limit = new_limit

        # If suspended on ESXi, automatically unsuspend!
        if s.is_suspended and s.esxi_host_id and s.vmid:
            host = db.execute(select(EsxiHost).where(EsxiHost.id == s.esxi_host_id)).scalar_one_or_none()
            if host:
                esxi_manager.set_vnic_connection(
                    host.ip, host.port, host.username, host.password, s.vmid, connected=True
                )
                s.is_suspended = False

        db.commit()
        await update.message.reply_text(
            f"✅ ترافیک سرور {s.name} با موفقیت به میزان {amount} GiB شارژ شد.\n"
            f"سقف جدید: {new_limit:.2f} GiB\n"
            "پورت شبکه سرور در ESXi آزاد و متصل گردید! 🚀"
        )
    finally:
        db.close()
    return ConversationHandler.END


async def setlimit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update.effective_user.id):
        await require_owner(update)
        return ConversationHandler.END
    db = SessionLocal()
    try:
        servers = db.execute(select(Server.id, Server.name)).all()
    finally:
        db.close()
    if not servers:
        await update.message.reply_text("هیچ سروری ثبت نشده است.")
        return ConversationHandler.END
    kb = [[InlineKeyboardButton(f"{sid} • {name}", callback_data=f"sl:{sid}")] for sid, name in servers]
    await update.message.reply_text("یک سرور را انتخاب کن:", reply_markup=InlineKeyboardMarkup(kb))
    return SELECT_SERVER


async def on_select_server(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_owner(update.effective_user.id):
        await q.edit_message_text("دسترسی ندارید.")
        return ConversationHandler.END
    sid = int(q.data.split(":")[1])
    context.user_data["sid"] = sid
    await q.edit_message_text("حد جدید (GiB) را بفرست:")
    return SET_VALUE


async def on_set_value(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        val = float(update.message.text.strip())
        if val < 0:
            raise ValueError()
    except ValueError:
        await update.message.reply_text("عدد معتبر بفرست.")
        return SET_VALUE

    sid = context.user_data["sid"]
    db = SessionLocal()
    try:
        s = db.execute(select(Server).where(Server.id == sid)).scalar_one_or_none()
        if s:
            s.traffic_limit = val
            if s.is_suspended and val > (s.traffic_usage or 0.0) and s.esxi_host_id and s.vmid:
                host = db.execute(select(EsxiHost).where(EsxiHost.id == s.esxi_host_id)).scalar_one_or_none()
                if host:
                    esxi_manager.set_vnic_connection(
                        host.ip, host.port, host.username, host.password, s.vmid, connected=True
                    )
                    s.is_suspended = False
            db.commit()
    finally:
        db.close()
    await update.message.reply_text(f"حد ترافیک سرور {sid} روی {val} GiB تنظیم شد و شبکه در صورت مسدودی فعال گردید.")
    return ConversationHandler.END


FIELDS = {
    "name": "نام",
    "ip": "IP",
    "username": "کاربر SSH",
    "password": "پسورد SSH",
    "reset_date": "تاریخ ریست (YYYY-MM)",
}


async def edit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await require_admin(update)
        return ConversationHandler.END
    db = SessionLocal()
    try:
        servers = db.execute(select(Server.id, Server.name)).all()
    finally:
        db.close()
    if not servers:
        await update.message.reply_text("هیچ سروری ثبت نشده است.")
        return ConversationHandler.END
    kb = [[InlineKeyboardButton(f"{sid} • {name}", callback_data=f"ed:{sid}")] for sid, name in servers]
    await update.message.reply_text("یک سرور را انتخاب کن:", reply_markup=InlineKeyboardMarkup(kb))
    return SELECT_SERVER


async def on_select_server_edit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(update.effective_user.id):
        await q.edit_message_text("دسترسی ندارید.")
        return ConversationHandler.END
    sid = int(q.data.split(":")[1])
    context.user_data["sid"] = sid
    kb = [[InlineKeyboardButton(label, callback_data=f"field:{key}")] for key, label in FIELDS.items()]
    await q.edit_message_text("کدام فیلد را ویرایش کنم؟", reply_markup=InlineKeyboardMarkup(kb))
    return FIELD_SELECT


async def on_field_selected(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    key = q.data.split(":")[1]
    context.user_data["field"] = key
    await q.edit_message_text(f"مقدار جدید ({FIELDS[key]}) را بفرست:")
    return INPUT_VALUE


async def on_value_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    sid = context.user_data["sid"]
    field = context.user_data["field"]
    val = update.message.text.strip()
    if field == "reset_date" and val and not RESET_DATE_RE.match(val):
        await update.message.reply_text("فرمت تاریخ ریست باید YYYY-MM باشد.")
        return INPUT_VALUE

    db = SessionLocal()
    try:
        db.execute(update(Server).where(Server.id == sid).values({field: val}))
        db.commit()
    finally:
        db.close()
    await update.message.reply_text(f"فیلد {FIELDS[field]} برای سرور {sid} تنظیم شد.")
    return ConversationHandler.END


async def events(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await require_admin(update)
    db = SessionLocal()
    try:
        evs = db.query(Event).order_by(Event.created_at.desc()).limit(20).all()
    finally:
        db.close()
    if not evs:
        return await update.message.reply_text("رخدادی نیست.")
    txt = "\n".join([f"{e.created_at:%Y-%m-%d %H:%M} [{e.level}] {e.message}" for e in evs])
    await update.message.reply_text(txt)


def main():
    token = os.getenv("BOT_TOKEN") or os.getenv("TELEGRAM_TOKEN")
    if not token:
        raise RuntimeError("BOT_TOKEN env not set")
    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("list", list_servers))
    app.add_handler(CommandHandler("events", events))

    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("recharge", recharge)],
            states={
                SELECT_SERVER: [CallbackQueryHandler(on_select_server_recharge, pattern=r"^rc:\d+$")],
                RECHARGE_VAL: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_recharge_val)],
            },
            fallbacks=[],
        )
    )

    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("setlimit", setlimit)],
            states={
                SELECT_SERVER: [CallbackQueryHandler(on_select_server, pattern=r"^sl:\d+$")],
                SET_VALUE: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_set_value)],
            },
            fallbacks=[],
        )
    )

    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("edit", edit)],
            states={
                SELECT_SERVER: [CallbackQueryHandler(on_select_server_edit, pattern=r"^ed:\d+$")],
                FIELD_SELECT: [CallbackQueryHandler(on_field_selected, pattern=r"^field:")],
                INPUT_VALUE: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_value_input)],
            },
            fallbacks=[],
        )
    )

    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
