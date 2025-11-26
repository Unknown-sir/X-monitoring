
import os
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ConversationHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters
from sqlalchemy import select, update
from db import SessionLocal
from models import Server, Event

ADMINS = {int(x) for x in os.getenv("BOT_ADMINS","").split(",") if x}
BOT_OWNER_ID = int(os.getenv("BOT_OWNER_ID", "0") or 0)

def is_owner(user_id: int) -> bool:
    """
    Only the main bot owner (BOT_OWNER_ID) can change traffic limits.
    If BOT_OWNER_ID is not set, fall back to regular admin permissions.
    """
    if BOT_OWNER_ID == 0:
        return is_admin(user_id)
    return user_id == BOT_OWNER_ID

async def require_owner(update: Update):
    await update.message.reply_text("فقط مدیر اصلی ربات می‌تواند حد مجاز ترافیک سرورها را تغییر دهد.")

SELECT_SERVER, SET_VALUE, FIELD_SELECT, INPUT_VALUE = range(4)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "XMonitor Bot\n"
        "/list — لیست سرورها\n"
        "/setlimit — تنظیم حد ترافیک (فقط برای Owner)\n"
        "/edit — ویرایش تنظیمات سرور\n"
        "/events — آخرین رخدادها"
    )

def is_admin(user_id: int) -> bool:
    return user_id in ADMINS

async def require_admin(update: Update):
    await update.message.reply_text("دسترسی ندارید.")

async def list_servers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await require_admin(update)
    db = SessionLocal()
    rows = db.execute(select(Server.id, Server.name, Server.ip, Server.traffic_usage, Server.traffic_limit, Server.active)).all()
    db.close()
    txt = "\n".join([f"{r[0]} • {r[1]} ({r[2]}) — {r[3]:.2f}/{r[4] or 0} GiB — {'ON' if r[5] else 'OFF'}" for r in rows]) or "هیچ سروری نیست."
    await update.message.reply_text(txt)

async def setlimit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Only the main bot owner is allowed to change traffic limits
    if not is_owner(update.effective_user.id):
        return await require_owner(update)
    db = SessionLocal(); servers = db.execute(select(Server.id, Server.name)).all(); db.close()
    kb = [[InlineKeyboardButton(f"{sid} • {name}", callback_data=f"sl:{sid}")] for sid,name in servers]
    await update.message.reply_text("یک سرور را انتخاب کن:", reply_markup=InlineKeyboardMarkup(kb))
    return SELECT_SERVER

async def on_select_server(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    sid = int(q.data.split(":")[1])
    context.user_data["sid"] = sid
    await q.edit_message_text(f"حد جدید (GiB) را بفرست:")
    return SET_VALUE

async def on_set_value(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        val = float(update.message.text)
    except:
        return await update.message.reply_text("عدد معتبر بفرست.")
    sid = context.user_data["sid"]
    db = SessionLocal()
    db.execute(update(Server).where(Server.id==sid).values(traffic_limit=val))
    db.commit(); db.close()
    await update.message.reply_text(f"حد ترافیک سرور {sid} روی {val} GiB تنظیم شد.")
    return ConversationHandler.END

FIELDS = {
    "name": "نام",
    "ip": "IP",
    "username": "کاربر SSH",
    "password": "پسورد SSH",
    "reset_date": "تاریخ ریست (YYYY-MM)"
}

async def edit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await require_admin(update)
    db = SessionLocal(); servers = db.execute(select(Server.id, Server.name)).all(); db.close()
    kb = [[InlineKeyboardButton(f"{sid} • {name}", callback_data=f"ed:{sid}")] for sid,name in servers]
    await update.message.reply_text("یک سرور را انتخاب کن:", reply_markup=InlineKeyboardMarkup(kb))
    return SELECT_SERVER

async def on_select_server_edit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    sid = int(q.data.split(":")[1])
    context.user_data["sid"] = sid
    kb = [[InlineKeyboardButton(label, callback_data=f"field:{key}")] for key,label in FIELDS.items()]
    await q.edit_message_text("کدام فیلد را ویرایش کنم؟", reply_markup=InlineKeyboardMarkup(kb))
    return FIELD_SELECT

async def on_field_selected(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query; await q.answer()
    key = q.data.split(":")[1]
    context.user_data["field"] = key
    await q.edit_message_text(f"مقدار جدید ({FIELDS[key]}) را بفرست:")
    return INPUT_VALUE

async def on_value_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    sid = context.user_data["sid"]; field = context.user_data["field"]; val = update.message.text
    db = SessionLocal()
    db.execute(update(Server).where(Server.id==sid).values({field: val}))
    db.commit(); db.close()
    await update.message.reply_text(f"فیلد {field} برای سرور {sid} تنظیم شد.")
    return ConversationHandler.END

async def events(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return await require_admin(update)
    db = SessionLocal()
    evs = db.query(Event).order_by(Event.created_at.desc()).limit(20).all()
    db.close()
    if not evs:
        return await update.message.reply_text("رخدادی نیست.")
    txt = "\n".join([f"{e.created_at:%Y-%m-%d %H:%M} [{e.level}] {e.message}" for e in evs])
    await update.message.reply_text(txt)

def main():
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("BOT_TOKEN env not set")
    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("list", list_servers))
    app.add_handler(CommandHandler("events", events))

    app.add_handler(ConversationHandler(
        entry_points=[CommandHandler("setlimit", setlimit)],
        states={
            SELECT_SERVER: [CallbackQueryHandler(on_select_server, pattern=r"^sl:\d+$")],
            SET_VALUE: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_set_value)]
        },
        fallbacks=[]
    ))

    app.add_handler(ConversationHandler(
        entry_points=[CommandHandler("edit", edit)],
        states={
            SELECT_SERVER: [CallbackQueryHandler(on_select_server_edit, pattern=r"^ed:\d+$")],
            FIELD_SELECT: [CallbackQueryHandler(on_field_selected, pattern=r"^field:")],
            INPUT_VALUE: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_value_input)]
        },
        fallbacks=[]
    ))

    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
