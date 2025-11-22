#!/usr/bin/env python3
"""
Telegram "Get 2FA" bot that mimics the UI in your screenshot.
- /get2fa starts an interaction asking for the secret.
- Accepts BASE32 secrets or otpauth:// URIs.
- Replies with current TOTP code, seconds remaining, shows the secret formatted.
- Stateless: secrets are NOT stored on disk. Short-lived ephemeral tokens used for Refresh.
"""

import os
import time
import uuid
import logging
import re
from typing import Tuple
from dotenv import load_dotenv
import pyotp
from telegram import (
    Update,
    InlineKeyboardMarkup, InlineKeyboardButton,
    ReplyKeyboardMarkup, KeyboardButton
)
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters, ConversationHandler
)

# ---- Config ----
load_dotenv()
TG_TOKEN = os.getenv("TG_TOKEN")
if not TG_TOKEN:
    raise SystemExit("Please set TG_TOKEN in .env")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ---- Ephemeral storage (token -> (secret, ts, label)) ----
EPHEMERAL: dict[str, tuple[str, float, str]] = {}
EPHEMERAL_TTL = 300  # seconds

def cleanup():
    now = time.time()
    for k in list(EPHEMERAL.keys()):
        if now - EPHEMERAL[k][1] > EPHEMERAL_TTL:
            del EPHEMERAL[k]

def store_ephemeral(secret: str, label: str = "") -> str:
    cleanup()
    token = uuid.uuid4().hex
    EPHEMERAL[token] = (secret, time.time(), label)
    return token

def get_ephemeral(token: str):
    cleanup()
    return EPHEMERAL.get(token)

# ---- Helpers ----
BASE32_RE = re.compile(r'^[A-Z2-7]+=*$', re.I)

def try_parse_secret(text: str):
    txt = text.strip()
    # otpauth URI
    if txt.lower().startswith("otpauth://"):
        try:
            obj = pyotp.parse_uri(txt)
            return obj.secret, getattr(obj, "name", "") or ""
        except Exception:
            return None
    # otherwise assume base32-like secret (allow spaces)
    cand = txt.replace(" ", "")
    if BASE32_RE.fullmatch(cand):
        return cand, ""
    return None

def compute_totp(secret: str) -> tuple[str,int]:
    totp = pyotp.TOTP(secret)
    code = totp.now()
    interval = getattr(totp, "interval", 30)
    rem = int(interval - (time.time() % interval))
    return code, rem

def pretty_secret(secret: str, group=4) -> str:
    s = secret.strip().upper().replace(" ", "")
    # keep padding '=' at end separate
    pad = ""
    if s.endswith("="):
        # move all trailing '=' to pad
        i = len(s) - 1
        while i >= 0 and s[i] == "=":
            i -= 1
        pad = s[i+1:]
        s = s[:i+1]
    parts = [s[i:i+group] for i in range(0, len(s), group)]
    if pad:
        parts.append(pad)
    return " ".join(parts)

# ---- Conversation states ----
ASK_SECRET = 1

# ---- Handlers ----
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Salam! Use /get2fa to start.\n"
        "Send a BASE32 secret (e.g. JBSWY3DPEHPK3PXP) or an otpauth:// URI."
    )

async def get2fa_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    kb = ReplyKeyboardMarkup([[KeyboardButton("Cancel")]], one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text(
        "🔒 2FA Authenticator\n\n"
        "আপনার 2FA Secret Key পাঠান।\n\n"
        "📄 Format:\nABCD EFGH IGK84 LM44 NSER3 LM44\n\n"
        "বাতিল করতে /cancel বা Cancel বোতাম চাপুন।",
        reply_markup=kb
    )
    return ASK_SECRET

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Cancelled. Use /get2fa to start again.")
    return ConversationHandler.END

async def receive_secret(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    parsed = try_parse_secret(text)
    if not parsed:
        await update.message.reply_text(
            "Invalid secret format. দিন BASE32 বা otpauth:// URI।\n"
            "উদাহরণ: JBSWY3DPEHPK3PXP\n"
            "আবার চেষ্টা করুন বা /cancel দিন."
        )
        return ASK_SECRET

    secret, label = parsed
    try:
        code, rem = compute_totp(secret)
    except Exception:
        await update.message.reply_text("Secret থেকে কোড জেনারেট করা গেল না — ভুল ফরম্যাট হতে পারে।")
        return ASK_SECRET

    token = store_ephemeral(secret, label)
    kb = InlineKeyboardMarkup.from_row([
        InlineKeyboardButton("🔁 Refresh", callback_data=f"refresh:{token}"),
        InlineKeyboardButton("🗑️ Remove", callback_data=f"expire:{token}")
    ])

    pretty = pretty_secret(secret)
    label_text = f"*{label}*\n" if label else ""
    # Reply with styling similar to your screenshot
    msg = (
        "🔐 *2FA কোড জেনারেট হয়েছে!*\n\n"
        f"🔐 কোড: `{code}`\n"
        f"⏱️ মেয়াদ: *{rem} সেকেন্ড*\n\n"
        f"💡 Google Authenticator এ এই কোড ব্যবহার করুন।\n\n"
        f"📘 Secret Key: `{pretty}`"
    )
    # remove reply keyboard (set reply_markup=kb which is inline)
    await update.message.reply_markdown(msg, reply_markup=kb)
    return ConversationHandler.END

async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data or ""
    if data.startswith("refresh:"):
        token = data.split(":",1)[1]
        rec = get_ephemeral(token)
        if not rec:
            await q.edit_message_text("This ephemeral secret expired or was removed. Send the secret again to get a new code.")
            return
        secret, ts, label = rec
        try:
            code, rem = compute_totp(secret)
        except Exception:
            await q.edit_message_text("Secret invalid now.")
            return
        pretty = pretty_secret(secret)
        label_text = f"*{label}*\n" if label else ""
        msg = (
            "🔐 *2FA কোড (refreshed)*\n\n"
            f"🔐 কোড: `{code}`\n"
            f"⏱️ মেয়াদ: *{rem} সেকেন্ড*\n\n"
            f"📘 Secret Key: `{pretty}`"
        )
        kb = InlineKeyboardMarkup.from_row([
            InlineKeyboardButton("🔁 Refresh", callback_data=f"refresh:{token}"),
            InlineKeyboardButton("🗑️ Remove", callback_data=f"expire:{token}")
        ])
        await q.edit_message_text(msg, parse_mode="Markdown", reply_markup=kb)
    elif data.startswith("expire:"):
        token = data.split(":",1)[1]
        if token in EPHEMERAL:
            del EPHEMERAL[token]
        await q.edit_message_text("Ephemeral secret removed. Send it again if you want a new code.")
    else:
        await q.edit_message_text("Unknown action.")

# ---- Main ----
def main():
    app = ApplicationBuilder().token(TG_TOKEN).build()

    conv = ConversationHandler(
        entry_points=[CommandHandler("get2fa", get2fa_start)],
        states={
            ASK_SECRET: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_secret)]
        },
        fallbacks=[CommandHandler("cancel", cancel), MessageHandler(filters.Regex(r'(?i)^cancel$'), cancel)],
        conversation_timeout=180
    )

    app.add_handler(conv)
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CallbackQueryHandler(callback_handler))

    log.info("Bot ready. Run with polling.")
    app.run_polling()

if __name__ == "__main__":
    main()
