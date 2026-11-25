# -*- coding: utf-8 -*-
"""
بوت تيليجرام لتوقيع وتوزيع ملفات IPA عبر رابط OTA (itms-services)

التثبيت على السيرفر:
    pip install "python-telegram-bot[job-queue]" aiohttp cryptography
    + تثبيت zsign على السيرفر (وضعه في PATH أو غيّر ZSIGN_PATH)
    + openssl (لقراءة تاريخ انتهاء البروفايل)
    + نطاق HTTPS (توفره الاستضافة تلقائياً عند النشر بـ Docker)

التشغيل:
    python bot.py
"""

import asyncio
import html
import os
import plistlib
import secrets
import sqlite3
import subprocess
import zipfile
from datetime import datetime, timedelta
from functools import wraps

from aiohttp import web
from cryptography.fernet import Fernet
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler,
                          ContextTypes, MessageHandler, filters)

# ╔══════════════════════════════════════════════════════════╗
# ║                  الإعدادات (عدّل هنا)                      ║
# ╚══════════════════════════════════════════════════════════╝
BOT_TOKEN = os.getenv("BOT_TOKEN", "9064582501:AAGZEZyw4iKBoGb77EuUePIrip9CWjnSN6c")   # ← ضع توكن البوت هنا (من @BotFather)
OWNER_ID = int(os.getenv("OWNER_ID", "7788474071"))                # ← ضع رقمك هنا (من @userinfobot)

# ─── لا تحتاج تعديل ما بعد هذا السطر (إلا إذا أردت) ───
def _detect_base_url():
    """يكتشف رابط الموقع تلقائياً من متغيرات الاستضافة، أو من BASE_URL."""
    u = os.getenv("BASE_URL")
    if u:
        return u.rstrip("/")
    for var in ("RENDER_EXTERNAL_URL", "KOYEB_PUBLIC_DOMAIN",
                "RAILWAY_PUBLIC_DOMAIN", "SPACE_HOST"):
        v = os.getenv(var)
        if v:
            return (v if v.startswith("http") else "https://" + v).rstrip("/")
    return "https://yourdomain.com"   # ← ضع رابط استضافتك هنا إن لم يُكتشف تلقائياً

BASE_URL = _detect_base_url()
PORT = int(os.getenv("PORT", "8080"))
ZSIGN_PATH = os.getenv("ZSIGN_PATH", "zsign")
DATA_DIR = os.getenv("DATA_DIR", "data")      # مجلد البيانات (إن وفّرت الاستضافة قرصاً دائماً وجّهه إليه)
STORAGE_DIR = f"{DATA_DIR}/storage"
DB_FILE = f"{DATA_DIR}/bot.db"
KEY_FILE = f"{DATA_DIR}/.secret.key"
EXPIRY_CHECK_HOURS = 6
FREE_ACCOUNT_DAYS = 7

# ═══════════════════ نصوص الواجهة (عدّل كما تشاء) ═══════════════════
T = {
    "welcome": "أهلاً بك 👋\nاختر من القائمة:",
    "no_perm": "⛔ ليست لديك صلاحية",
    "send_ipa": "📱 أرسل الآن ملف الـ IPA:",
    "not_ipa": "أرسل ملف بصيغة .ipa فقط",
    "no_accounts": "⚠️ لا توجد حسابات صالحة حالياً. تواصل مع المشرف.",
    "choose_account": "اختر الحساب للتوقيع:",
    "signing": "⏳ جاري التوقيع...",
    "sign_fail": "❌ فشل التوقيع:\n",
    "signed_ok": "✅ تم التوقيع!\nافتح الرابط من الآيفون (Safari) ثم اضغط تثبيت:",
}
# ═══════════════════════════════════════════════════════════════

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(f"{STORAGE_DIR}/ipa_original", exist_ok=True)
os.makedirs(f"{STORAGE_DIR}/ipa_signed", exist_ok=True)
os.makedirs(f"{STORAGE_DIR}/certs", exist_ok=True)

# ───────────────────────── التشفير ─────────────────────────
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
    os.chmod(KEY_FILE, 0o600)
fernet = Fernet(open(KEY_FILE, "rb").read())


def enc(s: str) -> str:
    return fernet.encrypt(s.encode()).decode()


def dec(s: str) -> str:
    return fernet.decrypt(s.encode()).decode()


# ───────────────────────── قاعدة البيانات ─────────────────────────
db = sqlite3.connect(DB_FILE)
db.row_factory = sqlite3.Row
db.executescript("""
CREATE TABLE IF NOT EXISTS admins (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    added_by INTEGER,
    added_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    p12_path TEXT,
    p12_pass TEXT,
    profile_path TEXT,
    expires_at TEXT,
    added_by INTEGER
);
CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    bundle_id TEXT,
    version TEXT,
    orig_path TEXT,
    signed_path TEXT,
    token TEXT UNIQUE,
    account_id INTEGER,
    signed_at TEXT,
    notified INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    at TEXT DEFAULT CURRENT_TIMESTAMP
);
""")
db.commit()


def log(uid, action):
    db.execute("INSERT INTO logs (user_id, action) VALUES (?,?)", (uid, action))
    db.commit()


def now():
    return datetime.utcnow()


def days_left(expires_at: str) -> int:
    return (datetime.fromisoformat(expires_at) - now()).days


def is_valid(row) -> bool:
    return datetime.fromisoformat(row["expires_at"]) > now()


# ───────────────────────── الأدوار ─────────────────────────
def is_admin(uid):
    return db.execute("SELECT 1 FROM admins WHERE user_id=?", (uid,)).fetchone() is not None


def role(uid):
    if uid == OWNER_ID:
        return "owner"
    if is_admin(uid):
        return "admin"
    return "user"


def require(*allowed):
    """تحقق من الصلاحية داخل كل دالة (لا تكتفِ بإخفاء الأزرار)."""
    def deco(fn):
        @wraps(fn)
        async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE, *a, **kw):
            q = update.callback_query
            uid = q.from_user.id if q else update.effective_user.id
            if role(uid) not in allowed:
                if q:
                    await q.answer(T["no_perm"], show_alert=True)
                return
            return await fn(update, ctx, *a, **kw)
        return wrapper
    return deco


# ───────────────────────── القوائم ─────────────────────────
def btn(text, data):
    return InlineKeyboardButton(text, callback_data=data)


def main_menu(uid):
    r = role(uid)
    rows = [
        [btn("📱 رفع IPA جديد", "upload")],
        [btn("📂 تطبيقاتي", "apps")],
    ]
    if r in ("owner", "admin"):
        rows.append([btn("👤 إدارة الحسابات", "accounts")])
    if r == "owner":
        rows.append([btn("🛡 إدارة المشرفين", "admins")])
    return InlineKeyboardMarkup(rows)


def back_home():
    return InlineKeyboardMarkup([[btn("🔙 القائمة الرئيسية", "home")]])


# ───────────────────────── أدوات IPA والتوقيع ─────────────────────────
def read_ipa_info(path):
    """يقرأ الاسم والـ bundle id والإصدار من داخل IPA."""
    try:
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                parts = n.split("/")
                if len(parts) == 3 and parts[0] == "Payload" and parts[2] == "Info.plist" \
                        and parts[1].endswith(".app"):
                    info = plistlib.loads(z.read(n))
                    return {
                        "name": info.get("CFBundleDisplayName") or info.get("CFBundleName") or "App",
                        "bundle_id": info.get("CFBundleIdentifier", "unknown"),
                        "version": str(info.get("CFBundleShortVersionString", "1.0")),
                    }
    except Exception:
        pass
    return {"name": os.path.basename(path), "bundle_id": "unknown", "version": "1.0"}


def profile_expiry(profile_path):
    """يقرأ تاريخ انتهاء mobileprovision (يحتاج openssl). عند الفشل: الآن + 7 أيام."""
    try:
        out = subprocess.run(
            ["openssl", "smime", "-inform", "der", "-verify", "-noverify", "-in", profile_path],
            capture_output=True, check=True).stdout
        exp = plistlib.loads(out).get("ExpirationDate")
        if exp:
            return exp.replace(tzinfo=None)
    except Exception:
        pass
    return now() + timedelta(days=FREE_ACCOUNT_DAYS)


async def run_zsign(ipa, p12, password, profile, out):
    proc = await asyncio.create_subprocess_exec(
        ZSIGN_PATH, "-k", p12, "-p", password, "-m", profile, "-o", out, ipa,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    so, se = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError((se or so).decode(errors="ignore")[-500:])


async def sign_app(app_id: int, account_id: int):
    """يوقّع التطبيق بالحساب المحدد (ويُستخدم أيضاً لتغيير الحساب)."""
    app = db.execute("SELECT * FROM apps WHERE id=?", (app_id,)).fetchone()
    acc = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    out = f"{STORAGE_DIR}/ipa_signed/{app['token']}.ipa"
    await run_zsign(app["orig_path"], acc["p12_path"], dec(acc["p12_pass"]),
                    acc["profile_path"], out)
    db.execute("UPDATE apps SET signed_path=?, account_id=?, signed_at=?, notified=0 WHERE id=?",
               (out, account_id, now().isoformat(), app_id))
    db.commit()


def install_page_url(token):
    return f"{BASE_URL}/install/{token}"


# ───────────────────────── خادم الويب (OTA) ─────────────────────────
async def h_ipa(request):
    token = request.match_info["token"]
    row = db.execute("SELECT signed_path FROM apps WHERE token=?", (token,)).fetchone()
    if not row or not row["signed_path"] or not os.path.exists(row["signed_path"]):
        raise web.HTTPNotFound()
    return web.FileResponse(row["signed_path"], headers={
        "Content-Type": "application/octet-stream"})


async def h_manifest(request):
    token = request.match_info["token"]
    row = db.execute("SELECT * FROM apps WHERE token=?", (token,)).fetchone()
    if not row:
        raise web.HTTPNotFound()
    data = plistlib.dumps({"items": [{
        "assets": [{"kind": "software-package", "url": f"{BASE_URL}/ipa/{token}.ipa"}],
        "metadata": {"bundle-identifier": row["bundle_id"], "bundle-version": row["version"],
                     "kind": "software", "title": row["name"]}}]})
    return web.Response(body=data, content_type="text/xml")


async def h_install(request):
    token = request.match_info["token"]
    row = db.execute("SELECT * FROM apps WHERE token=?", (token,)).fetchone()
    if not row:
        raise web.HTTPNotFound()
    link = f"itms-services://?action=download-manifest&url={BASE_URL}/manifest/{token}.plist"
    page = f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(row['name'])}</title>
<style>body{{font-family:-apple-system,sans-serif;text-align:center;padding:60px 20px}}
a{{display:inline-block;background:#007aff;color:#fff;padding:16px 36px;border-radius:14px;
text-decoration:none;font-size:20px}}</style></head><body>
<h2>{html.escape(row['name'])}</h2><p>الإصدار {html.escape(row['version'])}</p>
<a href="{link}">⬇️ تثبيت</a></body></html>"""
    return web.Response(text=page, content_type="text/html")


async def h_health(request):
    return web.Response(text="OK")


async def start_web(app: Application):
    web_app = web.Application()
    web_app.add_routes([
        web.get("/ipa/{token}.ipa", h_ipa),
        web.get("/manifest/{token}.plist", h_manifest),
        web.get("/install/{token}", h_install),
        web.get("/", h_health),
    ])
    runner = web.AppRunner(web_app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start()


# ───────────────────────── المعالجات: عام ─────────────────────────
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text(T["welcome"], reply_markup=main_menu(update.effective_user.id))


async def show_home(q, ctx):
    ctx.user_data.clear()
    await q.edit_message_text(T["welcome"], reply_markup=main_menu(q.from_user.id))


# ───────────────────────── رفع IPA والتوقيع ─────────────────────────
def accounts_buttons(prefix, valid_only=True):
    rows = []
    for a in db.execute("SELECT * FROM accounts").fetchall():
        if valid_only and not is_valid(a):
            continue
        rows.append([btn(f"{a['name']} ({max(days_left(a['expires_at']), 0)} يوم)",
                         f"{prefix}{a['id']}")])
    return rows


async def receive_ipa(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if not doc or not (doc.file_name or "").lower().endswith(".ipa"):
        return await update.message.reply_text(T["not_ipa"])
    msg = await update.message.reply_text("⬇️ جاري تحميل الملف...")
    uid = update.effective_user.id
    path = f"{STORAGE_DIR}/ipa_original/{uid}_{secrets.token_hex(4)}_{doc.file_name}"
    f = await doc.get_file()
    await f.download_to_drive(path)
    info = read_ipa_info(path)
    ctx.user_data["pending"] = {"path": path, **info}
    ctx.user_data["state"] = None
    rows = accounts_buttons("sign_")
    if not rows:
        return await msg.edit_text(T["no_accounts"], reply_markup=back_home())
    rows.append([btn("🔙 إلغاء", "home")])
    await msg.edit_text(f"📦 {info['name']} ({info['version']})\n{T['choose_account']}",
                        reply_markup=InlineKeyboardMarkup(rows))


async def do_sign_new(q, ctx, account_id):
    p = ctx.user_data.get("pending")
    if not p:
        return await q.answer("أرسل IPA من جديد", show_alert=True)
    await q.answer()
    await q.edit_message_text(T["signing"])
    token = secrets.token_urlsafe(12)
    cur = db.execute(
        "INSERT INTO apps (user_id,name,bundle_id,version,orig_path,token) VALUES (?,?,?,?,?,?)",
        (q.from_user.id, p["name"], p["bundle_id"], p["version"], p["path"], token))
    db.commit()
    try:
        await sign_app(cur.lastrowid, account_id)
    except Exception as e:
        return await q.edit_message_text(T["sign_fail"] + str(e)[:400], reply_markup=back_home())
    ctx.user_data.pop("pending", None)
    await q.edit_message_text(
        f"{T['signed_ok']}\n\n{install_page_url(token)}", reply_markup=back_home())


# ───────────────────────── تطبيقاتي / إعادة التوقيع / تغيير الحساب ─────────────────────────
async def apps_menu(q, ctx):
    await q.answer()
    rows = []
    for a in db.execute("SELECT * FROM apps WHERE user_id=? ORDER BY id DESC LIMIT 30",
                        (q.from_user.id,)).fetchall():
        rows.append([btn(f"📦 {a['name']} {a['version']}", f"app_{a['id']}")])
    rows.append([btn("🔙 رجوع", "home")])
    await q.edit_message_text("📂 تطبيقاتك:" if len(rows) > 1 else "لا توجد تطبيقات بعد.",
                              reply_markup=InlineKeyboardMarkup(rows))


async def app_detail(q, ctx, app_id):
    await q.answer()
    a = db.execute("SELECT * FROM apps WHERE id=? AND user_id=?", (app_id, q.from_user.id)).fetchone()
    if not a:
        return
    acc = db.execute("SELECT * FROM accounts WHERE id=?", (a["account_id"],)).fetchone()
    status = "—"
    if acc:
        status = f"{acc['name']} — " + (f"{days_left(acc['expires_at'])} يوم" if is_valid(acc) else "منتهي ⚠️")
    text = f"📦 {a['name']} {a['version']}\n🆔 {a['bundle_id']}\n👤 الحساب: {status}\n\n{install_page_url(a['token'])}"
    rows = [[btn("🔄 إعادة التوقيع / تغيير الحساب", f"resign_{a['id']}")],
            [btn("🗑 حذف", f"delapp_{a['id']}")],
            [btn("🔙 رجوع", "apps")]]
    await q.edit_message_text(text, reply_markup=InlineKeyboardMarkup(rows))


async def resign_choose(q, ctx, app_id):
    await q.answer()
    rows = accounts_buttons(f"resignwith_{app_id}_")
    if not rows:
        return await q.edit_message_text(T["no_accounts"], reply_markup=back_home())
    rows.append([btn("🔙 رجوع", f"app_{app_id}")])
    await q.edit_message_text("اختر الحساب الجديد للتوقيع:", reply_markup=InlineKeyboardMarkup(rows))


async def resign_do(q, ctx, app_id, account_id):
    a = db.execute("SELECT * FROM apps WHERE id=? AND user_id=?", (app_id, q.from_user.id)).fetchone()
    if not a:
        return await q.answer("غير موجود", show_alert=True)
    await q.answer()
    await q.edit_message_text(T["signing"])
    try:
        await sign_app(app_id, account_id)
    except Exception as e:
        return await q.edit_message_text(T["sign_fail"] + str(e)[:400], reply_markup=back_home())
    await q.edit_message_text(f"✅ تم التوقيع بالحساب الجديد.\n\n{install_page_url(a['token'])}",
                              reply_markup=back_home())


async def delete_app(q, ctx, app_id):
    a = db.execute("SELECT * FROM apps WHERE id=? AND user_id=?", (app_id, q.from_user.id)).fetchone()
    if a:
        for p in (a["orig_path"], a["signed_path"]):
            if p and os.path.exists(p):
                os.remove(p)
        db.execute("DELETE FROM apps WHERE id=?", (app_id,))
        db.commit()
    await q.answer("🗑 تم الحذف")
    await apps_menu(q, ctx)


# ───────────────────────── إدارة الحسابات (مالك + مشرف) ─────────────────────────
@require("owner", "admin")
async def accounts_menu(update, ctx):
    q = update.callback_query
    await q.answer()
    rows = []
    for a in db.execute("SELECT * FROM accounts").fetchall():
        icon = "✅" if is_valid(a) else "⚠️"
        left = f"{max(days_left(a['expires_at']), 0)} يوم" if is_valid(a) else "منتهي"
        rows.append([btn(f"{icon} {a['name']} ({left})", "noop"),
                     btn("🗑", f"delacc_{a['id']}")])
    rows.append([btn("➕ إضافة حساب", "add_account")])
    rows.append([btn("🔙 رجوع", "home")])
    await q.edit_message_text("👤 الحسابات:", reply_markup=InlineKeyboardMarkup(rows))


@require("owner", "admin")
async def add_account_start(update, ctx):
    q = update.callback_query
    await q.answer()
    ctx.user_data["state"] = "awaiting_p12"
    ctx.user_data["new_acc"] = {}
    await q.edit_message_text(
        "1️⃣ أرسل ملف الشهادة (.p12):",
        reply_markup=InlineKeyboardMarkup([[btn("❌ إلغاء", "accounts")]]))


@require("owner", "admin")
async def delete_account(update, ctx, acc_id):
    q = update.callback_query
    acc = db.execute("SELECT * FROM accounts WHERE id=?", (acc_id,)).fetchone()
    if acc:
        for p in (acc["p12_path"], acc["profile_path"]):
            if p and os.path.exists(p):
                os.remove(p)
        db.execute("DELETE FROM accounts WHERE id=?", (acc_id,))
        db.commit()
        log(q.from_user.id, f"delete_account {acc['name']}")
    await q.answer("🗑 تم حذف الحساب")
    await accounts_menu(update, ctx)


# ───────────────────────── إدارة المشرفين (مالك فقط) ─────────────────────────
@require("owner")
async def admins_menu(update, ctx):
    q = update.callback_query
    await q.answer()
    rows = []
    for a in db.execute("SELECT * FROM admins").fetchall():
        rows.append([btn(f"👥 @{a['username'] or a['user_id']}", "noop"),
                     btn("🗑 إزالة", f"rmadmin_{a['user_id']}")])
    rows.append([btn("➕ إضافة مشرف", "add_admin")])
    rows.append([btn("🔙 رجوع", "home")])
    await q.edit_message_text("🛡 المشرفون:", reply_markup=InlineKeyboardMarkup(rows))


@require("owner")
async def add_admin_start(update, ctx):
    q = update.callback_query
    await q.answer()
    ctx.user_data["state"] = "awaiting_admin"
    await q.edit_message_text(
        "أرسل الآن إحدى هذه:\n• رسالة محوّلة (Forward) من الشخص\n• أو رقمه (Telegram ID)",
        reply_markup=InlineKeyboardMarkup([[btn("❌ إلغاء", "admins")]]))


@require("owner")
async def remove_admin(update, ctx, uid):
    q = update.callback_query
    db.execute("DELETE FROM admins WHERE user_id=?", (uid,))
    db.commit()
    log(q.from_user.id, f"remove_admin {uid}")
    await q.answer("🗑 تمت الإزالة")
    await admins_menu(update, ctx)


# ───────────────────────── موجّه الأزرار ─────────────────────────
async def on_button(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    d = q.data
    uid = q.from_user.id

    if d == "noop":
        return await q.answer()
    if d == "home":
        await q.answer()
        return await show_home(q, ctx)
    if d == "upload":
        await q.answer()
        ctx.user_data["state"] = "awaiting_ipa"
        return await q.edit_message_text(T["send_ipa"], reply_markup=back_home())
    if d == "apps":
        return await apps_menu(q, ctx)
    if d.startswith("app_"):
        return await app_detail(q, ctx, int(d.split("_")[1]))
    if d.startswith("sign_"):
        return await do_sign_new(q, ctx, int(d.split("_")[1]))
    if d.startswith("resignwith_"):
        _, app_id, acc_id = d.split("_")
        return await resign_do(q, ctx, int(app_id), int(acc_id))
    if d.startswith("resign_"):
        return await resign_choose(q, ctx, int(d.split("_")[1]))
    if d.startswith("delapp_"):
        return await delete_app(q, ctx, int(d.split("_")[1]))

    # الحسابات
    if d == "accounts":
        return await accounts_menu(update, ctx)
    if d == "add_account":
        return await add_account_start(update, ctx)
    if d.startswith("delacc_"):
        return await delete_account(update, ctx, int(d.split("_")[1]))

    # المشرفون
    if d == "admins":
        return await admins_menu(update, ctx)
    if d == "add_admin":
        return await add_admin_start(update, ctx)
    if d.startswith("rmadmin_"):
        return await remove_admin(update, ctx, int(d.split("_")[1]))

    await q.answer()


# ───────────────────────── موجّه الرسائل (حسب الحالة) ─────────────────────────
async def on_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    uid = update.effective_user.id
    state = ctx.user_data.get("state")
    r = role(uid)

    # رفع IPA (أي مستخدم)
    if state == "awaiting_ipa":
        return await receive_ipa(update, ctx)

    # إضافة مشرف (مالك فقط)
    if state == "awaiting_admin" and r == "owner":
        origin = getattr(msg, "forward_origin", None)
        if origin is not None and getattr(origin, "sender_user", None):
            u = origin.sender_user
            new_id, uname = u.id, u.username
        elif msg.text and msg.text.strip().isdigit():
            new_id, uname = int(msg.text.strip()), None
        else:
            return await msg.reply_text("لم أستطع التعرف عليه. أرسل الرقم أو حوّل رسالة منه.")
        db.execute("INSERT OR IGNORE INTO admins (user_id, username, added_by) VALUES (?,?,?)",
                   (new_id, uname, uid))
        db.commit()
        log(uid, f"add_admin {new_id}")
        ctx.user_data.clear()
        return await msg.reply_text("✅ تمت إضافة المشرف.", reply_markup=main_menu(uid))

    # إضافة حساب (مالك + مشرف)
    if r in ("owner", "admin") and state in ("awaiting_p12", "awaiting_p12_pass", "awaiting_profile"):
        acc = ctx.user_data.setdefault("new_acc", {})

        if state == "awaiting_p12":
            doc = msg.document
            if not doc or not (doc.file_name or "").lower().endswith(".p12"):
                return await msg.reply_text("أرسل ملف .p12")
            path = f"{STORAGE_DIR}/certs/{secrets.token_hex(6)}.p12"
            await (await doc.get_file()).download_to_drive(path)
            acc["p12"] = path
            acc["name"] = os.path.splitext(doc.file_name)[0]
            ctx.user_data["state"] = "awaiting_p12_pass"
            return await msg.reply_text("2️⃣ أرسل كلمة مرور الشهادة (سأحذف رسالتك فوراً):")

        if state == "awaiting_p12_pass":
            if not msg.text:
                return
            acc["pass"] = msg.text
            try:
                await msg.delete()
            except Exception:
                pass
            ctx.user_data["state"] = "awaiting_profile"
            return await ctx.bot.send_message(uid, "3️⃣ أرسل ملف البروفايل (.mobileprovision):")

        if state == "awaiting_profile":
            doc = msg.document
            if not doc or not (doc.file_name or "").lower().endswith(".mobileprovision"):
                return await msg.reply_text("أرسل ملف .mobileprovision")
            path = f"{STORAGE_DIR}/certs/{secrets.token_hex(6)}.mobileprovision"
            await (await doc.get_file()).download_to_drive(path)
            expiry = profile_expiry(path)
            db.execute(
                "INSERT INTO accounts (name,p12_path,p12_pass,profile_path,expires_at,added_by) "
                "VALUES (?,?,?,?,?,?)",
                (acc["name"], acc["p12"], enc(acc["pass"]), path, expiry.isoformat(), uid))
            db.commit()
            log(uid, f"add_account {acc['name']}")
            ctx.user_data.clear()
            return await msg.reply_text(
                f"✅ تمت إضافة الحساب «{acc['name']}»\nتنتهي بعد {max((expiry - now()).days, 0)} يوم.",
                reply_markup=main_menu(uid))

    # لا حالة نشطة
    await msg.reply_text(T["welcome"], reply_markup=main_menu(uid))


# ───────────────────────── تنبيه انتهاء الصلاحية ─────────────────────────
async def check_expiry(ctx: ContextTypes.DEFAULT_TYPE):
    limit = (now() + timedelta(days=1)).isoformat()
    rows = db.execute(
        "SELECT apps.*, accounts.name AS acc_name FROM apps "
        "JOIN accounts ON accounts.id = apps.account_id "
        "WHERE apps.notified=0 AND accounts.expires_at <= ?", (limit,)).fetchall()
    for a in rows:
        try:
            await ctx.bot.send_message(
                a["user_id"],
                f"⏳ صلاحية توقيع «{a['name']}» (حساب {a['acc_name']}) تنتهي قريباً أو انتهت.",
                reply_markup=InlineKeyboardMarkup([
                    [btn("🔄 إعادة التوقيع / تغيير الحساب", f"resign_{a['id']}")]]))
        except Exception:
            pass
        db.execute("UPDATE apps SET notified=1 WHERE id=?", (a["id"],))
    db.commit()


# ───────────────────────── التشغيل ─────────────────────────
def main():
    app = Application.builder().token(BOT_TOKEN).post_init(start_web).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.ALL & ~filters.COMMAND, on_message))
    app.job_queue.run_repeating(check_expiry, interval=EXPIRY_CHECK_HOURS * 3600, first=60)
    app.run_polling()


if __name__ == "__main__":
    main()
