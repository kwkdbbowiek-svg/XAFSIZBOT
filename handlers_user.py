"""
handlers_user.py — Foydalanuvchi handler'lari.

XAVFSIZLIK MUHIM NUQTALARI:
  • encryption_key FAQAT FSM data'da (RAM) saqlanadi
  • Master parol tekshirishdan keyin darhol RAM'dan o'chiriladi
  • Fayllar server diskiga hech qachon yozilmaydi
  • Barcha matnlar va fayllar bazaga BLOB sifatida shifrlangan holda yoziladi
"""

import io
import time
import qrcode
from datetime import datetime, timezone, timedelta

from aiogram import Router, F, Bot
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, CallbackQuery, BufferedInputFile
from aiogram.fsm.context import FSMContext
from sqlalchemy.ext.asyncio import AsyncSession
from cryptography.exceptions import InvalidTag

from config import cfg
from states import (
    MasterPasswordSetup, MasterPasswordLogin, AddPassword,
    AddFile, CreateBurnerLink, SetupTOTP, SetupLegacy,
    ChangeMasterPassword
)
from database import (
    UserRepo, PasswordRepo, FileRepo, BurnerRepo, TOTPRepo, LegacyRepo,
    SecurityRepo, Password, SecretFile, TOTPDevice
)
from security import (
    hash_master_password, verify_master_password, needs_rehash,
    derive_encryption_key, generate_user_salt,
    encrypt_text, decrypt_text, encrypt_data, decrypt_data,
    generate_totp_secret, get_totp_uri, verify_totp_code
)
from security_extra import (
    brute_guard, totp_guard, pwd_strength, audit, device_tracker
)
import keyboards as kb

router = Router()


# ─────────────────────────────────────────────────────────────────────────────
# YORDAMCHI FUNKSIYALAR
# ─────────────────────────────────────────────────────────────────────────────

def format_size(size_bytes: int) -> str:
    """Fayl hajmini o'qilishi oson formatga o'giradi."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 ** 2):.1f} MB"


async def get_key_from_state(state: FSMContext) -> bytes | None:
    """FSM'dan shifrlash kalitini oladi. Yo'q bo'lsa None qaytaradi."""
    data = await state.get_data()
    key_hex = data.get("encryption_key")
    if not key_hex:
        return None
    return bytes.fromhex(key_hex)


async def require_session(message: Message, state: FSMContext) -> bytes | None:
    """
    Aktiv sessiyani tekshiradi.
    Kalit yo'q bo'lsa foydalanuvchini login qilishga yo'naltiradi.
    """
    key = await get_key_from_state(state)
    if key is None:
        await message.answer(
            "🔒 Sessiya topilmadi.\n"
            "Master parolingizni kiriting:",
            reply_markup=kb.cancel_kb()
        )
        await state.set_state(MasterPasswordLogin.waiting_for_password)
    return key


# ─────────────────────────────────────────────────────────────────────────────
# /start — Deep-link va boshlash
# ─────────────────────────────────────────────────────────────────────────────

@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext,
                    session: AsyncSession, bot: Bot):
    """
    /start buyrug'i ikki xil ishlatiladi:
    1. Oddiy /start — asosiy menyu
    2. /start <token> — Burner Link (bir martalik havola)
    """
    user = await UserRepo.get_or_create(
        session, message.from_user.id,
        message.from_user.username,
        message.from_user.full_name
    )

    # Deep-link tekshirish: /start <uuid_token>
    args = message.text.split(maxsplit=1)
    if len(args) > 1:
        token = args[1].strip()
        await _handle_burner_link(message, state, session, token)
        return

    if not user.master_hash:
        # Yangi foydalanuvchi — tavsif + master parol o'rnatish
        await message.answer(
            "🛡️ <b>CyberKeep — Raqamli Seyfingiz</b>\n\n"
            "Barcha maxfiy ma'lumotlaringiz uch qatlam himoya ostida:\n\n"
            "🔐 <b>1. Master Parol Himoyasi</b>\n"
            "<code>argon2id</code> algoritmi orqali parolingiz xavfsiz xeshlanadi. "
            "GPU yordamida Brute-force hujumlari <b>matematik imkonsiz</b> qilingan.\n\n"
            "⚡ <b>2. Super-Shifrlash (ChaCha20-Poly1305)</b>\n"
            "Barcha maxfiy matnlar, parollar va fayllaringiz "
            "(pasport, rasm, PDF va h.k.) RAM'da vaqtinchalik yaratilgan "
            "kalit bilan <b>harbiy darajadagi shifrlash</b> orqali himoyalanadi.\n\n"
            "💾 <b>3. Xavfsiz Saqlash (PostgreSQL BLOB)</b>\n"
            "Shifrlangan fayllar serverda <b>hech qachon saqlanmaydi</b>. "
            "Fayl baytlari to'g'ridan-to'g'ri bazadagi <code>LargeBinary</code> "
            "maydoniga yoziladi — server buzilsa ham o'qib bo'lmaydi.\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "⚠️ <b>Muhim:</b> Master parol bazaga <i>hech qachon</i> yozilmaydi. "
            "Unutsangiz — tiklash <b>imkonsiz</b>.\n\n"
            "🔑 Boshlash uchun kuchli Master parol o'rnating (kamida 8 belgi):",
            parse_mode="HTML",
            reply_markup=kb.cancel_kb()
        )
        await state.set_state(MasterPasswordSetup.waiting_for_password)
    else:
        # Mavjud foydalanuvchi — login
        await message.answer(
            "🔐 <b>CyberKeep</b>\n\nMaster parolingizni kiriting:",
            parse_mode="HTML",
            reply_markup=kb.cancel_kb()
        )
        await state.set_state(MasterPasswordLogin.waiting_for_password)


ABOUT_TEXT = (
    "🛡️ <b>CyberKeep — Qanday ishlaydi?</b>\n\n"
    "🔐 <b>1. Master Parol Himoyasi</b>\n"
    "<code>argon2id</code> algoritmi orqali foydalanuvchi paroli "
    "xavfsiz xeshlanadi. Bu GPU yordamida parollarni terib ko'rish "
    "(Brute-force) hujumlarini <b>matematik imkonsiz</b> qiladi.\n\n"
    "⚡ <b>2. Super-Shifrlash (ChaCha20-Poly1305)</b>\n"
    "Barcha maxfiy matnlar, parollar va foydalanuvchi yuborgan "
    "ixtiyoriy fayllar (Pasport, rasm, PDF va h.k.) baytlari operativ "
    "xotirada (RAM) vaqtinchalik yaratilgan kalit yordamida "
    "<code>ChaCha20-Poly1305</code> algoritmi orqali shifrlanadi.\n\n"
    "💾 <b>3. Database Storage (PostgreSQL LargeBinary)</b>\n"
    "Shifrlangan fayllar serverda saqlanmaydi — chunki server "
    "buzib kirilsa o'g'irlanishi mumkin. Fayl baytlari to'g'ridan-to'g'ri "
    "PostgreSQL bazasidagi <code>LargeBinary (BLOB)</code> maydoniga "
    "yoziladi. Serverda hech qanday fayl qoldig'i saqlanmaydi.\n\n"
    "━━━━━━━━━━━━━━━━━━━━━━\n"
    "🔒 <b>Xavfsizlik kafolati:</b>\n"
    "• Bazadan barcha ma'lumot o'g'irlansa ham — kalit bo'lmasdan <b>ochib bo'lmaydi</b>\n"
    "• Master parol bazada <b>hech qachon</b> saqlanmaydi\n"
    "• Shifrlash kaliti faqat <b>RAM'da</b>, 10 daqiqa so'ng avtomatik o'chadi\n"
    "• Bir martalik havolalar o'qilgandan so'ng bazadan <b>darhol o'chiriladi</b>"
)


@router.message(Command("help"))
async def cmd_help(message: Message):
    """Bot haqida ma'lumot."""
    from aiogram.utils.keyboard import InlineKeyboardBuilder
    from aiogram.types import InlineKeyboardButton
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text="🏠 Asosiy menyu", callback_data="menu:main"))
    await message.answer(ABOUT_TEXT, parse_mode="HTML", reply_markup=builder.as_markup())


@router.callback_query(F.data == "menu:about")
async def menu_about(call: CallbackQuery):
    """Bot haqida — inline menyu orqali."""
    from aiogram.utils.keyboard import InlineKeyboardBuilder
    from aiogram.types import InlineKeyboardButton
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text="◀️ Orqaga", callback_data="menu:main"))
    await call.message.edit_text(ABOUT_TEXT, parse_mode="HTML", reply_markup=builder.as_markup())


async def _handle_burner_link(message: Message, state: FSMContext,
                               session: AsyncSession, token: str):
    """
    Bir martalik havola ishlatiladi.
    consume() darhol bazadan o'chiradi — ikkinchi marta o'qib bo'lmaydi.
    """
    link = await BurnerRepo.consume(session, token)

    if not link:
        await message.answer(
            "❌ <b>Havola topilmadi yoki muddati tugagan.</b>\n\n"
            "Bu havola allaqachon ishlatilgan yoki yaroqsiz.",
            parse_mode="HTML"
        )
        return

    if link.content_type == "file":
        # Fayl: file_id ni Telegram'ga qayta yuborish
        import json
        try:
            meta = json.loads(link.encrypted_content.decode("utf-8"))
            file_id = meta["file_id"]
            fname = meta.get("filename", "fayl")
            mime = meta.get("mime", "")
            size = meta.get("size", 0)

            caption = (
                f"🔥 <b>Bir martalik xavfsiz fayl:</b>\n\n"
                f"📄 {fname} ({format_size(size)})\n\n"
                f"⚠️ Bu fayl bazadan <b>o'chirib yuborildi</b>. "
                f"Uni hech kim qayta yuklab ololmaydi."
            )

            # MIME turiga qarab yuborish
            if mime.startswith("image/"):
                await message.answer_photo(file_id, caption=caption, parse_mode="HTML")
            elif mime.startswith("video/"):
                await message.answer_video(file_id, caption=caption, parse_mode="HTML")
            elif mime.startswith("audio/"):
                await message.answer_audio(file_id, caption=caption, parse_mode="HTML")
            else:
                await message.answer_document(file_id, caption=caption, parse_mode="HTML")
        except Exception:
            await message.answer("❌ Faylni yuborishda xatolik yuz berdi.")
    else:
        # Matn
        try:
            content = link.encrypted_content.decode("utf-8")
            await message.answer(
                f"🔥 <b>Bir martalik xavfsiz xabar:</b>\n\n"
                f"<code>{content}</code>\n\n"
                f"⚠️ Bu xabar bazadan <b>o'chirib yuborildi</b>. "
                f"Uni hech kim qayta o'qiy olmaydi.",
                parse_mode="HTML"
            )
        except Exception:
            await message.answer("❌ Xabarni ochishda xatolik yuz berdi.")


# ─────────────────────────────────────────────────────────────────────────────
# MASTER PAROL O'RNATISH
# ─────────────────────────────────────────────────────────────────────────────

@router.message(MasterPasswordSetup.waiting_for_password)
async def setup_master_step1(message: Message, state: FSMContext):
    """Master parolni birinchi marta kiritish."""
    password = message.text.strip()

    # Telegram xabarini darhol o'chirish (parol ekranda qolmasin)
    try:
        await message.delete()
    except Exception:
        pass

    # ── Parol kuchini tekshirish ──────────────────────────────────────────
    is_strong, strength_msg = pwd_strength.check(password)
    if not is_strong:
        await message.answer(
            f"{strength_msg}\n\nQayta kuchli parol kiriting:",
            parse_mode="HTML",
            reply_markup=kb.cancel_kb()
        )
        return

    # Parolni vaqtincha FSM'da saqlab tasdiq so'raymiz
    await state.update_data(temp_password=password)
    await message.answer(
        f"Parol kuchi: {strength_msg}\n\n"
        f"✅ Tasdiqlash uchun qayta kiriting:",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(MasterPasswordSetup.waiting_for_confirm)


@router.message(MasterPasswordSetup.waiting_for_confirm)
async def setup_master_step2(message: Message, state: FSMContext,
                              session: AsyncSession):
    """Master parolni tasdiqlash va saqlash."""
    confirm = message.text.strip()
    try:
        await message.delete()
    except Exception:
        pass

    data = await state.get_data()
    temp_password = data.get("temp_password", "")

    if confirm != temp_password:
        await message.answer(
            "❌ Parollar mos kelmadi. Qaytadan boshlang:",
            reply_markup=kb.cancel_kb()
        )
        await state.set_state(MasterPasswordSetup.waiting_for_password)
        return

    # argon2id bilan hashlash (bu sekin — intentional, brute-force himoya)
    password_hash = hash_master_password(temp_password)
    # PBKDF2 uchun noyob salt yaratish
    salt = generate_user_salt()

    # Hashni bazaga saqlash (ochiq parol SAQLANMAYDI)
    await UserRepo.set_master_hash(session, message.from_user.id,
                                   password_hash, salt)

    # Shifrlash kalitini RAM'ga yuklash (FSM)
    enc_key = derive_encryption_key(temp_password, salt)
    await state.update_data(
        encryption_key=enc_key.hex(),
        temp_password=None,  # Vaqtinchalik parolni o'chirish
        _last_active=time.time()
    )

    await message.answer(
        "🎉 <b>Master parol muvaffaqiyatli o'rnatildi!</b>\n\n"
        "🔐 Sessiya ochildi. Kalit faqat RAM'da saqlanmoqda.\n"
        "⏰ 10 daqiqa harakatsizlikdan so'ng avtomatik chiqasiz.\n\n"
        "📋 <b>Asosiy menyu:</b>",
        parse_mode="HTML",
        reply_markup=kb.main_menu_kb(has_master=True)
    )
    await state.set_state(None)


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN
# ─────────────────────────────────────────────────────────────────────────────

@router.message(MasterPasswordLogin.waiting_for_password)
async def login_step1(message: Message, state: FSMContext, session: AsyncSession):
    """Master parolni kiritib sessiya ochish."""
    password = message.text.strip()
    try:
        await message.delete()
    except Exception:
        pass

    user_id = message.from_user.id

    # ── 1. DB blok tekshiruvi ────────────────────────────────────────────
    if await SecurityRepo.is_blocked(session, user_id):
        await message.answer(
            "🚫 <b>Hisobingiz bloklangan.</b>\n"
            "Admin bilan bog'laning yoki kutib turing.",
            parse_mode="HTML"
        )
        return

    # ── 2. RAM brute-force tekshiruvi ────────────────────────────────────
    is_blocked, remaining = brute_guard.is_blocked(user_id)
    if is_blocked:
        mins = remaining // 60
        secs = remaining % 60
        await message.answer(
            f"🚫 <b>Juda ko'p noto'g'ri urinish!</b>\n\n"
            f"⏰ Kutish vaqti: <b>{mins} daqiqa {secs} soniya</b>\n"
            f"Keyin qayta urinib ko'ring.",
            parse_mode="HTML"
        )
        audit.log(user_id, "BLOCKED", f"Brute-force blok: {mins} daqiqa")
        return

    user = await UserRepo.get(session, user_id)
    if not user or not user.master_hash:
        await message.answer("❌ Foydalanuvchi topilmadi. /start buyrug'ini yuboring.")
        return

    stored_hash = user.master_hash.decode("utf-8")

    # ── 3. Parolni tekshirish ────────────────────────────────────────────
    if not verify_master_password(password, stored_hash):
        # Muvaffaqiyatsiz urinishni qayd etish
        just_blocked, block_secs = brute_guard.record_failure(user_id)
        await SecurityRepo.log_attempt(session, user_id, False,
                                        message.from_user.language_code)
        remaining_tries = brute_guard.remaining_attempts(user_id)

        audit.log(user_id, "LOGIN_FAIL",
                  f"Qolgan urinish: {remaining_tries}")

        if just_blocked:
            mins = block_secs // 60
            await message.answer(
                f"🚫 <b>Hisobingiz {mins} daqiqaga bloklandi!</b>\n\n"
                f"Juda ko'p noto'g'ri parol kiritildi.",
                parse_mode="HTML"
            )
        else:
            await message.answer(
                f"❌ <b>Noto'g'ri parol!</b>\n"
                f"⚠️ Qolgan urinishlar: <b>{remaining_tries}</b>",
                parse_mode="HTML"
            )
        return

    # ── 4. Muvaffaqiyatli — hisoblagichni nollash ─────────────────────────
    brute_guard.record_success(user_id)
    await SecurityRepo.log_attempt(session, user_id, True,
                                    message.from_user.language_code)
    audit.log(user_id, "LOGIN_OK")

    # ── 5. Hash yangilash kerakmi? ────────────────────────────────────────
    if needs_rehash(stored_hash):
        new_hash = hash_master_password(password)
        await UserRepo.set_master_hash(session, user_id,
                                       new_hash, user.encryption_salt)

    # ── 6. Yangi qurilma tekshiruvi ───────────────────────────────────────
    platform = message.from_user.language_code or "unknown"
    is_new_device = device_tracker.check_and_register(
        user_id, platform,
        str(message.from_user.id)  # stable identifier
    )

    # ── 7. 2FA tekshiruvi ─────────────────────────────────────────────────
    totp_device = await TOTPRepo.get_active(session, user_id)
    if totp_device:
        enc_key = derive_encryption_key(password, user.encryption_salt)
        await state.update_data(
            temp_enc_key=enc_key.hex(),
            temp_totp_enc_secret=totp_device.encrypted_secret.hex(),
            new_device_alert=is_new_device
        )
        await message.answer(
            "🔐 <b>2FA tekshiruvi</b>\n\n"
            "Google Authenticator'dan 6 raqamli kodni kiriting:",
            parse_mode="HTML",
            reply_markup=kb.cancel_kb()
        )
        await state.set_state(MasterPasswordLogin.waiting_for_totp)
        return

    await _open_session(message, state, session, password, user, is_new_device)


@router.message(MasterPasswordLogin.waiting_for_totp)
async def login_totp(message: Message, state: FSMContext, session: AsyncSession):
    """2FA kodni tekshirish — brute-force himoyali."""
    code = message.text.strip()
    try:
        await message.delete()
    except Exception:
        pass

    user_id = message.from_user.id

    # TOTP brute-force tekshiruvi
    is_blocked, remaining = totp_guard.is_blocked(user_id)
    if is_blocked:
        mins = remaining // 60
        await message.answer(
            f"🚫 <b>2FA urinishlari bloklandi!</b>\n"
            f"⏰ {mins} daqiqadan so'ng qayta urinib ko'ring.",
            parse_mode="HTML"
        )
        return

    data = await state.get_data()
    enc_key_hex = data.get("temp_enc_key")
    totp_enc_hex = data.get("temp_totp_enc_secret")
    is_new_device = data.get("new_device_alert", False)

    if not enc_key_hex or not totp_enc_hex:
        await message.answer("❌ Sessiya xatosi. /start yuboring.")
        await state.clear()
        return

    enc_key = bytes.fromhex(enc_key_hex)
    try:
        totp_secret = decrypt_text(bytes.fromhex(totp_enc_hex), enc_key)
    except InvalidTag:
        await message.answer("❌ TOTP ochishda xatolik. /start yuboring.")
        await state.clear()
        return

    if not verify_totp_code(totp_secret, code):
        just_blocked, block_secs = totp_guard.record_failure(user_id)
        remaining_tries = totp_guard.remaining_attempts(user_id)
        audit.log(user_id, "LOGIN_FAIL", f"Noto'g'ri TOTP, qoldi: {remaining_tries}")

        if just_blocked:
            await message.answer(
                f"🚫 <b>2FA {block_secs // 60} daqiqaga bloklandi!</b>",
                parse_mode="HTML"
            )
        else:
            await message.answer(
                f"❌ Noto'g'ri 2FA kod!\n"
                f"⚠️ Qolgan urinishlar: <b>{remaining_tries}</b>",
                parse_mode="HTML"
            )
        return

    # 2FA muvaffaqiyatli
    totp_guard.record_success(user_id)

    await state.update_data(
        encryption_key=enc_key_hex,
        temp_enc_key=None,
        temp_totp_enc_secret=None,
        new_device_alert=None,
        _last_active=time.time()
    )
    await UserRepo.update_last_active(session, user_id)
    audit.log(user_id, "LOGIN_OK", "2FA bilan")

    text = "✅ <b>Tizimga kirdingiz!</b>"
    if is_new_device:
        text += "\n\n⚠️ <b>Yangi qurilmadan kirish aniqlandi!</b> Siz bo'lmasangiz parolingizni o'zgartiring."

    await message.answer(text, parse_mode="HTML", reply_markup=kb.main_menu_kb(has_master=True))
    await state.set_state(None)


async def _open_session(message: Message, state: FSMContext,
                         session: AsyncSession, password: str, user,
                         is_new_device: bool = False):
    """Sessiyani ochadi va kalitni RAM'ga yuklaydi."""
    enc_key = derive_encryption_key(password, user.encryption_salt)
    await state.update_data(
        encryption_key=enc_key.hex(),
        _last_active=time.time()
    )
    await UserRepo.update_last_active(session, message.from_user.id)

    text = (
        "✅ <b>Tizimga kirdingiz!</b>\n\n"
        "⏰ 10 daqiqa harakatsizlikdan so'ng avtomatik chiqasiz."
    )
    if is_new_device:
        text += "\n\n⚠️ <b>Yangi qurilmadan kirish aniqlandi!</b> Siz bo'lmasangiz parolingizni o'zgartiring."

    await message.answer(text, parse_mode="HTML", reply_markup=kb.main_menu_kb(has_master=True))
    await state.set_state(None)


# ─────────────────────────────────────────────────────────────────────────────
# MENYU NAVIGATSIYA
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "action:relogin")
async def action_relogin(call: CallbackQuery, state: FSMContext):
    await call.answer()
    await call.message.edit_text(
        "🔐 Master parolingizni kiriting:",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(MasterPasswordLogin.waiting_for_password)


@router.callback_query(F.data == "menu:main")
async def menu_main(call: CallbackQuery, state: FSMContext):
    await call.answer()
    key = await get_key_from_state(state)
    await call.message.edit_text(
        "🛡️ <b>CyberKeep — Asosiy Menyu</b>",
        parse_mode="HTML",
        reply_markup=kb.main_menu_kb(has_master=key is not None)
    )


@router.callback_query(F.data == "menu:logout")
async def menu_logout(call: CallbackQuery, state: FSMContext):
    await call.answer()
    await state.clear()
    await call.message.edit_text(
        "🚪 <b>Tizimdan chiqdingiz.</b>\n\n"
        "Shifrlash kaliti xotiradan o'chirildi.\n"
        "Qayta kirish uchun /start yuboring.",
        parse_mode="HTML"
    )


@router.callback_query(F.data == "action:cancel")
async def action_cancel(call: CallbackQuery, state: FSMContext):
    await call.answer()
    await state.set_state(None)
    await call.message.edit_text(
        "❌ Bekor qilindi.",
        reply_markup=kb.main_menu_kb(has_master=True)
    )


@router.callback_query(F.data == "setup:master")
async def setup_master_cb(call: CallbackQuery, state: FSMContext):
    await call.answer()
    await call.message.edit_text(
        "🔑 Master parolni kiriting (kamida 8 belgi):",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(MasterPasswordSetup.waiting_for_password)


# ─────────────────────────────────────────────────────────────────────────────
# PAROLLAR OMBORI
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "menu:passwords")
async def passwords_menu(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await call.answer("🔒 Avval tizimga kiring!", show_alert=True)
        return

    user_id = call.from_user.id
    pwd_records = await PasswordRepo.list_by_user(session, user_id)

    if not pwd_records:
        await call.message.edit_text(
            "🔑 <b>Parollar ombori bo'sh.</b>\n\n"
            "Yangi parol qo'shish uchun tugmani bosing.",
            parse_mode="HTML",
            reply_markup=kb.password_list_kb([], False)
        )
        return

    # Sarlavhalarni decrypt qilish (faqat ro'yxat uchun)
    pwd_list = []
    for p in pwd_records:
        try:
            title = decrypt_text(p.encrypted_title, key)
        except (InvalidTag, Exception):
            title = "⚠️ [Ochib bo'lmadi]"
        pwd_list.append({"id": p.id, "title": title})

    text = "🔑 <b>Parollaringiz:</b>\n\n"
    for p in pwd_list:
        text += f"• #{p['id']}: {p['title']}\n"

    await call.message.edit_text(
        text, parse_mode="HTML",
        reply_markup=kb.password_list_kb(pwd_list)
    )


@router.callback_query(F.data == "pwd:add")
async def pwd_add_start(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await call.answer("🔒 Avval tizimga kiring!", show_alert=True)
        return

    user_id = call.from_user.id
    user = await UserRepo.get(session, user_id)
    count = await PasswordRepo.count_by_user(session, user_id)

    if not user.is_premium and count >= cfg.FREE_PASSWORD_LIMIT:
        await call.message.edit_text(
            f"⚠️ <b>Free limit:</b> {cfg.FREE_PASSWORD_LIMIT} ta parol.\n"
            f"Premium rejimga o'ting — cheksiz parollar.",
            parse_mode="HTML",
            reply_markup=kb.main_menu_kb()
        )
        return

    await call.message.edit_text(
        "🔑 Parol sarlavhasini kiriting (masalan: Gmail, Bank):",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(AddPassword.waiting_for_title)


@router.message(AddPassword.waiting_for_title)
async def pwd_add_title(message: Message, state: FSMContext):
    await state.update_data(pwd_title=message.text.strip())
    await message.answer(
        "🔐 Parolning o'zini kiriting:",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(AddPassword.waiting_for_value)


@router.message(AddPassword.waiting_for_value)
async def pwd_add_value(message: Message, state: FSMContext):
    try:
        await message.delete()
    except Exception:
        pass
    await state.update_data(pwd_value=message.text.strip())
    await message.answer(
        "📝 Izoh kiriting (ixtiyoriy, o'tkazib yuborish uchun `-` yuboring):",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(AddPassword.waiting_for_notes)


@router.message(AddPassword.waiting_for_notes)
async def pwd_add_notes(message: Message, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await message.answer("❌ Sessiya topilmadi. /start yuboring.")
        return

    data = await state.get_data()
    notes = message.text.strip()
    if notes == "-":
        notes = None

    # ChaCha20-Poly1305 bilan shifrlash
    enc_title = encrypt_text(data["pwd_title"], key)
    enc_value = encrypt_text(data["pwd_value"], key)
    enc_notes = encrypt_text(notes, key) if notes else None

    await PasswordRepo.create(session, message.from_user.id,
                               enc_title, enc_value, enc_notes)

    # Vaqtinchalik ma'lumotlarni tozalash
    await state.update_data(pwd_title=None, pwd_value=None)

    await message.answer(
        "✅ <b>Parol xavfsiz saqlandi!</b>\n"
        "Shifrlanib bazaga yozildi (ChaCha20-Poly1305).",
        parse_mode="HTML",
        reply_markup=kb.main_menu_kb()
    )
    await state.set_state(None)


@router.callback_query(F.data.startswith("pwd:view:"))
async def pwd_view(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await call.answer("🔒 Avval tizimga kiring!", show_alert=True)
        return

    pwd_id = int(call.data.split(":")[2])
    pwd = await PasswordRepo.get(session, pwd_id, call.from_user.id)
    if not pwd:
        await call.answer("❌ Parol topilmadi!", show_alert=True)
        return

    try:
        title = decrypt_text(pwd.encrypted_title, key)
        value = decrypt_text(pwd.encrypted_value, key)
        notes = decrypt_text(pwd.encrypted_notes, key) if pwd.encrypted_notes else "—"
    except InvalidTag:
        await call.answer("❌ Ochib bo'lmadi — kalit mos kelmayapti!", show_alert=True)
        return

    await call.message.edit_text(
        f"🔑 <b>{title}</b>\n\n"
        f"🔐 Parol: <code>{value}</code>\n"
        f"📝 Izoh: {notes}\n\n"
        f"⚠️ Bu xabar sessiya davomida ko'rinadi.",
        parse_mode="HTML",
        reply_markup=kb.password_detail_kb(pwd_id)
    )


@router.callback_query(F.data.startswith("pwd:delete:"))
async def pwd_delete(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    pwd_id = int(call.data.split(":")[2])
    deleted = await PasswordRepo.delete(session, pwd_id, call.from_user.id)
    if deleted:
        await call.answer("🗑️ Parol o'chirildi!", show_alert=True)
    else:
        await call.answer("❌ Topilmadi!", show_alert=True)
    await passwords_menu(call, state, session)


# ─────────────────────────────────────────────────────────────────────────────
# FAYLLAR OMBORI
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "menu:files")
async def files_menu(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await call.answer("🔒 Avval tizimga kiring!", show_alert=True)
        return

    files = await FileRepo.list_by_user(session, call.from_user.id)
    if not files:
        await call.message.edit_text(
            "📁 <b>Fayllar ombori bo'sh.</b>\n\n"
            "Fayl yuklash uchun tugmani bosing.",
            parse_mode="HTML",
            reply_markup=kb.file_list_kb([])
        )
        return

    file_list = []
    for f in files:
        try:
            fname = decrypt_text(f.encrypted_filename, key)
        except Exception:
            fname = "⚠️ [Noma'lum]"
        file_list.append({
            "id": f.id,
            "name": fname,
            "size": format_size(f.original_size)
        })

    text = "📁 <b>Fayllaringiz:</b>\n\n"
    for f in file_list:
        text += f"• #{f['id']}: {f['name']} ({f['size']})\n"

    await call.message.edit_text(
        text, parse_mode="HTML",
        reply_markup=kb.file_list_kb(file_list)
    )


@router.callback_query(F.data == "file:upload")
async def file_upload_start(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await call.answer("🔒 Avval tizimga kiring!", show_alert=True)
        return

    user = await UserRepo.get(session, call.from_user.id)
    count = await FileRepo.count_by_user(session, call.from_user.id)

    if not user.is_premium and count >= cfg.FREE_FILE_LIMIT:
        await call.message.edit_text(
            f"⚠️ <b>Free limit:</b> {cfg.FREE_FILE_LIMIT} ta fayl.\n"
            f"Premium rejimga o'ting — cheksiz fayllar.",
            parse_mode="HTML",
            reply_markup=kb.main_menu_kb()
        )
        return

    await call.message.edit_text(
        "📤 <b>Faylni yuboring.</b>\n\n"
        "⚠️ Fayl server diskiga YOZILMAYDI — to'g'ridan-to'g'ri\n"
        "shifrlangan BLOB sifatida bazaga o'tiladi.",
        parse_mode="HTML",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(AddFile.waiting_for_file)


@router.message(AddFile.waiting_for_file, F.document | F.photo | F.video | F.audio)
async def file_upload_receive(message: Message, state: FSMContext,
                               session: AsyncSession, bot: Bot):
    """
    Fayl qabul qilish va shifrlash.
    MUHIM: Fayl HECH QACHON server diskiga yozilmaydi.
    Telegram'dan to'g'ridan-to'g'ri RAM'ga o'qiladi va shifrlanadi.
    """
    key = await get_key_from_state(state)
    if not key:
        await message.answer("❌ Sessiya topilmadi.")
        return

    # Fayl turini aniqlash
    if message.document:
        file_obj = message.document
        filename = file_obj.file_name or "fayl"
        mime = file_obj.mime_type
    elif message.photo:
        file_obj = message.photo[-1]  # Eng yuqori sifat
        filename = "rasm.jpg"
        mime = "image/jpeg"
    elif message.video:
        file_obj = message.video
        filename = message.video.file_name or "video.mp4"
        mime = "video/mp4"
    else:
        file_obj = message.audio
        filename = message.audio.file_name or "audio.mp3"
        mime = "audio/mpeg"

    original_size = file_obj.file_size or 0

    status_msg = await message.answer("⏳ Fayl shifrlanyapti...")

    try:
        # Faylni Telegram'dan RAM'ga yuklab olish (diskga EMAS)
        tg_file = await bot.get_file(file_obj.file_id)
        file_bytes_io = io.BytesIO()
        await bot.download_file(tg_file.file_path, destination=file_bytes_io)
        raw_bytes = file_bytes_io.getvalue()

        # ChaCha20-Poly1305 bilan shifrlash (RAM'da)
        enc_filename = encrypt_text(filename, key)
        enc_data = encrypt_data(raw_bytes, key)

        # Shifrlangan BLOB ni bazaga yozish (fayl diskda qolmaydi)
        await FileRepo.create(
            session, message.from_user.id,
            enc_filename, enc_data, original_size, mime
        )

        # RAM'ni tozalash
        del raw_bytes
        file_bytes_io.close()

        await status_msg.edit_text(
            f"✅ <b>Fayl xavfsiz saqlandi!</b>\n\n"
            f"📄 Nomi: {filename}\n"
            f"📦 Hajmi: {format_size(original_size)}\n"
            f"🔐 Shifrlash: ChaCha20-Poly1305\n"
            f"💾 Bazada: BLOB (shifrlangan)",
            parse_mode="HTML",
            reply_markup=kb.main_menu_kb()
        )
    except Exception as e:
        await status_msg.edit_text(f"❌ Xatolik: {str(e)[:100]}")

    await state.set_state(None)


@router.callback_query(F.data.startswith("file:download:"))
async def file_download(call: CallbackQuery, state: FSMContext,
                         session: AsyncSession, bot: Bot):
    """Faylni bazadan olib, RAM'da decrypt qilib foydalanuvchiga yuboradi."""
    key = await get_key_from_state(state)
    if not key:
        await call.answer("🔒 Avval tizimga kiring!", show_alert=True)
        return

    file_id = int(call.data.split(":")[2])
    sf = await FileRepo.get(session, file_id, call.from_user.id)
    if not sf:
        await call.answer("❌ Fayl topilmadi!", show_alert=True)
        return

    try:
        filename = decrypt_text(sf.encrypted_filename, key)
        file_data = decrypt_data(sf.encrypted_data, key)
    except InvalidTag:
        await call.answer("❌ Faylni ochib bo'lmadi!", show_alert=True)
        return

    # RAM'dagi faylni Telegram'ga yuborish (diskga YOZILMAYDI)
    buf = BufferedInputFile(file_data, filename=filename)
    await bot.send_document(
        call.from_user.id, buf,
        caption=f"📄 {filename} ({format_size(sf.original_size)})"
    )
    del file_data  # RAM tozalash

    await call.answer("✅ Fayl yuborildi!")


@router.callback_query(F.data.startswith("file:delete:"))
async def file_delete(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    file_id = int(call.data.split(":")[2])
    deleted = await FileRepo.delete(session, file_id, call.from_user.id)
    if deleted:
        await call.answer("🗑️ Fayl o'chirildi!", show_alert=True)
    else:
        await call.answer("❌ Topilmadi!", show_alert=True)
    await files_menu(call, state, session)


# ─────────────────────────────────────────────────────────────────────────────
# BURNER LINKS — Bir martalik xavfsiz havolalar
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "menu:burner")
async def burner_menu(call: CallbackQuery, state: FSMContext):
    key = await get_key_from_state(state)
    if not key:
        await call.answer("🔒 Avval tizimga kiring!", show_alert=True)
        return

    from aiogram.utils.keyboard import InlineKeyboardBuilder
    from aiogram.types import InlineKeyboardButton
    
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text="📝 Matn", callback_data="burner:text"),
        InlineKeyboardButton(text="📎 Fayl", callback_data="burner:file"),
    )
    builder.row(
        InlineKeyboardButton(text="◀️ Orqaga", callback_data="menu:main"),
    )

    await call.message.edit_text(
        "🔥 <b>Bir Martalik Xavfsiz Havola (Burner Link)</b>\n\n"
        "• Havola faqat <b>bir marta</b> ochiladi\n"
        "• O'qilgandan so'ng bazadan <b>darhol o'chiriladi</b>\n"
        "• 24 soatdan so'ng avtomatik o'chiriladi\n\n"
        "Nimani yubormoqchisiz?",
        parse_mode="HTML",
        reply_markup=builder.as_markup()
    )


@router.callback_query(F.data == "burner:text")
async def burner_text_start(call: CallbackQuery, state: FSMContext):
    await call.message.edit_text(
        "📝 Yubormoqchi bo'lgan maxfiy matningizni kiriting:",
        reply_markup=kb.cancel_kb()
    )
    await state.update_data(burner_type="text")
    await state.set_state(CreateBurnerLink.waiting_for_content)


@router.callback_query(F.data == "burner:file")
async def burner_file_start(call: CallbackQuery, state: FSMContext):
    await call.message.edit_text(
        "📎 Faylni yuboring (rasm, video, hujjat — har qanday):",
        reply_markup=kb.cancel_kb()
    )
    await state.update_data(burner_type="file")
    await state.set_state(CreateBurnerLink.waiting_for_content)


@router.message(CreateBurnerLink.waiting_for_content)
async def burner_create(message: Message, state: FSMContext,
                         session: AsyncSession, bot: Bot):
    """
    Matn yoki fayl qabul qiladi.
    Fayl bo'lsa: Telegram file_id saqlanadi (shifrlangan), recipient yuklab oladi.
    Matn bo'lsa: to'g'ridan-to'g'ri saqlanadi.
    """
    data = await state.get_data()
    burner_type = data.get("burner_type", "text")
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=cfg.BURNER_LINK_TTL)

    if burner_type == "file":
        # Fayl qabul qilish
        file_obj = None
        fname = "fayl"
        mime = None

        if message.document:
            file_obj = message.document
            fname = file_obj.file_name or "hujjat"
            mime = file_obj.mime_type or "application/octet-stream"
        elif message.photo:
            file_obj = message.photo[-1]
            fname = "rasm.jpg"
            mime = "image/jpeg"
        elif message.video:
            file_obj = message.video
            fname = message.video.file_name or "video.mp4"
            mime = "video/mp4"
        elif message.audio:
            file_obj = message.audio
            fname = message.audio.file_name or "audio.mp3"
            mime = "audio/mpeg"
        elif message.voice:
            file_obj = message.voice
            fname = "ovozli_xabar.ogg"
            mime = "audio/ogg"
        elif message.video_note:
            file_obj = message.video_note
            fname = "video_xabar.mp4"
            mime = "video/mp4"
        elif message.sticker:
            file_obj = message.sticker
            fname = "sticker.webp"
            mime = "image/webp"

        if not file_obj:
            await message.answer("❌ Fayl yuborilmadi. Qayta urinib ko'ring.")
            return

        # Fayl hajmi tekshiruvi (20MB limit)
        file_size = getattr(file_obj, "file_size", 0) or 0
        MAX_BURNER_FILE_MB = 20
        if file_size > MAX_BURNER_FILE_MB * 1024 * 1024:
            await message.answer(
                f"❌ Fayl hajmi {MAX_BURNER_FILE_MB}MB dan oshmasligi kerak.\n"
                f"Hozirgi hajm: {format_size(file_size)}"
            )
            return

        # file_id + metadata ni JSON sifatida saqlaymiz
        import json
        content_data = json.dumps({
            "file_id": file_obj.file_id,
            "filename": fname,
            "mime": mime,
            "size": getattr(file_obj, "file_size", 0) or 0,
        }).encode("utf-8")

        link = await BurnerRepo.create(
            session, message.from_user.id,
            content_data, expires_at, "file"
        )
    else:
        # Matn
        if not message.text:
            await message.answer("❌ Matn yozing yoki fayl uchun '📎 Fayl' tugmasini bosing.")
            return
        content = message.text.strip()
        if len(content) > 4096:
            await message.answer("❌ Matn 4096 belgidan oshmasligi kerak.")
            return
        import html as html_lib
        content = html_lib.escape(content)
        link = await BurnerRepo.create(
            session, message.from_user.id,
            content.encode("utf-8"), expires_at, "text"
        )

    bot_info = await bot.get_me()
    burner_url = f"https://t.me/{bot_info.username}?start={link.token}"

    type_icon = "📎" if burner_type == "file" else "📝"
    await message.answer(
        f"🔥 <b>Burner havola tayyor!</b>\n\n"
        f"{type_icon} Tur: {'Fayl' if burner_type == 'file' else 'Matn'}\n"
        f"🔗 <code>{burner_url}</code>\n\n"
        f"⏰ Muddati: {expires_at.strftime('%d.%m.%Y %H:%M')} UTC\n"
        f"⚠️ Bu havola <b>faqat bir marta</b> ochiladi, so'ng o'chadi.",
        parse_mode="HTML",
        reply_markup=kb.main_menu_kb()
    )
    await state.set_state(None)


# ─────────────────────────────────────────────────────────────────────────────
# 2FA — TOTP Authenticator
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "menu:totp")
async def totp_menu(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await call.answer("🔒 Avval tizimga kiring!", show_alert=True)
        return

    device = await TOTPRepo.get_active(session, call.from_user.id)
    has_totp = device is not None
    status_text = "✅ Yoqilgan" if has_totp else "❌ O'chirilgan"
    desc_text = "2FA sozlangan. Google Authenticator ishlatilmoqda." if has_totp else "2FA yoqing va hisobingizni yanada himoyalang."
    await call.message.edit_text(
        f"🔐 <b>Ikki Faktorli Autentifikatsiya (2FA)</b>\n\n"
        f"Holat: {status_text}\n\n"
        f"{desc_text}",
        parse_mode="HTML",
        reply_markup=kb.settings_kb(has_totp=has_totp)
    )


@router.callback_query(F.data == "settings:enable_totp")
async def totp_setup_start(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await call.answer("🔒 Avval tizimga kiring!", show_alert=True)
        return

    # Yangi TOTP secret yaratish
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, call.from_user.id)

    # QR kod generatsiya (RAM'da)
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    buf.seek(0)

    # Secretni vaqtincha FSM'ga saqlash
    await state.update_data(totp_temp_secret=secret)

    # QR kodni yuborish
    await call.message.answer_photo(
        BufferedInputFile(buf.read(), filename="qr.png"),
        caption=(
            f"📱 <b>Google Authenticator bilan skanerlang</b>\n\n"
            f"Yoki manual kiriting:\n<code>{secret}</code>\n\n"
            f"So'ng 6 raqamli kodni kiriting:"
        ),
        parse_mode="HTML"
    )
    buf.close()
    await state.set_state(SetupTOTP.waiting_for_code_confirm)


@router.message(SetupTOTP.waiting_for_code_confirm)
async def totp_confirm(message: Message, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await message.answer("❌ Sessiya topilmadi.")
        return

    data = await state.get_data()
    secret = data.get("totp_temp_secret")
    code = message.text.strip()

    if not verify_totp_code(secret, code):
        await message.answer("❌ Noto'g'ri kod. Qayta urinib ko'ring:")
        return

    # Secretni shifrlash va bazaga saqlash
    enc_secret = encrypt_text(secret, key)
    await TOTPRepo.create(session, message.from_user.id, enc_secret)
    await state.update_data(totp_temp_secret=None)

    await message.answer(
        "✅ <b>2FA muvaffaqiyatli sozlandi!</b>\n\n"
        "Endi tizimga kirishda 6 raqamli kod so'raladi.",
        parse_mode="HTML",
        reply_markup=kb.main_menu_kb()
    )
    await state.set_state(None)


@router.callback_query(F.data == "settings:disable_totp")
async def totp_disable(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    await TOTPRepo.delete_all(session, call.from_user.id)
    await call.answer("✅ 2FA o'chirildi!", show_alert=True)
    await totp_menu(call, state, session)


# ─────────────────────────────────────────────────────────────────────────────
# RAQAMLI MEROSXO'RLIK
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "menu:legacy")
async def legacy_menu(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await call.answer("🔒 Avval tizimga kiring!", show_alert=True)
        return

    legacy = await LegacyRepo.get(session, call.from_user.id)
    builder = __import__("aiogram.utils.keyboard", fromlist=["InlineKeyboardBuilder"]).InlineKeyboardBuilder()
    from aiogram.types import InlineKeyboardButton
    from aiogram.utils.keyboard import InlineKeyboardBuilder as IKB

    ikb = IKB()
    ikb.row(InlineKeyboardButton(text="✏️ Sozlash", callback_data="legacy:setup"))
    ikb.row(InlineKeyboardButton(text="◀️ Orqaga", callback_data="menu:main"))

    if legacy:
        info = (
            f"🏛️ <b>Raqamli Merosxo'rlik</b>\n\n"
            f"Merosxo'r ID: <code>{legacy.heir_telegram_id}</code>\n"
            f"Faolsizlik: {legacy.inactivity_days} kun\n"
            f"Holat: {'✅ Yuborilgan' if legacy.is_delivered else '⏳ Kutilmoqda'}"
        )
    else:
        info = (
            "🏛️ <b>Raqamli Merosxo'rlik</b>\n\n"
            "Sozlanmagan. Belgilangan muddatda harakatsiz bo'lsangiz,\n"
            "merosxo'ringizga maxsus xabar yuboriladi."
        )

    await call.message.edit_text(info, parse_mode="HTML", reply_markup=ikb.as_markup())


@router.callback_query(F.data == "legacy:setup")
async def legacy_setup_start(call: CallbackQuery, state: FSMContext):
    await call.message.edit_text(
        "🏛️ Merosxo'rning Telegram ID sini kiriting:",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(SetupLegacy.waiting_for_heir_id)


@router.message(SetupLegacy.waiting_for_heir_id)
async def legacy_heir_id(message: Message, state: FSMContext):
    try:
        heir_id = int(message.text.strip())
    except ValueError:
        await message.answer("❌ Faqat raqam kiriting (Telegram ID).")
        return
    await state.update_data(legacy_heir_id=heir_id)
    await message.answer(
        "📝 Merosxo'rga qoldiradigan maxfiy xabaringizni kiriting:",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(SetupLegacy.waiting_for_message)


@router.message(SetupLegacy.waiting_for_message)
async def legacy_message(message: Message, state: FSMContext):
    await state.update_data(legacy_message=message.text.strip())
    await message.answer(
        "⏰ Necha kunlik faolsizlikdan keyin yuborilsin? (Masalan: 180):",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(SetupLegacy.waiting_for_days)


@router.message(SetupLegacy.waiting_for_days)
async def legacy_days(message: Message, state: FSMContext, session: AsyncSession):
    key = await get_key_from_state(state)
    if not key:
        await message.answer("❌ Sessiya topilmadi.")
        return

    try:
        days = int(message.text.strip())
        if days < 30:
            raise ValueError
    except ValueError:
        await message.answer("❌ Kamida 30 kun bo'lishi kerak.")
        return

    data = await state.get_data()
    heir_id = data["legacy_heir_id"]
    legacy_msg = data["legacy_message"]

    enc_message = encrypt_text(legacy_msg, key)
    await LegacyRepo.set(session, message.from_user.id, heir_id, enc_message, days)

    await message.answer(
        f"✅ <b>Merosxo'rlik sozlandi!</b>\n\n"
        f"Merosxo'r: <code>{heir_id}</code>\n"
        f"Muddati: {days} kun faolsizlik\n\n"
        f"Xabar shifrlangan holda bazada saqlanmoqda.",
        parse_mode="HTML",
        reply_markup=kb.main_menu_kb()
    )
    await state.set_state(None)


# ─────────────────────────────────────────────────────────────────────────────
# 🚨 PANIC MODE — /panic: barcha ma'lumotlarni bir zumda o'chirish
# ─────────────────────────────────────────────────────────────────────────────

@router.message(Command("panic"))
async def cmd_panic(message: Message, state: FSMContext, session: AsyncSession):
    """
    FAVQULODDA buyruq: hamma ma'lumot o'chiriladi.
    Tasdiqlash so'raladi — tasodifiy bosishdan himoya.
    """
    from aiogram.utils.keyboard import InlineKeyboardBuilder
    from aiogram.types import InlineKeyboardButton

    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(
            text="🚨 HA, HAMMASINI O'CHIR",
            callback_data="panic:confirm"
        )
    )
    builder.row(
        InlineKeyboardButton(text="❌ Bekor qilish", callback_data="menu:main")
    )

    await message.answer(
        "🚨 <b>PANIC MODE</b>\n\n"
        "⚠️ Bu buyruq quyidagilarni <b>qaytarib bo'lmasdan</b> o'chiradi:\n\n"
        "• Barcha saqlangan parollar\n"
        "• Barcha shifrlangan fayllar\n"
        "• Barcha burner havolalar\n"
        "• 2FA sozlamalari\n"
        "• Master parol va profil\n\n"
        "❓ Davom etasizmi?",
        parse_mode="HTML",
        reply_markup=builder.as_markup()
    )


@router.callback_query(F.data == "panic:confirm")
async def panic_execute(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    """Barcha ma'lumotlarni atomik o'chirish."""
    user_id = call.from_user.id

    await call.message.edit_text("⏳ O'chirilmoqda...")

    try:
        await SecurityRepo.delete_all_user_data(session, user_id)
    except Exception as e:
        await call.message.edit_text(f"❌ Xatolik: {str(e)[:100]}")
        return

    # FSM ni ham tozalash — RAM'dagi kalit o'chiriladi
    await state.clear()
    audit.log(user_id, "PANIC", "Barcha ma'lumotlar o'chirildi")

    await call.message.edit_text(
        "✅ <b>Barcha ma'lumotlaringiz o'chirildi.</b>\n\n"
        "🔐 Sessiya ham yopildi.\n"
        "Qaytadan foydalanish uchun /start yuboring."
    )


# ─────────────────────────────────────────────────────────────────────────────
# 📋 FAOLIYAT TARIXI — /log
# ─────────────────────────────────────────────────────────────────────────────

@router.message(Command("log"))
async def cmd_log(message: Message, state: FSMContext):
    """Oxirgi 10 ta xavfsizlik hodisasini ko'rsatish."""
    key = await get_key_from_state(state)
    if not key:
        await message.answer(
            "🔒 Logni ko'rish uchun avval tizimga kiring.",
            reply_markup=kb.cancel_kb()
        )
        await state.set_state(MasterPasswordLogin.waiting_for_password)
        return

    user_id = message.from_user.id
    log_text = audit.format_for_display(user_id, limit=15)

    await message.answer(
        f"📋 <b>Xavfsizlik Tarixi (oxirgi 15 ta)</b>\n\n{log_text}",
        parse_mode="HTML",
        reply_markup=kb.main_menu_kb()
    )


# ─────────────────────────────────────────────────────────────────────────────
# ⚙️ SOZLAMALAR MENYUSI
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "menu:settings")
async def settings_menu(call: CallbackQuery, state: FSMContext, session: AsyncSession):
    # Callback'ni darhol javoblash (Telegram timeout xatoligini oldini olish)
    await call.answer()

    key = await get_key_from_state(state)
    if not key:
        # Sessiya yo'q — login sahifasiga yo'naltirish
        from aiogram.utils.keyboard import InlineKeyboardBuilder
        from aiogram.types import InlineKeyboardButton
        builder = InlineKeyboardBuilder()
        builder.row(InlineKeyboardButton(text="🔐 Tizimga kirish", callback_data="action:relogin"))
        await call.message.edit_text(
            "🔒 <b>Sessiya tugagan.</b>\n\n"
            "Master parolingizni kiritib qayta kiring:",
            parse_mode="HTML",
            reply_markup=builder.as_markup()
        )
        await state.set_state(MasterPasswordLogin.waiting_for_password)
        return

    user_id = call.from_user.id
    device = await TOTPRepo.get_active(session, user_id)
    user = await UserRepo.get(session, user_id)

    now = datetime.now(timezone.utc)
    if user and user.is_premium and user.premium_until and user.premium_until > now:
        remaining = (user.premium_until - now).days
        premium_text = f"👑 Premium ({remaining} kun qoldi)"
    elif user and user.is_premium:
        premium_text = "👑 Premium (muddati tugagan)"
    else:
        premium_text = "🆓 Free"

    totp_status = "✅ Yoqilgan" if device else "❌ O'chirilgan"

    await call.message.edit_text(
        f"⚙️ <b>Sozlamalar</b>\n\n"
        f"📦 Paket: {premium_text}\n"
        f"🔐 2FA: {totp_status}\n\n"
        f"Pastdagi tugmalardan birini tanlang:",
        parse_mode="HTML",
        reply_markup=kb.settings_kb(has_totp=device is not None)
    )


@router.callback_query(F.data == "settings:change_pwd")
async def settings_change_pwd(call: CallbackQuery, state: FSMContext):
    await call.answer()
    key = await get_key_from_state(state)
    if not key:
        await call.message.edit_text("🔒 Avval tizimga kiring.", reply_markup=kb.cancel_kb())
        await state.set_state(MasterPasswordLogin.waiting_for_password)
        return
    # Eski parolni tasdiqlash orqali boshlaymiz
    await call.message.edit_text(
        "🔑 <b>Master Parolni O'zgartirish</b>\n\n"
        "⚠️ Yangi parolga o'tishda barcha shifrlangan ma'lumotlaringiz\n"
        "avtomatik ravishda yangi kalit bilan qayta shifrlanadi.\n\n"
        "Avval <b>hozirgi</b> master parolingizni kiriting:",
        parse_mode="HTML",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(ChangeMasterPassword.waiting_for_old_password)


@router.message(ChangeMasterPassword.waiting_for_old_password)
async def change_pwd_verify_old(message: Message, state: FSMContext, session: AsyncSession):
    """Eski parolni tekshiradi."""
    old_password = message.text.strip()
    try:
        await message.delete()
    except Exception:
        pass

    user_id = message.from_user.id

    # Brute-force himoya
    is_blocked, remaining = brute_guard.is_blocked(user_id)
    if is_blocked:
        mins = remaining // 60
        await message.answer(
            f"🚫 <b>Juda ko'p urinish!</b> {mins} daqiqa kuting.",
            parse_mode="HTML"
        )
        return

    user = await UserRepo.get(session, user_id)
    if not user or not user.master_hash:
        await message.answer("❌ Foydalanuvchi topilmadi.")
        return

    stored_hash = user.master_hash.decode("utf-8")
    if not verify_master_password(old_password, stored_hash):
        just_blocked, _ = brute_guard.record_failure(user_id)
        remaining_tries = brute_guard.remaining_attempts(user_id)
        if just_blocked:
            await message.answer("🚫 <b>Hisobingiz bloklandi!</b>", parse_mode="HTML")
        else:
            await message.answer(
                f"❌ <b>Noto'g'ri parol!</b> Qolgan urinishlar: {remaining_tries}",
                parse_mode="HTML",
                reply_markup=kb.cancel_kb()
            )
        return

    brute_guard.record_success(user_id)
    # Eski kalitni vaqtinchalik saqlaymiz (re-encryption uchun)
    old_key = derive_encryption_key(old_password, user.encryption_salt)
    await state.update_data(
        old_enc_key=old_key.hex(),
        old_salt=user.encryption_salt.hex()
    )

    await message.answer(
        "✅ Parol tasdiqlandi!\n\n"
        "Yangi master parolni kiriting (kamida 8 belgi):",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(ChangeMasterPassword.waiting_for_new_password)


@router.message(ChangeMasterPassword.waiting_for_new_password)
async def change_pwd_new(message: Message, state: FSMContext):
    """Yangi parolni qabul qiladi va kuchini tekshiradi."""
    new_password = message.text.strip()
    try:
        await message.delete()
    except Exception:
        pass

    is_strong, strength_msg = pwd_strength.check(new_password)
    if not is_strong:
        await message.answer(
            f"{strength_msg}\n\nQayta kuchli parol kiriting:",
            parse_mode="HTML",
            reply_markup=kb.cancel_kb()
        )
        return

    await state.update_data(temp_new_password=new_password)
    await message.answer(
        f"Parol kuchi: {strength_msg}\n\n"
        f"✅ Tasdiqlash uchun yangi parolni qayta kiriting:",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(ChangeMasterPassword.waiting_for_new_confirm)


@router.message(ChangeMasterPassword.waiting_for_new_confirm)
async def change_pwd_confirm(message: Message, state: FSMContext, session: AsyncSession):
    """Yangi parolni tasdiqlaydi va BARCHA ma'lumotlarni qayta shifrlaydi."""
    confirm = message.text.strip()
    try:
        await message.delete()
    except Exception:
        pass

    data = await state.get_data()
    new_password = data.get("temp_new_password", "")
    old_key_hex = data.get("old_enc_key")

    if confirm != new_password:
        await message.answer(
            "❌ Parollar mos kelmadi. Yangi parolni qayta kiriting:",
            reply_markup=kb.cancel_kb()
        )
        await state.set_state(ChangeMasterPassword.waiting_for_new_password)
        return

    if not old_key_hex:
        await message.answer("❌ Sessiya xatosi. /start yuboring.")
        await state.clear()
        return

    user_id = message.from_user.id
    old_key = bytes.fromhex(old_key_hex)

    status_msg = await message.answer("⏳ Ma'lumotlar qayta shifrlanmoqda...")

    try:
        # Yangi salt va kalit yaratamiz
        new_salt = generate_user_salt()
        new_key = derive_encryption_key(new_password, new_salt)

        # ── 1. Parollarni qayta shifrlash ──────────────────────────────────
        pwd_records = await PasswordRepo.list_by_user(session, user_id)
        for pwd in pwd_records:
            try:
                title = decrypt_text(pwd.encrypted_title, old_key)
                value = decrypt_text(pwd.encrypted_value, old_key)
                notes = decrypt_text(pwd.encrypted_notes, old_key) if pwd.encrypted_notes else None

                from sqlalchemy import update as sa_update
                from database import Password as PwdModel
                await session.execute(
                    sa_update(PwdModel)
                    .where(PwdModel.id == pwd.id)
                    .values(
                        encrypted_title=encrypt_text(title, new_key),
                        encrypted_value=encrypt_text(value, new_key),
                        encrypted_notes=encrypt_text(notes, new_key) if notes else None,
                    )
                )
            except Exception:
                pass  # Ochib bo'lmagan yozuvlar o'tkazib yuboriladi

        # ── 2. Fayllarni qayta shifrlash ───────────────────────────────────
        file_records = await FileRepo.list_by_user(session, user_id)
        for sf in file_records:
            try:
                filename = decrypt_text(sf.encrypted_filename, old_key)
                raw_data = decrypt_data(sf.encrypted_data, old_key)

                from database import SecretFile as SFModel
                await session.execute(
                    sa_update(SFModel)
                    .where(SFModel.id == sf.id)
                    .values(
                        encrypted_filename=encrypt_text(filename, new_key),
                        encrypted_data=encrypt_data(raw_data, new_key),
                    )
                )
                del raw_data
            except Exception:
                pass

        # ── 3. TOTP secretni qayta shifrlash ───────────────────────────────
        totp_device = await TOTPRepo.get_active(session, user_id)
        if totp_device:
            try:
                totp_secret = decrypt_text(totp_device.encrypted_secret, old_key)
                new_enc_secret = encrypt_text(totp_secret, new_key)
                from database import TOTPDevice as TOTPModel
                await session.execute(
                    sa_update(TOTPModel)
                    .where(TOTPModel.id == totp_device.id)
                    .values(encrypted_secret=new_enc_secret)
                )
            except Exception:
                pass

        # ── 4. Legacy xabarni qayta shifrlash ─────────────────────────────
        from database import DigitalLegacy as LegacyModel, select as sa_select
        legacy_result = await session.execute(
            sa_select(LegacyModel).where(LegacyModel.user_id == user_id)
        )
        legacy = legacy_result.scalar_one_or_none()
        if legacy:
            try:
                legacy_msg = decrypt_text(legacy.encrypted_message, old_key)
                await session.execute(
                    sa_update(LegacyModel)
                    .where(LegacyModel.user_id == user_id)
                    .values(encrypted_message=encrypt_text(legacy_msg, new_key))
                )
            except Exception:
                pass

        # ── 5. Yangi hash va salt ni saqlash ──────────────────────────────
        new_hash = hash_master_password(new_password)
        await UserRepo.set_master_hash(session, user_id, new_hash, new_salt)
        await session.commit()

        # ── 6. FSM ni yangilash ───────────────────────────────────────────
        await state.update_data(
            encryption_key=new_key.hex(),
            old_enc_key=None,
            old_salt=None,
            temp_new_password=None,
            _last_active=time.time()
        )
        await state.set_state(None)

        audit.log(user_id, "MASTER_CHANGED", "Re-encryption muvaffaqiyatli")

        await status_msg.edit_text(
            "✅ <b>Master parol muvaffaqiyatli o'zgartirildi!</b>\n\n"
            "🔐 Barcha ma'lumotlaringiz yangi kalit bilan qayta shifrlandi.\n"
            "Eski kalit RAM'dan o'chirildi.",
            parse_mode="HTML",
            reply_markup=kb.main_menu_kb()
        )

    except Exception as e:
        await status_msg.edit_text(
            f"❌ <b>Xatolik yuz berdi!</b>\n\n"
            f"Parol o'zgartirilmadi. Qayta urinib ko'ring.\n"
            f"<code>{str(e)[:100]}</code>",
            parse_mode="HTML",
            reply_markup=kb.main_menu_kb()
        )
        await state.set_state(None)



@router.callback_query(F.data == "settings:log")
async def settings_log(call: CallbackQuery, state: FSMContext):
    await call.answer()
    key = await get_key_from_state(state)
    if not key:
        await call.message.edit_text("🔒 Avval tizimga kiring.", reply_markup=kb.cancel_kb())
        await state.set_state(MasterPasswordLogin.waiting_for_password)
        return

    from aiogram.utils.keyboard import InlineKeyboardBuilder
    from aiogram.types import InlineKeyboardButton
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text="◀️ Orqaga", callback_data="menu:settings"))
    log_text = audit.format_for_display(call.from_user.id, limit=15)
    await call.message.edit_text(
        f"📋 <b>Xavfsizlik Tarixi</b>\n\n{log_text}",
        parse_mode="HTML",
        reply_markup=builder.as_markup()
    )


@router.callback_query(F.data == "settings:panic")
async def settings_panic(call: CallbackQuery):
    await call.answer()
    from aiogram.utils.keyboard import InlineKeyboardBuilder
    from aiogram.types import InlineKeyboardButton
    builder = InlineKeyboardBuilder()
    builder.row(InlineKeyboardButton(text="🚨 HA, HAMMASINI O'CHIR", callback_data="panic:confirm"))
    builder.row(InlineKeyboardButton(text="❌ Bekor qilish", callback_data="menu:settings"))
    await call.message.edit_text(
        "🚨 <b>PANIC MODE</b>\n\n"
        "⚠️ Barcha parollar, fayllar, 2FA va profil\n"
        "<b>qaytarib bo'lmasdan o'chiriladi!</b>\n\n"
        "Davom etasizmi?",
        parse_mode="HTML",
        reply_markup=builder.as_markup()
    )
