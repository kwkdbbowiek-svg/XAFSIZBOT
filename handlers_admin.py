"""
handlers_admin.py — Admin panel.

KIRISH: Faqat ADMIN_ID (config.py) ga ruxsat beriladi.
"""

import asyncio
from datetime import datetime, timezone, timedelta

from aiogram import Router, F, Bot
from aiogram.filters import Command
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.fsm.context import FSMContext
from aiogram.utils.keyboard import InlineKeyboardBuilder
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from config import cfg
from states import AdminBroadcast, AdminPremium
from database import UserRepo, User, AsyncSessionFactory
import keyboards as kb

router = Router()

# Premium paketlar — (nomi, kunlar, callback_data)
PREMIUM_PACKAGES = [
    ("1 kun",  1,   "pkg:1"),
    ("7 kun",  7,   "pkg:7"),
    ("1 oy",   30,  "pkg:30"),
    ("3 oy",   90,  "pkg:90"),
    ("6 oy",   180, "pkg:180"),
    ("1 yil",  365, "pkg:365"),
    ("Maxsus", 0,   "pkg:custom"),
]


def is_admin(user_id: int) -> bool:
    return user_id == cfg.ADMIN_ID


def premium_packages_kb() -> InlineKeyboardMarkup:
    """Premium paket tanlash klaviaturasi."""
    builder = InlineKeyboardBuilder()
    btns = [InlineKeyboardButton(text=n, callback_data=c) for n, d, c in PREMIUM_PACKAGES]
    builder.row(*btns[:3])
    builder.row(*btns[3:6])
    builder.row(btns[6])
    builder.row(InlineKeyboardButton(text="◀️ Orqaga", callback_data="admin:back"))
    return builder.as_markup()


# ─────────────────────────────────────────────────────────────────────────────
# Admin filtri
# ─────────────────────────────────────────────────────────────────────────────

@router.message(Command("admin"))
async def admin_panel(message: Message):
    if not is_admin(message.from_user.id):
        await message.answer("⛔ Ruxsat yo'q.")
        return

    await message.answer(
        "👑 <b>Admin Panel — CyberKeep</b>\n\n"
        "Boshqaruv opsiyalarini tanlang:",
        parse_mode="HTML",
        reply_markup=kb.admin_kb()
    )


# ─────────────────────────────────────────────────────────────────────────────
# STATISTIKA
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "admin:stats")
async def admin_stats(call: CallbackQuery, session: AsyncSession):
    if not is_admin(call.from_user.id):
        await call.answer("⛔ Ruxsat yo'q!", show_alert=True)
        return

    total = await UserRepo.count_all(session)
    premium = await UserRepo.count_premium(session)
    free = total - premium

    await call.message.edit_text(
        f"📊 <b>Bot Statistikasi</b>\n\n"
        f"👥 Jami foydalanuvchilar: <b>{total}</b>\n"
        f"👑 Premium: <b>{premium}</b>\n"
        f"🆓 Free: <b>{free}</b>\n\n"
        f"🕐 {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M')} UTC",
        parse_mode="HTML",
        reply_markup=kb.admin_kb()
    )


# ─────────────────────────────────────────────────────────────────────────────
# PREMIUM BERISH
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "admin:back")
async def admin_back(call: CallbackQuery, state: FSMContext):
    if not is_admin(call.from_user.id):
        return
    await state.set_state(None)
    await call.message.edit_text(
        "👑 <b>Admin Panel — CyberKeep</b>",
        parse_mode="HTML",
        reply_markup=kb.admin_kb()
    )


# ─────────────────────────────────────────────────────────────────────────────
# PREMIUM BERISH — 2 bosqich: ID → Paket tanlash
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "admin:premium")
async def admin_premium_start(call: CallbackQuery, state: FSMContext):
    if not is_admin(call.from_user.id):
        await call.answer("⛔ Ruxsat yo'q!", show_alert=True)
        return
    await call.message.edit_text(
        "👑 <b>Premium Berish</b>\n\nFoydalanuvchi Telegram ID sini kiriting:",
        parse_mode="HTML",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(AdminPremium.waiting_for_user_id)


@router.message(AdminPremium.waiting_for_user_id)
async def admin_premium_userid(message: Message, state: FSMContext, session: AsyncSession):
    if not is_admin(message.from_user.id):
        return
    try:
        uid = int(message.text.strip())
    except ValueError:
        await message.answer("❌ Noto'g'ri ID. Faqat raqam kiriting:")
        return

    # Foydalanuvchi mavjudligini tekshirish
    user = await UserRepo.get(session, uid)
    if not user:
        await message.answer(
            f"⚠️ ID <code>{uid}</code> bazada topilmadi.\n"
            f"Shunga qaramay davom etasizmi?\n\n"
            f"Paket tanlang:",
            parse_mode="HTML",
            reply_markup=premium_packages_kb()
        )
    else:
        now = datetime.now(timezone.utc)
        status = ""
        if user.is_premium and user.premium_until and user.premium_until > now:
            remaining = (user.premium_until - now).days
            status = f"\n📅 Hozirgi muddati: {user.premium_until.strftime('%d.%m.%Y')} ({remaining} kun qoldi)"

        await message.answer(
            f"👤 Foydalanuvchi: <code>{uid}</code>"
            f"{status}\n\n"
            f"Paket tanlang:",
            parse_mode="HTML",
            reply_markup=premium_packages_kb()
        )

    await state.update_data(target_user_id=uid)
    await state.set_state(AdminPremium.waiting_for_days)


# Tayyor paket tanlandi (1, 7, 30, 90, 180, 365 kun)
@router.callback_query(F.data.startswith("pkg:"), AdminPremium.waiting_for_days)
async def admin_premium_package(call: CallbackQuery, state: FSMContext,
                                 session: AsyncSession, bot: Bot):
    if not is_admin(call.from_user.id):
        return

    pkg = call.data.split(":")[1]

    if pkg == "custom":
        # Maxsus kun soni so'raladi
        await call.message.edit_text(
            "✏️ Necha kun Premium berilsin? (Raqam kiriting):",
            reply_markup=kb.cancel_kb()
        )
        # State o'zgartirilmaydi — waiting_for_days da qolamiz,
        # lekin endi matn kutamiz
        await state.update_data(waiting_custom=True)
        return

    days = int(pkg)
    await _apply_premium(call.message, state, session, bot, call.from_user.id, days)


@router.message(AdminPremium.waiting_for_days)
async def admin_premium_custom_days(message: Message, state: FSMContext,
                                     session: AsyncSession, bot: Bot):
    if not is_admin(message.from_user.id):
        return

    data = await state.get_data()
    if not data.get("waiting_custom"):
        # Paket callback kutilmoqda, matn kerak emas
        return

    try:
        days = int(message.text.strip())
        if days <= 0:
            raise ValueError
    except ValueError:
        await message.answer("❌ Musbat son kiriting (masalan: 14):")
        return

    await _apply_premium(message, state, session, bot, message.from_user.id, days)


async def _apply_premium(event, state: FSMContext, session: AsyncSession,
                          bot: Bot, admin_id: int, days: int):
    """Premium muddatini bazaga yozib, foydalanuvchiga xabar beradi."""
    data = await state.get_data()
    target_id = data.get("target_user_id")

    if not target_id:
        return

    # Foydalanuvchi yo'q bo'lsa ham yaratib qo'yamiz (keyinroq kiradi)
    user = await UserRepo.get(session, target_id)
    if not user:
        from database import UserRepo as UR
        async with AsyncSessionFactory() as s:
            await UR.get_or_create(s, target_id)
        async with AsyncSessionFactory() as s:
            user = await UR.get(s, target_id)

    now = datetime.now(timezone.utc)
    current_until = user.premium_until if user else None
    if current_until and current_until > now:
        new_until = current_until + timedelta(days=days)
    else:
        new_until = now + timedelta(days=days)

    await UserRepo.set_premium(session, target_id, new_until)

    # Paket nomini topish
    pkg_name = f"{days} kun"
    for name, d, _ in PREMIUM_PACKAGES:
        if d == days:
            pkg_name = name
            break

    # Foydalanuvchiga xabar
    try:
        await bot.send_message(
            target_id,
            f"🎉 <b>Premium aktivlashtirildi!</b>\n\n"
            f"📦 Paket: <b>{pkg_name}</b>\n"
            f"⏰ Muddati: <b>{new_until.strftime('%d.%m.%Y')}</b>\n\n"
            f"🔓 Cheksiz parollar va fayllar saqlash imkoni ochildi.",
            parse_mode="HTML"
        )
    except Exception:
        pass

    reply_text = (
        f"✅ <b>Premium berildi!</b>\n\n"
        f"👤 ID: <code>{target_id}</code>\n"
        f"📦 Paket: <b>{pkg_name}</b>\n"
        f"⏰ Muddati: <b>{new_until.strftime('%d.%m.%Y %H:%M')}</b> UTC"
    )

    if hasattr(event, "edit_text") and hasattr(event, "message_id"):
        # CallbackQuery.message — edit qilish mumkin
        try:
            await event.edit_text(reply_text, parse_mode="HTML", reply_markup=kb.admin_kb())
        except Exception:
            await event.answer(reply_text, parse_mode="HTML", reply_markup=kb.admin_kb())
    else:
        # Message — yangi xabar yuborish
        await event.answer(reply_text, parse_mode="HTML", reply_markup=kb.admin_kb())

    await state.set_state(None)


# ─────────────────────────────────────────────────────────────────────────────
# BROADCAST — Asinxron xavfsiz reklama yuborish
# ─────────────────────────────────────────────────────────────────────────────

@router.callback_query(F.data == "admin:broadcast")
async def broadcast_start(call: CallbackQuery, state: FSMContext):
    if not is_admin(call.from_user.id):
        await call.answer("⛔ Ruxsat yo'q!", show_alert=True)
        return

    await call.message.edit_text(
        "📢 <b>Broadcast — Reklama Yuborish</b>\n\n"
        "Barcha foydalanuvchilarga yuboriladigan xabarni kiriting:\n"
        "(Matn, rasm yoki video bo'lishi mumkin)",
        parse_mode="HTML",
        reply_markup=kb.cancel_kb()
    )
    await state.set_state(AdminBroadcast.waiting_for_message)


@router.message(AdminBroadcast.waiting_for_message)
async def broadcast_preview(message: Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return

    # Xabar ID sini saqlash (forward uchun)
    await state.update_data(
        broadcast_msg_id=message.message_id,
        broadcast_chat_id=message.chat.id
    )

    await message.answer(
        "👁️ Yuqoridagi xabar barcha foydalanuvchilarga yuboriladi.\n\n"
        "✅ Tasdiqlaysizmi?",
        reply_markup=kb.confirm_kb("broadcast:confirm", "action:cancel")
    )
    await state.set_state(AdminBroadcast.waiting_for_confirm)


@router.callback_query(F.data == "broadcast:confirm", AdminBroadcast.waiting_for_confirm)
async def broadcast_execute(call: CallbackQuery, state: FSMContext, bot: Bot):
    """
    Asinxron broadcast: har foydalanuvchiga ketma-ket yuboradi.
    Rate limit: Telegram 30 msg/sec, biz 20/sec ishlatamiz (xavfsizlik chegarasi).
    Bloklaganlar avtomatik o'tkazib yuboriladi.
    """
    if not is_admin(call.from_user.id):
        await call.answer("⛔ Ruxsat yo'q!", show_alert=True)
        return

    data = await state.get_data()
    src_msg_id = data.get("broadcast_msg_id")
    src_chat_id = data.get("broadcast_chat_id")

    await call.message.edit_text("⏳ Broadcast boshlandi...")
    await state.set_state(None)

    # Foydalanuvchilar ro'yxatini olish (alohida sessiya)
    async with AsyncSessionFactory() as session:
        result = await session.execute(select(User.id))
        user_ids = [row[0] for row in result.all()]

    total = len(user_ids)
    sent = 0
    failed = 0

    for user_id in user_ids:
        try:
            # Xabarni forward qilish (asl formatni saqlaydi)
            await bot.forward_message(
                chat_id=user_id,
                from_chat_id=src_chat_id,
                message_id=src_msg_id
            )
            sent += 1
        except Exception:
            # Bot bloklangan, foydalanuvchi mavjud emas — o'tkazib yuboriladi
            failed += 1

        # Rate limiting: Telegram flood'dan himoya
        # 30 msg/sec maksimum, biz 20 ishlatamiz
        if (sent + failed) % 20 == 0:
            await asyncio.sleep(1)

    await bot.send_message(
        call.from_user.id,
        f"✅ <b>Broadcast tugadi!</b>\n\n"
        f"👥 Jami: {total}\n"
        f"✅ Yuborildi: {sent}\n"
        f"❌ Xato: {failed}",
        parse_mode="HTML",
        reply_markup=kb.admin_kb()
    )
