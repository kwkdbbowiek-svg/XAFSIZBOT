"""
keyboards.py — Telegram inline va reply klaviaturalari.
"""

from aiogram.types import (
    InlineKeyboardMarkup, InlineKeyboardButton,
    ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
)
from aiogram.utils.keyboard import InlineKeyboardBuilder


def main_menu_kb(has_master: bool = True) -> InlineKeyboardMarkup:
    """Asosiy menyu."""
    builder = InlineKeyboardBuilder()
    if has_master:
        builder.row(
            InlineKeyboardButton(text="🔑 Parollar", callback_data="menu:passwords"),
            InlineKeyboardButton(text="📁 Fayllar", callback_data="menu:files"),
        )
        builder.row(
            InlineKeyboardButton(text="🔥 Burner havola", callback_data="menu:burner"),
            InlineKeyboardButton(text="🔐 2FA", callback_data="menu:totp"),
        )
        builder.row(
            InlineKeyboardButton(text="🏛️ Merosxo'rlik", callback_data="menu:legacy"),
            InlineKeyboardButton(text="⚙️ Sozlamalar", callback_data="menu:settings"),
        )
        builder.row(
            InlineKeyboardButton(text="ℹ️ Bot haqida", callback_data="menu:about"),
            InlineKeyboardButton(text="🚪 Chiqish", callback_data="menu:logout"),
        )
    else:
        builder.row(
            InlineKeyboardButton(text="🔒 Master Parol O'rnatish", callback_data="setup:master"),
        )
        builder.row(
            InlineKeyboardButton(text="ℹ️ Bot haqida", callback_data="menu:about"),
        )
    return builder.as_markup()


def password_list_kb(passwords: list, has_more: bool = False) -> InlineKeyboardMarkup:
    """Parollar ro'yxati klaviaturasi."""
    builder = InlineKeyboardBuilder()
    for pwd in passwords:
        builder.row(
            InlineKeyboardButton(
                text=f"🔑 #{pwd['id']}",
                callback_data=f"pwd:view:{pwd['id']}"
            )
        )
    builder.row(
        InlineKeyboardButton(text="➕ Yangi parol", callback_data="pwd:add"),
        InlineKeyboardButton(text="🏠 Menyu", callback_data="menu:main"),
    )
    return builder.as_markup()


def password_detail_kb(pwd_id: int) -> InlineKeyboardMarkup:
    """Parol tafsilotlari klaviaturasi."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text="🗑️ O'chirish", callback_data=f"pwd:delete:{pwd_id}"),
        InlineKeyboardButton(text="◀️ Orqaga", callback_data="menu:passwords"),
    )
    return builder.as_markup()


def file_list_kb(files: list) -> InlineKeyboardMarkup:
    """Fayllar ro'yxati."""
    builder = InlineKeyboardBuilder()
    for f in files:
        builder.row(
            InlineKeyboardButton(
                text=f"📄 #{f['id']} ({f['size']})",
                callback_data=f"file:download:{f['id']}"
            )
        )
    builder.row(
        InlineKeyboardButton(text="📤 Fayl yuklash", callback_data="file:upload"),
        InlineKeyboardButton(text="🏠 Menyu", callback_data="menu:main"),
    )
    return builder.as_markup()


def file_detail_kb(file_id: int) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text="⬇️ Yuklab olish", callback_data=f"file:download:{file_id}"),
        InlineKeyboardButton(text="🗑️ O'chirish", callback_data=f"file:delete:{file_id}"),
    )
    builder.row(
        InlineKeyboardButton(text="◀️ Orqaga", callback_data="menu:files"),
    )
    return builder.as_markup()


def confirm_kb(yes_data: str, no_data: str) -> InlineKeyboardMarkup:
    """Tasdiqlash dialogı."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text="✅ Ha", callback_data=yes_data),
        InlineKeyboardButton(text="❌ Yo'q", callback_data=no_data),
    )
    return builder.as_markup()


def settings_kb(has_totp: bool = False) -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text="🔑 Parolni o'zgartirish", callback_data="settings:change_pwd"),
        InlineKeyboardButton(text="📋 Faoliyat logi", callback_data="settings:log"),
    )
    if has_totp:
        builder.row(
            InlineKeyboardButton(text="🔐 2FA o'chirish", callback_data="settings:disable_totp"),
        )
    else:
        builder.row(
            InlineKeyboardButton(text="🔐 2FA yoqish", callback_data="settings:enable_totp"),
        )
    builder.row(
        InlineKeyboardButton(text="🏛️ Merosxo'rlik", callback_data="menu:legacy"),
        InlineKeyboardButton(text="🚨 Panic", callback_data="settings:panic"),
    )
    builder.row(
        InlineKeyboardButton(text="◀️ Orqaga", callback_data="menu:main"),
    )
    return builder.as_markup()


def admin_kb() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text="📊 Statistika", callback_data="admin:stats"),
        InlineKeyboardButton(text="👑 Premium berish", callback_data="admin:premium"),
    )
    builder.row(
        InlineKeyboardButton(text="📢 Reklama yuborish", callback_data="admin:broadcast"),
    )
    return builder.as_markup()


def cancel_kb() -> InlineKeyboardMarkup:
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(text="❌ Bekor qilish", callback_data="action:cancel"),
    )
    return builder.as_markup()


def remove_kb() -> ReplyKeyboardRemove:
    return ReplyKeyboardRemove()
