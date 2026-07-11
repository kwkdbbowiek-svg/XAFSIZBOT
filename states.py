"""
states.py — Aiogram FSM holatlari (Finite State Machine).

FSM foydalanuvchi sessiyasini boshqaradi.
Master parol va shifrlash kalitlari FAQAT FSM data'sida (RAM'da) saqlanadi,
diskka yozilmaydi.
"""

from aiogram.fsm.state import State, StatesGroup


class MasterPasswordSetup(StatesGroup):
    """Master parolni birinchi marta o'rnatish."""
    waiting_for_password = State()
    waiting_for_confirm = State()


class MasterPasswordLogin(StatesGroup):
    """Master parolni kiritib sessiya ochish."""
    waiting_for_password = State()
    waiting_for_totp = State()   # 2FA yoqilgan bo'lsa


class AddPassword(StatesGroup):
    """Yangi parol qo'shish jarayoni."""
    waiting_for_title = State()
    waiting_for_value = State()
    waiting_for_notes = State()


class AddFile(StatesGroup):
    """Fayl yuklash jarayoni."""
    waiting_for_file = State()


class CreateBurnerLink(StatesGroup):
    """Bir martalik havola yaratish."""
    waiting_for_content = State()
    waiting_for_content_type = State()  # matn yoki fayl tanlash


class SetupTOTP(StatesGroup):
    """2FA sozlash jarayoni."""
    waiting_for_code_confirm = State()


class SetupLegacy(StatesGroup):
    """Raqamli merosxo'rlik sozlash."""
    waiting_for_heir_id = State()
    waiting_for_message = State()
    waiting_for_days = State()


class ChangeMasterPassword(StatesGroup):
    """Master parolni o'zgartirish (mavjud ma'lumotlarni qayta shifrlash bilan)."""
    waiting_for_old_password = State()
    waiting_for_new_password = State()
    waiting_for_new_confirm  = State()


class AdminBroadcast(StatesGroup):
    """Admin: reklama yuborish."""
    waiting_for_message = State()
    waiting_for_confirm = State()


class AdminPremium(StatesGroup):
    """Admin: premium berish."""
    waiting_for_user_id = State()
    waiting_for_days = State()
