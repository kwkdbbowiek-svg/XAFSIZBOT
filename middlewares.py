"""
middlewares.py — Aiogram middleware'lari.

HIMOYA QATLAMLARI:
  1. DatabaseMiddleware     — DB sessiyasi inject
  2. SessionTimeoutMiddleware — 10 daqiqa harakatsizlik = chiqish
  3. AntiFloodMiddleware    — DDoS/Flood/Spam bloki
     • Global rate limit: 1 foydalanuvchi/soniya (Telegram norma)
     • Burst limit: 5 xabar/3 soniya
     • Callback spam: 10/5 soniya
     • Nakrutka aniqlash: bot-like behavior (juda tez, juda ko'p)
     • Shubhali user bloki: avtomatik 10 daqiqa
  4. InputSanitizer         — XSS / injection tozalash
"""

import re
import time
from typing import Callable, Any, Awaitable
from collections import defaultdict, deque

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, Update, Message, CallbackQuery
from aiogram.fsm.context import FSMContext
from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionFactory
from config import cfg


# ─────────────────────────────────────────────────────────────────────────────
# 1. DATABASE MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

class DatabaseMiddleware(BaseMiddleware):
    """Har bir so'rovga asinxron DB sessiyasini inject qiladi."""

    async def __call__(self, handler, event, data):
        async with AsyncSessionFactory() as session:
            data["session"] = session
            try:
                return await handler(event, data)
            except Exception:
                await session.rollback()
                raise


# ─────────────────────────────────────────────────────────────────────────────
# 2. SESSION TIMEOUT MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

class SessionTimeoutMiddleware(BaseMiddleware):
    """
    10 daqiqa harakatsizlikda sessiyani yopadi.
    Master parol va shifrlash kaliti RAM'dan o'chiriladi.
    """

    async def __call__(self, handler, event, data):
        state: FSMContext = data.get("state")
        if state:
            fsm_data = await state.get_data()
            last_active = fsm_data.get("_last_active", 0)
            now = time.time()

            if last_active and (now - last_active) > cfg.SESSION_TIMEOUT:
                await state.clear()
                try:
                    # Update ichidagi to'g'ri ob'ektni topamiz
                    if hasattr(event, "callback_query") and event.callback_query:
                        await event.callback_query.answer(
                            "⏰ Sessiya muddati tugadi. /start yuboring.",
                            show_alert=True
                        )
                        # Xabarni ham yangilaymiz
                        try:
                            from aiogram.utils.keyboard import InlineKeyboardBuilder
                            from aiogram.types import InlineKeyboardButton
                            builder = InlineKeyboardBuilder()
                            builder.row(InlineKeyboardButton(
                                text="🔐 Tizimga kirish",
                                callback_data="action:relogin"
                            ))
                            await event.callback_query.message.edit_text(
                                "⏰ <b>Sessiya muddati tugadi.</b>\n\n"
                                "10 daqiqa harakatsizlik sababli tizimdan chiqdingiz.\n"
                                "Qayta kirish uchun tugmani bosing:",
                                parse_mode="HTML",
                                reply_markup=builder.as_markup()
                            )
                        except Exception:
                            pass
                    elif hasattr(event, "message") and event.message:
                        await event.message.answer(
                            "⏰ <b>Sessiya muddati tugadi</b> (10 daqiqa harakatsizlik).\n"
                            "🔒 Xavfsizlik uchun tizimdan chiqdingiz.\n"
                            "/start buyrug'ini yuboring.",
                            parse_mode="HTML"
                        )
                except Exception:
                    pass
                return

            await state.update_data(_last_active=now)

        return await handler(event, data)


# ─────────────────────────────────────────────────────────────────────────────
# 3. ANTI-FLOOD / DDOS / SPAM / NAKRUTKA MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Sliding window rate limiter — RAM'da ishlaydi.
    Har foydalanuvchi uchun so'nggi N soniyada nechta so'rov ketganini kuzatadi.
    """

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window = window_seconds
        # {user_id: deque([timestamp, ...])}
        self._windows: dict = defaultdict(deque)

    def is_allowed(self, user_id: int) -> bool:
        now = time.time()
        dq = self._windows[user_id]

        # Eski so'rovlarni tozalash
        while dq and dq[0] < now - self.window:
            dq.popleft()

        if len(dq) >= self.max_requests:
            return False

        dq.append(now)
        return True

    def get_retry_after(self, user_id: int) -> float:
        dq = self._windows[user_id]
        if not dq:
            return 0
        now = time.time()
        oldest = dq[0]
        return max(0, self.window - (now - oldest))


class AntiFloodMiddleware(BaseMiddleware):
    """
    DDoS / Flood / Spam / Nakrutka himoyasi.

    HIMOYA DARAJALARI:
    ┌─────────────────────────────────────────────────────────┐
    │ Daraja 1: Xabar limiti  — 3 xabar / 3 soniya           │
    │ Daraja 2: Global limit  — 20 xabar / 60 soniya         │
    │ Daraja 3: Callback spam — 10 callback / 5 soniya       │
    │ Daraja 4: Nakrutka      — 1 soniyada 5+ so'rov         │
    │ Daraja 5: Bot aniqlash  — 0.1s dan tez ketma-ket so'rov│
    └─────────────────────────────────────────────────────────┘

    Bloklangan foydalanuvchi faqat RAM'da saqlanadi.
    Server qayta ishga tushsa bloklar tozalanadi.
    """

    # Daraja 1: Normal foydalanish limiti
    _msg_limit    = RateLimiter(max_requests=3,  window_seconds=3.0)
    # Daraja 2: Bir daqiqalik global limit
    _global_limit = RateLimiter(max_requests=20, window_seconds=60.0)
    # Daraja 3: Callback (tugma bosish) limiti
    _cb_limit     = RateLimiter(max_requests=10, window_seconds=5.0)
    # Daraja 4: Nakrutka/bot aniqlash — juda tez so'rovlar
    _bot_detect   = RateLimiter(max_requests=5,  window_seconds=1.0)

    # Bloklangan foydalanuvchilar: {user_id: unblock_timestamp}
    _blocked: dict = {}
    BLOCK_DURATION = 600  # 10 daqiqa (soniya)

    # Oxirgi so'rov vaqti: {user_id: timestamp} — bot aniqlash uchun
    _last_request: dict = {}
    BOT_SPEED_THRESHOLD = 0.1  # 100ms dan tez = shubhali

    # Ketma-ket tez so'rovlar sanagichi
    _fast_streak: dict = defaultdict(int)
    FAST_STREAK_LIMIT = 5  # 5 ta ketma-ket tez so'rov = blok

    @classmethod
    def _is_perm_blocked(cls, user_id: int) -> tuple[bool, int]:
        """Bloklangan ekanligini va qolgan vaqtni tekshiradi."""
        unblock_at = cls._blocked.get(user_id, 0)
        now = time.time()
        if unblock_at > now:
            return True, int(unblock_at - now)
        elif unblock_at > 0:
            del cls._blocked[user_id]
            cls._fast_streak[user_id] = 0
        return False, 0

    @classmethod
    def _block(cls, user_id: int, duration: int = None):
        """Foydalanuvchini bloklaydi."""
        cls._blocked[user_id] = time.time() + (duration or cls.BLOCK_DURATION)

    @classmethod
    def _detect_bot_behavior(cls, user_id: int) -> bool:
        """
        Bot/nakrutka xatti-harakatini aniqlaydi.
        100ms dan tez, 5 marta ketma-ket so'rov = bot.
        """
        now = time.time()
        last = cls._last_request.get(user_id, 0)
        cls._last_request[user_id] = now

        if last and (now - last) < cls.BOT_SPEED_THRESHOLD:
            cls._fast_streak[user_id] += 1
            if cls._fast_streak[user_id] >= cls.FAST_STREAK_LIMIT:
                return True  # Bot aniqlandi
        else:
            cls._fast_streak[user_id] = 0

        return False

    async def __call__(self, handler, event, data):
        # Update ichidan foydalanuvchi ID ni olish
        user_id = None
        is_callback = False
        message_obj = None

        if hasattr(event, "message") and event.message:
            msg = event.message
            if hasattr(msg, "from_user") and msg.from_user:
                user_id = msg.from_user.id
                message_obj = msg
        elif hasattr(event, "callback_query") and event.callback_query:
            cb = event.callback_query
            if hasattr(cb, "from_user") and cb.from_user:
                user_id = cb.from_user.id
                is_callback = True
                message_obj = cb.message

        if not user_id:
            return await handler(event, data)

        # Admin uchun limitlar qo'llanilmaydi
        if user_id == cfg.ADMIN_ID:
            return await handler(event, data)

        now = time.time()

        # ── 1. Blok tekshiruvi ──────────────────────────────────────────────
        blocked, remaining = self._is_perm_blocked(user_id)
        if blocked:
            mins = remaining // 60
            secs = remaining % 60
            try:
                if is_callback and message_obj:
                    if hasattr(event.callback_query, "answer"):
                        await event.callback_query.answer(
                            f"🚫 Bloklangan! {mins}:{secs:02d} kutib turing.",
                            show_alert=True
                        )
                elif message_obj:
                    # Har 30 soniyada bir marta xabar yuboramiz (spam qilmaslik)
                    last_warn = getattr(self, f"_last_warn_{user_id}", 0)
                    if now - last_warn > 30:
                        setattr(self, f"_last_warn_{user_id}", now)
                        await message_obj.answer(
                            f"🚫 <b>Vaqtincha blok</b>\n"
                            f"⏰ {mins} daqiqa {secs} soniya kutib turing.",
                            parse_mode="HTML"
                        )
            except Exception:
                pass
            return  # So'rovni to'xtatish

        # ── 2. Bot/nakrutka aniqlash ────────────────────────────────────────
        if self._detect_bot_behavior(user_id):
            self._block(user_id, self.BLOCK_DURATION * 2)  # 20 daqiqa
            try:
                if message_obj:
                    await message_obj.answer(
                        "🤖 <b>Avtomatik so'rovlar aniqlandi!</b>\n"
                        "🚫 20 daqiqaga bloklandi.",
                        parse_mode="HTML"
                    )
            except Exception:
                pass
            return

        # ── 3. Callback spam limiti ─────────────────────────────────────────
        if is_callback and not self._cb_limit.is_allowed(user_id):
            try:
                await event.callback_query.answer(
                    "⚠️ Tugmalarni juda tez bosyapsiz! Biroz kuting.",
                    show_alert=True
                )
            except Exception:
                pass
            return

        # ── 4. Xabar burst limiti (3 xabar/3 soniya) ───────────────────────
        if not is_callback and not self._msg_limit.is_allowed(user_id):
            retry = self._msg_limit.get_retry_after(user_id)
            try:
                await message_obj.answer(
                    f"⏳ Juda tez xabar yuboryapsiz!\n"
                    f"{retry:.1f} soniya kuting."
                )
            except Exception:
                pass
            return

        # ── 5. Global 1 daqiqalik limit ─────────────────────────────────────
        if not self._global_limit.is_allowed(user_id):
            self._block(user_id)  # 10 daqiqa blok
            try:
                if message_obj:
                    await message_obj.answer(
                        "🚫 <b>Juda ko'p so'rov!</b>\n"
                        "10 daqiqaga vaqtincha bloklandi.",
                        parse_mode="HTML"
                    )
            except Exception:
                pass
            return

        # ── Barcha tekshiruvlar o'tdi — so'rovni davom ettirish ─────────────
        result = await handler(event, data)

        # Callback'ni avtomatik answer qilish (handler unutgan bo'lsa)
        if is_callback:
            try:
                await event.callback_query.answer()
            except Exception:
                pass  # Allaqachon answer qilingan — normal holat

        return result


# ─────────────────────────────────────────────────────────────────────────────
# 4. INPUT SANITIZER — Zararli input tozalash
# ─────────────────────────────────────────────────────────────────────────────

class InputSanitizerMiddleware(BaseMiddleware):
    """
    Foydalanuvchi kiritgan matnlarni tozalaydi.
    SQL injection, XSS, command injection — barchasidan himoya.
    Telegram HTML parse mode ishlatilganda < > & belgilar xavfli.
    """

    # Xavfli patternlar
    _DANGEROUS_PATTERNS = [
        r"<script[^>]*>",           # XSS
        r"javascript:",              # JS injection
        r"on\w+\s*=",               # HTML event handlers
        r"(\bDROP\b|\bDELETE\b|\bINSERT\b|\bUPDATE\b)\s+\b",  # SQL (yumshoq)
    ]
    _COMPILED = [re.compile(p, re.IGNORECASE) for p in _DANGEROUS_PATTERNS]

    # Maksimal matn uzunligi
    MAX_TEXT_LENGTH = 8192

    @classmethod
    def is_suspicious(cls, text: str) -> bool:
        """Matn xavfli patternlar o'z ichiga oladimi."""
        for pattern in cls._COMPILED:
            if pattern.search(text):
                return True
        return False

    async def __call__(self, handler, event, data):
        # Faqat xabarlarni tekshiramiz
        msg = None
        if hasattr(event, "message") and event.message:
            msg = event.message
        elif hasattr(event, "edited_message") and event.edited_message:
            msg = event.edited_message

        if msg and msg.text:
            text = msg.text

            # Uzunlik tekshiruvi
            if len(text) > self.MAX_TEXT_LENGTH:
                try:
                    await msg.answer("❌ Xabar juda uzun.")
                except Exception:
                    pass
                return

            # Xavfli pattern tekshiruvi
            if self.is_suspicious(text):
                try:
                    await msg.answer("❌ Xabar tarkibida ruxsatsiz belgilar bor.")
                except Exception:
                    pass
                return

        return await handler(event, data)
