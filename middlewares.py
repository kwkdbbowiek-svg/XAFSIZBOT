"""
middlewares.py — CyberKeep xavfsizlik middleware'lari.

HIMOYA QATLAMLARI (tartib muhim — main.py ga shu tartibda qo'shiladi):
  1. AntiFloodMiddleware     — DDoS/Flood/Bot: Silent Drop
  2. InputSanitizerMiddleware — XSS / Injection tozalash
  3. DatabaseMiddleware      — DB sessiyasi inject
  4. SessionTimeoutMiddleware — 10 daqiqa harakatsizlik = kalit o'chirish

SILENT DROP MEXANIZMI:
  • Foydalanuvchi limit buzganida → 1 marta ogohlantirish + blokka qo'shish
  • Bloklangan foydalanuvchi → hech qanday javob yo'q (silent drop)
  • handler() CHAQIRILMAYDI → aiogram "not handled" sifatida ko'radi
  • Telegram API ga hech qanday so'rov ketmaydi → Flood Control xavfi yo'q
"""

import gc
import re
import time
import html as html_module
from collections import defaultdict, deque

from aiogram import BaseMiddleware
from aiogram.types import InlineKeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.fsm.context import FSMContext

from database import AsyncSessionFactory
from config import cfg


# ─────────────────────────────────────────────────────────────────────────────
# YORDAMCHI: Sliding Window Rate Limiter
# ─────────────────────────────────────────────────────────────────────────────

class _RateLimiter:
    """O(1) amortized sliding window. Thread-safe emas — asyncio single-thread."""

    def __init__(self, max_req: int, window: float):
        self._max = max_req
        self._win = window
        self._q: dict[int, deque] = defaultdict(deque)

    def is_allowed(self, uid: int) -> bool:
        now = time.monotonic()
        dq = self._q[uid]
        cutoff = now - self._win
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self._max:
            return False
        dq.append(now)
        return True

    def retry_after(self, uid: int) -> float:
        dq = self._q[uid]
        if not dq:
            return 0.0
        return max(0.0, self._win - (time.monotonic() - dq[0]))


# ─────────────────────────────────────────────────────────────────────────────
# 1. ANTI-FLOOD MIDDLEWARE — Silent Drop
# ─────────────────────────────────────────────────────────────────────────────

class AntiFloodMiddleware(BaseMiddleware):
    """
    Ko'p qatlamli DDoS / Flood / Bot himoyasi.

    QOIDALAR:
    ┌─────────────────────────────────────────────────────────────────┐
    │ D1 Burst      — 2 xabar / 1 soniya   → 5 daqiqa blok          │
    │ D2 Callback   — 8 tugma / 4 soniya   → 5 daqiqa blok          │
    │ D3 Global     — 25 so'rov / 60 soniya → 10 daqiqa blok        │
    │ D4 Bot detect — 150ms dan tez × 5    → 20 daqiqa blok         │
    └─────────────────────────────────────────────────────────────────┘

    SILENT DROP LOGIKASI:
      blok_yangi   = True  → 1 marta ogohlantirish xabari yuboriladi
      blok_yangi   = False → hech narsa yuborilmaydi (silent drop)
      handler()    HECH QACHON chaqirilmaydi bloklangan user uchun

    FSM state.clear() + gc.collect() → RAM'dagi kalit o'chadi
    """

    # ── Rate limiterlar (class-level — barcha instancelar uchun umumiy) ──
    _burst  = _RateLimiter(max_req=2,  window=1.0)
    _cb     = _RateLimiter(max_req=8,  window=4.0)
    _global = _RateLimiter(max_req=25, window=60.0)

    # ── Qora ro'yxat: {user_id: unblock_time (monotonic)} ──────────────
    _blocked: dict[int, float] = {}

    # ── "Birinchi ogohlantirish yuborildi" tracker ──────────────────────
    # {user_id: warned_until_time} — blok davomida faqat 1 marta xabar
    _warned: dict[int, float] = {}

    # ── Bot xatti-harakat aniqlash ──────────────────────────────────────
    _last_req:    dict[int, float] = {}
    _fast_streak: dict[int, int]   = defaultdict(int)

    # ── Konstantalar ────────────────────────────────────────────────────
    BLOCK_FLOOD  = 300    # 5 daqiqa
    BLOCK_GLOBAL = 600    # 10 daqiqa
    BLOCK_BOT    = 1200   # 20 daqiqa
    BOT_THRESHOLD = 0.15  # 150ms
    BOT_STREAK    = 5

    # ── Yordamchi metodlar ───────────────────────────────────────────────

    @classmethod
    def _is_blocked(cls, uid: int) -> bool:
        """Bloklangan ekanligini tekshiradi. Muddati o'tgan bo'lsa tozalaydi."""
        until = cls._blocked.get(uid, 0.0)
        if until > time.monotonic():
            return True
        if until:
            # Muddati tugagan — tozalaymiz
            cls._blocked.pop(uid, None)
            cls._warned.pop(uid, None)
        return False

    @classmethod
    def _block(cls, uid: int, duration: int) -> bool:
        """
        Foydalanuvchini bloklaydi.
        Returns: True — yangi blok (ogohlantirish kerak)
                 False — allaqachon bloklangan edi (silent drop)
        """
        now = time.monotonic()
        already = uid in cls._blocked and cls._blocked[uid] > now
        cls._blocked[uid] = now + duration

        # Ogohlantirish faqat bir marta: yangi blok va hali warn bo'lmagan
        warned_until = cls._warned.get(uid, 0.0)
        if not already and warned_until <= now:
            cls._warned[uid] = now + duration  # blok tugaguncha warn qilingan
            return True   # → xabar yuborilsin
        return False      # → silent drop

    @classmethod
    def _detect_bot(cls, uid: int) -> bool:
        now = time.monotonic()
        last = cls._last_req.get(uid, 0.0)
        cls._last_req[uid] = now
        if last and (now - last) < cls.BOT_THRESHOLD:
            cls._fast_streak[uid] += 1
            if cls._fast_streak[uid] >= cls.BOT_STREAK:
                cls._fast_streak[uid] = 0
                return True
        else:
            cls._fast_streak[uid] = 0
        return False

    # ── Asosiy middleware ────────────────────────────────────────────────

    async def __call__(self, handler, event, data):
        # ── User ID va ob'ektlarni olish ──────────────────────────────
        uid     = None
        is_cb   = False
        msg_obj = None

        if hasattr(event, "message") and event.message:
            m = event.message
            if m.from_user:
                uid     = m.from_user.id
                msg_obj = m
        elif hasattr(event, "callback_query") and event.callback_query:
            cb = event.callback_query
            if cb.from_user:
                uid     = cb.from_user.id
                is_cb   = True
                msg_obj = cb.message

        if not uid:
            return await handler(event, data)

        # ── Admin — barcha limitlardan ozod ──────────────────────────
        if uid == cfg.ADMIN_ID:
            return await handler(event, data)

        state: FSMContext | None = data.get("state")

        # ═══════════════════════════════════════════════════════════════
        # BLOK TEKSHIRUVI — SILENT DROP
        # ═══════════════════════════════════════════════════════════════
        if self._is_blocked(uid):
            # Bloklangan — hech narsa qilmaymiz, handler chaqirilmaydi
            # Telegram'ga hech qanday javob ketmaydi → "Duration 0 ms"
            return   # ← SILENT DROP

        # ═══════════════════════════════════════════════════════════════
        # D4: BOT XATTI-HARAKATI
        # ═══════════════════════════════════════════════════════════════
        if self._detect_bot(uid):
            send_warn = self._block(uid, self.BLOCK_BOT)
            if state:
                await state.clear()
                gc.collect()
            if send_warn and msg_obj:
                try:
                    await msg_obj.answer(
                        "🤖 <b>Avtomatik so'rovlar aniqlandi!</b>\n"
                        "🚫 20 daqiqaga bloklandi. Keyingi xabarlaringiz e'tiborga olinmaydi.",
                        parse_mode="HTML"
                    )
                except Exception:
                    pass
            return   # ← SILENT DROP

        # ═══════════════════════════════════════════════════════════════
        # D2: CALLBACK SPAM
        # ═══════════════════════════════════════════════════════════════
        if is_cb and not self._cb.is_allowed(uid):
            send_warn = self._block(uid, self.BLOCK_FLOOD)
            if state:
                await state.clear()
                gc.collect()
            if send_warn:
                try:
                    await event.callback_query.answer(
                        "⚠️ Tugmalarni juda tez bosyapsiz! 5 daqiqa kuting.",
                        show_alert=True
                    )
                except Exception:
                    pass
            return   # ← SILENT DROP

        # ═══════════════════════════════════════════════════════════════
        # D1: BURST XABAR
        # ═══════════════════════════════════════════════════════════════
        if not is_cb and not self._burst.is_allowed(uid):
            send_warn = self._block(uid, self.BLOCK_FLOOD)
            if state:
                await state.clear()
                gc.collect()
            if send_warn and msg_obj:
                retry = self._burst.retry_after(uid)
                try:
                    await msg_obj.answer(
                        f"⏳ <b>Juda tez xabar yuboryapsiz!</b>\n"
                        f"5 daqiqaga bloklandi. Keyingi xabarlaringiz e'tiborga olinmaydi.\n"
                        f"({retry:.1f} soniya kuting)",
                        parse_mode="HTML"
                    )
                except Exception:
                    pass
            return   # ← SILENT DROP

        # ═══════════════════════════════════════════════════════════════
        # D3: GLOBAL LIMIT
        # ═══════════════════════════════════════════════════════════════
        if not self._global.is_allowed(uid):
            send_warn = self._block(uid, self.BLOCK_GLOBAL)
            if state:
                await state.clear()
                gc.collect()
            if send_warn and msg_obj:
                try:
                    await msg_obj.answer(
                        "🚫 <b>Juda ko'p so'rov!</b>\n"
                        "10 daqiqaga bloklandi. Keyingi xabarlaringiz e'tiborga olinmaydi.",
                        parse_mode="HTML"
                    )
                except Exception:
                    pass
            return   # ← SILENT DROP

        # ═══════════════════════════════════════════════════════════════
        # BARCHA TEKSHIRUVLAR O'TDI — handler ga o'tamiz
        # ═══════════════════════════════════════════════════════════════
        result = await handler(event, data)

        # Callback'ni avtomatik yopish (handler unutgan bo'lsa)
        if is_cb:
            try:
                await event.callback_query.answer()
            except Exception:
                pass

        return result


# ─────────────────────────────────────────────────────────────────────────────
# 2. INPUT SANITIZER MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

class InputSanitizerMiddleware(BaseMiddleware):
    """
    Foydalanuvchi matnini middleware darajasida tozalaydi.

    • html.escape()  → XSS / HTML Injection imkonsiz
    • Regex patterns → SQL Injection belgilari blok
    • 8192 belgi     → buffer overflow / ReDoS himoya

    ORM parameterized query bilan IKKI QATLAM himoya.
    """

    _PATTERNS = [
        re.compile(r"<script[^>]*>",                              re.I),
        re.compile(r"javascript\s*:",                             re.I),
        re.compile(r"on\w+\s*=",                                  re.I),
        re.compile(r"(union\s+select|drop\s+table|exec\s*\()",   re.I),
        re.compile(r"(\bxp_\w+|\bsp_\w+)",                       re.I),
        re.compile(r"(/\*|\*/|--\s)",                             re.I),
    ]
    MAX_LEN = 8192

    @classmethod
    def sanitize(cls, text: str) -> tuple[bool, str]:
        """(ruxsat, tozalangan_matn). Xavfli pattern → (False, '')."""
        if len(text) > cls.MAX_LEN:
            return False, ""
        for p in cls._PATTERNS:
            if p.search(text):
                return False, ""
        return True, html_module.escape(text)

    async def __call__(self, handler, event, data):
        msg = None
        if hasattr(event, "message") and event.message:
            msg = event.message
        elif hasattr(event, "edited_message") and event.edited_message:
            msg = event.edited_message

        if msg and msg.text:
            ok, _ = self.sanitize(msg.text)
            if not ok:
                try:
                    await msg.answer(
                        "❌ Xabar tarkibida ruxsatsiz belgilar bor.\n"
                        "Oddiy matn kiriting."
                    )
                except Exception:
                    pass
                return   # handler chaqirilmaydi

        return await handler(event, data)


# ─────────────────────────────────────────────────────────────────────────────
# 3. DATABASE MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

class DatabaseMiddleware(BaseMiddleware):
    """Har so'rovga async DB sessiyasi inject qiladi. Error → rollback."""

    async def __call__(self, handler, event, data):
        async with AsyncSessionFactory() as session:
            data["session"] = session
            try:
                return await handler(event, data)
            except Exception:
                await session.rollback()
                raise


# ─────────────────────────────────────────────────────────────────────────────
# 4. SESSION TIMEOUT MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

class SessionTimeoutMiddleware(BaseMiddleware):
    """
    10 daqiqa harakatsizlikda sessiyani yopadi.
    Shifrlash kaliti state.clear() + gc.collect() bilan RAM'dan o'chiriladi.
    """

    async def __call__(self, handler, event, data):
        state: FSMContext | None = data.get("state")

        if state:
            fsm_data = await state.get_data()
            last_active = fsm_data.get("_last_active", 0)
            now = time.monotonic()

            if last_active and (now - last_active) > cfg.SESSION_TIMEOUT:
                await state.clear()
                gc.collect()

                try:
                    if hasattr(event, "callback_query") and event.callback_query:
                        await event.callback_query.answer(
                            "⏰ Sessiya tugadi. Qayta kiring.", show_alert=True
                        )
                        try:
                            b = InlineKeyboardBuilder()
                            b.row(InlineKeyboardButton(
                                text="🔐 Tizimga kirish",
                                callback_data="action:relogin"
                            ))
                            await event.callback_query.message.edit_text(
                                "⏰ <b>Sessiya muddati tugadi.</b>\n\n"
                                "10 daqiqa harakatsizlik sababli tizimdan chiqdingiz.\n"
                                "Qayta kirish uchun tugmani bosing:",
                                parse_mode="HTML",
                                reply_markup=b.as_markup()
                            )
                        except Exception:
                            pass
                    elif hasattr(event, "message") and event.message:
                        await event.message.answer(
                            "⏰ <b>Sessiya tugadi</b> (10 daqiqa harakatsizlik).\n"
                            "🔒 Kalit xotiradan o'chirildi. /start yuboring.",
                            parse_mode="HTML"
                        )
                except Exception:
                    pass
                return   # handler chaqirilmaydi

            await state.update_data(_last_active=now)

        return await handler(event, data)
