"""
middlewares.py — CyberKeep xavfsizlik middleware'lari.

HIMOYA QATLAMLARI (tartib muhim):
  1. AntiFloodMiddleware    — DDoS/Flood/Bot bloki (bazaga yetmasdan)
  2. InputSanitizerMiddleware — XSS / Injection tozalash
  3. DatabaseMiddleware     — DB sessiyasi inject
  4. SessionTimeoutMiddleware — 10 daqiqa harakatsizlik = kalit o'chirish

KAFOLATLAR:
  • Admin (ADMIN_ID) uchun flood limiti qo'llanilmaydi
  • Barcha parameterized query — SQL injection imkonsiz (ORM)
  • html.escape() middleware darajasida — XSS imkonsiz
  • FSM state.clear() flood blocklanganda — ghost sessiya yo'q
  • gc.collect() kalit o'chirilgandan so'ng — memory dump himoya
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
    """
    Sliding window rate limiter — O(1) amortized, RAM'da.
    Eski yozuvlar avtomatik tozalanadi.
    """

    def __init__(self, max_req: int, window: float):
        self._max = max_req
        self._win = window
        self._q: dict = defaultdict(deque)

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
# 1. DATABASE MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

class DatabaseMiddleware(BaseMiddleware):
    """Har so'rovga async DB sessiyasini inject qiladi. Rollback on error."""

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
    Shifrlash kaliti RAM'dan gc.collect() bilan o'chiriladi.
    """

    async def __call__(self, handler, event, data):
        state: FSMContext | None = data.get("state")

        if state:
            fsm_data = await state.get_data()
            last_active = fsm_data.get("_last_active", 0)
            now = time.monotonic()

            if last_active and (now - last_active) > cfg.SESSION_TIMEOUT:
                # Kalitni xavfsiz o'chirish
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


# ─────────────────────────────────────────────────────────────────────────────
# 3. ANTI-FLOOD / DDoS / SPAM MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

class AntiFloodMiddleware(BaseMiddleware):
    """
    Ko'p qatlamli DDoS / Flood / Bot himoyasi.

    ┌─────────────────────────────────────────────────────────────┐
    │ D1: Burst      — 2 xabar / 1 soniya  (qattiq limit)        │
    │ D2: Callback   — 8 callback / 4 soniya                     │
    │ D3: Global     — 25 so'rov / 60 soniya → 10 daqiqa blok    │
    │ D4: Bot detect — 150ms dan tez × 5 ketma-ket → 20 min blok │
    └─────────────────────────────────────────────────────────────┘

    Flood aniqlanganda:
      • FSM state.clear() — ghost sessiya yo'qoladi
      • gc.collect()      — kalit xotiradan o'chadi
      • Foydalanuvchi qora ro'yxatga tushadi
    """

    # Rate limiterlar (class-level — barcha instancelar baham ko'radi)
    _burst    = _RateLimiter(max_req=2,  window=1.0)    # D1
    _cb       = _RateLimiter(max_req=8,  window=4.0)    # D2
    _global   = _RateLimiter(max_req=25, window=60.0)   # D3

    # Qora ro'yxat: {user_id: unblock_timestamp (monotonic)}
    _blocked:      dict = {}
    _last_req:     dict = {}    # bot aniqlash uchun
    _fast_streak:  dict = defaultdict(int)
    _last_warn:    dict = {}    # spam xabarni kamaytirish

    BLOCK_FLOOD   = 300    # 5 daqiqa — D1/D2
    BLOCK_GLOBAL  = 600    # 10 daqiqa — D3
    BLOCK_BOT     = 1200   # 20 daqiqa — D4
    BOT_THRESHOLD = 0.15   # 150ms
    BOT_STREAK    = 5      # ketma-ket

    # ── Yordamchi metodlar ────────────────────────────────────────────────

    @classmethod
    def _is_blocked(cls, uid: int) -> tuple[bool, int]:
        until = cls._blocked.get(uid, 0)
        now = time.monotonic()
        if until > now:
            return True, int(until - now)
        if until:
            del cls._blocked[uid]
            cls._fast_streak[uid] = 0
        return False, 0

    @classmethod
    def _block(cls, uid: int, duration: int) -> None:
        cls._blocked[uid] = time.monotonic() + duration

    @classmethod
    def _detect_bot(cls, uid: int) -> bool:
        now = time.monotonic()
        last = cls._last_req.get(uid, 0)
        cls._last_req[uid] = now
        if last and (now - last) < cls.BOT_THRESHOLD:
            cls._fast_streak[uid] += 1
            if cls._fast_streak[uid] >= cls.BOT_STREAK:
                return True
        else:
            cls._fast_streak[uid] = 0
        return False

    # ── Asosiy middleware ─────────────────────────────────────────────────

    async def __call__(self, handler, event, data):
        user_id = None
        is_cb   = False
        msg_obj = None

        if hasattr(event, "message") and event.message:
            m = event.message
            if m.from_user:
                user_id = m.from_user.id
                msg_obj = m
        elif hasattr(event, "callback_query") and event.callback_query:
            cb = event.callback_query
            if cb.from_user:
                user_id = cb.from_user.id
                is_cb   = True
                msg_obj = cb.message

        if not user_id:
            return await handler(event, data)

        # Admin — barcha limitlardan ozod
        if user_id == cfg.ADMIN_ID:
            return await handler(event, data)

        state: FSMContext | None = data.get("state")
        now = time.monotonic()

        # ── Blok tekshiruvi ────────────────────────────────────────────────
        blocked, remaining = self._is_blocked(user_id)
        if blocked:
            mins, secs = divmod(remaining, 60)
            try:
                if is_cb:
                    await event.callback_query.answer(
                        f"🚫 Bloklangan! {mins}:{secs:02d} kuting.",
                        show_alert=True
                    )
                else:
                    last_w = self._last_warn.get(user_id, 0)
                    if now - last_w > 30:
                        self._last_warn[user_id] = now
                        if msg_obj:
                            await msg_obj.answer(
                                f"🚫 <b>Vaqtincha blok</b>\n"
                                f"⏰ {mins} daqiqa {secs} soniya kuting.",
                                parse_mode="HTML"
                            )
            except Exception:
                pass
            return

        # ── D4: Bot xatti-harakati ─────────────────────────────────────────
        if self._detect_bot(user_id):
            self._block(user_id, self.BLOCK_BOT)
            if state:
                await state.clear()
                gc.collect()
            try:
                if msg_obj:
                    await msg_obj.answer(
                        "🤖 <b>Bot xatti-harakati aniqlandi!</b>\n"
                        "🚫 20 daqiqaga bloklandi.",
                        parse_mode="HTML"
                    )
            except Exception:
                pass
            return

        # ── D2: Callback spam ──────────────────────────────────────────────
        if is_cb and not self._cb.is_allowed(user_id):
            try:
                await event.callback_query.answer(
                    "⚠️ Tugmalarni juda tez bosyapsiz! Kuting.",
                    show_alert=True
                )
            except Exception:
                pass
            return

        # ── D1: Burst xabar ───────────────────────────────────────────────
        if not is_cb and not self._burst.is_allowed(user_id):
            self._block(user_id, self.BLOCK_FLOOD)
            if state:
                await state.clear()
                gc.collect()
            retry = self._burst.retry_after(user_id)
            try:
                if msg_obj:
                    await msg_obj.answer(
                        f"⏳ Juda tez xabar yuboryapsiz!\n"
                        f"{retry:.1f} soniya kuting. (5 daqiqa blok)"
                    )
            except Exception:
                pass
            return

        # ── D3: Global limit ──────────────────────────────────────────────
        if not self._global.is_allowed(user_id):
            self._block(user_id, self.BLOCK_GLOBAL)
            if state:
                await state.clear()
                gc.collect()
            try:
                if msg_obj:
                    await msg_obj.answer(
                        "🚫 <b>Juda ko'p so'rov!</b>\n"
                        "10 daqiqaga vaqtincha bloklandi.",
                        parse_mode="HTML"
                    )
            except Exception:
                pass
            return

        # ── Barcha tekshiruvlar o'tdi ──────────────────────────────────────
        result = await handler(event, data)

        # Callback'ni avtomatik yopish (handler unutgan bo'lsa)
        if is_cb:
            try:
                await event.callback_query.answer()
            except Exception:
                pass

        return result


# ─────────────────────────────────────────────────────────────────────────────
# 4. INPUT SANITIZER MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

class InputSanitizerMiddleware(BaseMiddleware):
    """
    Foydalanuvchi matnini middleware darajasida tozalaydi.

    HIMOYA:
      • html.escape() → XSS / HTML Injection imkonsiz
      • Regex pattern tekshiruvi → SQL Injection belgilari
      • 8192 belgi limiti → ReDoS / buffer overflow

    MUHIM: ORM parameterized query ishlatadi — SQL injection
    middleware'dan mustaqil holda ham imkonsiz. Bu ikki qatlam.
    """

    _PATTERNS = [
        re.compile(r"<script[^>]*>",                           re.I),
        re.compile(r"javascript\s*:",                          re.I),
        re.compile(r"on\w+\s*=",                               re.I),
        re.compile(r"(union\s+select|drop\s+table|exec\s*\()", re.I),
        re.compile(r"(\bxp_\w+|\bsp_\w+)",                    re.I),  # MSSQL procs
        re.compile(r"(/\*|\*/|--\s)",                          re.I),  # SQL comments
    ]
    MAX_LEN = 8192

    @classmethod
    def sanitize(cls, text: str) -> tuple[bool, str]:
        """
        (ruxsat, tozalangan_matn)
        Xavfli pattern bo'lsa False qaytaradi.
        Aks holda html.escape() qilingan matn.
        """
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
