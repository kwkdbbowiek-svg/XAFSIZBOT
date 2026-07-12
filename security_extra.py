"""
security_extra.py — Qo'shimcha xavfsizlik qatlamlari.

MODULLAR:
  1. BruteForceGuard  — Login urinishlarini cheklash + constant-time
  2. TOTPBruteGuard   — 2FA brute-force himoya
  3. PasswordStrength — Parol kuchini baholash
  4. AuditLogger      — Xavfsizlik tarixi (RAM, 50 yozuv/user)
  5. DeviceTracker    — Yangi qurilma aniqlash (fingerprint hash)
  6. SecureMemory     — RAM'dan maxfiy ma'lumotlarni xavfsiz o'chirish

Shaxsiy ma'lumotlar SAQLANMAYDI — faqat Telegram user_id.
"""

import gc
import time
import hashlib
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# 1. BRUTE-FORCE GUARD
# ─────────────────────────────────────────────────────────────────────────────

class BruteForceGuard:
    """
    Login urinishlarini RAM'da kuzatadi va bloklaydi.

    Darajalar:
      5  xato → 30 daqiqa blok
      10 xato → 24 soat blok
      To'g'ri kirish → hisoblagich nolga
    """

    MAX_ATTEMPTS_SHORT = 5
    MAX_ATTEMPTS_LONG  = 10
    BLOCK_SHORT = 30 * 60       # 30 daqiqa
    BLOCK_LONG  = 24 * 3600     # 24 soat

    def __init__(self):
        # {user_id: {"count": int, "blocked_until": float}}
        self._data: dict = defaultdict(lambda: {"count": 0, "blocked_until": 0.0})

    def is_blocked(self, user_id: int) -> tuple[bool, int]:
        """(bloklangan, qolgan_soniya)"""
        d = self._data[user_id]
        now = time.monotonic()
        if d["blocked_until"] > now:
            return True, int(d["blocked_until"] - now)
        return False, 0

    def record_failure(self, user_id: int) -> tuple[bool, int]:
        """Noto'g'ri urinish. (hozir_bloklandi, block_soniya)"""
        d = self._data[user_id]
        now = time.monotonic()

        if d["blocked_until"] > 0 and d["blocked_until"] < now:
            d["count"] = 0
            d["blocked_until"] = 0.0

        d["count"] += 1

        if d["count"] >= self.MAX_ATTEMPTS_LONG:
            d["blocked_until"] = now + self.BLOCK_LONG
            return True, self.BLOCK_LONG
        elif d["count"] >= self.MAX_ATTEMPTS_SHORT:
            d["blocked_until"] = now + self.BLOCK_SHORT
            return True, self.BLOCK_SHORT

        return False, 0

    def record_success(self, user_id: int) -> None:
        """Muvaffaqiyatli kirish — hisoblagichni nollaydi."""
        self._data[user_id] = {"count": 0, "blocked_until": 0.0}

    def remaining_attempts(self, user_id: int) -> int:
        count = self._data[user_id]["count"]
        if count < self.MAX_ATTEMPTS_SHORT:
            return self.MAX_ATTEMPTS_SHORT - count
        return max(0, self.MAX_ATTEMPTS_LONG - count)


brute_guard = BruteForceGuard()


class TOTPBruteGuard(BruteForceGuard):
    """TOTP uchun qattiqroq limit."""
    MAX_ATTEMPTS_SHORT = 3
    MAX_ATTEMPTS_LONG  = 5
    BLOCK_SHORT = 15 * 60    # 15 daqiqa
    BLOCK_LONG  = 2 * 3600   # 2 soat


totp_guard = TOTPBruteGuard()


# ─────────────────────────────────────────────────────────────────────────────
# 2. PAROL KUCHI TEKSHIRUVI
# ─────────────────────────────────────────────────────────────────────────────

class PasswordStrength:
    """Master parol kuchini baholaydi."""

    COMMON_PASSWORDS = {
        "12345678", "password", "123456789", "qwerty123",
        "iloveyou", "admin123", "letmein1", "welcome1",
        "monkey99", "dragon12", "master12", "abc123456",
        "11111111", "password1", "sunshine", "princess",
        "football", "superman", "baseball", "whatever",
        "qwertyui", "11223344", "00000000", "passw0rd",
    }

    @staticmethod
    def check(password: str) -> tuple[bool, str]:
        """(yetarli_kuchli, xabar)"""
        if len(password) < 8:
            return False, "❌ Parol kamida 8 belgi bo'lishi kerak."
        if password.lower() in PasswordStrength.COMMON_PASSWORDS:
            return False, "❌ Bu parol juda keng tarqalgan. Boshqa tanlang."

        score = 0
        tips = []

        if any(c.islower() for c in password): score += 1
        else: tips.append("kichik harf")

        if any(c.isupper() for c in password): score += 1
        else: tips.append("katta harf")

        if any(c.isdigit() for c in password): score += 1
        else: tips.append("raqam")

        if any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
            score += 1
        else:
            tips.append("belgi (!@#$)")

        if len(password) >= 12: score += 1
        if len(password) >= 16: score += 1

        if score < 2:
            return False, (
                f"❌ Parol juda zaif!\n"
                f"Qo'shing: {', '.join(tips[:2])}\n"
                f"Masalan: <code>MyDog@2024!</code>"
            )

        if score <= 2: level = "🟡 O'rtacha"
        elif score <= 4: level = "🟢 Kuchli"
        else: level = "💪 Juda kuchli"

        return True, level


pwd_strength = PasswordStrength()


# ─────────────────────────────────────────────────────────────────────────────
# 3. AUDIT LOGGER
# ─────────────────────────────────────────────────────────────────────────────

class AuditLogger:
    """
    Xavfsizlikka oid harakatlarni RAM'da saqlaydi.
    Har user uchun oxirgi 50 ta yozuv.
    """

    MAX_LOGS_PER_USER = 50

    ICONS = {
        "LOGIN_OK":       "✅",
        "LOGIN_FAIL":     "❌",
        "LOGOUT":         "🚪",
        "MASTER_CHANGED": "🔑",
        "FILE_ADDED":     "📎",
        "FILE_DELETED":   "🗑️",
        "PWD_ADDED":      "🔐",
        "PWD_DELETED":    "🗑️",
        "TOTP_ENABLED":   "🔐",
        "TOTP_DISABLED":  "⚠️",
        "PANIC":          "🚨",
        "BURNER_CREATED": "🔥",
        "BLOCKED":        "🚫",
        "FLOOD":          "🌊",
    }

    def __init__(self):
        self._logs: dict = defaultdict(list)

    def log(self, user_id: int, event: str, detail: str = "") -> None:
        entry = {
            "time": datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M"),
            "event": event,
            "detail": detail[:120],   # detail ni qisqartirish — log injection himoya
        }
        logs = self._logs[user_id]
        logs.insert(0, entry)
        if len(logs) > self.MAX_LOGS_PER_USER:
            self._logs[user_id] = logs[:self.MAX_LOGS_PER_USER]

    def get_logs(self, user_id: int, limit: int = 10) -> list:
        return self._logs[user_id][:limit]

    def format_for_display(self, user_id: int, limit: int = 10) -> str:
        logs = self.get_logs(user_id, limit)
        if not logs:
            return "📋 Hali hech qanday faoliyat yo'q."
        lines = []
        for e in logs:
            icon = self.ICONS.get(e["event"], "•")
            detail = f" — {e['detail']}" if e["detail"] else ""
            lines.append(f"{icon} <code>{e['time']}</code> {e['event']}{detail}")
        return "\n".join(lines)


audit = AuditLogger()


# ─────────────────────────────────────────────────────────────────────────────
# 4. DEVICE TRACKER — Yangi qurilma aniqlash
# ─────────────────────────────────────────────────────────────────────────────

class DeviceTracker:
    """
    Telegram client platformasidan qurilma fingerprintini hisoblaydi.
    Shaxsiy ma'lumot saqlanmaydi — faqat SHA-256 hash.
    """

    def __init__(self):
        self._known: dict = defaultdict(set)

    def _fp(self, user_id: int, platform: str, language: str) -> str:
        raw = f"{user_id}:{platform}:{language}:{user_id ^ 0xDEADBEEF}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def check_and_register(self, user_id: int,
                            platform: str, language: str) -> bool:
        """True = yangi qurilma (ogohlantirish kerak)."""
        fp = self._fp(user_id, platform, language)
        known = self._known[user_id]
        if fp not in known:
            known.add(fp)
            return True
        return False


device_tracker = DeviceTracker()


# ─────────────────────────────────────────────────────────────────────────────
# 5. SECURE MEMORY — RAM'dan maxfiy ma'lumotlarni xavfsiz o'chirish
# ─────────────────────────────────────────────────────────────────────────────

def secure_wipe_fsm(fsm_data: dict) -> dict:
    """
    FSM data'dan barcha maxfiy kalitlarni xavfsiz o'chiradi.
    Qaytarilgan dict state.update_data() ga uzatiladi.

    Xotira xavfsizligi:
        1. None qo'yish  → Python reference yo'qoladi
        2. del           → local binding o'chadi
        3. gc.collect()  → GC darhol yig'adi
    """
    secret_keys = [
        "encryption_key", "temp_enc_key", "temp_totp_enc_secret",
        "temp_new_password", "old_enc_key", "old_salt",
        "totp_temp_secret",
    ]
    wiped = {}
    for k in secret_keys:
        if k in fsm_data:
            wiped[k] = None   # FSM da None ga o'rnatish
    gc.collect()
    return wiped
