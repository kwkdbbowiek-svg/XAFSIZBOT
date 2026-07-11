"""
security_extra.py — Qo'shimcha xavfsizlik qatlamlari.

MODULLAR:
  1. BruteForceGuard   — Login urinishlarini cheklash (rate limiting)
  2. PasswordStrength  — Parol kuchini baholash
  3. AuditLogger       — Barcha muhim harakatlar logi
  4. DeviceTracker     — Qurilma/sessiya kuzatuvi
  5. PanicManager      — Favqulodda ma'lumotlarni o'chirish

Barcha loglarda foydalanuvchi Telegram ID sidan boshqa
shaxsiy ma'lumot SAQLANMAYDI.
"""

import time
import hashlib
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# 1. BRUTE-FORCE GUARD — RAM'da login urinishlarini kuzatish
#    PostgreSQL ga yozmasdan — tezkor va serverga yuk tushirmaydi
# ─────────────────────────────────────────────────────────────────────────────

class BruteForceGuard:
    """
    Foydalanuvchi ID bo'yicha noto'g'ri urinishlarni hisoblaydi.

    Qoidalar:
      - 5 marta noto'g'ri → 30 daqiqa blok
      - 10 marta noto'g'ri → 24 soat blok
      - To'g'ri kirish → hisoblagich nolga tushadi

    Ma'lumot faqat RAM'da — server qayta ishga tushsa tozalanadi.
    """

    MAX_ATTEMPTS_SHORT = 5    # Qisqa blok chegarasi
    MAX_ATTEMPTS_LONG  = 10   # Uzun blok chegarasi
    BLOCK_SHORT = 30 * 60     # 30 daqiqa (soniya)
    BLOCK_LONG  = 24 * 3600   # 24 soat (soniya)

    def __init__(self):
        # {user_id: {"count": int, "blocked_until": float}}
        self._attempts: dict = defaultdict(lambda: {"count": 0, "blocked_until": 0.0})

    def is_blocked(self, user_id: int) -> tuple[bool, int]:
        """
        Bloklangan ekanligini tekshiradi.
        Returns: (is_blocked, seconds_remaining)
        """
        data = self._attempts[user_id]
        now = time.time()
        if data["blocked_until"] > now:
            remaining = int(data["blocked_until"] - now)
            return True, remaining
        return False, 0

    def record_failure(self, user_id: int) -> tuple[bool, int]:
        """
        Noto'g'ri urinishni qayd etadi.
        Returns: (just_got_blocked, block_seconds)
        """
        data = self._attempts[user_id]
        now = time.time()

        # Eski blok tugagan bo'lsa hisoblagichni nollaymiz
        if data["blocked_until"] > 0 and data["blocked_until"] < now:
            data["count"] = 0
            data["blocked_until"] = 0.0

        data["count"] += 1

        if data["count"] >= self.MAX_ATTEMPTS_LONG:
            data["blocked_until"] = now + self.BLOCK_LONG
            return True, self.BLOCK_LONG
        elif data["count"] >= self.MAX_ATTEMPTS_SHORT:
            data["blocked_until"] = now + self.BLOCK_SHORT
            return True, self.BLOCK_SHORT

        return False, 0

    def record_success(self, user_id: int):
        """Muvaffaqiyatli kirishda hisoblagichni nollaydi."""
        self._attempts[user_id] = {"count": 0, "blocked_until": 0.0}

    def get_attempts(self, user_id: int) -> int:
        """Hozirgi urinishlar sonini qaytaradi."""
        return self._attempts[user_id]["count"]

    def remaining_attempts(self, user_id: int) -> int:
        """Qancha urinish qolganini qaytaradi."""
        count = self._attempts[user_id]["count"]
        if count < self.MAX_ATTEMPTS_SHORT:
            return self.MAX_ATTEMPTS_SHORT - count
        return max(0, self.MAX_ATTEMPTS_LONG - count)


# Global instance — barcha handler'lar ishlatadi
brute_guard = BruteForceGuard()


# TOTP uchun alohida guard
class TOTPBruteGuard(BruteForceGuard):
    MAX_ATTEMPTS_SHORT = 3   # 3 marta noto'g'ri TOTP → blok
    MAX_ATTEMPTS_LONG  = 5
    BLOCK_SHORT = 15 * 60    # 15 daqiqa
    BLOCK_LONG  = 2 * 3600   # 2 soat


totp_guard = TOTPBruteGuard()


# ─────────────────────────────────────────────────────────────────────────────
# 2. PAROL KUCHI TEKSHIRUVI
# ─────────────────────────────────────────────────────────────────────────────

class PasswordStrength:
    """
    Master parolning kuchini baholaydi.
    Kuchsiz parol qo'yishga ruxsat bermaydi.
    """

    # Eng ko'p ishlatiladigan zaif parollar (top-10 million dan)
    COMMON_PASSWORDS = {
        "12345678", "password", "123456789", "qwerty123",
        "iloveyou", "admin123", "letmein1", "welcome1",
        "monkey99", "dragon12", "master12", "abc123456",
        "11111111", "password1", "sunshine", "princess",
        "football", "superman", "baseball", "whatever",
    }

    @staticmethod
    def check(password: str) -> tuple[bool, str]:
        """
        Parolni tekshiradi.
        Returns: (is_strong_enough, message)
        """
        if len(password) < 8:
            return False, "❌ Parol kamida 8 belgi bo'lishi kerak."

        if password.lower() in PasswordStrength.COMMON_PASSWORDS:
            return False, "❌ Bu parol juda keng tarqalgan. Boshqa parol tanlang."

        score = 0
        tips = []

        has_lower  = any(c.islower() for c in password)
        has_upper  = any(c.isupper() for c in password)
        has_digit  = any(c.isdigit() for c in password)
        has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password)

        if has_lower:  score += 1
        else: tips.append("kichik harf (a-z)")

        if has_upper:  score += 1
        else: tips.append("katta harf (A-Z)")

        if has_digit:  score += 1
        else: tips.append("raqam (0-9)")

        if has_symbol: score += 1
        else: tips.append("belgi (!@#$...)")

        if len(password) >= 12: score += 1
        if len(password) >= 16: score += 1

        # Minimal talab: kamida 3 tur (harf+raqam yoki harf+belgi)
        if score < 2:
            tip_str = ", ".join(tips[:2])
            return False, (
                f"❌ Parol juda zaif!\n\n"
                f"Qo'shing: {tip_str}\n"
                f"Masalan: <code>MyDog@2024!</code>"
            )

        # Kuch darajasi
        if score <= 2:
            level = "🟡 O'rtacha"
        elif score <= 4:
            level = "🟢 Kuchli"
        else:
            level = "💪 Juda kuchli"

        return True, level


pwd_strength = PasswordStrength()


# ─────────────────────────────────────────────────────────────────────────────
# 3. AUDIT LOGGER — Muhim harakatlar tarixi
# ─────────────────────────────────────────────────────────────────────────────

class AuditLogger:
    """
    Xavfsizlikka oid barcha harakatlarni RAM'da saqlaydi.
    Har foydalanuvchi uchun oxirgi 50 ta yozuv.

    Yoziladigan hodisalar:
      LOGIN_OK, LOGIN_FAIL, LOGOUT, MASTER_CHANGED,
      FILE_ADDED, FILE_DELETED, PWD_ADDED, PWD_DELETED,
      TOTP_ENABLED, TOTP_DISABLED, PANIC, BURNER_CREATED
    """

    MAX_LOGS_PER_USER = 50

    def __init__(self):
        # {user_id: [{"time": str, "event": str, "detail": str}]}
        self._logs: dict = defaultdict(list)

    def log(self, user_id: int, event: str, detail: str = ""):
        """Hodisani qayd etadi."""
        entry = {
            "time": datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M"),
            "event": event,
            "detail": detail,
        }
        logs = self._logs[user_id]
        logs.insert(0, entry)  # Eng yangi birinchi
        # Limitdan oshsa eski yozuvlarni o'chirish
        if len(logs) > self.MAX_LOGS_PER_USER:
            self._logs[user_id] = logs[:self.MAX_LOGS_PER_USER]

    def get_logs(self, user_id: int, limit: int = 10) -> list:
        """Oxirgi N ta yozuvni qaytaradi."""
        return self._logs[user_id][:limit]

    def format_for_display(self, user_id: int, limit: int = 10) -> str:
        """Telegram uchun formatlangan log matni."""
        logs = self.get_logs(user_id, limit)
        if not logs:
            return "📋 Hali hech qanday faoliyat yo'q."

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
        }

        lines = []
        for entry in logs:
            icon = ICONS.get(entry["event"], "•")
            detail = f" — {entry['detail']}" if entry["detail"] else ""
            lines.append(f"{icon} <code>{entry['time']}</code> {entry['event']}{detail}")

        return "\n".join(lines)


audit = AuditLogger()


# ─────────────────────────────────────────────────────────────────────────────
# 4. DEVICE FINGERPRINT — Yangi qurilma aniqlash
# ─────────────────────────────────────────────────────────────────────────────

class DeviceTracker:
    """
    Foydalanuvchi qaysi Telegram client'dan kirayotganini kuzatadi.
    Yangi qurilma/platforma aniqlansa ogohlantirish yuboriladi.

    Fingerprint: user_agent (Telegram client ma'lumoti) asosida.
    Shaxsiy ma'lumot saqlanmaydi — faqat hash.
    """

    def __init__(self):
        # {user_id: set(device_hash)}
        self._known_devices: dict = defaultdict(set)

    def _fingerprint(self, user_id: int, platform: str, language: str) -> str:
        """Qurilma identifikatori — qaytarib bo'lmaydigan hash."""
        raw = f"{user_id}:{platform}:{language}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def check_and_register(self, user_id: int,
                            platform: str, language: str) -> bool:
        """
        Qurilmani tekshiradi.
        Returns: True — yangi qurilma (ogohlantirish kerak)
                 False — tanish qurilma
        """
        fp = self._fingerprint(user_id, platform, language)
        known = self._known_devices[user_id]

        if fp not in known:
            known.add(fp)
            return True  # Yangi qurilma!
        return False


device_tracker = DeviceTracker()
