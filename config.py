"""
config.py — Muhit o'zgaruvchilarini boshqarish moduli.

Barcha maxfiy ma'lumotlar (token, DB URL, admin ID) .env faylidan
yoki Railway environment variables orqali o'qiladi.
Hech qanday sir kod ichida qattiq yozilmaydi (no hardcoded secrets).
"""

import os
from dataclasses import dataclass
from dotenv import load_dotenv

# .env faylini yuklash (lokal ishlab chiqish uchun)
load_dotenv()


def _require(key: str) -> str:
    """Muhit o'zgaruvchisi bo'lmasa ishga tushishni to'xtatadi."""
    value = os.getenv(key)
    if not value:
        raise RuntimeError(
            f"❌ Muhit o'zgaruvchisi topilmadi: '{key}'. "
            f"Railway Variables yoki .env faylini tekshiring."
        )
    return value


@dataclass(frozen=True)
class Config:
    # ── Telegram ──────────────────────────────────────────────────────────────
    BOT_TOKEN: str
    ADMIN_ID: int          # Faqat shu Telegram ID admin panelga kiradi

    # ── PostgreSQL (Railway avtomatik beradi) ─────────────────────────────────
    DATABASE_URL: str      # postgresql+asyncpg://user:pass@host/db

    # ── Xavfsizlik ────────────────────────────────────────────────────────────
    # 32 baytlik tasodifiy hex string — fayllar/matnlar uchun qo'shimcha
    # server-side shifrlash "peperi". Generatsiya: python -c "import secrets; print(secrets.token_hex(32))"
    SERVER_PEPPER: str

    # ── Limitlar ──────────────────────────────────────────────────────────────
    FREE_PASSWORD_LIMIT: int = 5
    FREE_FILE_LIMIT: int = 2

    # ── Sessiya timeout (soniya) ───────────────────────────────────────────────
    SESSION_TIMEOUT: int = 600   # 10 daqiqa

    # ── Bir martalik havola TTL (soniya) ──────────────────────────────────────
    BURNER_LINK_TTL: int = 86400  # 24 soat (o'qilmasa o'chadi)


def _get_db_url() -> str:
    """DATABASE_URL ni driver prefixi bilan to'g'rilaydi."""
    url = _require("DATABASE_URL")
    if url.startswith("postgresql://") or url.startswith("postgres://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    # sqlite+aiosqlite — lokal test uchun, o'zgartirilmaydi
    return url


def load_config() -> Config:
    """Config obyektini muhit o'zgaruvchilaridan yaratadi."""
    return Config(
        BOT_TOKEN=_require("BOT_TOKEN"),
        ADMIN_ID=int(_require("ADMIN_ID")),
        DATABASE_URL=_get_db_url(),
        SERVER_PEPPER=_require("SERVER_PEPPER"),
        FREE_PASSWORD_LIMIT=int(os.getenv("FREE_PASSWORD_LIMIT", "5")),
        FREE_FILE_LIMIT=int(os.getenv("FREE_FILE_LIMIT", "2")),
        SESSION_TIMEOUT=int(os.getenv("SESSION_TIMEOUT", "600")),
        BURNER_LINK_TTL=int(os.getenv("BURNER_LINK_TTL", "86400")),
    )


# Global config obyekti — boshqa modullar shu yerdan import qiladi
cfg: Config = load_config()
