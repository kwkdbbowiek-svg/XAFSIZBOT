"""
main.py — CyberKeep bot kirish nuqtasi.

Ishga tushirish tartibi:
  1. Config va DB tekshiriladi
  2. Jadvallar yaratiladi (create_tables)
  3. Middleware'lar ulanchiladi
  4. Router'lar ro'yxatdan o'tkaziladi
  5. Polling boshlanadi
"""

import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.fsm.storage.memory import MemoryStorage

from config import cfg
from database import create_tables
from middlewares import DatabaseMiddleware, SessionTimeoutMiddleware, AntiFloodMiddleware, InputSanitizerMiddleware
from handlers_user import router as user_router
from handlers_admin import router as admin_router

# Logging sozlamalari
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


async def main():
    logger.info("🚀 CyberKeep bot ishga tushmoqda...")

    # Ma'lumotlar bazasini tayyorlash
    logger.info("📦 Ma'lumotlar bazasi jadvallar tekshirilmoqda...")
    await create_tables()
    logger.info("✅ Jadvallar tayyor.")

    # Bot va Dispatcher yaratish
    bot = Bot(
        token=cfg.BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )

    # MemoryStorage: FSM ma'lumotlari (kalit, sessiya) RAM'da saqlanadi
    # Redis ishlatilsa kalit diskka tushishi mumkin — xavfsizlik uchun Memory
    storage = MemoryStorage()
    dp = Dispatcher(storage=storage)

    # Middleware'larni ulash — tartib muhim!
    # 1. AntiFlood — birinchi, zararli so'rovlarni darhol to'xtatadi
    dp.update.middleware(AntiFloodMiddleware())
    # 2. InputSanitizer — matnlarni tozalaydi
    dp.update.middleware(InputSanitizerMiddleware())
    # 3. Database — DB sessiyasini inject qiladi
    dp.update.middleware(DatabaseMiddleware())
    # 4. SessionTimeout — sessiya vaqtini boshqaradi
    dp.update.middleware(SessionTimeoutMiddleware())

    # Router'larni ulash (admin birinchi — priority)
    dp.include_router(admin_router)
    dp.include_router(user_router)

    logger.info("🔐 Xavfsizlik qatlamlari aktiv:")
    logger.info("  ✅ argon2id (Master parol hashlash)")
    logger.info("  ✅ ChaCha20-Poly1305 (Authenticated Encryption)")
    logger.info("  ✅ PBKDF2-HMAC-SHA256 (Kalit derivatsiyasi)")
    logger.info("  ✅ FSM MemoryStorage (Kalit faqat RAM'da)")
    logger.info("  ✅ Session timeout: 10 daqiqa")
    logger.info("  ✅ AntiFlood: 3msg/3s, 20msg/60s, 10cb/5s")
    logger.info("  ✅ Bot-detector: 100ms tezlik aniqlash")
    logger.info("  ✅ Input sanitizer: XSS/Injection himoya")
    logger.info("🤖 Bot polling boshlanmoqda...")

    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        await bot.session.close()
        logger.info("👋 Bot to'xtatildi.")


if __name__ == "__main__":
    asyncio.run(main())
