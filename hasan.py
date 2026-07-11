import asyncio
import datetime
import logging
import os

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.account import UpdateProfileRequest

# Loglarni sozlash
logging.basicConfig(
    format='[%(levelname) 5s/%(asctime)s] %(name)s: %(message)s',
    level=logging.INFO
)

# --- Environment variables orqali olinadi (Railway da sozlanadi) ---
API_ID = int(os.environ.get("API_ID", "33255751"))
API_HASH = os.environ.get("API_HASH", "0b819489997c5c75cfcc4d1c4f6fa6a9")
SESSION_STRING = os.environ.get("SESSION_STRING", "")
# ------------------------------------------------------------------

if SESSION_STRING:
    # Railway da StringSession ishlatiladi (fayl saqlab bo'lmaydi)
    client = TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH)
else:
    # Lokal ishlatganda fayl session ishlatiladi
    client = TelegramClient("soat_sessiyasi", API_ID, API_HASH)


async def main():
    await client.start()
    print("Userbot muvaffaqiyatli ishga tushdi!")

    oxirgi_vaqt = ""

    while True:
        # UTC+5 (Toshkent vaqti) ga moslashtirish
        toshkent_vaqt = datetime.datetime.utcnow() + datetime.timedelta(hours=5)
        hozirgi_vaqt = toshkent_vaqt.strftime("%H:%M")

        if hozirgi_vaqt != oxirgi_vaqt:
            try:
                await client(UpdateProfileRequest(first_name=hozirgi_vaqt, last_name=""))
                oxirgi_vaqt = hozirgi_vaqt
                print(f"Profil ismi o'zgartirildi: {hozirgi_vaqt}")
            except Exception as e:
                print(f"Xatolik yuz berdi: {e}")

        await asyncio.sleep(15)


if __name__ == "__main__":
    asyncio.run(main())
