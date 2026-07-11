import asyncio
import datetime
import logging
import os
import sys

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.functions.account import UpdateProfileRequest

# Loglarni sozlash
logging.basicConfig(
    format='[%(levelname) 5s/%(asctime)s] %(name)s: %(message)s',
    level=logging.INFO
)

# --- Environment variables ---
API_ID = int(os.environ.get("API_ID", "0"))
API_HASH = os.environ.get("API_HASH", "")
SESSION_STRING = os.environ.get("SESSION_STRING", "")

# SESSION_STRING majburiy — yo'q bo'lsa ishga tushmaydi
if not SESSION_STRING:
    print("❌ XATO: SESSION_STRING environment variable topilmadi!")
    print("Railway -> Variables bo'limiga SESSION_STRING qo'shing.")
    sys.exit(1)

if not API_ID or not API_HASH:
    print("❌ XATO: API_ID yoki API_HASH topilmadi!")
    sys.exit(1)

client = TelegramClient(StringSession(SESSION_STRING), API_ID, API_HASH)


async def main():
    await client.connect()

    if not await client.is_user_authorized():
        print("❌ XATO: Session yaroqsiz! Yangi SESSION_STRING oling.")
        sys.exit(1)

    me = await client.get_me()
    print(f"✅ Userbot ishga tushdi! Hisob: {me.first_name}")

    oxirgi_vaqt = ""

    while True:
        # UTC+5 (Toshkent vaqti)
        toshkent_vaqt = datetime.datetime.utcnow() + datetime.timedelta(hours=5)
        hozirgi_vaqt = toshkent_vaqt.strftime("%H:%M")

        if hozirgi_vaqt != oxirgi_vaqt:
            try:
                await client(UpdateProfileRequest(first_name=hozirgi_vaqt, last_name=""))
                oxirgi_vaqt = hozirgi_vaqt
                print(f"✅ Vaqt yangilandi: {hozirgi_vaqt}")
            except Exception as e:
                print(f"❌ Xatolik: {e}")

        await asyncio.sleep(15)


if __name__ == "__main__":
    asyncio.run(main())
