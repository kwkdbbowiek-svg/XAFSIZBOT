# 🛡️ CyberKeep — Xavfsiz Telegram Seyfi

CyberKeep — foydalanuvchilarning maxfiy ma'lumotlarini (parollar, fayllar, 2FA) harbiy darajadagi shifrlash bilan himoyalovchi Telegram bot.

## 🔐 Xavfsizlik Arxitekturasi

```
Master Parol (foydalanuvchi xotirasida)
    │
    ▼
argon2id hash ──► PostgreSQL (tekshirish uchun)
    │
    ▼
PBKDF2-HMAC-SHA256 ──► 32 bayt Encryption Key (RAM)
    │
    ▼
ChaCha20-Poly1305 ──► Shifrlangan BLOB (PostgreSQL)
```

### Himoya Qatlamlari

| Qatlam | Texnologiya | Maqsad |
|--------|-------------|--------|
| 1 | argon2id (64MB RAM, 3 iter) | Master parol hashlash |
| 2 | PBKDF2-HMAC-SHA256 (600k iter) | Shifrlash kaliti derivatsiyasi |
| 3 | ChaCha20-Poly1305 | Authenticated Encryption |
| 4 | Server Pepper | Bazadan hash o'g'irlashga qarshi |
| 5 | Brute-force Guard | 5 urinish → 30 min blok |
| 6 | TOTP 2FA | Ikkinchi autentifikatsiya faktori |
| 7 | Session Timeout | 10 daqiqa harakatsizlik = chiqish |
| 8 | AntiFlood | DDoS/Spam himoyasi |
| 9 | Input Sanitizer | XSS/Injection himoyasi |
| 10 | Panic Mode | Favqulodda barcha ma'lumotlarni o'chirish |

## 🚀 Funksiyalar

- 🔑 **Parollar Ombori** — Shifrlangan parollarni saqlash
- 📁 **Xavfsiz Fayllar** — Har qanday faylni shifrlangan BLOB sifatida saqlash
- 🔥 **Burner Link** — Bir martalik xavfsiz havolalar (24 soat TTL)
- 🔐 **2FA TOTP** — Google Authenticator integratsiyasi
- 🏛️ **Merosxo'rlik** — Raqamli meros tizimi
- 🚨 **Panic Mode** — Barcha ma'lumotlarni bir zumda o'chirish
- ⚙️ **Sozlamalar** — Parol o'zgartirish, faoliyat logi

## 🛠️ O'rnatish

### Talablar
- Python 3.12+
- PostgreSQL 15+
- Telegram Bot Token ([@BotFather](https://t.me/BotFather))

### Lokal Ishga Tushirish

```bash
# 1. Reponi klonlash
git clone https://github.com/kwkdbbowiek-svg/XAFSIZBOT.git
cd XAFSIZBOT

# 2. Virtual muhit yaratish
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# 3. Kutubxonalarni o'rnatish
pip install -r requirements.txt

# 4. .env faylini yaratish
copy .env.example .env
# .env faylini to'ldiring

# 5. Botni ishga tushirish
python main.py
```

### .env Konfiguratsiya

```env
BOT_TOKEN=your_bot_token_here
ADMIN_ID=your_telegram_id
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/cyberkeep
SERVER_PEPPER=your_64_char_hex_string_here

# Ixtiyoriy
FREE_PASSWORD_LIMIT=5
FREE_FILE_LIMIT=2
SESSION_TIMEOUT=600
BURNER_LINK_TTL=86400
```

**SERVER_PEPPER yaratish:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## 🚂 Railway Deployment

1. [Railway.app](https://railway.app) ga kiring
2. "New Project" → "Deploy from GitHub repo"
3. Reponi tanlang
4. PostgreSQL plugin qo'shing
5. Variables bo'limida `.env` qiymatlarini kiriting:
   - `BOT_TOKEN`
   - `ADMIN_ID`
   - `DATABASE_URL` (Railway avtomatik beradi)
   - `SERVER_PEPPER`
6. Deploy!

## 🐳 Docker

```bash
docker build -t cyberkeep .
docker run -d \
  -e BOT_TOKEN=your_token \
  -e ADMIN_ID=your_id \
  -e DATABASE_URL=postgresql+asyncpg://... \
  -e SERVER_PEPPER=your_pepper \
  cyberkeep
```

## ⚠️ Muhim Eslatmalar

- **Master parolni unutmang** — tiklash imkonsiz
- **SERVER_PEPPER ni o'zgartirmang** — o'zgarsa barcha hashlar bekor bo'ladi
- **DATABASE_URL ni xavfsiz saqlang** — bazaga kirish imkoniyati
- `.env` faylini **hech qachon** git'ga qo'shmang

## 📊 Texnik Tafsilotlar

- **Framework:** aiogram 3.x (async)
- **ORM:** SQLAlchemy 2.0 (async)
- **DB:** PostgreSQL 15+ / asyncpg
- **Shifrlash:** cryptography (ChaCha20-Poly1305)
- **Hashing:** argon2-cffi
- **2FA:** pyotp + qrcode

## 📄 Litsenziya

MIT License — ko'proq ma'lumot uchun [LICENSE](LICENSE) ga qarang.

---

> ⚠️ **Ogohlantirish:** Bu bot maxfiy ma'lumotlarni saqlash uchun mo'ljallangan. Ishlatishdan oldin barcha xavfsizlik sozlamalarini tekshiring.
