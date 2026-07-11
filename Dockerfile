# ─────────────────────────────────────────────────────────────────────────────
# CyberKeep — Production Dockerfile
# Railway platformasi uchun optimallashtirilgan
# ─────────────────────────────────────────────────────────────────────────────

# Multi-stage build: kichik final image
FROM python:3.12-slim AS builder

# Tizim kutubxonalari (cryptography va asyncpg uchun)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Avval dependencies (cache optimizatsiyasi)
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─────────────────────────────────────────────────────────────────────────────
# Final image — minimal
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

# Runtime kutubxonalari
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user yaratish (xavfsizlik uchun root emas)
RUN useradd --no-create-home --shell /bin/false cyberkeep

WORKDIR /app

# Builder'dan o'rnatilgan paketlarni ko'chirish
COPY --from=builder /install /usr/local

# Bot kodini ko'chirish
COPY config.py database.py security.py middlewares.py states.py keyboards.py .
COPY handlers_user.py handlers_admin.py main.py .

# Fayllar egasini o'rnatish
RUN chown -R cyberkeep:cyberkeep /app

# Non-root foydalanuvchiga o'tish
USER cyberkeep

# Portni ochmaymiz (Telegram bot — WebSocket/HTTPS polling)
# Railway PORT env variable'ni avtomatik boshqaradi

# Salomatlik tekshiruvi
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import asyncio; from config import cfg; print('OK')" || exit 1

# Botni ishga tushirish
CMD ["python", "main.py"]
