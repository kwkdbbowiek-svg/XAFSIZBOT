"""
security.py — CyberKeep xavfsizlik yadrosи.

ARXITEKTURA:
  ┌─────────────────────────────────────────────────────────┐
  │  Master Parol (foydalanuvchi xotirasida)                │
  │      │                                                  │
  │      ▼                                                  │
  │  argon2id hash  ──► PostgreSQL (tekshirish uchun)       │
  │      │                                                  │
  │      ▼                                                  │
  │  PBKDF2-HMAC-SHA256 ──► 32 bayt Encryption Key (RAM)   │
  │      │                                                  │
  │      ▼                                                  │
  │  ChaCha20-Poly1305 ──► Shifrlangan BLOB (PostgreSQL)   │
  └─────────────────────────────────────────────────────────┘

HECH QANDAY KALIT DISKKA YOZILMAYDI.
"""

import os
import hmac
import hashlib
import secrets
from typing import Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from config import cfg

# ─────────────────────────────────────────────────────────────────────────────
# 1. ARGON2ID — Master parolni hashlash
#    Parametrlar OWASP 2023 tavsiyasidan olingan:
#    time_cost=3, memory_cost=65536 (64MB), parallelism=4
# ─────────────────────────────────────────────────────────────────────────────
_ph = PasswordHasher(
    time_cost=3,          # Iteratsiya soni — CPU vaqti
    memory_cost=65536,    # 64 MB RAM — GPU/ASIC uchun qimmat
    parallelism=4,        # Parallel threadlar
    hash_len=32,
    salt_len=16,
    encoding="utf-8",
)


def hash_master_password(plain_password: str) -> str:
    """
    Master parolni argon2id bilan hashlaydi.
    Qaytariladigan string bazaga yozish uchun xavfsiz.

    Argon2 o'z ichiga salt qo'shadi — alohida salt saqlash shart emas.
    """
    # Server pepper qo'shish: bazadan hash o'g'irlansa ham
    # pepper bo'lmasa crack qilib bo'lmaydi
    peppered = plain_password + cfg.SERVER_PEPPER
    return _ph.hash(peppered)


def verify_master_password(plain_password: str, stored_hash: str) -> bool:
    """
    Foydalanuvchi kiritgan parolni bazadagi hash bilan solishtiradi.
    Mos kelmasa False qaytaradi, hech qachon exception ko'tarmaydi.
    """
    peppered = plain_password + cfg.SERVER_PEPPER
    try:
        return _ph.verify(stored_hash, peppered)
    except (VerifyMismatchError, VerificationError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """
    Argon2 parametrlari yangilansa eski hashlarni qayta hishlash kerakmi?
    (Xavfsizlik yangilanishlarini avtomatik qo'llash)
    """
    return _ph.check_needs_rehash(stored_hash)


# ─────────────────────────────────────────────────────────────────────────────
# 2. PBKDF2 — Master paroldan shifrlash kaliti olish
#    Kalit FAQAT RAM'da yashaydi, diskka hech qachon yozilmaydi.
# ─────────────────────────────────────────────────────────────────────────────

def derive_encryption_key(plain_password: str, salt: bytes) -> bytes:
    """
    Master paroldan 32 baytlik ChaCha20 kalitini chiqaradi (Key Derivation).

    Args:
        plain_password: Foydalanuvchi kiritgan Master parol (RAM'da)
        salt: Har foydalanuvchi uchun noyob 32 bayt (bazada saqlanadi)

    Returns:
        32 bayt shifrlash kaliti — FAQAT RAM'da, bazaga yozilmaydi!

    Xavfsizlik qatlami:
        - Server pepper: bazadan salt o'g'irlansa ham kalit topilmaydi
        - iterations=600000: NIST 2023 tavsiyasi
    """
    peppered_password = (plain_password + cfg.SERVER_PEPPER).encode("utf-8")

    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=peppered_password,
        salt=salt,
        iterations=600_000,   # NIST SP 800-132 tavsiyasi
        dklen=32,             # ChaCha20 uchun 256 bit
    )
    return key


def generate_user_salt() -> bytes:
    """Har foydalanuvchi uchun bir marta yaratiladi, bazada ochiq saqlanadi."""
    return secrets.token_bytes(32)


# ─────────────────────────────────────────────────────────────────────────────
# 3. ChaCha20-Poly1305 — Authenticated Encryption
#    - Shifrlash + butunlik tekshiruvi bir algoritmda
#    - AES-GCM'dan tezroq, ARM/x86 hardwaresiz ham xavfsiz
# ─────────────────────────────────────────────────────────────────────────────

NONCE_SIZE = 12  # ChaCha20-Poly1305 uchun standart nonce o'lchami


def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """
    Berilgan baytlarni ChaCha20-Poly1305 bilan shifrlaydi.

    Nonce (Number Used Once):
        - Har shifrlashda tasodifiy yaratiladi (12 bayt)
        - Shifrlangan ma'lumotning oldiga qo'yiladi: [nonce(12)] + [ciphertext+tag]
        - Bir kalit bilan bir nonce HECH QACHON qayta ishlatilmaydi

    Args:
        plaintext: Shifrlash uchun xom baytlar (matn yoki fayl)
        key: 32 baytlik shifrlash kaliti (RAM'dan)

    Returns:
        nonce + ciphertext + authentication_tag (hammasi birlashtirilgan)
    """
    if len(key) != 32:
        raise ValueError("Shifrlash kaliti 32 bayt bo'lishi shart!")

    nonce = secrets.token_bytes(NONCE_SIZE)  # Kriptografik tasodifiy nonce
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, None)  # AAD yo'q

    return nonce + ciphertext  # [12 byte nonce][N byte ciphertext][16 byte tag]


def decrypt_data(ciphertext_with_nonce: bytes, key: bytes) -> bytes:
    """
    ChaCha20-Poly1305 bilan shifrlangan ma'lumotni ochadi.

    Authentication tag tekshiruvi:
        Ma'lumot o'zgartirilgan bo'lsa (hacker tamper qilsa),
        cryptography.exceptions.InvalidTag xatosi chiqadi.

    Args:
        ciphertext_with_nonce: encrypt_data() qaytargan baytlar
        key: 32 baytlik shifrlash kaliti (RAM'dan)

    Returns:
        Asl xom baytlar

    Raises:
        cryptography.exceptions.InvalidTag: Ma'lumot buzilgan yoki kalit noto'g'ri
        ValueError: Noto'g'ri format
    """
    if len(key) != 32:
        raise ValueError("Shifrlash kaliti 32 bayt bo'lishi shart!")

    if len(ciphertext_with_nonce) < NONCE_SIZE + 16:
        raise ValueError("Shifrlangan ma'lumot juda qisqa — buzilgan bo'lishi mumkin!")

    nonce = ciphertext_with_nonce[:NONCE_SIZE]
    ciphertext = ciphertext_with_nonce[NONCE_SIZE:]

    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None)


def encrypt_text(text: str, key: bytes) -> bytes:
    """Matnni UTF-8 baytga o'girib shifrlaydi."""
    return encrypt_data(text.encode("utf-8"), key)


def decrypt_text(encrypted: bytes, key: bytes) -> str:
    """Shifrlangan baytlardan matnni tiklaydi."""
    return decrypt_data(encrypted, key).decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Xavfsiz taqqoslash — Timing Attack'dan himoya
# ─────────────────────────────────────────────────────────────────────────────

def secure_compare(a: str, b: str) -> bool:
    """
    Ikkita stringni vaqt hujumidan (timing attack) xavfsiz solishtiradi.
    Oddiy == operatori turli vaqt oladigan javob berishi mumkin.
    """
    return hmac.compare_digest(
        a.encode("utf-8"),
        b.encode("utf-8")
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5. TOTP (2FA) — pyotp orqali
# ─────────────────────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """
    Yangi TOTP secret yaratadi (base32, 32 belgi).
    Bu secret BAZAGA SHIFRLANGAN holda yoziladi (encrypt_text bilan).
    """
    import pyotp
    return pyotp.random_base32()


def get_totp_uri(secret: str, user_id: int) -> str:
    """Google Authenticator uchun QR kod URI si."""
    import pyotp
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=f"user_{user_id}",
        issuer_name="CyberKeep"
    )


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Foydalanuvchi kiritgan 6 raqamli kodni tekshiradi.
    valid_window=1: 30 soniya oldin/keyin ham qabul qiladi (soat farqi uchun).
    """
    import pyotp
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
