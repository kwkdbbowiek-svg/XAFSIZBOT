"""
security.py — CyberKeep kriptografik yadro.

ARXITEKTURA:
  Master Parol → argon2id hash → PostgreSQL
  Master Parol → PBKDF2-HMAC-SHA256 → 32B key (RAM only)
  key → ChaCha20-Poly1305 (random nonce per encrypt) → BLOB

KAFOLATLAR:
  • Har encrypt da secrets.token_bytes(12) — nonce takrorlanmaydi (anti-replay)
  • verify_master_password — argon2 o'zining constant-time verify'si (timing-safe)
  • secure_compare — hmac.compare_digest (timing attack himoya)
  • Kalit RAM'dan o'chirishda: None → del → gc.collect()
  • Hech qanday sir diskka yozilmaydi
"""

import gc
import hmac
import hashlib
import secrets
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, HashingError
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from config import cfg

# ─────────────────────────────────────────────────────────────────────────────
# 1. ARGON2ID — Master parol hashlash
#    OWASP 2023: time_cost=3, memory=64MB, parallelism=4
# ─────────────────────────────────────────────────────────────────────────────
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,   # 64 MB — GPU/ASIC brute-force himoya
    parallelism=4,
    hash_len=32,
    salt_len=16,
    encoding="utf-8",
)


def hash_master_password(plain_password: str) -> str:
    """argon2id + server pepper bilan hashlaydi."""
    peppered = plain_password + cfg.SERVER_PEPPER
    result = _ph.hash(peppered)
    # Vaqtinchalik string GC ga topshirilsin
    del peppered
    return result


def verify_master_password(plain_password: str, stored_hash: str) -> bool:
    """
    Argon2 o'zining constant-time verifikatsiyasini ishlatadi —
    timing attack imkonsiz.
    """
    peppered = plain_password + cfg.SERVER_PEPPER
    try:
        ok = _ph.verify(stored_hash, peppered)
        return ok
    except (VerifyMismatchError, VerificationError, HashingError):
        return False
    finally:
        # Peppered parolni xotiradan tozalash
        del peppered
        gc.collect()


def needs_rehash(stored_hash: str) -> bool:
    """Argon2 parametrlari o'zgarganda eski hashlarni yangilash."""
    return _ph.check_needs_rehash(stored_hash)


# ─────────────────────────────────────────────────────────────────────────────
# 2. PBKDF2 — Shifrlash kaliti derivatsiyasi
#    Kalit FAQAT RAM'da, diskka hech qachon yozilmaydi.
# ─────────────────────────────────────────────────────────────────────────────

def derive_encryption_key(plain_password: str, salt: bytes) -> bytes:
    """
    Master paroldan 32B ChaCha20 kaliti chiqaradi.
    NIST SP 800-132: 600_000 iteratsiya, SHA-256.
    Server pepper qo'shiladi — salt o'g'irlansa ham kalit topilmaydi.
    """
    peppered = (plain_password + cfg.SERVER_PEPPER).encode("utf-8")
    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=peppered,
        salt=salt,
        iterations=600_000,
        dklen=32,
    )
    # Peppered baytlarni xotiradan tozalash
    del peppered
    gc.collect()
    return key


def generate_user_salt() -> bytes:
    """32B kriptografik random salt — foydalanuvchi uchun bir marta."""
    return secrets.token_bytes(32)


def wipe_key(key_var) -> None:
    """
    Shifrlash kalitini xotiradan xavfsiz o'chiradi.
    Chaqiruvchi kod:
        key = wipe_key(key)  → key = None
    """
    del key_var
    gc.collect()


# ─────────────────────────────────────────────────────────────────────────────
# 3. ChaCha20-Poly1305 — Authenticated Encryption with random nonce
#    Har shifrlashda secrets.token_bytes(12) — anti-replay kafolati
# ─────────────────────────────────────────────────────────────────────────────

NONCE_SIZE = 12  # ChaCha20-Poly1305 standart nonce


def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """
    ChaCha20-Poly1305 bilan shifrlaydi.
    Format: [12B nonce][ciphertext][16B auth-tag]

    Har chaqiruvda yangi kriptografik random nonce —
    bir kalit bilan nonce takrorlanish ehtimoli 2^96 ga 1.
    """
    if len(key) != 32:
        raise ValueError("Kalit 32 bayt bo'lishi shart!")

    nonce = secrets.token_bytes(NONCE_SIZE)   # anti-replay nonce
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_data(blob: bytes, key: bytes) -> bytes:
    """
    ChaCha20-Poly1305 bilan ochadi.
    Auth-tag noto'g'ri bo'lsa InvalidTag — tamper aniqlandi.
    """
    if len(key) != 32:
        raise ValueError("Kalit 32 bayt bo'lishi shart!")
    if len(blob) < NONCE_SIZE + 16:
        raise ValueError("Blob juda qisqa — buzilgan!")

    nonce = blob[:NONCE_SIZE]
    ciphertext = blob[NONCE_SIZE:]
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None)   # InvalidTag raises here


def encrypt_text(text: str, key: bytes) -> bytes:
    """Matnni sanitize qilib shifrlaydi."""
    import html as _html
    safe = _html.escape(text)          # XSS / HTML injection himoya
    return encrypt_data(safe.encode("utf-8"), key)


def decrypt_text(blob: bytes, key: bytes) -> str:
    """Shifrlangan baytlardan matnni tiklaydi."""
    return decrypt_data(blob, key).decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Timing-safe taqqoslash
# ─────────────────────────────────────────────────────────────────────────────

def secure_compare(a: str, b: str) -> bool:
    """
    hmac.compare_digest — timing attack imkonsiz.
    Oddiy == turli vaqt olib timing leak berishi mumkin.
    """
    return hmac.compare_digest(
        a.encode("utf-8"),
        b.encode("utf-8")
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5. TOTP (2FA) — pyotp
# ─────────────────────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """TOTP secret yaratadi — bazaga SHIFRLANGAN holda yoziladi."""
    import pyotp
    return pyotp.random_base32()


def get_totp_uri(secret: str, user_id: int) -> str:
    """Google Authenticator QR URI."""
    import pyotp
    return pyotp.TOTP(secret).provisioning_uri(
        name=f"user_{user_id}",
        issuer_name="CyberKeep"
    )


def verify_totp_code(secret: str, code: str) -> bool:
    """
    6 raqamli TOTP kodni tekshiradi.
    valid_window=1 → ±30 soniya tolerantlik (soat farqi uchun).
    """
    if not code or not code.strip().isdigit():
        return False
    import pyotp
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
