"""
database.py — PostgreSQL ma'lumotlar bazasi modeli va CRUD operatsiyalari.

XAVFSIZLIK ARXITEKTURASI:
  • Bazada HECH QANDAY ochiq matn saqlanmaydi
  • Parollar: argon2id hash
  • Matnlar/Fayllar: ChaCha20-Poly1305 BLOB
  • TOTP secret: shifrlangan BLOB
  • Encryption salt: ochiq (salt maxfiy emas, kalit emas)

Jadvallar:
  users          — Foydalanuvchi profili, master_hash, salt, premium
  passwords      — Shifrlangan parollar ombori
  secret_files   — Shifrlangan fayllar (BLOB)
  burner_links   — Bir martalik havolalar
  totp_devices   — 2FA qurilmalari
  digital_legacy — Raqamli merosxo'rlik yozuvlari
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from sqlalchemy import (
    BigInteger, String, Boolean, DateTime, LargeBinary,
    Integer, Text, ForeignKey, select, delete, func, update, text
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import (
    AsyncSession, AsyncEngine,
    create_async_engine, async_sessionmaker
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from config import cfg

# ─────────────────────────────────────────────────────────────────────────────
# Engine va Session Factory
# ─────────────────────────────────────────────────────────────────────────────

def _make_engine() -> AsyncEngine:
    """SQLite va PostgreSQL uchun alohida sozlamalar."""
    url = cfg.DATABASE_URL
    if url.startswith("sqlite"):
        # SQLite — pool_size parametrsiz
        return create_async_engine(url, echo=False)
    else:
        return create_async_engine(
            url,
            echo=False,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
        )


engine: AsyncEngine = _make_engine()

AsyncSessionFactory = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_session() -> AsyncSession:
    """Dependency injection uchun — yoki kontekst menejeri sifatida."""
    async with AsyncSessionFactory() as session:
        yield session


# ─────────────────────────────────────────────────────────────────────────────
# Base Model
# ─────────────────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# JADVALLAR
# ─────────────────────────────────────────────────────────────────────────────

class User(Base):
    """
    Foydalanuvchi jadvali.
    master_hash: argon2id hash (parol emas!)
    encryption_salt: PBKDF2 uchun 32 bayt (ochiq saqlash xavfsiz)
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Telegram user_id — primary key

    username: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Master parol argon2id hashi — ochiq parol HECH QACHON saqlanmaydi
    master_hash: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    # PBKDF2 uchun noyob salt (maxfiy emas, lekin har foydalanuvchi uchun unique)
    encryption_salt: Mapped[Optional[bytes]] = mapped_column(LargeBinary(32), nullable=True)

    # Premium status
    is_premium: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    premium_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Raqamli merosxo'rlik — Telegram ID
    heir_user_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    last_active: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    passwords: Mapped[List["Password"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    files: Mapped[List["SecretFile"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    burner_links: Mapped[List["BurnerLink"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    totp_devices: Mapped[List["TOTPDevice"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Password(Base):
    """
    Shifrlangan parollar ombori.
    encrypted_title: Sarlavha (ChaCha20 bilan shifrlangan)
    encrypted_value: Parol o'zi (ChaCha20 bilan shifrlangan)
    BLOB maydon — faqat bytes, hech qachon ochiq matn emas.
    """
    __tablename__ = "passwords"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )

    encrypted_title: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_value: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_notes: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    user: Mapped["User"] = relationship(back_populates="passwords")


class SecretFile(Base):
    """
    Shifrlangan fayllar ombori.
    encrypted_data: Fayl baytlari ChaCha20-Poly1305 bilan shifrlangan BLOB.
    Fayl server diskida HECH QACHON saqlanmaydi — to'g'ridan-to'g'ri BLOB.
    """
    __tablename__ = "secret_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )

    encrypted_filename: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Fayl hajmi (bayt) — shifrlashdan oldin (UI uchun)
    original_size: Mapped[int] = mapped_column(Integer, default=0)
    mime_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    user: Mapped["User"] = relationship(back_populates="files")


class BurnerLink(Base):
    """
    Bir martalik xavfsiz havolalar.
    Havola bir marta ochiladi → ma'lumot uzatiladi → DARHOL o'chiriladi.
    token: UUID4 (taxminlab topish imkonsiz)
    """
    __tablename__ = "burner_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )

    # UUID4 token — URL'da ishlatiladi: t.me/bot?start=<token>
    token: Mapped[str] = mapped_column(
        String(36), unique=True, index=True,
        default=lambda: str(uuid.uuid4())
    )

    # Shifrlangan kontent (matn yoki fayl nomi ko'rsatkichi)
    encrypted_content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_type: Mapped[str] = mapped_column(String(20), default="text")  # text / file_id

    # TTL: yaratilgan vaqt + BURNER_LINK_TTL soniya
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Ishlatilganmi? (qo'shimcha himoya — ikki marta ochilishiga qarshi)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    user: Mapped["User"] = relationship(back_populates="burner_links")


class TOTPDevice(Base):
    """
    2FA qurilmalari.
    encrypted_secret: TOTP secret ChaCha20 bilan shifrlangan.
    """
    __tablename__ = "totp_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )

    device_name: Mapped[str] = mapped_column(String(64), default="Asosiy qurilma")
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    user: Mapped["User"] = relationship(back_populates="totp_devices")


class DigitalLegacy(Base):
    """
    Raqamli merosxo'rlik — foydalanuvchi belgilagan vaqtda
    merosxo'rga shifrlangan ma'lumotlarni topshirish.
    """
    __tablename__ = "digital_legacy"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    heir_telegram_id: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Merosxo'rga yuboriladigan shifrlangan xabar
    encrypted_message: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Necha kun faolsizlikdan keyin merosxo'rga yuborilsin
    inactivity_days: Mapped[int] = mapped_column(Integer, default=180)

    is_delivered: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class LoginAttempt(Base):
    """
    Login urinishlari tarixi (persistent log).
    RAM'dagi BruteForceGuard bilan parallel ishlaydi —
    bu jadval uzoq muddatli tahlil uchun.
    """
    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, index=True, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # Qurilma platformasi (Telegram client)
    platform: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )


class BlockedUser(Base):
    """
    Bloklangan foydalanuvchilar (admin tomonidan yoki avtomatik).
    """
    __tablename__ = "blocked_users"

    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    reason: Mapped[str] = mapped_column(String(256), default="Brute-force")
    blocked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )  # NULL = doimiy blok
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


# ─────────────────────────────────────────────────────────────────────────────
# CRUD OPERATSIYALARI
# ─────────────────────────────────────────────────────────────────────────────

class UserRepo:
    """Foydalanuvchilar bilan ishlash."""

    @staticmethod
    async def get_or_create(session: AsyncSession, user_id: int,
                            username: str = None, full_name: str = None) -> User:
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            user = User(id=user_id, username=username, full_name=full_name)
            session.add(user)
            await session.commit()
            await session.refresh(user)
        return user

    @staticmethod
    async def get(session: AsyncSession, user_id: int) -> Optional[User]:
        result = await session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def set_master_hash(session: AsyncSession, user_id: int,
                               hash_value: str, salt: bytes) -> None:
        """
        Master parol hashini va saltni bazaga saqlaydi.
        hash_value string (argon2 formati), lekin bytes sifatida saqlanadi.
        """
        await session.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                master_hash=hash_value.encode("utf-8"),
                encryption_salt=salt
            )
        )
        await session.commit()

    @staticmethod
    async def update_last_active(session: AsyncSession, user_id: int) -> None:
        await session.execute(
            update(User)
            .where(User.id == user_id)
            .values(last_active=datetime.now(timezone.utc))
        )
        await session.commit()

    @staticmethod
    async def set_premium(session: AsyncSession, user_id: int,
                           until: datetime) -> None:
        await session.execute(
            update(User)
            .where(User.id == user_id)
            .values(is_premium=True, premium_until=until)
        )
        await session.commit()

    @staticmethod
    async def count_all(session: AsyncSession) -> int:
        result = await session.execute(select(func.count(User.id)))
        return result.scalar_one()

    @staticmethod
    async def count_premium(session: AsyncSession) -> int:
        result = await session.execute(
            select(func.count(User.id)).where(User.is_premium == True)
        )
        return result.scalar_one()


class PasswordRepo:
    """Shifrlangan parollar bilan ishlash."""

    @staticmethod
    async def create(session: AsyncSession, user_id: int,
                     enc_title: bytes, enc_value: bytes,
                     enc_notes: bytes = None) -> Password:
        pwd = Password(
            user_id=user_id,
            encrypted_title=enc_title,
            encrypted_value=enc_value,
            encrypted_notes=enc_notes,
        )
        session.add(pwd)
        await session.commit()
        await session.refresh(pwd)
        return pwd

    @staticmethod
    async def list_by_user(session: AsyncSession, user_id: int) -> List[Password]:
        result = await session.execute(
            select(Password)
            .where(Password.user_id == user_id)
            .order_by(Password.created_at.desc())
        )
        return result.scalars().all()

    @staticmethod
    async def get(session: AsyncSession, pwd_id: int,
                  user_id: int) -> Optional[Password]:
        result = await session.execute(
            select(Password).where(
                Password.id == pwd_id,
                Password.user_id == user_id
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def delete(session: AsyncSession, pwd_id: int, user_id: int) -> bool:
        result = await session.execute(
            delete(Password).where(
                Password.id == pwd_id,
                Password.user_id == user_id
            )
        )
        await session.commit()
        return result.rowcount > 0

    @staticmethod
    async def count_by_user(session: AsyncSession, user_id: int) -> int:
        result = await session.execute(
            select(func.count(Password.id)).where(Password.user_id == user_id)
        )
        return result.scalar_one()


class FileRepo:
    """Shifrlangan fayllar bilan ishlash."""

    @staticmethod
    async def create(session: AsyncSession, user_id: int,
                     enc_filename: bytes, enc_data: bytes,
                     original_size: int, mime_type: str = None) -> SecretFile:
        sf = SecretFile(
            user_id=user_id,
            encrypted_filename=enc_filename,
            encrypted_data=enc_data,
            original_size=original_size,
            mime_type=mime_type,
        )
        session.add(sf)
        await session.commit()
        await session.refresh(sf)
        return sf

    @staticmethod
    async def list_by_user(session: AsyncSession, user_id: int) -> List[SecretFile]:
        result = await session.execute(
            select(SecretFile)
            .where(SecretFile.user_id == user_id)
            .order_by(SecretFile.created_at.desc())
        )
        return result.scalars().all()

    @staticmethod
    async def get(session: AsyncSession, file_id: int,
                  user_id: int) -> Optional[SecretFile]:
        result = await session.execute(
            select(SecretFile).where(
                SecretFile.id == file_id,
                SecretFile.user_id == user_id
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def delete(session: AsyncSession, file_id: int, user_id: int) -> bool:
        result = await session.execute(
            delete(SecretFile).where(
                SecretFile.id == file_id,
                SecretFile.user_id == user_id
            )
        )
        await session.commit()
        return result.rowcount > 0

    @staticmethod
    async def count_by_user(session: AsyncSession, user_id: int) -> int:
        result = await session.execute(
            select(func.count(SecretFile.id)).where(SecretFile.user_id == user_id)
        )
        return result.scalar_one()


class BurnerRepo:
    """Bir martalik havolalar bilan ishlash."""

    @staticmethod
    async def create(session: AsyncSession, user_id: int,
                     enc_content: bytes, expires_at: datetime,
                     content_type: str = "text") -> BurnerLink:
        link = BurnerLink(
            user_id=user_id,
            encrypted_content=enc_content,
            expires_at=expires_at,
            content_type=content_type,
        )
        session.add(link)
        await session.commit()
        await session.refresh(link)
        return link

    @staticmethod
    async def get_by_token(session: AsyncSession, token: str) -> Optional[BurnerLink]:
        result = await session.execute(
            select(BurnerLink).where(BurnerLink.token == token)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def consume(session: AsyncSession, token: str) -> Optional[BurnerLink]:
        """
        Havolani bir marta ishlatib, DARHOL o'chiradi.
        Atomik operatsiya: o'qish va o'chirish bitta tranzaksiyada.
        """
        result = await session.execute(
            select(BurnerLink).where(
                BurnerLink.token == token,
                BurnerLink.is_used == False,
                BurnerLink.expires_at > datetime.now(timezone.utc)
            )
        )
        link = result.scalar_one_or_none()
        if link:
            # Darhol o'chiriladi — ikkinchi marta o'qib bo'lmaydi
            await session.execute(
                delete(BurnerLink).where(BurnerLink.token == token)
            )
            await session.commit()
        return link

    @staticmethod
    async def cleanup_expired(session: AsyncSession) -> int:
        """Muddati o'tgan havolalarni tozalash (periodic task uchun)."""
        result = await session.execute(
            delete(BurnerLink).where(
                BurnerLink.expires_at < datetime.now(timezone.utc)
            )
        )
        await session.commit()
        return result.rowcount


class TOTPRepo:
    """2FA qurilmalari bilan ishlash."""

    @staticmethod
    async def create(session: AsyncSession, user_id: int,
                     enc_secret: bytes, device_name: str = "Asosiy qurilma") -> TOTPDevice:
        device = TOTPDevice(
            user_id=user_id,
            encrypted_secret=enc_secret,
            device_name=device_name,
        )
        session.add(device)
        await session.commit()
        await session.refresh(device)
        return device

    @staticmethod
    async def get_active(session: AsyncSession, user_id: int) -> Optional[TOTPDevice]:
        result = await session.execute(
            select(TOTPDevice).where(
                TOTPDevice.user_id == user_id,
                TOTPDevice.is_active == True
            ).limit(1)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def delete_all(session: AsyncSession, user_id: int) -> None:
        await session.execute(
            delete(TOTPDevice).where(TOTPDevice.user_id == user_id)
        )
        await session.commit()


class LegacyRepo:
    """Raqamli merosxo'rlik bilan ishlash."""

    @staticmethod
    async def set(session: AsyncSession, user_id: int, heir_id: int,
                  enc_message: bytes, inactivity_days: int = 180) -> DigitalLegacy:
        # Mavjud bo'lsa yangilaydi
        existing = await session.execute(
            select(DigitalLegacy).where(DigitalLegacy.user_id == user_id)
        )
        legacy = existing.scalar_one_or_none()
        if legacy:
            legacy.heir_telegram_id = heir_id
            legacy.encrypted_message = enc_message
            legacy.inactivity_days = inactivity_days
            legacy.is_delivered = False
        else:
            legacy = DigitalLegacy(
                user_id=user_id,
                heir_telegram_id=heir_id,
                encrypted_message=enc_message,
                inactivity_days=inactivity_days,
            )
            session.add(legacy)
        await session.commit()
        return legacy

    @staticmethod
    async def get(session: AsyncSession, user_id: int) -> Optional[DigitalLegacy]:
        result = await session.execute(
            select(DigitalLegacy).where(DigitalLegacy.user_id == user_id)
        )
        return result.scalar_one_or_none()


# ─────────────────────────────────────────────────────────────────────────────
# Ma'lumotlar bazasini yaratish (birinchi ishga tushishda)
# ─────────────────────────────────────────────────────────────────────────────

async def create_tables() -> None:
    """
    Barcha jadvallarni yaratadi va yetishmayotgan ustunlarni qo'shadi.
    Mavjud jadval bo'lsa o'zgartirmaydi — lekin yangi ustunlar ADD COLUMN bilan qo'shiladi.
    """
    async with engine.begin() as conn:
        # Jadvallarni yaratish (yangi o'rnatishlar uchun)
        await conn.run_sync(Base.metadata.create_all)

        # ── Migration: yetishmayotgan ustunlarni qo'shish ──────────────────
        # Eski bazalarda bo'lmasligi mumkin bo'lgan ustunlar
        migrations = [
            # (jadval, ustun, SQL turi)
            ("users", "full_name",       "VARCHAR(128)"),
            ("users", "username",        "VARCHAR(64)"),
            ("users", "heir_user_id",    "BIGINT"),
            ("users", "is_premium",      "BOOLEAN DEFAULT FALSE"),
            ("users", "premium_until",   "TIMESTAMPTZ"),
            ("users", "encryption_salt", "BYTEA"),
            ("users", "last_active",     "TIMESTAMPTZ DEFAULT NOW()"),
        ]

        for table, column, col_type in migrations:
            try:
                await conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {col_type}")
                )
            except Exception:
                pass  # Ustun allaqachon mavjud yoki jadval yo'q — o'tkazib yuboramiz


class SecurityRepo:
    """Xavfsizlik — login log va bloklar."""

    @staticmethod
    async def log_attempt(session: AsyncSession, user_id: int,
                           success: bool, platform: str = None):
        attempt = LoginAttempt(
            user_id=user_id, success=success, platform=platform
        )
        session.add(attempt)
        await session.commit()

    @staticmethod
    async def get_fail_count_last_hour(session: AsyncSession, user_id: int) -> int:
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        result = await session.execute(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.user_id == user_id,
                LoginAttempt.success == False,
                LoginAttempt.created_at >= since
            )
        )
        return result.scalar_one()

    @staticmethod
    async def is_blocked(session: AsyncSession, user_id: int) -> bool:
        result = await session.execute(
            select(BlockedUser).where(BlockedUser.user_id == user_id)
        )
        block = result.scalar_one_or_none()
        if not block:
            return False
        if block.blocked_until is None:
            return True  # Doimiy blok
        if block.blocked_until > datetime.now(timezone.utc):
            return True
        # Muddati o'tgan — o'chirish
        await session.execute(
            delete(BlockedUser).where(BlockedUser.user_id == user_id)
        )
        await session.commit()
        return False

    @staticmethod
    async def block_user(session: AsyncSession, user_id: int,
                          reason: str, until: datetime = None):
        existing = await session.execute(
            select(BlockedUser).where(BlockedUser.user_id == user_id)
        )
        block = existing.scalar_one_or_none()
        if block:
            block.reason = reason
            block.blocked_until = until
        else:
            session.add(BlockedUser(
                user_id=user_id, reason=reason, blocked_until=until
            ))
        await session.commit()

    @staticmethod
    async def unblock_user(session: AsyncSession, user_id: int):
        await session.execute(
            delete(BlockedUser).where(BlockedUser.user_id == user_id)
        )
        await session.commit()

    @staticmethod
    async def delete_all_user_data(session: AsyncSession, user_id: int):
        """
        PANIC MODE: Foydalanuvchining barcha ma'lumotlarini o'chirish.
        Cascade delete orqali bog'liq barcha yozuvlar ham o'chadi.
        """
        from sqlalchemy import delete as sa_delete
        # Parollar, fayllar, burner links, TOTP — cascade orqali o'chadi
        await session.execute(
            sa_delete(User).where(User.id == user_id)
        )
        await session.commit()

