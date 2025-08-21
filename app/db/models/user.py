from datetime import datetime
from sqlalchemy import Boolean, String, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.db.base import Base


class User(Base):
    """Модель базы данных пользователя"""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="id пользователя"
    )
    username: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        comment="Логин пользователя",
        unique=True
    )
    first_name: Mapped[str] = mapped_column(
        String(30),
        nullable=True,
        comment="Имя пользователя"
    )
    last_name: Mapped[str] = mapped_column(
        String(30),
        nullable=True,
        comment="Фамилия пользователя"
    )
    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        comment="Почта пользователя")
    password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Захешированный пароль пользователя"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean(),
        default=False,
        comment="Флаг активности учётной записи"
    )
    date_joined: Mapped[datetime] = mapped_column(
        DateTime(),
        nullable=False,
        server_default=func.now(),
        comment="Дата регистрации"
    )
    last_login: Mapped[datetime] = mapped_column(
        DateTime(),
        nullable=True,
        comment="Дата и время последнего входаи"
    )
    is_superuser: Mapped[bool] = mapped_column(
        Boolean(),
        nullable=False,
        default=False,
        comment="Является ли администратором пользователь"
    )

    