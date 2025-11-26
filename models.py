
from sqlalchemy import Integer, String, Float, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from db import Base

class Server(Base):
    __tablename__ = "servers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120))
    ip: Mapped[str] = mapped_column(String(64))
    username: Mapped[str] = mapped_column(String(64))
    password: Mapped[str] = mapped_column(Text)
    traffic_limit: Mapped[float] = mapped_column(Float, default=0.0)
    telegram_chat_id: Mapped[str] = mapped_column(String(64), nullable=True)
    traffic_usage: Mapped[float] = mapped_column(Float, default=0.0)
    reset_date: Mapped[str] = mapped_column(String(10), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    samples: Mapped[list["TrafficSample"]] = relationship(back_populates="server", cascade="all,delete-orphan")
    events: Mapped[list["Event"]] = relationship(back_populates="server", cascade="all,delete-orphan")

class TrafficSample(Base):
    __tablename__ = "traffic_samples"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(Integer, ForeignKey("servers.id", ondelete="CASCADE"))
    usage_gib: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    server: Mapped["Server"] = relationship(back_populates="samples")

class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(Integer, ForeignKey("servers.id", ondelete="CASCADE"))
    level: Mapped[str] = mapped_column(String(16))
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    notified: Mapped[bool] = mapped_column(Boolean, default=False)
    server: Mapped["Server"] = relationship(back_populates="events")
