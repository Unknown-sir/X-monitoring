from sqlalchemy import Integer, String, Float, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from db import Base


class EsxiHost(Base):
    __tablename__ = "esxi_hosts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120))
    ip: Mapped[str] = mapped_column(String(64))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(64), default="root")
    password: Mapped[str] = mapped_column(Text)
    default_datastore: Mapped[str] = mapped_column(String(128), default="datastore1")
    default_network: Mapped[str] = mapped_column(String(128), default="VM Network")
    template_vmdk: Mapped[str] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    servers: Mapped[list["Server"]] = relationship(back_populates="esxi_host")


class VpsPlan(Base):
    __tablename__ = "vps_plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True)
    name_fa: Mapped[str] = mapped_column(String(120))
    name_en: Mapped[str] = mapped_column(String(120))
    cpus: Mapped[int] = mapped_column(Integer, default=1)
    ram_gb: Mapped[int] = mapped_column(Integer, default=2)
    disk_gb: Mapped[int] = mapped_column(Integer, default=20)
    traffic_gib: Mapped[float] = mapped_column(Float, default=1000.0)
    price_toman: Mapped[int] = mapped_column(Integer, default=1190000)
    badge: Mapped[str] = mapped_column(String(64), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class IpPool(Base):
    __tablename__ = "ip_pool"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(64), unique=True)
    netmask: Mapped[str] = mapped_column(String(32), default="24")
    gateway: Mapped[str] = mapped_column(String(64))
    ipv6: Mapped[str] = mapped_column(String(128), nullable=True)
    ipv6_gateway: Mapped[str] = mapped_column(String(128), nullable=True)
    mac_address: Mapped[str] = mapped_column(String(32), nullable=True)
    is_allocated: Mapped[bool] = mapped_column(Boolean, default=False)
    server_id: Mapped[int] = mapped_column(Integer, ForeignKey("servers.id", ondelete="SET NULL"), nullable=True)
    notes: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


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

    # ESXi and Network Specific Fields
    esxi_host_id: Mapped[int] = mapped_column(Integer, ForeignKey("esxi_hosts.id", ondelete="SET NULL"), nullable=True)
    vmid: Mapped[int] = mapped_column(Integer, nullable=True)
    vm_name: Mapped[str] = mapped_column(String(120), nullable=True)
    is_suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    netmask: Mapped[str] = mapped_column(String(32), default="24")
    gateway: Mapped[str] = mapped_column(String(64), nullable=True)
    ipv6: Mapped[str] = mapped_column(String(128), nullable=True)
    ipv6_gateway: Mapped[str] = mapped_column(String(128), nullable=True)
    extra_ips: Mapped[str] = mapped_column(Text, nullable=True)
    mac_address: Mapped[str] = mapped_column(String(32), nullable=True)
    plan_name: Mapped[str] = mapped_column(String(64), nullable=True)
    cpus: Mapped[int] = mapped_column(Integer, default=2)
    ram_mb: Mapped[int] = mapped_column(Integer, default=2048)
    disk_gb: Mapped[int] = mapped_column(Integer, default=20)

    esxi_host: Mapped["EsxiHost"] = relationship(back_populates="servers")
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
