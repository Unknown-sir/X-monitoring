import os
import re
import time
import threading
from datetime import datetime
import paramiko
from sqlalchemy import select, update, insert
from db import SessionLocal, engine
from models import Base, Server, EsxiHost, TrafficSample, Event
import esxi_manager

Base.metadata.create_all(bind=engine)
MONITOR_INTERVAL = float(os.getenv("MONITOR_INTERVAL", "10.0"))
SSH_KEEPALIVE = int(os.getenv("SSH_KEEPALIVE", "30"))
RESET_DATE_RE = re.compile(r"^\d{4}-\d{2}$")
IFACE_RE = re.compile(r"^[a-zA-Z0-9_.:-]+$")


def detect_iface(ssh) -> str:
    try:
        _, stdout, _ = ssh.exec_command("ip -o -4 route show to default | awk '{print $5}'")
        nic = stdout.read().decode().strip().splitlines()[0] if stdout else ""
        if nic and IFACE_RE.match(nic):
            return nic
        return "ens34"
    except Exception:
        return "ens34"


def vnstat_cmd(reset_date: str | None, nic: str) -> str:
    safe_nic = nic if IFACE_RE.match(nic or "") else "ens34"
    if reset_date and RESET_DATE_RE.match(reset_date.strip()):
        clean_date = reset_date.strip()
        return (
            f"vnstat -m -i {safe_nic} | awk '/[0-9]{{4}}-[0-9]{{2}}/ && $1 >= \"{clean_date}\" && !/estimated/ "
            "{if ($9==\"TiB\") s+=$8*1024; else s+=$8} END{print s?s:0}'"
        )
    return (
        f"vnstat -m -i {safe_nic} | awk '/[0-9]{{4}}-[0-9]{{2}}/ && !/estimated/ "
        "{if ($9==\"TiB\") s+=$8*1024; else s+=$8} END{print s?s:0}'"
    )


def monitor_one(server_id: int):
    while True:
        db = SessionLocal()
        try:
            s = db.execute(select(Server).where(Server.id == server_id, Server.active == True)).scalar_one()
        except Exception:
            db.close()
            time.sleep(3)
            continue

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(s.ip, username=s.username, password=s.password, timeout=10)
            if ssh.get_transport():
                ssh.get_transport().set_keepalive(SSH_KEEPALIVE)
            nic = detect_iface(ssh)
            while True:
                db.refresh(s)
                if not s.active:
                    break
                cmd = vnstat_cmd(s.reset_date, nic)
                _, stdout, _ = ssh.exec_command(cmd)
                out = (stdout.read().decode() or "").strip()
                try:
                    usage = float(out.splitlines()[-1]) if out else 0.0
                except ValueError:
                    usage = 0.0

                now = datetime.utcnow()
                db.execute(
                    update(Server)
                    .where(Server.id == server_id)
                    .values(traffic_usage=usage, updated_at=now)
                )
                db.execute(
                    insert(TrafficSample).values(
                        server_id=server_id,
                        usage_gib=usage,
                        created_at=now,
                    )
                )
                db.commit()

                # بررسی حد مجاز ترافیک
                if s.traffic_limit and s.traffic_limit > 0 and usage > s.traffic_limit:
                    if s.esxi_host_id and s.vmid and not s.is_suspended:
                        host = db.execute(select(EsxiHost).where(EsxiHost.id == s.esxi_host_id)).scalar_one_or_none()
                        if host:
                            esxi_manager.set_vnic_connection(
                                host.ip, host.port, host.username, host.password, s.vmid, connected=False
                            )
                            db.execute(update(Server).where(Server.id == server_id).values(is_suspended=True))
                            db.execute(
                                insert(Event).values(
                                    server_id=server_id,
                                    level="critical",
                                    message=f"Server {s.name} ({s.ip}) exceeded limit {s.traffic_limit} GiB; Network suspended on ESXi.",
                                    created_at=now,
                                )
                            )
                            db.commit()
                    elif not s.is_suspended:
                        try:
                            ssh.exec_command("sudo shutdown -h now")
                        except Exception:
                            pass
                        db.execute(
                            insert(Event).values(
                                server_id=server_id,
                                level="critical",
                                message=f"Server {s.name} ({s.ip}) exceeded limit {s.traffic_limit} GiB; shutdown issued.",
                                created_at=now,
                            )
                        )
                        db.commit()

                # بازگردانی خودکار شبکه در صورت افزایش مجدد سقف ترافیک
                elif s.is_suspended and s.traffic_limit and usage <= s.traffic_limit and s.esxi_host_id and s.vmid:
                    host = db.execute(select(EsxiHost).where(EsxiHost.id == s.esxi_host_id)).scalar_one_or_none()
                    if host:
                        esxi_manager.set_vnic_connection(
                            host.ip, host.port, host.username, host.password, s.vmid, connected=True
                        )
                        db.execute(update(Server).where(Server.id == server_id).values(is_suspended=False))
                        db.execute(
                            insert(Event).values(
                                server_id=server_id,
                                level="info",
                                message=f"Traffic limit updated for {s.name}; Network unsuspended on ESXi.",
                                created_at=now,
                            )
                        )
                        db.commit()

                time.sleep(MONITOR_INTERVAL)
        except Exception:
            time.sleep(3)
        finally:
            try:
                ssh.close()
            except Exception:
                pass
            db.close()


def manager():
    threads = {}
    while True:
        db = SessionLocal()
        try:
            ids = db.execute(select(Server.id).where(Server.active == True)).scalars().all()
        finally:
            db.close()
        for sid in ids:
            t = threads.get(sid)
            if not t or not t.is_alive():
                t = threading.Thread(target=monitor_one, args=(sid,), daemon=True)
                t.start()
                threads[sid] = t
        time.sleep(10)


if __name__ == "__main__":
    manager()
