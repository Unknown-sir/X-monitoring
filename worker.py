
import time, os, threading
from datetime import datetime
import paramiko
from sqlalchemy import select, update, insert
from db import SessionLocal, engine
from models import Base, Server, TrafficSample, Event

Base.metadata.create_all(bind=engine)
MONITOR_INTERVAL = float(os.getenv("MONITOR_INTERVAL", "1.0"))
SSH_KEEPALIVE = int(os.getenv("SSH_KEEPALIVE", "30"))

def detect_iface(ssh) -> str:
    try:
        _, stdout, _ = ssh.exec_command("ip -o -4 route show to default | awk '{print $5}'")
        nic = stdout.read().decode().strip()
        return nic or "ens34"
    except Exception:
        return "ens34"

def vnstat_cmd(reset_date: str|None, nic: str) -> str:
    if reset_date:
        return (f"vnstat -m -i {nic} | awk '/[0-9]{{4}}-[0-9]{{2}}/ && $1 >= "{reset_date}" && !/estimated/ "
                "{if ($9=="TiB") s+=$8*1024; else s+=$8} END{print s?s:0}'")
    return (f"vnstat -m -i {nic} | awk '/[0-9]{{4}}-[0-9]{{2}}/ && !/estimated/ "
            "{if ($9=="TiB") s+=$8*1024; else s+=$8} END{print s?s:0}'")

def monitor_one(server_id: int):
    while True:
        db = SessionLocal()
        try:
            s = db.execute(select(Server).where(Server.id==server_id, Server.active==True)).scalar_one()
        except Exception:
            db.close(); time.sleep(3); continue

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(s.ip, username=s.username, password=s.password, timeout=10)
            if ssh.get_transport():
                ssh.get_transport().set_keepalive(SSH_KEEPALIVE)
            nic = detect_iface(ssh)
            while True:
                cmd = vnstat_cmd(s.reset_date, nic)
                _, stdout, _ = ssh.exec_command(cmd)
                out = (stdout.read().decode() or "").strip()
                usage = float(out) if out else 0.0
                db.execute(update(Server).where(Server.id==server_id).values(traffic_usage=usage, updated_at=datetime.utcnow()))
                db.execute(insert(TrafficSample).values(server_id=server_id, usage_gib=usage))
                db.commit()
                if s.traffic_limit and usage > s.traffic_limit:
                    try: ssh.exec_command("sudo shutdown -h now")
                    except Exception: pass
                    db.execute(insert(Event).values(server_id=server_id, level="critical", message=f"Server {s.name} ({s.ip}) exceeded limit {s.traffic_limit} GiB; shutdown issued."))
                    db.commit()
                time.sleep(MONITOR_INTERVAL)
        except Exception:
            time.sleep(3)
        finally:
            try: ssh.close()
            except: pass
            db.close()

def manager():
    threads = {}
    while True:
        db = SessionLocal()
        ids = db.execute(select(Server.id).where(Server.active==True)).scalars().all()
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
