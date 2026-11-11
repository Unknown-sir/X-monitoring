import sys
import sqlite3
from db import SessionLocal, engine
from models import Base, Server


def main(sqlite_path: str):
    src = sqlite3.connect(sqlite_path)
    cur = src.cursor()
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for row in cur.execute(
            "SELECT id, name, ip, username, password, traffic_limit, telegram_chat_id, traffic_usage, reset_date, active FROM servers"
        ):
            s = Server(
                id=row[0],
                name=row[1],
                ip=row[2],
                username=row[3],
                password=row[4],
                traffic_limit=row[5] or 0.0,
                telegram_chat_id=row[6],
                traffic_usage=row[7] or 0.0,
                reset_date=row[8],
                active=bool(row[9]) if row[9] is not None else True,
            )
            db.merge(s)
        db.commit()
    finally:
        db.close()
        src.close()
    print("Migration done.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python migrate_sqlite_to_mysql.py /path/to/database.db")
        sys.exit(1)
    main(sys.argv[1])
