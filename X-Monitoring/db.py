
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

class Base(DeclarativeBase):
    pass

def get_db_url():
    url = os.getenv("DB_URL")
    if not url:
        raise RuntimeError("DB_URL not set. Example: mysql+pymysql://user:pass@127.0.0.1/xmonitor?charset=utf8mb4")
    return url

engine = create_engine(
    get_db_url(),
    pool_pre_ping=True,
    pool_recycle=1800,
    isolation_level="AUTOCOMMIT"
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
