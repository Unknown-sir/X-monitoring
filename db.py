import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

load_dotenv()


class Base(DeclarativeBase):
    pass


def get_db_url() -> str:
    url = os.getenv("DB_URL")
    if not url:
        # Fallback to local SQLite database if DB_URL is not configured
        return "sqlite:///database.db"
    return url


db_url = get_db_url()
engine_kwargs = {
    "pool_pre_ping": True,
    "pool_recycle": 1800,
}
if not db_url.startswith("sqlite"):
    engine_kwargs["isolation_level"] = "AUTOCOMMIT"

engine = create_engine(db_url, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)