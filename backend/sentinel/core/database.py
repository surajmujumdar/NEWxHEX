from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool
import os
import logging
from app.config import settings

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT_DIR = os.path.dirname(BASE_DIR)
LOCAL_SQLITE_PATH = os.path.join(ROOT_DIR, "sentinal.db")
if not os.path.exists(LOCAL_SQLITE_PATH):
    LOCAL_SQLITE_PATH = os.path.join(BASE_DIR, "sentinal.db")

raw_db_url = os.getenv("SENTINEL_DATABASE_URL") or getattr(settings, "DATABASE_URL", f"sqlite:///{LOCAL_SQLITE_PATH}")

def create_sentinel_engine(url):
    if url.startswith("sqlite"):
        eng = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30}, poolclass=NullPool, echo=False)
        @event.listens_for(eng, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            try:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA busy_timeout=5000")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.close()
            except Exception:
                pass
        return eng
    else:
        try:
            eng = create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10, echo=False)
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            return eng
        except Exception as e:
            logger.warning(f"[SENTINEL] Remote PostgreSQL unavailable ({e}). Falling back to local SQLite DB: {LOCAL_SQLITE_PATH}")
            return create_sentinel_engine(f"sqlite:///{LOCAL_SQLITE_PATH}")

engine = create_sentinel_engine(raw_db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
