from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
import os
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_DIR = os.path.dirname(BASE_DIR)
LOCAL_SQLITE_PATH = os.path.join(ROOT_DIR, "ai_security.db")
if not os.path.exists(LOCAL_SQLITE_PATH):
    LOCAL_SQLITE_PATH = os.path.join(BASE_DIR, "ai_security.db")

raw_db_url = os.getenv("VAJRA_DATABASE_URL") or os.getenv("DATABASE_URL") or f"sqlite:///{LOCAL_SQLITE_PATH}"

if raw_db_url.startswith("sqlite:///."):
    db_relative = raw_db_url.replace("sqlite:///./", "").replace("sqlite:///", "")
    DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, db_relative)}"
elif raw_db_url.startswith("postgres://"):
    DATABASE_URL = raw_db_url.replace("postgres://", "postgresql://", 1)
else:
    DATABASE_URL = raw_db_url

def create_configured_engine(url):
    if url.startswith("sqlite"):
        eng = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30}, poolclass=NullPool)
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
            eng = create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10)
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            return eng
        except Exception as e:
            logger.warning(f"[VAJRA] Remote PostgreSQL unavailable ({e}). Falling back to local SQLite DB: {LOCAL_SQLITE_PATH}")
            return create_configured_engine(f"sqlite:///{LOCAL_SQLITE_PATH}")

engine = create_configured_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
