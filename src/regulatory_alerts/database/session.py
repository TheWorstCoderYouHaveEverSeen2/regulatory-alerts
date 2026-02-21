from functools import lru_cache
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, sessionmaker

from regulatory_alerts.config import get_settings


def _enable_sqlite_fk(dbapi_conn, connection_record):
    """Enable foreign key enforcement for SQLite connections."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@lru_cache()
def get_async_engine():
    settings = get_settings()
    pool_kwargs = {} if settings.is_sqlite else {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    }
    engine = create_async_engine(settings.DATABASE_URL, echo=False, **pool_kwargs)
    if settings.is_sqlite:
        event.listen(engine.sync_engine, "connect", _enable_sqlite_fk)
    return engine


@lru_cache()
def get_async_session_factory() -> async_sessionmaker[AsyncSession]:
    engine = get_async_engine()
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@lru_cache()
def get_sync_engine():
    settings = get_settings()
    pool_kwargs = {} if settings.is_sqlite else {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    }
    engine = create_engine(settings.DATABASE_URL_SYNC, echo=False, **pool_kwargs)
    if settings.is_sqlite:
        # Ensure the data directory exists for SQLite
        db_path = settings.DATABASE_URL_SYNC.replace("sqlite:///", "")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        event.listen(engine, "connect", _enable_sqlite_fk)
    return engine


@lru_cache()
def get_sync_session_factory() -> sessionmaker[Session]:
    engine = get_sync_engine()
    return sessionmaker(engine, expire_on_commit=False)
