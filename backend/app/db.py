"""Database engine and session helpers. Imported only by roles that hold DATABASE_URL."""
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

_engine = None
_Session: sessionmaker | None = None


def get_engine():
    global _engine, _Session
    if _engine is None:
        url = get_settings().database_url
        if not url:
            raise RuntimeError("DATABASE_URL is not set for this role")
        _engine = create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=10, pool_recycle=1800)
        _Session = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def new_session() -> Session:
    get_engine()
    assert _Session is not None
    return _Session()


@contextmanager
def session_scope() -> Iterator[Session]:
    session = new_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, committed by the endpoint."""
    session = new_session()
    try:
        yield session
    finally:
        session.close()
