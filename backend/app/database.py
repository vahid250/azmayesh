import asyncio
import os
from functools import lru_cache

from fastapi import HTTPException, Request
from sqlalchemy import URL, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import NullPool

from app.config import settings


def normalize_database_url(database_url: str) -> str:
    """Use the installed psycopg v3 driver for provider PostgreSQL URLs."""
    if database_url.startswith("postgres://"):
        return "postgresql+psycopg://" + database_url[len("postgres://"):]
    if database_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + database_url[len("postgresql://"):]
    return database_url


def resolve_migration_database_url(database_url: str, direct_database_url: str | None = None) -> str:
    """Prefer a provider's direct connection for schema migrations, when configured."""
    return normalize_database_url(direct_database_url or database_url)


DATABASE_URL = normalize_database_url(settings.database_url)
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Hyperdrive owns the upstream connection pool. NullPool prevents a Worker
# isolate from retaining a client connection between requests.
_worker_db_lock = asyncio.Lock()


class Base(DeclarativeBase):
    pass


def _hyperdrive_url(binding: object) -> URL:
    """Build a SQLAlchemy URL from the documented Python Hyperdrive fields."""
    try:
        host = getattr(binding, "host")
        port = int(getattr(binding, "port"))
        username = getattr(binding, "user")
        password = getattr(binding, "password")
        database = getattr(binding, "database")
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Cloudflare Hyperdrive binding is incomplete") from exc

    if not host or not username or password is None or not database:
        raise HTTPException(status_code=503, detail="Cloudflare Hyperdrive binding is incomplete")

    return URL.create(
        "postgresql+psycopg",
        username=str(username),
        password=str(password),
        host=str(host),
        port=port,
        database=str(database),
    )


@lru_cache(maxsize=4)
def _worker_session_factory(database_url: URL):
    worker_engine = create_engine(
        database_url,
        poolclass=NullPool,
        pool_pre_ping=True,
        connect_args={"prepare_threshold": None},
    )
    return sessionmaker(bind=worker_engine, autoflush=False, autocommit=False)


def get_db(request: Request):
    """Yield a database session; Cloudflare requests must use Hyperdrive.

    A Worker must never silently fall back to its ephemeral SQLite filesystem.
    Synchronous SQLAlchemy access is serialized because Hyperdrive's Python
    Worker runtime documents this requirement.
    """
    worker_runtime = os.environ.get("RMA_CLOUDFLARE_WORKER") == "1"
    if worker_runtime:
        env = request.scope.get("env")
        try:
            hyperdrive = getattr(env, "HYPERDRIVE")
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Database is not connected: configure the HYPERDRIVE binding first",
            ) from exc
        factory = _worker_session_factory(_hyperdrive_url(hyperdrive))
        # The async dependency keeps the lock for the full lifetime of the
        # synchronous SQLAlchemy session and releases it even on request errors.
        async def worker_session():
            await _worker_db_lock.acquire()
            db = factory()
            try:
                yield db
            finally:
                db.close()
                _worker_db_lock.release()
        return worker_session()

    def local_session():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    return local_session()
