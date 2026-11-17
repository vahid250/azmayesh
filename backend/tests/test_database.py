import asyncio
from types import SimpleNamespace

import pytest
from starlette.requests import Request

import app.database as database
from app.database import normalize_database_url, resolve_migration_database_url


def test_postgres_provider_url_uses_psycopg_v3():
    assert normalize_database_url("postgres://user:pass@host/db") == (
        "postgresql+psycopg://user:pass@host/db"
    )


def test_postgresql_provider_url_uses_psycopg_v3():
    assert normalize_database_url("postgresql://user:pass@host/db?sslmode=require") == (
        "postgresql+psycopg://user:pass@host/db?sslmode=require"
    )


def test_sqlite_url_is_unchanged():
    assert normalize_database_url("sqlite:///./rma_backend.db") == "sqlite:///./rma_backend.db"


def test_migrations_prefer_direct_database_url_when_configured():
    assert resolve_migration_database_url(
        "postgresql://pooled-user:pass@pooler/db",
        "postgresql://direct-user:pass@direct/db",
    ) == "postgresql+psycopg://direct-user:pass@direct/db"


def test_migrations_fall_back_to_runtime_url_when_direct_url_is_missing():
    assert resolve_migration_database_url(
        "postgresql://pooled-user:pass@pooler/db",
    ) == "postgresql+psycopg://pooled-user:pass@pooler/db"



def test_worker_database_lock_is_released_when_session_factory_raises(monkeypatch):
    monkeypatch.setenv("RMA_CLOUDFLARE_WORKER", "1")
    binding = SimpleNamespace(
        host="db.example.test",
        port=5432,
        user="worker",
        password="test-password",
        database="rma",
    )
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "env": SimpleNamespace(HYPERDRIVE=binding)})

    def failing_factory():
        raise RuntimeError("session construction failed")

    monkeypatch.setattr(database, "_worker_session_factory", lambda _url: failing_factory)

    async def exercise():
        generator = database.get_db(request)
        with pytest.raises(RuntimeError, match="session construction failed"):
            await anext(generator)
        assert not database._worker_db_lock.locked()

    asyncio.run(exercise())
