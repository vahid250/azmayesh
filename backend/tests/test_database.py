from app.database import normalize_database_url


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
