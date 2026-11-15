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
