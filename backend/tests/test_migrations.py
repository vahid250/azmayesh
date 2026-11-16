from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _config() -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return config


def test_initial_migration_is_registered_and_has_expected_tables():
    scripts = ScriptDirectory.from_config(_config())
    revision = scripts.get_revision("head")

    assert revision is not None
    assert revision.revision == "0002_billing_ledger"
    source = Path(revision.path).read_text(encoding="utf-8")
    assert '"wireguard_clients"' in source
    assert '"wireguard_client_owners"' in source
    assert '"orders"' in source
    assert '"entitlements"' in source
    assert '"usage_records"' in source
    assert "ondelete=" + chr(34) + "RESTRICT" + chr(34) in source


def test_initial_migration_executes_against_empty_sqlite_database(tmp_path, monkeypatch):
    from app.config import settings

    database_file = tmp_path / "migration-test.sqlite"
    monkeypatch.setattr(settings, "database_url", f"sqlite:///{database_file}")
    command.upgrade(_config(), "head")

    engine = create_engine(f"sqlite:///{database_file}")
    try:
        inspector = inspect(engine)
        assert set(inspector.get_table_names()) == {
            "alembic_version",
            "wireguard_clients",
            "wireguard_client_owners",
            "plans",
            "orders",
            "payment_events",
            "entitlements",
            "usage_records",
        }
        columns = {column["name"] for column in inspector.get_columns("wireguard_clients")}
        assert {"private_key_encrypted", "config_encrypted", "created_at"} <= columns
    finally:
        engine.dispose()


def test_render_start_command_runs_migrations_before_api():
    import yaml

    render_config = yaml.safe_load((BACKEND_DIR.parent / "render.yaml").read_text(encoding="utf-8"))
    service = render_config["services"][0]
    assert service["startCommand"].startswith("alembic upgrade head && ")
    assert "uvicorn app.main:app" in service["startCommand"]
