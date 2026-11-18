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
    assert revision.revision == "0008_usd_plan_order_prices"
    source = Path(scripts.get_revision("0002_billing_ledger").path).read_text(encoding="utf-8")
    payment_method_migration = Path(scripts.get_revision("0003_order_payment_method").path).read_text(encoding="utf-8")
    terms_migration = Path(scripts.get_revision("0004_order_terms_acceptance").path).read_text(encoding="utf-8")
    sessions_migration = Path(scripts.get_revision("0005_user_sessions").path).read_text(encoding="utf-8")
    quotes_migration = Path(scripts.get_revision("0006_expiring_payment_quotes").path).read_text(encoding="utf-8")
    order_link_migration = Path(scripts.get_revision("0007_payment_intent_order_link").path).read_text(encoding="utf-8")
    usd_price_migration = Path(revision.path).read_text(encoding="utf-8")
    initial = Path(scripts.get_revision("0001_initial").path).read_text(encoding="utf-8")
    assert '"wireguard_clients"' in initial
    assert '"wireguard_client_owners"' in initial
    assert '"orders"' in source
    assert '"entitlements"' in source
    assert '"usage_records"' in source
    assert "payment_method" in payment_method_migration
    assert '"order_terms_acceptances"' in terms_migration
    assert "terms_version" in terms_migration
    assert '"user_sessions"' in sessions_migration
    assert "token_hash" in sessions_migration
    assert "exchange_key_hash" in sessions_migration
    assert '"payment_intents"' in quotes_migration
    assert '"exchange_rates"' in quotes_migration
    assert '"payment_assets"' in quotes_migration
    assert "order_id" in order_link_migration
    assert "fk_payment_intents_order_id_orders" in order_link_migration
    assert "ondelete=" + chr(34) + "RESTRICT" + chr(34) in source
    assert "price_usd_minor" in usd_price_migration


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
            "order_terms_acceptances",
            "user_sessions",
            "exchange_rates",
            "payment_assets",
            "payment_intents",
        }
        columns = {column["name"] for column in inspector.get_columns("wireguard_clients")}
        assert {"private_key_encrypted", "config_encrypted", "created_at"} <= columns
        order_columns = {column["name"] for column in inspector.get_columns("orders")}
        assert "payment_method" in order_columns
        session_columns = {column["name"] for column in inspector.get_columns("user_sessions")}
        assert {"telegram_user_id", "token_hash", "exchange_key_hash", "init_data_hash", "expires_at", "revoked_at"} <= session_columns
        plan_columns = {column["name"] for column in inspector.get_columns("plans")}
        order_columns = {column["name"] for column in inspector.get_columns("orders")}
        assert "price_usd_minor" in plan_columns
        assert "price_usd_minor" in order_columns
        quote_columns = {column["name"] for column in inspector.get_columns("payment_intents")}
        assert {"order_id", "price_usd_minor", "payment_amount_minor", "units_per_usd", "source_snapshot", "quote_issued_at", "quote_expires_at", "payment_first_seen_at"} <= quote_columns
        quote_forekeys = inspector.get_foreign_keys("payment_intents")
        assert any(fk["referred_table"] == "orders" and fk["constrained_columns"] == ["order_id"] for fk in quote_forekeys)
        quote_indexes = inspector.get_indexes("payment_intents")
        assert any(index["name"] == "ix_payment_intents_order_id" for index in quote_indexes)
        acceptance_columns = {column["name"] for column in inspector.get_columns("order_terms_acceptances")}
        assert {"order_id", "telegram_user_id", "terms_version", "accepted_at"} <= acceptance_columns
    finally:
        engine.dispose()


def test_render_start_command_runs_migrations_before_api():
    import yaml

    render_config = yaml.safe_load((BACKEND_DIR.parent / "render.yaml").read_text(encoding="utf-8"))
    service = render_config["services"][0]
    assert service["startCommand"].startswith("alembic upgrade head && ")
    assert "uvicorn app.main:app" in service["startCommand"]
