from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


BACKEND_DIR = Path(__file__).resolve().parents[1]


def test_initial_migration_is_registered_and_has_expected_tables():
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    scripts = ScriptDirectory.from_config(config)

    revision = scripts.get_revision("head")
    assert revision is not None
    assert revision.revision == "0001_initial"
    source = Path(revision.path).read_text(encoding="utf-8")
    assert 'op.create_table(\n        "wireguard_clients"' in source
    assert 'op.create_table(\n        "wireguard_client_owners"' in source
    assert "ondelete=\"CASCADE\"" in source


def test_render_start_command_runs_migrations_before_api():
    import yaml

    render_config = yaml.safe_load((BACKEND_DIR.parent / "render.yaml").read_text(encoding="utf-8"))
    service = render_config["services"][0]
    assert service["startCommand"].startswith("alembic upgrade head && ")
    assert "uvicorn app.main:app" in service["startCommand"]
