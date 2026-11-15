from pathlib import Path

import json
import tomllib
import yaml


def test_render_blueprint_targets_experimental_branch_and_safe_mock_mode():
    blueprint_path = Path(__file__).resolve().parents[2] / "render.yaml"
    blueprint = yaml.safe_load(blueprint_path.read_text(encoding="utf-8"))

    assert len(blueprint["services"]) == 1
    service = blueprint["services"][0]
    assert service["type"] == "web"
    assert service["runtime"] == "python"
    assert service["plan"] == "free"
    assert service["branch"] == "work/rma-backend-dashboard"
    assert service["rootDir"] == "backend"
    assert service["healthCheckPath"] == "/health"
    assert service["autoDeployTrigger"] == "checksPass"

    env = {item["key"]: item for item in service["envVars"]}
    assert env["APP_ENV"]["value"] == "production"
    assert env["MOCK_MODE"]["value"] == "true"
    for key in ("DATABASE_URL", "DIRECT_DATABASE_URL"):
        assert env[key]["sync"] is False
    assert env["ENCRYPTION_KEY"]["generateValue"] is True
    assert "TELEGRAM_BOT_TOKEN" not in env
    assert "TELEGRAM_WEBHOOK_SECRET" not in env


def test_cloudflare_pages_config_serves_frontend_root_and_functions():
    frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
    config = tomllib.loads((frontend_dir / "wrangler.toml").read_text(encoding="utf-8"))

    assert config["name"] == "rma-miniapp"
    assert config["pages_build_output_dir"] == "."
    assert config["compatibility_date"] == "2026-11-15"
    assert (frontend_dir / "index.html").is_file()
    assert (frontend_dir / "functions" / "api" / "[[path]].js").is_file()
    assert (frontend_dir / "functions" / "health.js").is_file()


def test_cloudflare_python_worker_config_keeps_mock_mode_and_hyperdrive_binding():
    backend_dir = Path(__file__).resolve().parents[1]
    config = json.loads((backend_dir / "wrangler.jsonc").read_text(encoding="utf-8"))

    assert config["name"] == "rma-api"
    assert config["main"] == "worker.py"
    assert "python_workers" in config["compatibility_flags"]
    assert config["vars"]["MOCK_MODE"] == "true"

    hyperdrive = config["hyperdrive"]
    assert len(hyperdrive) == 1
    assert hyperdrive[0]["binding"] == "HYPERDRIVE"
    assert hyperdrive[0]["id"] == "22ea3c86d6a842d2a57415dc16dc1b66"

    project = tomllib.loads((backend_dir / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["requires-python"] == ">=3.13"
    dependencies = project["project"]["dependencies"]
    for required in ("fastapi", "httpx", "pydantic-settings", "sqlalchemy", "cryptography", "psycopg[binary]"):
        assert required in dependencies
