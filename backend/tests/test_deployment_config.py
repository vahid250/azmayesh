from pathlib import Path

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
    for key in ("DATABASE_URL", "DIRECT_DATABASE_URL", "ENCRYPTION_KEY", "TELEGRAM_BOT_TOKEN", "TELEGRAM_WEBHOOK_SECRET"):
        assert env[key]["sync"] is False


def test_cloudflare_pages_config_serves_frontend_root_and_functions():
    import tomllib

    frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
    config = tomllib.loads((frontend_dir / "wrangler.toml").read_text(encoding="utf-8"))

    assert config["name"] == "rma-miniapp"
    assert config["pages_build_output_dir"] == "."
    assert config["compatibility_date"] == "2026-11-15"
    assert (frontend_dir / "index.html").is_file()
    assert (frontend_dir / "functions" / "api" / "[[path]].js").is_file()
    assert (frontend_dir / "functions" / "health.js").is_file()
