from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.telegram_bot import build_start_reply


def test_start_reply_has_no_mini_app_button_without_https_url():
    reply = build_start_reply("")
    assert "R&MA VPN" in reply["text"]
    assert "reply_markup" not in reply


def test_start_reply_adds_mini_app_button_for_https_url():
    reply = build_start_reply("https://rma.example.pages.dev")
    button = reply["reply_markup"]["inline_keyboard"][0][0]
    assert button["web_app"]["url"] == "https://rma.example.pages.dev"


def test_start_reply_rejects_non_https_url():
    assert "reply_markup" not in build_start_reply("http://example.com")
    assert "reply_markup" not in build_start_reply("javascript:alert(1)")


def test_webhook_requires_secret(monkeypatch):
    monkeypatch.setattr(settings, "telegram_webhook_secret", "unit-test-secret")
    client = TestClient(app)
    response = client.post(
        "/telegram/webhook",
        json={"message": {"text": "/start", "chat": {"id": 123}}},
    )
    assert response.status_code == 401


def test_webhook_rejects_malformed_json(monkeypatch):
    monkeypatch.setattr(settings, "telegram_webhook_secret", "unit-test-secret")
    response = TestClient(app).post(
        "/telegram/webhook",
        headers={"X-Telegram-Bot-Api-Secret-Token": "unit-test-secret"},
        content=b"{invalid-json",
    )
    assert response.status_code == 400


def test_webhook_rejects_oversized_payload(monkeypatch):
    monkeypatch.setattr(settings, "telegram_webhook_secret", "unit-test-secret")
    response = TestClient(app).post(
        "/telegram/webhook",
        headers={"X-Telegram-Bot-Api-Secret-Token": "unit-test-secret"},
        content=b" " * 65537,
    )
    assert response.status_code == 413


def test_webhook_ignores_non_start_updates(monkeypatch):
    monkeypatch.setattr(settings, "telegram_webhook_secret", "unit-test-secret")
    client = TestClient(app)
    response = client.post(
        "/telegram/webhook",
        headers={"X-Telegram-Bot-Api-Secret-Token": "unit-test-secret"},
        json={"message": {"text": "hello", "chat": {"id": 123}}},
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_webhook_handles_start_and_telegram_username(monkeypatch):
    import asyncio
    import app.telegram_bot as bot

    monkeypatch.setattr(settings, "telegram_webhook_secret", "unit-test-secret")
    monkeypatch.setattr(settings, "mini_app_url", "")
    sent = []

    async def fake_send(chat_id, reply):
        sent.append((chat_id, reply))

    monkeypatch.setattr(bot, "send_telegram_message", fake_send)
    client = TestClient(app)
    response = client.post(
        "/telegram/webhook",
        headers={"X-Telegram-Bot-Api-Secret-Token": "unit-test-secret"},
        json={"message": {"text": "/start@RMA_Connect_Bot", "chat": {"id": 123}}},
    )
    assert response.status_code == 200
    assert len(sent) == 1
    assert sent[0][0] == 123
    assert "R&MA VPN" in sent[0][1]["text"]
    assert "reply_markup" not in sent[0][1]


def test_webhook_handles_empty_text(monkeypatch):
    monkeypatch.setattr(settings, "telegram_webhook_secret", "unit-test-secret")
    client = TestClient(app)
    response = client.post(
        "/telegram/webhook",
        headers={"X-Telegram-Bot-Api-Secret-Token": "unit-test-secret"},
        json={"message": {"text": "", "chat": {"id": 123}}},
    )
    assert response.status_code == 200
