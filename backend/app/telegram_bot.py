import hmac
import json
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Header, HTTPException, Request

from app.config import get_settings

router = APIRouter()


def build_start_reply(mini_app_url: str = "") -> dict:
    text = (
        "🌐 به R&MA VPN خوش آمدید\n\n"
        "مینی‌اپ R&MA در حال آماده‌سازی است. پس از تکمیل میزبانی امن، "
        "دکمه ورود در همین بخش فعال خواهد شد.\n\n"
        "💙 R&MA Connect\n"
        "Connect • Secure • Freedom"
    )
    reply = {"text": text}
    parsed = urlparse(mini_app_url.strip())
    if parsed.scheme == "https" and parsed.netloc and not parsed.username and not parsed.password:
        reply["reply_markup"] = {
            "inline_keyboard": [[
                {
                    "text": "🚀 ورود به مینی‌اپ R&MA",
                    "web_app": {"url": mini_app_url.strip()},
                }
            ]]
        }
    return reply


async def send_telegram_message(chat_id: int, reply: dict) -> None:
    token = get_settings().telegram_bot_token.strip()
    if not token:
        raise HTTPException(status_code=503, detail="Telegram bot is not configured")

    payload = {"chat_id": chat_id, "text": reply["text"]}
    if "reply_markup" in reply:
        payload["reply_markup"] = reply["reply_markup"]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json=payload,
            )
            response.raise_for_status()
            result = response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Telegram message delivery failed") from exc

    if not result.get("ok"):
        raise HTTPException(status_code=502, detail="Telegram message delivery failed")


@router.post("/telegram/webhook")
async def telegram_webhook(
    request: Request,
    x_telegram_bot_api_secret_token: str | None = Header(default=None),
):
    expected = get_settings().telegram_webhook_secret.strip()
    supplied = x_telegram_bot_api_secret_token or ""
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=401, detail="Invalid webhook secret")

    raw_body = await request.body()
    if len(raw_body) > 65536:
        raise HTTPException(status_code=413, detail="Telegram update is too large")
    try:
        update = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid Telegram update payload") from None
    if not isinstance(update, dict):
        raise HTTPException(status_code=400, detail="Invalid Telegram update payload")
    message = update.get("message") or update.get("edited_message") or {}
    if not isinstance(message, dict):
        return {"ok": True}
    chat = message.get("chat") or {}
    if not isinstance(chat, dict):
        return {"ok": True}
    chat_id = chat.get("id")
    text = message.get("text", "")

    if not isinstance(chat_id, int) or not isinstance(text, str):
        return {"ok": True}

    parts = text.strip().split(maxsplit=1)
    command = parts[0].split("@", 1)[0].lower() if parts else ""
    if command == "/start":
        await send_telegram_message(chat_id, build_start_reply(get_settings().mini_app_url))

    return {"ok": True}
