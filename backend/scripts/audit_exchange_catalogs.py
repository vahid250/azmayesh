"""Read-only audit of official exchange market catalogs.

This utility never writes to the database, enables payment assets, or places orders.
It records candidate direct-USD markets for human review. Kraken currency aliases
are deliberately not normalized automatically: inspect base/quote and aliases
against Kraken's current AssetPairs documentation before approving a mapping.

Usage:
    python scripts/audit_exchange_catalogs.py --output market-catalog-audit.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

URLS = {
    "coinbase": "https://api.exchange.coinbase.com/products",
    "kraken": "https://api.kraken.com/0/public/AssetPairs",
    "bitstamp": "https://www.bitstamp.net/api/v2/markets/",
}
TARGET_ASSETS = {"USDT", "USDC"}
TIMEOUT_SECONDS = 12.0


def _contains_target(value: Any) -> bool:
    text = str(value or "").upper()
    return any(asset in text for asset in TARGET_ASSETS)


def _coinbase_candidates(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise ValueError("Coinbase products response is not a list")
    rows = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        base, quote = str(item.get("base_currency", "")).upper(), str(item.get("quote_currency", "")).upper()
        if (base in TARGET_ASSETS and quote == "USD") or (base == "USD" and quote in TARGET_ASSETS):
            rows.append({
                "product_id": item.get("id"),
                "base_currency": base,
                "quote_currency": quote,
                "status": item.get("status"),
                "trading_disabled": item.get("trading_disabled"),
                "cancel_only": item.get("cancel_only"),
                "post_only": item.get("post_only"),
                "limit_only": item.get("limit_only"),
            })
    return rows


def _kraken_candidates(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or payload.get("error"):
        raise ValueError("Kraken AssetPairs response contains an error or invalid shape")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise ValueError("Kraken AssetPairs response has no result object")
    rows = []
    usd_aliases = {"USD", "ZUSD"}
    for rest_key, item in result.items():
        if not isinstance(item, dict):
            continue
        base = str(item.get("base") or "").upper()
        quote = str(item.get("quote") or "").upper()
        # Kraken commonly represents USD as ZUSD in its REST catalog.
        # Keep that raw alias for review, but only emit an exact direct-USD
        # candidate; cross pairs such as ADA/USDC and USDC/USDT are excluded.
        direct_usd = (
            (base in TARGET_ASSETS and quote in usd_aliases)
            or (base in usd_aliases and quote in TARGET_ASSETS)
        )
        if not direct_usd:
            continue
        rows.append({
            "rest_key": rest_key,
            "altname": item.get("altname"),
            "wsname": item.get("wsname"),
            "base": base,
            "quote": quote,
            "canonical_base_currency": base if base in TARGET_ASSETS else "USD",
            "canonical_quote_currency": "USD" if quote in usd_aliases else quote,
            "status": item.get("status"),
            "candidate_only": True,
            "review_note": "Direct USD candidate only; verify Kraken aliases, status, ticker response and liquidity before any manual approval.",
        })
    return rows


def _bitstamp_candidates(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        raise ValueError("Bitstamp markets response is not a list")
    rows = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        base = str(item.get("base_currency", "")).upper()
        quote = str(item.get("counter_currency", "")).upper()
        if (base in TARGET_ASSETS and quote == "USD") or (base == "USD" and quote in TARGET_ASSETS):
            rows.append({
                "market_symbol": item.get("market_symbol"),
                "base_currency": base,
                "counter_currency": quote,
                "trading": item.get("trading"),
                "matching": item.get("matching"),
                "candidate_only": True,
                "review_note": "Do not use commercially until Bitstamp data-license terms are resolved.",
            })
    return rows


PARSERS = {
    "coinbase": _coinbase_candidates,
    "kraken": _kraken_candidates,
    "bitstamp": _bitstamp_candidates,
}


def fetch_catalogs(client: httpx.Client) -> dict[str, Any]:
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "database_touched": False,
        "orders_placed": False,
        "automatic_mapping_approval": False,
        "sources": {},
    }
    for source, url in URLS.items():
        response = client.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        raw = response.content
        payload = response.json()
        report["sources"][source] = {
            "url": url,
            "http_status": response.status_code,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "response_sha256": hashlib.sha256(raw).hexdigest(),
            "candidate_markets": PARSERS[source](payload),
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only official exchange market-catalog audit")
    parser.add_argument("--output", default="market-catalog-audit.json", help="Output JSON path")
    args = parser.parse_args()
    with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=True) as client:
        report = fetch_catalogs(client)
    destination = Path(args.output)
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Saved read-only catalog audit: {destination.resolve()}")
    for source, data in report["sources"].items():
        print(f"{source}: {len(data['candidate_markets'])} candidate row(s)")


if __name__ == "__main__":
    main()
