import asyncio
from datetime import datetime, timezone
from decimal import Decimal

import httpx
import pytest

from app.rate_sources import (
    fetch_dual_exchange_observations,
    parse_coinbase_midpoint,
    parse_kraken_midpoint,
)


def test_coinbase_midpoint_uses_best_bid_and_ask():
    assert parse_coinbase_midpoint({"bid": "0.999", "ask": "1.001"}) == Decimal("1.000")


def test_kraken_midpoint_uses_best_bid_and_ask():
    payload = {"error": [], "result": {"USDTUSD": {"b": ["0.999", "10"], "a": ["1.001", "10"]}}}
    assert parse_kraken_midpoint(payload) == Decimal("1.000")


def test_rate_parser_rejects_invalid_or_empty_market_data():
    with pytest.raises(ValueError):
        parse_coinbase_midpoint({"bid": "0", "ask": "1"})
    with pytest.raises(ValueError):
        parse_kraken_midpoint({"error": ["EQuery:Unknown asset pair"], "result": {}})


def test_fetches_both_independent_sources_server_side():
    async def run_test():
        def handler(request):
            if request.url.host == "api.exchange.coinbase.com":
                return httpx.Response(200, json={"bid": "0.999", "ask": "1.001"})
            return httpx.Response(
                200,
                json={"error": [], "result": {"USDTUSD": {"b": ["0.998", "10"], "a": ["1.002", "10"]}}},
            )

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            now = datetime(2026, 11, 18, tzinfo=timezone.utc)
            rows = await fetch_dual_exchange_observations(
                coinbase_product_id="USDT-USD",
                kraken_pair="USDTUSD",
                now=now,
                client=client,
            )
        finally:
            await client.aclose()

        assert [row.source for row in rows] == ["coinbase", "kraken"]
        assert rows[0].units_per_usd == Decimal("1.000")
        assert rows[1].units_per_usd == Decimal("1.000")
        assert all(row.observed_at == now for row in rows)

    asyncio.run(run_test())


def test_fetch_fails_closed_if_one_exchange_is_unavailable():
    async def run_test():
        def handler(request):
            if request.url.host == "api.exchange.coinbase.com":
                return httpx.Response(200, json={"bid": "1", "ask": "1"})
            return httpx.Response(503)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            with pytest.raises(ValueError, match="both independent"):
                await fetch_dual_exchange_observations(
                    coinbase_product_id="USDT-USD",
                    kraken_pair="USDTUSD",
                    client=client,
                )
        finally:
            await client.aclose()

    asyncio.run(run_test())
