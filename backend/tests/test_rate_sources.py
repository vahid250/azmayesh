import asyncio
from datetime import datetime, timezone
from decimal import Decimal

import httpx
import pytest

from app.rate_sources import (
    fetch_three_exchange_observations,
    parse_bitstamp_midpoint,
    parse_coinbase_midpoint,
    parse_kraken_midpoint,
)


def test_coinbase_midpoint_uses_best_bid_and_ask():
    assert parse_coinbase_midpoint({"bid": "0.999", "ask": "1.001"}) == Decimal("1.000")


def test_kraken_midpoint_uses_best_bid_and_ask():
    payload = {"error": [], "result": {"USDTUSD": {"b": ["0.999", "10"], "a": ["1.001", "10"]}}}
    assert parse_kraken_midpoint(payload) == Decimal("1.000")


def test_bitstamp_midpoint_uses_best_bid_and_ask():
    assert parse_bitstamp_midpoint({"bid": "0.999", "ask": "1.001"}) == Decimal("1.000")


def test_rate_parsers_reject_invalid_market_data():
    with pytest.raises(ValueError):
        parse_coinbase_midpoint({"bid": "0", "ask": "1"})
    with pytest.raises(ValueError):
        parse_kraken_midpoint({"error": ["EQuery:Unknown asset pair"], "result": {}})
    with pytest.raises(ValueError):
        parse_bitstamp_midpoint({"bid": "2", "ask": "1"})


def test_disagreement_uses_already_started_backup_source():
    async def run_test():
        def handler(request):
            if request.url.host == "api.exchange.coinbase.com":
                return httpx.Response(200, json={"bid": "1", "ask": "1"})
            if request.url.host == "api.kraken.com":
                return httpx.Response(200, json={"error": [], "result": {"USDTUSD": {"b": ["1.1", "10"], "a": ["1.1", "10"]}}})
            return httpx.Response(200, json={"bid": "1.001", "ask": "1.001"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            now = datetime(2026, 11, 18, tzinfo=timezone.utc)
            rows = await fetch_three_exchange_observations(
                coinbase_product_id="USDT-USD",
                kraken_pair="USDTUSD",
                bitstamp_market_symbol="usdtusd",
                now=now,
                client=client,
            )
        finally:
            await client.aclose()
        assert [row.source for row in rows] == ["coinbase", "kraken", "bitstamp"]
        assert all(row.observed_at == now for row in rows)

    asyncio.run(run_test())


def test_agreeing_primary_sources_do_not_wait_for_backup():
    async def run_test():
        async def handler(request):
            if request.url.host == "api.exchange.coinbase.com":
                return httpx.Response(200, json={"bid": "1", "ask": "1"})
            if request.url.host == "api.kraken.com":
                return httpx.Response(200, json={"error": [], "result": {"USDTUSD": {"b": ["1", "10"], "a": ["1", "10"]}}})
            await asyncio.sleep(0.5)
            return httpx.Response(200, json={"bid": "1", "ask": "1"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            rows = await asyncio.wait_for(
                fetch_three_exchange_observations(
                    coinbase_product_id="USDT-USD",
                    kraken_pair="USDTUSD",
                    bitstamp_market_symbol="usdtusd",
                    client=client,
                ),
                timeout=0.25,
            )
        finally:
            await client.aclose()
        assert [row.source for row in rows] == ["coinbase", "kraken"]

    asyncio.run(run_test())


def test_primary_failure_blocks_quote_but_backup_failure_is_tolerated_if_primaries_agree():
    async def run_test():
        def handler(request):
            if request.url.host == "api.exchange.coinbase.com":
                return httpx.Response(200, json={"bid": "1", "ask": "1"})
            if request.url.host == "api.kraken.com":
                return httpx.Response(200, json={"error": [], "result": {"USDTUSD": {"b": ["1", "10"], "a": ["1", "10"]}}})
            return httpx.Response(503)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            rows = await fetch_three_exchange_observations(
                coinbase_product_id="USDT-USD",
                kraken_pair="USDTUSD",
                bitstamp_market_symbol="usdtusd",
                client=client,
            )
        finally:
            await client.aclose()
        assert [row.source for row in rows] == ["coinbase", "kraken"]

    asyncio.run(run_test())


def test_production_observation_timestamp_is_recorded_after_response_arrives():
    async def run_test():
        request_started = {}

        async def handler(request):
            request_started[request.url.host] = datetime.now(timezone.utc)
            await asyncio.sleep(0.02)
            if request.url.host == "api.exchange.coinbase.com":
                return httpx.Response(200, json={"bid": "1", "ask": "1"})
            if request.url.host == "api.kraken.com":
                return httpx.Response(200, json={"error": [], "result": {"USDTUSD": {"b": ["1", "10"], "a": ["1", "10"]}}})
            return httpx.Response(200, json={"bid": "1", "ask": "1"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            rows = await fetch_three_exchange_observations(
                coinbase_product_id="USDT-USD",
                kraken_pair="USDTUSD",
                bitstamp_market_symbol="usdtusd",
                client=client,
            )
        finally:
            await client.aclose()

        assert len(rows) == 2
        for row in rows:
            host = {
                "coinbase": "api.exchange.coinbase.com",
                "kraken": "api.kraken.com",
            }[row.source]
            assert row.observed_at >= request_started[host]

    asyncio.run(run_test())
