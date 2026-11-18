"""Three independent public exchange ticker adapters.

Coinbase and Kraken are primary. Bitstamp is a continuously polled/parallel
standby source. All three requests are launched concurrently so fallback
selection never waits for a second sequential network round-trip.
"""
import asyncio
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import httpx

from app.quote_engine import RateObservation


COINBASE_TICKER_URL = "https://api.exchange.coinbase.com/products/{product_id}/ticker"
KRAKEN_TICKER_URL = "https://api.kraken.com/0/public/Ticker"
BITSTAMP_TICKER_URL = "https://www.bitstamp.net/api/v2/ticker/{market_symbol}/"


def _decimal_midpoint(bid: object, ask: object) -> Decimal:
    try:
        bid_value, ask_value = Decimal(str(bid)), Decimal(str(ask))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError("market source returned an invalid bid/ask") from None
    if not bid_value.is_finite() or not ask_value.is_finite() or bid_value <= 0 or ask_value <= 0 or ask_value < bid_value:
        raise ValueError("market source returned an invalid bid/ask")
    return (bid_value + ask_value) / Decimal(2)


def parse_coinbase_midpoint(payload: dict) -> Decimal:
    return _decimal_midpoint(payload.get("bid"), payload.get("ask"))


def parse_kraken_midpoint(payload: dict) -> Decimal:
    if payload.get("error"):
        raise ValueError("Kraken returned a market-data error")
    result = payload.get("result")
    if not isinstance(result, dict) or len(result) != 1:
        raise ValueError("Kraken response did not contain exactly one requested market")
    ticker = next(iter(result.values()))
    try:
        return _decimal_midpoint(ticker["b"][0], ticker["a"][0])
    except (KeyError, IndexError, TypeError):
        raise ValueError("Kraken ticker response is incomplete") from None


def parse_bitstamp_midpoint(payload: dict) -> Decimal:
    return _decimal_midpoint(payload.get("bid"), payload.get("ask"))


async def _fetch_coinbase(client: httpx.AsyncClient, product_id: str, observed_at: datetime) -> RateObservation:
    response = await client.get(COINBASE_TICKER_URL.format(product_id=product_id))
    response.raise_for_status()
    return RateObservation("coinbase", parse_coinbase_midpoint(response.json()), observed_at)


async def _fetch_kraken(client: httpx.AsyncClient, pair: str, observed_at: datetime) -> RateObservation:
    response = await client.get(KRAKEN_TICKER_URL, params={"pair": pair})
    response.raise_for_status()
    return RateObservation("kraken", parse_kraken_midpoint(response.json()), observed_at)


async def _fetch_bitstamp(client: httpx.AsyncClient, market_symbol: str, observed_at: datetime) -> RateObservation:
    response = await client.get(BITSTAMP_TICKER_URL.format(market_symbol=market_symbol))
    response.raise_for_status()
    return RateObservation("bitstamp", parse_bitstamp_midpoint(response.json()), observed_at)


async def fetch_three_exchange_observations(
    *,
    coinbase_product_id: str,
    kraken_pair: str,
    bitstamp_market_symbol: str,
    now: datetime | None = None,
    timeout_seconds: float = 3.0,
    client: httpx.AsyncClient | None = None,
) -> list[RateObservation]:
    """Fetch all sources concurrently; fail only if a primary is missing.

    If Bitstamp is unavailable, its missing observation is tolerated only when
    Coinbase and Kraken agree. The quote engine rejects primary disagreement
    without a fresh third observation.
    """
    product = coinbase_product_id.strip().upper()
    pair = kraken_pair.strip()
    market = bitstamp_market_symbol.strip().lower()
    if not product or "/" in product or not pair or not market or not market.isalnum():
        raise ValueError("explicit Coinbase, Kraken and Bitstamp market mappings are required")
    observed_at = now or datetime.now(timezone.utc)

    async def fetch_with(active_client: httpx.AsyncClient) -> list[RateObservation]:
        tasks = [
            _fetch_coinbase(active_client, product, observed_at),
            _fetch_kraken(active_client, pair, observed_at),
            _fetch_bitstamp(active_client, market, observed_at),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        primary_results = results[:2]
        if any(isinstance(item, BaseException) for item in primary_results):
            raise ValueError("both primary exchange sources are required") from next(
                item for item in primary_results if isinstance(item, BaseException)
            )
        observations = [primary_results[0], primary_results[1]]
        if not isinstance(results[2], BaseException):
            observations.append(results[2])
        return observations

    if client is not None:
        return await fetch_with(client)
    async with httpx.AsyncClient(timeout=timeout_seconds) as active_client:
        return await fetch_with(active_client)
