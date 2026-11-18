"""Public, unauthenticated spot-price adapters for Coinbase Exchange and Kraken.

Both observations are fetched server-side at quote time. A failure or missing
market on either venue must prevent quote issuance; never fall back to a single
source or accept prices supplied by the Mini App.
"""
import asyncio
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import httpx

from app.quote_engine import RateObservation


COINBASE_TICKER_URL = "https://api.exchange.coinbase.com/products/{product_id}/ticker"
KRAKEN_TICKER_URL = "https://api.kraken.com/0/public/Ticker"


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


async def _fetch_coinbase(client: httpx.AsyncClient, product_id: str, observed_at: datetime) -> RateObservation:
    response = await client.get(COINBASE_TICKER_URL.format(product_id=product_id))
    response.raise_for_status()
    return RateObservation("coinbase", parse_coinbase_midpoint(response.json()), observed_at)


async def _fetch_kraken(client: httpx.AsyncClient, pair: str, observed_at: datetime) -> RateObservation:
    response = await client.get(KRAKEN_TICKER_URL, params={"pair": pair})
    response.raise_for_status()
    return RateObservation("kraken", parse_kraken_midpoint(response.json()), observed_at)


async def fetch_dual_exchange_observations(
    *,
    coinbase_product_id: str,
    kraken_pair: str,
    now: datetime | None = None,
    timeout_seconds: float = 3.0,
    client: httpx.AsyncClient | None = None,
) -> list[RateObservation]:
    """Fetch a midpoint from each independent venue, failing closed on either error."""
    product = coinbase_product_id.strip().upper()
    pair = kraken_pair.strip()
    if not product or "/" in product or not pair:
        raise ValueError("explicit Coinbase product and Kraken pair mappings are required")
    observed_at = now or datetime.now(timezone.utc)

    async def fetch_with(active_client: httpx.AsyncClient) -> list[RateObservation]:
        results = await asyncio.gather(
            _fetch_coinbase(active_client, product, observed_at),
            _fetch_kraken(active_client, pair, observed_at),
            return_exceptions=True,
        )
        errors = [item for item in results if isinstance(item, BaseException)]
        if errors:
            raise ValueError("both independent exchange sources are required for a quote") from errors[0]
        return list(results)

    if client is not None:
        return await fetch_with(client)
    async with httpx.AsyncClient(timeout=timeout_seconds) as active_client:
        return await fetch_with(active_client)
